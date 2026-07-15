"""Purpose-bound OAuth transactions and cloud-document token grants."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
import urllib.parse
from typing import Any

from api import _kv
from api._employee_access import resolve_employee
from api._feishu import FeishuRequestError, env, refresh_user_token, revoke_user_token

OAUTH_TRANSACTION_TTL_SECONDS = 10 * 60
OAUTH_HANDOFF_TTL_SECONDS = 60
OAUTH_GRANT_MAX_TTL_SECONDS = 365 * 24 * 60 * 60
OAUTH_PURPOSES = {"employee_login", "desktop_login", "cloud_docs"}
LOGGER = logging.getLogger(__name__)


class OAuthConnectorError(ValueError):
    """Represent a rejected OAuth transaction, handoff, or token grant."""

    def __init__(self, code: str) -> None:
        """Initialize a connector error with a stable machine-readable code."""
        super().__init__(code)
        self.code = code


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _token_key(kind: str, token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"dianchi:oauth:{kind}:{digest}"


def _audit(
    event: str,
    *,
    purpose: str = "",
    app_key: str = "",
    employee_id: str = "",
) -> None:
    """Emit one structured event without raw identities, URLs, or tokens."""
    payload = {
        "component": "unified_feishu_connector",
        "event": event,
        "timestamp": int(time.time()),
    }
    if purpose:
        payload["purpose"] = purpose
    if app_key:
        payload["app"] = app_key
    if employee_id:
        payload["subject_hash"] = hashlib.sha256(
            employee_id.encode("utf-8")
        ).hexdigest()[:16]
    LOGGER.info(_canonical_json(payload))


def validate_return_url(value: str) -> str:
    """Validate an absolute OAuth return URL against configured origins.

    Args:
        value: Absolute HTTP(S) task callback URL.

    Returns:
        The normalized URL when its origin is allowlisted.

    Raises:
        OAuthConnectorError: If the URL is invalid or not allowlisted.
    """
    raw = str(value or "").strip()
    parsed = urllib.parse.urlsplit(raw)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise OAuthConnectorError("oauth_return_invalid")
    allowed_origins = {
        item.strip().rstrip("/")
        for item in env("FEISHU_OAUTH_RETURN_ORIGINS").split(",")
        if item.strip()
    }
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    if origin not in allowed_origins:
        raise OAuthConnectorError("oauth_return_not_allowed")
    return raw


def create_oauth_transaction(
    *,
    purpose: str,
    app_key: str,
    next_path: str,
    return_to: str = "",
) -> tuple[str, dict[str, Any]]:
    """Create one short-lived, server-consumed OAuth transaction.

    Args:
        purpose: Employee, desktop, or cloud-document OAuth purpose.
        app_key: Feishu application credential namespace.
        next_path: Safe local path for employee or desktop completion.
        return_to: Allowlisted absolute callback for cloud-document completion.

    Returns:
        Random state and the transaction payload signed into the state cookie.
    """
    if purpose not in OAUTH_PURPOSES:
        raise OAuthConnectorError("oauth_purpose_invalid")
    if purpose == "cloud_docs":
        return_to = validate_return_url(return_to)
    elif return_to:
        raise OAuthConnectorError("oauth_return_unexpected")
    now = int(time.time())
    state = secrets.token_urlsafe(32)
    payload = {
        "state": state,
        "purpose": purpose,
        "app": app_key,
        "next": next_path,
        "return_to": return_to,
        "nonce": secrets.token_urlsafe(24),
        "iat": now,
        "exp": now + OAUTH_TRANSACTION_TTL_SECONDS,
    }
    _kv.set_value(
        _token_key("transaction", state),
        _canonical_json(payload),
        ttl_seconds=OAUTH_TRANSACTION_TTL_SECONDS,
        strict=True,
    )
    _audit("oauth_transaction_created", purpose=purpose, app_key=app_key)
    return state, payload


def consume_oauth_transaction(
    state: str,
    signed_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """Atomically consume and cross-check an OAuth transaction."""
    if not state or len(state) > 256 or not isinstance(signed_payload, dict):
        raise OAuthConnectorError("oauth_state_invalid")
    if not secrets.compare_digest(
        state,
        str(signed_payload.get("state") or ""),
    ):
        raise OAuthConnectorError("oauth_state_invalid")
    raw = _kv.getdel_value(_token_key("transaction", state), strict=True)
    if not raw:
        raise OAuthConnectorError("oauth_state_expired")
    try:
        stored = json.loads(str(raw))
    except json.JSONDecodeError as exc:
        raise OAuthConnectorError("oauth_state_invalid") from exc
    if stored != signed_payload or float(stored.get("exp") or 0) < time.time():
        raise OAuthConnectorError("oauth_state_invalid")
    if stored.get("purpose") not in OAUTH_PURPOSES:
        raise OAuthConnectorError("oauth_purpose_invalid")
    _audit(
        "oauth_transaction_consumed",
        purpose=str(stored["purpose"]),
        app_key=str(stored.get("app") or ""),
    )
    return stored


def append_query(url: str, **values: str) -> str:
    """Append encoded query values to an already validated return URL."""
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.extend((key, value) for key, value in values.items())
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), "")
    )


def issue_cloud_docs_handoff(
    *,
    token_data: dict[str, Any],
    user: dict[str, Any],
    authorization: dict[str, Any],
    app_key: str,
) -> str:
    """Store Feishu tokens behind a 60-second one-time handoff code."""
    employee = authorization.get("employee") or {}
    access_token = str(token_data.get("access_token") or "")
    refresh_token = str(token_data.get("refresh_token") or "")
    if (
        not authorization.get("allowed")
        or employee.get("status") != "active"
        or not access_token
        or not refresh_token
    ):
        raise OAuthConnectorError("cloud_docs_token_incomplete")
    now = int(time.time())
    code = secrets.token_urlsafe(32)
    _kv.set_value(
        _token_key("handoff", code),
        _canonical_json(
            {
                "purpose": "cloud_docs",
                "app": app_key,
                "user": user,
                "employee_id": employee["employee_id"],
                "access_token": access_token,
                "access_token_expires_at": now
                + max(60, int(token_data.get("expires_in") or 7200)),
                "refresh_token": refresh_token,
                "refresh_token_expires_at": now
                + max(
                    60,
                    int(
                        token_data.get("refresh_token_expires_in")
                        or OAUTH_GRANT_MAX_TTL_SECONDS
                    ),
                ),
                "exp": now + OAUTH_HANDOFF_TTL_SECONDS,
            }
        ),
        ttl_seconds=OAUTH_HANDOFF_TTL_SECONDS,
        strict=True,
    )
    _audit(
        "cloud_docs_handoff_issued",
        purpose="cloud_docs",
        app_key=app_key,
        employee_id=str(employee["employee_id"]),
    )
    return code


def _grant_response(
    record: dict[str, Any],
    authorization: dict[str, Any],
) -> dict[str, Any]:
    now = int(time.time())
    refresh_expires_at = min(
        int(record["refresh_token_expires_at"]),
        now + OAUTH_GRANT_MAX_TTL_SECONDS,
    )
    ttl = max(60, refresh_expires_at - now)
    grant_token = secrets.token_urlsafe(32)
    _kv.set_value(
        _token_key("grant", grant_token),
        _canonical_json(
            {
                **record,
                "refresh_token_expires_at": refresh_expires_at,
                "grant_expires_at": refresh_expires_at,
            }
        ),
        ttl_seconds=ttl,
        strict=True,
    )
    return {
        "purpose": "cloud_docs",
        "access_token": record["access_token"],
        "access_token_expires_at": record["access_token_expires_at"],
        "grant_token": grant_token,
        "grant_expires_at": refresh_expires_at,
        "employee": authorization["employee"],
        "identity": authorization["identity"],
        "permissions": authorization.get("permissions") or [],
    }


def _active_authorization(record: dict[str, Any]) -> dict[str, Any]:
    authorization = resolve_employee(
        record.get("user") or {},
        expected_tenant=env("FEISHU_COMPANY_TENANT_KEY") or None,
    )
    if not authorization.get("allowed"):
        raise OAuthConnectorError(
            str(authorization.get("reason") or "employee_not_allowed")
        )
    if authorization["employee"].get("employee_id") != record.get("employee_id"):
        raise OAuthConnectorError("employee_identity_mismatch")
    return authorization


def exchange_cloud_docs_handoff(code: str) -> dict[str, Any]:
    """Consume a cloud-document handoff and issue an opaque rotatable grant."""
    if not code or len(code) > 256:
        raise OAuthConnectorError("handoff_invalid_or_expired")
    raw = _kv.getdel_value(_token_key("handoff", code), strict=True)
    if not raw:
        raise OAuthConnectorError("handoff_invalid_or_expired")
    try:
        record = json.loads(str(raw))
    except json.JSONDecodeError as exc:
        raise OAuthConnectorError("handoff_invalid_or_expired") from exc
    if (
        record.get("purpose") != "cloud_docs"
        or float(record.get("exp") or 0) < time.time()
    ):
        raise OAuthConnectorError("handoff_invalid_or_expired")
    authorization = _active_authorization(record)
    response = _grant_response(record, authorization)
    _audit(
        "cloud_docs_handoff_exchanged",
        purpose="cloud_docs",
        app_key=str(record.get("app") or ""),
        employee_id=str(record.get("employee_id") or ""),
    )
    return response


def check_cloud_docs_grant(grant_token: str) -> dict[str, Any]:
    """Recheck employee status before each cloud-document operation."""
    if not grant_token or len(grant_token) > 256:
        raise OAuthConnectorError("grant_invalid_or_expired")
    raw = _kv.get_value(_token_key("grant", grant_token), strict=True)
    if not raw:
        raise OAuthConnectorError("grant_invalid_or_expired")
    try:
        record = json.loads(str(raw))
    except json.JSONDecodeError as exc:
        raise OAuthConnectorError("grant_invalid_or_expired") from exc
    if float(record.get("grant_expires_at") or 0) < time.time():
        raise OAuthConnectorError("grant_invalid_or_expired")
    authorization = _active_authorization(record)
    _audit(
        "cloud_docs_grant_checked",
        purpose="cloud_docs",
        app_key=str(record.get("app") or ""),
        employee_id=str(record.get("employee_id") or ""),
    )
    return {
        "allowed": True,
        "employee": authorization["employee"],
        "identity": authorization["identity"],
        "permissions": authorization.get("permissions") or [],
    }


def refresh_cloud_docs_grant(grant_token: str) -> dict[str, Any]:
    """Rotate both the Feishu refresh token and opaque connector grant."""
    if not grant_token or len(grant_token) > 256:
        raise OAuthConnectorError("grant_invalid_or_expired")
    raw = _kv.getdel_value(_token_key("grant", grant_token), strict=True)
    if not raw:
        raise OAuthConnectorError("grant_invalid_or_expired")
    try:
        record = json.loads(str(raw))
    except json.JSONDecodeError as exc:
        raise OAuthConnectorError("grant_invalid_or_expired") from exc
    if float(record.get("grant_expires_at") or 0) < time.time():
        raise OAuthConnectorError("grant_invalid_or_expired")
    authorization = _active_authorization(record)
    try:
        token_data = refresh_user_token(record["refresh_token"], record.get("app"))
    except FeishuRequestError as exc:
        if not exc.retryable:
            raise OAuthConnectorError("cloud_docs_reauth_required") from exc
        ttl = max(60, int(record["grant_expires_at"] - time.time()))
        _kv.set_value(
            _token_key("grant", grant_token),
            _canonical_json(record),
            ttl_seconds=ttl,
            strict=True,
        )
        raise OAuthConnectorError("cloud_docs_refresh_failed") from exc
    except (KeyError, RuntimeError) as exc:
        ttl = max(60, int(record["grant_expires_at"] - time.time()))
        _kv.set_value(
            _token_key("grant", grant_token),
            _canonical_json(record),
            ttl_seconds=ttl,
            strict=True,
        )
        raise OAuthConnectorError("cloud_docs_refresh_failed") from exc
    now = int(time.time())
    refreshed = {
        **record,
        "access_token": token_data["access_token"],
        "access_token_expires_at": now
        + max(60, int(token_data.get("expires_in") or 7200)),
        "refresh_token": token_data["refresh_token"],
        "refresh_token_expires_at": now
        + max(
            60,
            int(
                token_data.get("refresh_token_expires_in")
                or OAUTH_GRANT_MAX_TTL_SECONDS
            ),
        ),
    }
    response = _grant_response(refreshed, authorization)
    _audit(
        "cloud_docs_grant_refreshed",
        purpose="cloud_docs",
        app_key=str(record.get("app") or ""),
        employee_id=str(record.get("employee_id") or ""),
    )
    return response


def revoke_cloud_docs_grant(grant_token: str) -> bool:
    """Consume a connector grant and revoke its Feishu token relationship."""
    if not grant_token or len(grant_token) > 256:
        return False
    raw = _kv.getdel_value(_token_key("grant", grant_token), strict=True)
    if not raw:
        return False
    try:
        record = json.loads(str(raw))
    except json.JSONDecodeError:
        return True
    refresh_token = str(record.get("refresh_token") or "")
    access_token = str(record.get("access_token") or "")
    app_key = str(record.get("app") or "")
    errors = []
    for token, token_type in (
        (refresh_token, "refresh_token"),
        (access_token, "access_token"),
    ):
        if not token:
            continue
        try:
            revoke_user_token(token, app_key, token_type_hint=token_type)
        except RuntimeError as exc:
            errors.append(exc)
    _audit(
        "cloud_docs_grant_revoked",
        purpose="cloud_docs",
        app_key=app_key,
        employee_id=str(record.get("employee_id") or ""),
    )
    if errors:
        raise OAuthConnectorError("cloud_docs_revoke_failed") from errors[0]
    return True
