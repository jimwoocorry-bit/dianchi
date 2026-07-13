"""One-time desktop authorization and refresh-token rotation."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import urllib.parse
from typing import Any

from api import _kv
from api._employee_access import resolve_employee
from api._feishu import SESSION_MAX_AGE, env, sign_payload


HANDOFF_TTL_SECONDS = 60
REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60


class DesktopAuthError(ValueError):
    """Represent a rejected desktop handoff or refresh operation."""

    def __init__(self, code: str) -> None:
        """Initialize a desktop authorization error.

        Args:
            code: Stable machine-readable rejection code.
        """
        super().__init__(code)
        self.code = code


def _token_key(prefix: str, token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"dianchi:desktop:{prefix}:{digest}"


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def issue_handoff(active_auth: dict[str, Any]) -> str:
    """Issue a 60-second one-time code for an active browser session.

    Args:
        active_auth: Current mirror-backed browser authorization result.

    Returns:
        Opaque one-time authorization code.

    Raises:
        DesktopAuthError: If the browser identity is not an active employee.
        RuntimeError: If persistent Redis is unavailable.
    """
    employee = active_auth.get("employee") or {}
    user = active_auth.get("user") or {}
    if (
        not active_auth.get("allowed")
        or employee.get("status") != "active"
        or not employee.get("employee_id")
        or not user.get("open_id")
    ):
        raise DesktopAuthError("employee_not_allowed")

    code = secrets.token_urlsafe(32)
    now = time.time()
    _kv.set_value(
        _token_key("handoff", code),
        _canonical_json(
            {
                "user": user,
                "employee_id": employee["employee_id"],
                "issued_at": now,
                "expires_at": now + HANDOFF_TTL_SECONDS,
            }
        ),
        ttl_seconds=HANDOFF_TTL_SECONDS,
        strict=True,
    )
    return code


def exchange_handoff(code: str, *, installation_id: str) -> dict[str, Any]:
    """Consume a one-time code and issue desktop access credentials.

    Args:
        code: Opaque browser handoff code.
        installation_id: Stable non-secret identifier for one desktop install.

    Returns:
        Signed access session, refresh token, and current employee identity.

    Raises:
        DesktopAuthError: If the code, installation, or employee is invalid.
        RuntimeError: If persistent Redis is unavailable.
    """
    if not code or len(code) > 256:
        raise DesktopAuthError("invalid_or_expired_code")
    if not installation_id or len(installation_id) > 256:
        raise DesktopAuthError("invalid_installation_id")

    raw_record = _kv.getdel_value(_token_key("handoff", code), strict=True)
    if not raw_record:
        raise DesktopAuthError("invalid_or_expired_code")
    try:
        record = json.loads(str(raw_record))
    except json.JSONDecodeError as exc:
        raise DesktopAuthError("invalid_or_expired_code") from exc
    if record.get("expires_at", 0) < time.time():
        raise DesktopAuthError("invalid_or_expired_code")

    user = record.get("user") or {}
    resolved = resolve_employee(
        user,
        expected_tenant=env("FEISHU_COMPANY_TENANT_KEY") or None,
    )
    if not resolved.get("allowed"):
        raise DesktopAuthError(resolved.get("reason", "employee_not_allowed"))
    employee = resolved["employee"]
    identity = resolved["identity"]
    if employee.get("employee_id") != record.get("employee_id"):
        raise DesktopAuthError("employee_identity_mismatch")

    user = {
        **user,
        "employee_id": employee["employee_id"],
        "employee_role": employee["role"],
        "employee_status": employee["status"],
    }
    now = int(time.time())
    session = sign_payload(
        {
            "user": user,
            "employee": employee,
            "identity": identity,
            "auth_status": "ok",
            "iat": now,
            "exp": now + SESSION_MAX_AGE,
        }
    )
    refresh_token = secrets.token_urlsafe(32)
    _kv.set_value(
        _token_key("refresh", refresh_token),
        _canonical_json(
            {
                "user": user,
                "employee_id": employee["employee_id"],
                "installation_id": installation_id,
                "issued_at": now,
                "expires_at": now + REFRESH_TTL_SECONDS,
            }
        ),
        ttl_seconds=REFRESH_TTL_SECONDS,
        strict=True,
    )
    return {
        "session": session,
        "refresh_token": refresh_token,
        "employee": employee,
        "identity": identity,
        "pet_api_url": env("DESKTOP_PET_API_URL"),
    }


def rotate_refresh(refresh_token: str, *, installation_id: str) -> dict[str, Any]:
    """Consume a refresh token and return a newly rotated credential pair.

    Args:
        refresh_token: Current opaque desktop refresh token.
        installation_id: Stable identifier of the requesting installation.

    Returns:
        Fresh signed access session, refresh token, and employee identity.

    Raises:
        DesktopAuthError: If refresh validation or employee authorization fails.
        RuntimeError: If persistent Redis is unavailable.
    """
    if not refresh_token or len(refresh_token) > 256:
        raise DesktopAuthError("invalid_or_expired_refresh")
    if not installation_id or len(installation_id) > 256:
        raise DesktopAuthError("invalid_installation_id")

    raw_record = _kv.getdel_value(
        _token_key("refresh", refresh_token),
        strict=True,
    )
    if not raw_record:
        raise DesktopAuthError("invalid_or_expired_refresh")
    try:
        record = json.loads(str(raw_record))
    except json.JSONDecodeError as exc:
        raise DesktopAuthError("invalid_or_expired_refresh") from exc
    if record.get("expires_at", 0) < time.time():
        raise DesktopAuthError("invalid_or_expired_refresh")
    if record.get("installation_id") != installation_id:
        raise DesktopAuthError("installation_mismatch")

    user = record.get("user") or {}
    resolved = resolve_employee(
        user,
        expected_tenant=env("FEISHU_COMPANY_TENANT_KEY") or None,
    )
    if not resolved.get("allowed"):
        raise DesktopAuthError(resolved.get("reason", "employee_not_allowed"))
    employee = resolved["employee"]
    identity = resolved["identity"]
    if employee.get("employee_id") != record.get("employee_id"):
        raise DesktopAuthError("employee_identity_mismatch")

    user = {
        **user,
        "employee_id": employee["employee_id"],
        "employee_role": employee["role"],
        "employee_status": employee["status"],
    }
    now = int(time.time())
    session = sign_payload(
        {
            "user": user,
            "employee": employee,
            "identity": identity,
            "auth_status": "ok",
            "iat": now,
            "exp": now + SESSION_MAX_AGE,
        }
    )
    new_refresh_token = secrets.token_urlsafe(32)
    _kv.set_value(
        _token_key("refresh", new_refresh_token),
        _canonical_json(
            {
                "user": user,
                "employee_id": employee["employee_id"],
                "installation_id": installation_id,
                "issued_at": now,
                "expires_at": now + REFRESH_TTL_SECONDS,
            }
        ),
        ttl_seconds=REFRESH_TTL_SECONDS,
        strict=True,
    )
    return {
        "session": session,
        "refresh_token": new_refresh_token,
        "employee": employee,
        "identity": identity,
        "pet_api_url": env("DESKTOP_PET_API_URL"),
    }


def desktop_authorize_url(code: str) -> str:
    """Build a desktop deep link containing only a one-time code.

    Args:
        code: Opaque one-time authorization code.

    Returns:
        URL protocol link consumed by the desktop app.
    """
    return "dianchi://authorize?" + urllib.parse.urlencode({"code": code})
