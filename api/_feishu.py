from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from http.cookies import SimpleCookie


FEISHU_AUTHORIZE_URL = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
FEISHU_TOKEN_URL = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
FEISHU_USER_INFO_URL = "https://open.feishu.cn/open-apis/authen/v1/user_info"
FEISHU_REVOKE_URL = "https://accounts.feishu.cn/oauth/v1/revoke"

STATE_COOKIE = "dc_feishu_oauth_state"
SESSION_COOKIE = "dc_feishu_session"
DESKTOP_BOOTSTRAP_COOKIE = "dc_feishu_desktop_bootstrap"
SESSION_MAX_AGE = 8 * 60 * 60
DESKTOP_BOOTSTRAP_MAX_AGE = 10 * 60
STATE_MAX_AGE = 10 * 60


class FeishuRequestError(RuntimeError):
    """Represent a classified Feishu request failure."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        """Initialize a machine-readable Feishu failure classification."""
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def env(name: str, fallback: str = "") -> str:
    return os.environ.get(name, fallback).strip()


def secret() -> bytes:
    raw = env("SITE_SESSION_SECRET") or env("FEISHU_SESSION_SECRET")
    if not raw:
        raw = "dc-agent-local-dev-secret-change-me"
    return raw.encode("utf-8")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def sign_payload(payload: dict) -> str:
    body = b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{b64(sig)}"


def verify_payload(value: str, *, max_age: int | None = None) -> dict | None:
    try:
        body, sig = value.split(".", 1)
        expected = hmac.new(secret(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(unb64(sig), expected):
            return None
        payload = json.loads(unb64(body).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None

    issued_at = int(payload.get("iat", 0))
    if max_age is not None and (not issued_at or time.time() - issued_at > max_age):
        return None
    return payload


def cookie_value(cookie_header: str | None, name: str) -> str | None:
    if not cookie_header:
        return None
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    item = cookie.get(name)
    return item.value if item else None


def set_cookie_header(name: str, value: str, *, max_age: int) -> str:
    return f"{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax; Secure"


def clear_cookie_header(name: str) -> str:
    return f"{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure"


FEISHU_APP_KEYS = ("promo", "tech", "agent")


def default_app_key() -> str:
    key = env("FEISHU_DEFAULT_APP", "promo").lower()
    return key if key in FEISHU_APP_KEYS else "promo"


def feishu_config(app_key: str | None = None) -> tuple[str, str, str, str]:
    key = (app_key or default_app_key()).lower()
    if key not in FEISHU_APP_KEYS:
        key = default_app_key()

    prefix = f"FEISHU_{key.upper()}_"
    app_id = env(prefix + "APP_ID")
    app_secret = env(prefix + "APP_SECRET")
    if key == "promo":
        app_id = app_id or env("FEISHU_APP_ID") or env("LARK_APP_ID")
        app_secret = app_secret or env("FEISHU_APP_SECRET") or env("LARK_APP_SECRET")

    scope = env("FEISHU_OAUTH_SCOPE", "contact:user.base:readonly")
    return key, app_id, app_secret, scope


def oauth_scope(app_key: str | None, purpose: str) -> str:
    """Return a purpose-specific OAuth scope without sharing token purposes."""
    if purpose == "cloud_docs":
        return env(
            "FEISHU_CLOUD_DOC_SCOPE",
            "offline_access drive:drive:readonly",
        )
    return feishu_config(app_key)[3]


def request_json(
    url: str, *, method: str, headers: dict, body: dict | None = None
) -> dict:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read().decode("utf-8")
        return json.loads(raw)
    except urllib.error.HTTPError as exc:
        exc.read()
        raise FeishuRequestError(
            f"feishu_http_{exc.code}",
            retryable=exc.code == 429 or exc.code >= 500,
        ) from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise FeishuRequestError(
            "feishu_transport_or_response_error",
            retryable=True,
        ) from exc


def exchange_code(
    code: str,
    redirect_uri: str,
    app_key: str | None = None,
    *,
    scope: str | None = None,
) -> dict:
    _key, app_id, app_secret, configured_scope = feishu_config(app_key)
    payload = {
        "grant_type": "authorization_code",
        "client_id": app_id,
        "client_secret": app_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    requested_scope = scope if scope is not None else configured_scope
    if requested_scope:
        payload["scope"] = requested_scope
    result = request_json(FEISHU_TOKEN_URL, method="POST", headers={}, body=payload)
    if result.get("code") not in (0, None):
        raise RuntimeError(f"Feishu token error: {result}")
    data = result.get("data") or result
    access_token = data.get("access_token")
    if not access_token:
        raise RuntimeError(f"Feishu token response missing access_token: {result}")
    return data


def refresh_user_token(refresh_token: str, app_key: str | None = None) -> dict:
    """Rotate a Feishu OAuth v2 refresh token.

    Args:
        refresh_token: Current one-time Feishu refresh token.
        app_key: Application credential namespace that issued the token.

    Returns:
        New access token and rotated refresh token response.
    """
    _key, app_id, app_secret, _scope = feishu_config(app_key)
    result = request_json(
        FEISHU_TOKEN_URL,
        method="POST",
        headers={},
        body={
            "grant_type": "refresh_token",
            "client_id": app_id,
            "client_secret": app_secret,
            "refresh_token": refresh_token,
        },
    )
    if result.get("code") not in (0, None):
        raise FeishuRequestError(
            f"feishu_token_rejected_{result.get('code')}",
            retryable=False,
        )
    data = result.get("data") or result
    if not data.get("access_token") or not data.get("refresh_token"):
        raise FeishuRequestError(
            "feishu_token_response_incomplete",
            retryable=False,
        )
    return data


def revoke_user_token(
    token: str,
    app_key: str | None = None,
    *,
    token_type_hint: str,
) -> None:
    """Revoke a Feishu user access or refresh token through RFC 7009.

    Args:
        token: Token value to revoke.
        app_key: Application credential namespace that issued the token.
        token_type_hint: ``access_token`` or ``refresh_token``.
    """
    if token_type_hint not in {"access_token", "refresh_token"}:
        raise ValueError("invalid Feishu token type hint")
    _key, app_id, app_secret, _scope = feishu_config(app_key)
    body = urllib.parse.urlencode(
        {
            "token": token,
            "client_id": app_id,
            "client_secret": app_secret,
            "token_type_hint": token_type_hint,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        FEISHU_REVOKE_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=12):
            return
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Feishu token revoke HTTP {exc.code}: {raw}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("Feishu token revoke transport error") from exc


def fetch_user_info(access_token: str) -> dict:
    result = request_json(
        FEISHU_USER_INFO_URL,
        method="GET",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if result.get("code") not in (0, None):
        raise RuntimeError(f"Feishu user_info error: {result}")
    return result.get("data") or result


def public_user(raw: dict) -> dict:
    return {
        "name": raw.get("name") or raw.get("en_name") or "飞书员工",
        "open_id": raw.get("open_id", ""),
        "union_id": raw.get("union_id", ""),
        "user_id": raw.get("user_id", ""),
        "email": raw.get("enterprise_email") or raw.get("email") or "",
        "avatar_url": raw.get("avatar_url") or raw.get("avatar_thumb") or "",
        "tenant_key": raw.get("tenant_key", ""),
    }
