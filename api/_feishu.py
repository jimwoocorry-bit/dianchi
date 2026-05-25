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

STATE_COOKIE = "dc_feishu_oauth_state"
SESSION_COOKIE = "dc_feishu_session"
SESSION_MAX_AGE = 8 * 60 * 60
STATE_MAX_AGE = 10 * 60


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
    return (
        f"{name}={value}; Path=/; Max-Age={max_age}; "
        "HttpOnly; SameSite=Lax; Secure"
    )


def clear_cookie_header(name: str) -> str:
    return f"{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure"


def feishu_config() -> tuple[str, str, str]:
    app_id = env("FEISHU_APP_ID") or env("LARK_APP_ID")
    app_secret = env("FEISHU_APP_SECRET") or env("LARK_APP_SECRET")
    scope = env("FEISHU_OAUTH_SCOPE", "contact:user.base:readonly")
    return app_id, app_secret, scope


def request_json(url: str, *, method: str, headers: dict, body: dict | None = None) -> dict:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Feishu HTTP {exc.code}: {raw}") from exc


def exchange_code(code: str, redirect_uri: str) -> dict:
    app_id, app_secret, scope = feishu_config()
    payload = {
        "grant_type": "authorization_code",
        "client_id": app_id,
        "client_secret": app_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if scope:
        payload["scope"] = scope
    result = request_json(FEISHU_TOKEN_URL, method="POST", headers={}, body=payload)
    if result.get("code") not in (0, None):
        raise RuntimeError(f"Feishu token error: {result}")
    data = result.get("data") or result
    access_token = data.get("access_token")
    if not access_token:
        raise RuntimeError(f"Feishu token response missing access_token: {result}")
    return data


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
