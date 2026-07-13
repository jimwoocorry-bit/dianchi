from __future__ import annotations

import secrets
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._feishu import (
    FEISHU_AUTHORIZE_URL,
    FEISHU_APP_KEYS,
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    STATE_COOKIE,
    STATE_MAX_AGE,
    cookie_value,
    default_app_key,
    env,
    feishu_config,
    set_cookie_header,
    sign_payload,
    verify_payload,
)


def redirect_uri(handler: BaseHTTPRequestHandler) -> str:
    configured = env("FEISHU_REDIRECT_URI")
    if configured:
        return configured
    proto = handler.headers.get("X-Forwarded-Proto", "https").split(",", 1)[0]
    host = handler.headers.get("Host", "")
    return f"{proto}://{host}/auth/feishu/callback"


def safe_next_path(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return "/agent.html"
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme or parsed.netloc or not raw.startswith("/"):
        return "/agent.html"
    return raw


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        next_path = safe_next_path((query.get("next") or [""])[0])

        signed_session = cookie_value(self.headers.get("Cookie"), SESSION_COOKIE)
        session_payload = verify_payload(signed_session or "", max_age=SESSION_MAX_AGE)
        if session_payload and session_payload.get("exp", 0) > time.time():
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", next_path)
            self.end_headers()
            return

        requested_app = query.get("app", [""])[0].lower()
        app_key = requested_app if requested_app in FEISHU_APP_KEYS else default_app_key()
        _key, app_id, app_secret, scope = feishu_config(app_key)
        if not app_id or not app_secret:
            body = (
                "Feishu login is not configured. "
                f"Set credentials for Feishu app '{app_key}' in Vercel environment variables."
            ).encode("utf-8")
            self.send_response(HTTPStatus.SERVICE_UNAVAILABLE)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        state = secrets.token_urlsafe(32)
        params = {
            "client_id": app_id,
            "redirect_uri": redirect_uri(self),
            "response_type": "code",
            "state": state,
        }
        if scope:
            params["scope"] = scope

        location = FEISHU_AUTHORIZE_URL + "?" + urllib.parse.urlencode(params)
        self.send_response(HTTPStatus.FOUND)
        self.send_header(
            "Set-Cookie",
            set_cookie_header(
                STATE_COOKIE,
                sign_payload(
                    {
                        "state": state,
                        "app": app_key,
                        "next": next_path,
                        "iat": int(time.time()),
                    }
                ),
                max_age=STATE_MAX_AGE,
            ),
        )
        self.send_header("Location", location)
        self.end_headers()
