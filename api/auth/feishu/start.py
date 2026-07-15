from __future__ import annotations

import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._feishu import (
    DESKTOP_BOOTSTRAP_COOKIE,
    DESKTOP_BOOTSTRAP_MAX_AGE,
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
    oauth_scope,
    set_cookie_header,
    sign_payload,
    verify_payload,
)
from api._oauth_connector import (
    OAUTH_PURPOSES,
    OAuthConnectorError,
    create_oauth_transaction,
)


def redirect_uri(handler: BaseHTTPRequestHandler) -> str:
    configured = env("FEISHU_REDIRECT_URI")
    if configured:
        return configured
    proto = handler.headers.get("X-Forwarded-Proto", "https").split(",", 1)[0]
    host = handler.headers.get("Host", "")
    return f"{proto}://{host}/auth/feishu/callback"


def safe_next_path(value: str | None, *, purpose: str = "employee_login") -> str:
    default = "/desktop.html" if purpose == "desktop_login" else "/agent.html"
    raw = (value or "").strip()
    if not raw:
        return default
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme or parsed.netloc or not raw.startswith("/"):
        return default
    return raw


def _render_error(
    handler: BaseHTTPRequestHandler,
    status: HTTPStatus,
    code: str,
) -> None:
    body = (f"飞书授权事务无法启动，请稍后重试。\n错误码：{code}").encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        purpose = str((query.get("purpose") or ["employee_login"])[0]).strip()
        if purpose not in OAUTH_PURPOSES:
            _render_error(self, HTTPStatus.BAD_REQUEST, "oauth_purpose_invalid")
            return
        next_path = safe_next_path(
            (query.get("next") or [""])[0],
            purpose=purpose,
        )
        return_to = str((query.get("return_to") or [""])[0]).strip()

        if purpose != "cloud_docs":
            session_cookie = (
                DESKTOP_BOOTSTRAP_COOKIE
                if purpose == "desktop_login"
                else SESSION_COOKIE
            )
            session_max_age = (
                DESKTOP_BOOTSTRAP_MAX_AGE
                if purpose == "desktop_login"
                else SESSION_MAX_AGE
            )
            signed_session = cookie_value(
                self.headers.get("Cookie"),
                session_cookie,
            )
            session_payload = verify_payload(
                signed_session or "",
                max_age=session_max_age,
            )
            if (
                session_payload
                and session_payload.get("exp", 0) > time.time()
                and session_payload.get("session_purpose") == purpose
            ):
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", next_path)
                self.end_headers()
                return

        requested_app = query.get("app", [""])[0].lower()
        app_key = (
            requested_app if requested_app in FEISHU_APP_KEYS else default_app_key()
        )
        _key, app_id, app_secret, _default_scope = feishu_config(app_key)
        if not app_id or not app_secret:
            _render_error(
                self, HTTPStatus.SERVICE_UNAVAILABLE, "oauth_app_unconfigured"
            )
            return

        try:
            state, transaction = create_oauth_transaction(
                purpose=purpose,
                app_key=app_key,
                next_path=next_path,
                return_to=return_to,
            )
        except OAuthConnectorError as exc:
            _render_error(self, HTTPStatus.BAD_REQUEST, exc.code)
            return
        except RuntimeError:
            _render_error(
                self, HTTPStatus.SERVICE_UNAVAILABLE, "oauth_store_unavailable"
            )
            return

        params = {
            "client_id": app_id,
            "redirect_uri": redirect_uri(self),
            "response_type": "code",
            "state": state,
        }
        scope = oauth_scope(app_key, purpose)
        if scope:
            params["scope"] = scope

        location = FEISHU_AUTHORIZE_URL + "?" + urllib.parse.urlencode(params)
        self.send_response(HTTPStatus.FOUND)
        self.send_header(
            "Set-Cookie",
            set_cookie_header(
                STATE_COOKIE,
                sign_payload(transaction),
                max_age=STATE_MAX_AGE,
            ),
        )
        self.send_header("Location", location)
        self.end_headers()
