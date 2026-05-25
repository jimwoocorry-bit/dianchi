from __future__ import annotations

import secrets
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._feishu import (
    FEISHU_AUTHORIZE_URL,
    STATE_COOKIE,
    STATE_MAX_AGE,
    env,
    feishu_config,
    set_cookie_header,
    sign_payload,
)


def redirect_uri(handler: BaseHTTPRequestHandler) -> str:
    configured = env("FEISHU_REDIRECT_URI")
    if configured:
        return configured
    proto = handler.headers.get("X-Forwarded-Proto", "https").split(",", 1)[0]
    host = handler.headers.get("Host", "")
    return f"{proto}://{host}/auth/feishu/callback"


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        app_id, app_secret, scope = feishu_config()
        if not app_id or not app_secret:
            body = (
                "Feishu login is not configured. "
                "Set FEISHU_APP_ID and FEISHU_APP_SECRET in Vercel environment variables."
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
                sign_payload({"state": state, "iat": int(time.time())}),
                max_age=STATE_MAX_AGE,
            ),
        )
        self.send_header("Location", location)
        self.end_headers()
