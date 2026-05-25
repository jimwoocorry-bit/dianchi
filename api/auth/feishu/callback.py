from __future__ import annotations

import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._feishu import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    STATE_COOKIE,
    STATE_MAX_AGE,
    clear_cookie_header,
    cookie_value,
    env,
    exchange_code,
    fetch_user_info,
    public_user,
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


def render_message(handler: BaseHTTPRequestHandler, title: str, message: str) -> None:
    body = f"""<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<body style="font-family:system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background:#f7f5ee;color:#101421;padding:48px">
  <h1>{title}</h1>
  <p>{message}</p>
  <p><a href="/">返回首页</a></p>
</body>
</html>""".encode("utf-8")
    handler.send_response(HTTPStatus.BAD_REQUEST)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        code = query.get("code", [""])[0]
        state = query.get("state", [""])[0]

        signed_state = cookie_value(self.headers.get("Cookie"), STATE_COOKIE)
        payload = verify_payload(signed_state or "", max_age=STATE_MAX_AGE)
        if not code or not state or not payload or payload.get("state") != state:
            render_message(self, "飞书登录失败", "授权状态已过期或不匹配，请重新发起登录。")
            return

        try:
            token_data = exchange_code(code, redirect_uri(self))
            user = public_user(fetch_user_info(token_data["access_token"]))
        except Exception as exc:  # noqa: BLE001
            render_message(self, "飞书登录失败", str(exc))
            return

        now = int(time.time())
        session = sign_payload(
            {"user": user, "iat": now, "exp": now + SESSION_MAX_AGE}
        )
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Set-Cookie", clear_cookie_header(STATE_COOKIE))
        self.send_header(
            "Set-Cookie",
            set_cookie_header(SESSION_COOKIE, session, max_age=SESSION_MAX_AGE),
        )
        self.send_header("Location", "/?login=success")
        self.end_headers()
