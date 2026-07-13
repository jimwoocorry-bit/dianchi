from __future__ import annotations

import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._employee_access import resolve_employee
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


def safe_next_path(value: str | None) -> str:
    raw = (value or "").strip()
    if not raw:
        return "/agent.html"
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme or parsed.netloc or not raw.startswith("/"):
        return "/agent.html"
    return raw


def render_message(
    handler: BaseHTTPRequestHandler,
    title: str,
    message: str,
    status: HTTPStatus = HTTPStatus.BAD_REQUEST,
    *,
    clear_oauth_state: bool = False,
) -> None:
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
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    if clear_oauth_state:
        handler.send_header("Set-Cookie", clear_cookie_header(STATE_COOKIE))
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def valid_session(cookie_header: str | None) -> bool:
    signed_session = cookie_value(cookie_header, SESSION_COOKIE)
    payload = verify_payload(signed_session or "", max_age=SESSION_MAX_AGE)
    return bool(payload and payload.get("exp", 0) > time.time())


def denial_message(reason: str) -> str:
    messages = {
        "employee_not_found": "当前飞书账号不是公司内部员工，无法使用巅池桌面助手。",
        "tenant_mismatch": "当前飞书账号不是公司内部员工，无法使用巅池桌面助手。",
        "status_pending": "员工账号尚未启用，请联系公司管理员。",
        "status_disabled": "员工账号已停用，请联系公司管理员。",
        "snapshot_missing": "员工身份服务暂不可用，请稍后重试。",
        "snapshot_invalid": "员工身份服务暂不可用，请稍后重试。",
        "snapshot_stale": "员工身份服务暂不可用，请稍后重试。",
        "authorization_unavailable": "员工身份服务暂不可用，请稍后重试。",
    }
    return messages.get(reason, "员工身份校验未通过，请联系公司管理员。")


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        code = query.get("code", [""])[0]
        state = query.get("state", [""])[0]

        signed_state = cookie_value(self.headers.get("Cookie"), STATE_COOKIE)
        payload = verify_payload(signed_state or "", max_age=STATE_MAX_AGE)
        if not code or not state or not payload or payload.get("state") != state:
            if valid_session(self.headers.get("Cookie")):
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/agent.html?already=1")
                self.end_headers()
                return
            render_message(self, "飞书登录失败", "授权状态已过期或不匹配，请重新发起登录。")
            return

        try:
            token_data = exchange_code(code, redirect_uri(self), payload.get("app"))
            user = public_user(fetch_user_info(token_data["access_token"]))
            auth = resolve_employee(
                user,
                expected_tenant=env("FEISHU_COMPANY_TENANT_KEY") or None,
            )
        except Exception as exc:  # noqa: BLE001
            render_message(self, "飞书登录失败", str(exc))
            return

        if not auth.get("allowed"):
            render_message(
                self,
                "员工身份未通过",
                denial_message(auth.get("reason", "unknown")),
                status=HTTPStatus.FORBIDDEN,
                clear_oauth_state=True,
            )
            return

        employee = auth.get("employee") or {}
        if employee:
            user = {
                **user,
                "employee_id": employee.get("employee_id", ""),
                "employee_role": employee.get("role", "employee"),
                "employee_status": employee.get("status", "pending"),
            }

        now = int(time.time())
        session = sign_payload(
            {
                "user": user,
                "employee": employee,
                "identity": auth.get("identity"),
                "auth_status": auth.get("reason", "unknown"),
                "iat": now,
                "exp": now + SESSION_MAX_AGE,
            }
        )
        next_path = safe_next_path(payload.get("next"))

        self.send_response(HTTPStatus.FOUND)
        self.send_header("Set-Cookie", clear_cookie_header(STATE_COOKIE))
        self.send_header(
            "Set-Cookie",
            set_cookie_header(SESSION_COOKIE, session, max_age=SESSION_MAX_AGE),
        )
        self.send_header("Location", next_path)
        self.end_headers()
