from __future__ import annotations

import html
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._employee_access import resolve_employee
from api._feishu import (
    DESKTOP_BOOTSTRAP_COOKIE,
    DESKTOP_BOOTSTRAP_MAX_AGE,
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    STATE_COOKIE,
    STATE_MAX_AGE,
    clear_cookie_header,
    cookie_value,
    env,
    exchange_code,
    fetch_user_info,
    oauth_scope,
    public_user,
    set_cookie_header,
    sign_payload,
    verify_payload,
)
from api._oauth_connector import (
    OAuthConnectorError,
    append_query,
    consume_oauth_transaction,
    issue_cloud_docs_handoff,
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
    error_code: str = "",
) -> None:
    safe_title = html.escape(title)
    safe_message = html.escape(message)
    code_html = (
        f"<p><small>错误码：<code>{html.escape(error_code)}</code></small></p>"
        if error_code
        else ""
    )
    body = f"""<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title>
<body style="font-family:system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background:#f7f5ee;color:#101421;padding:48px">
  <h1>{safe_title}</h1>
  <p>{safe_message}</p>
  {code_html}
  <p><a href="/api/auth/feishu/start">重新授权</a> · <a href="/">返回首页</a></p>
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


def denial_presentation(reason: str) -> tuple[str, str, HTTPStatus]:
    presentations = {
        "employee_not_found": (
            "员工账号未获授权",
            "当前飞书账号未匹配到公司员工目录。",
            HTTPStatus.FORBIDDEN,
        ),
        "tenant_mismatch": (
            "员工账号未获授权",
            "当前飞书账号不属于公司租户。",
            HTTPStatus.FORBIDDEN,
        ),
        "identity_conflict": (
            "员工身份需要修复",
            "当前飞书身份匹配到多条员工记录，请联系管理员修复身份映射。",
            HTTPStatus.FORBIDDEN,
        ),
        "status_pending": (
            "员工账号不可用",
            "员工账号尚未启用，请联系公司管理员。",
            HTTPStatus.FORBIDDEN,
        ),
        "status_disabled": (
            "员工账号不可用",
            "员工账号已停用，请联系公司管理员。",
            HTTPStatus.FORBIDDEN,
        ),
        "snapshot_stale": (
            "员工授权数据待恢复",
            "员工授权数据超过安全时限，系统已暂停新授权。请稍后重试。",
            HTTPStatus.SERVICE_UNAVAILABLE,
        ),
        "snapshot_missing": (
            "员工授权服务暂不可用",
            "员工授权快照尚未同步，请稍后重试。",
            HTTPStatus.SERVICE_UNAVAILABLE,
        ),
        "snapshot_invalid": (
            "员工授权服务暂不可用",
            "员工授权数据校验失败，系统已停止授权。请稍后重试。",
            HTTPStatus.SERVICE_UNAVAILABLE,
        ),
        "authorization_unavailable": (
            "员工授权服务暂不可用",
            "员工授权存储当前不可达，请稍后重试。",
            HTTPStatus.SERVICE_UNAVAILABLE,
        ),
    }
    return presentations.get(
        reason,
        (
            "员工身份校验未通过",
            "当前授权请求无法完成，请联系公司管理员。",
            HTTPStatus.FORBIDDEN,
        ),
    )


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        code = query.get("code", [""])[0]
        state = query.get("state", [""])[0]
        oauth_error = query.get("error", [""])[0]

        signed_state = cookie_value(self.headers.get("Cookie"), STATE_COOKIE)
        payload = verify_payload(signed_state or "", max_age=STATE_MAX_AGE)
        try:
            transaction = consume_oauth_transaction(state, payload)
        except OAuthConnectorError as exc:
            status = (
                HTTPStatus.GONE
                if exc.code == "oauth_state_expired"
                else HTTPStatus.BAD_REQUEST
            )
            render_message(
                self,
                "飞书授权事务已失效",
                "授权状态已过期或不匹配，请从原入口重新发起授权。",
                status=status,
                clear_oauth_state=True,
                error_code=exc.code,
            )
            return
        except RuntimeError:
            render_message(
                self,
                "飞书授权服务暂不可用",
                "授权事务存储当前不可达，请稍后从原入口重试。",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
                clear_oauth_state=True,
                error_code="oauth_store_unavailable",
            )
            return
        if oauth_error:
            render_message(
                self,
                "飞书授权未完成",
                "你取消了本次授权，可以返回原任务后重试。",
                status=HTTPStatus.BAD_REQUEST,
                clear_oauth_state=True,
                error_code="oauth_user_cancelled",
            )
            return
        if not code:
            render_message(
                self,
                "飞书授权事务已失效",
                "飞书回调未包含授权码，请从原入口重新授权。",
                status=HTTPStatus.BAD_REQUEST,
                clear_oauth_state=True,
                error_code="oauth_code_missing",
            )
            return

        try:
            token_data = exchange_code(
                code,
                redirect_uri(self),
                transaction.get("app"),
                scope=oauth_scope(
                    transaction.get("app"),
                    transaction.get("purpose", "employee_login"),
                ),
            )
            user = public_user(fetch_user_info(token_data["access_token"]))
            auth = resolve_employee(
                user,
                expected_tenant=env("FEISHU_COMPANY_TENANT_KEY") or None,
            )
        except Exception:  # noqa: BLE001
            render_message(
                self,
                "飞书授权服务暂不可用",
                "飞书授权交换失败，请稍后重新授权。",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
                error_code="oauth_exchange_failed",
            )
            return

        if not auth.get("allowed"):
            reason = str(auth.get("reason") or "unknown")
            title, message, status = denial_presentation(reason)
            render_message(
                self,
                title,
                message,
                status=status,
                clear_oauth_state=True,
                error_code=reason,
            )
            return

        if transaction.get("purpose") == "cloud_docs":
            try:
                handoff_code = issue_cloud_docs_handoff(
                    token_data=token_data,
                    user=user,
                    authorization=auth,
                    app_key=str(transaction.get("app") or ""),
                )
                location = append_query(
                    str(transaction.get("return_to") or ""),
                    handoff_code=handoff_code,
                )
            except OAuthConnectorError as exc:
                render_message(
                    self,
                    "云文档授权无法完成",
                    "云文档长期授权信息不完整，请从原任务重新授权。",
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                    clear_oauth_state=True,
                    error_code=exc.code,
                )
                return
            except RuntimeError:
                render_message(
                    self,
                    "云文档授权服务暂不可用",
                    "一次性交接服务当前不可达，请从原任务重试。",
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                    clear_oauth_state=True,
                    error_code="oauth_store_unavailable",
                )
                return
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Set-Cookie", clear_cookie_header(STATE_COOKIE))
            self.send_header("Location", location)
            self.end_headers()
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
                "permissions": auth.get("permissions") or [],
                "auth_status": auth.get("reason", "unknown"),
                "session_purpose": transaction.get("purpose", "employee_login"),
                "iat": now,
                "exp": now + SESSION_MAX_AGE,
            }
        )
        next_path = safe_next_path(transaction.get("next"))
        purpose = transaction.get("purpose", "employee_login")
        session_cookie = (
            DESKTOP_BOOTSTRAP_COOKIE if purpose == "desktop_login" else SESSION_COOKIE
        )
        session_max_age = (
            DESKTOP_BOOTSTRAP_MAX_AGE if purpose == "desktop_login" else SESSION_MAX_AGE
        )

        self.send_response(HTTPStatus.FOUND)
        self.send_header("Set-Cookie", clear_cookie_header(STATE_COOKIE))
        self.send_header(
            "Set-Cookie",
            set_cookie_header(session_cookie, session, max_age=session_max_age),
        )
        self.send_header("Location", next_path)
        self.end_headers()
