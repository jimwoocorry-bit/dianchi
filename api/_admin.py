"""巅池管理后台鉴权。

M1 v0：admin 白名单写死（蔡挺 = product owner / 最高管理员）。
M3：管理员名单挪到 KV，由蔡挺通过管理后台增删。
"""

from __future__ import annotations

import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._employee_access import resolve_employee
from api._feishu import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    cookie_value,
    env,
    verify_payload,
)


# v0 硬编码 admin（蔡挺）。后续从 KV 读。
DEFAULT_ADMIN_OPEN_IDS = {
    "ou_129defaa7d62fdb15ffc1eab436791d6",  # 蔡挺
}


def resolve_user(headers) -> dict | None:
    auth = resolve_auth(headers)
    return auth["user"] if auth["logged_in"] else None


def resolve_auth(headers) -> dict:
    signed = cookie_value(headers.get("Cookie"), SESSION_COOKIE)
    payload = verify_payload(signed or "", max_age=SESSION_MAX_AGE)
    if not payload or payload.get("exp", 0) < time.time():
        return {
            "logged_in": False,
            "allowed": False,
            "auth_status": "not_logged_in",
            "user": None,
            "employee": None,
            "identity": None,
        }

    user = payload.get("user") or {}
    employee = None
    identity = None
    auth_status = "invalid_session_user"
    allowed = False

    if user:
        try:
            resolved = resolve_employee(
                user,
                expected_tenant=env("FEISHU_COMPANY_TENANT_KEY") or None,
            )
            employee = resolved.get("employee")
            identity = resolved.get("identity")
            auth_status = resolved.get("reason", "unknown")
            allowed = bool(resolved.get("allowed"))
            if employee:
                user = {
                    **user,
                    "employee_id": employee.get("employee_id", ""),
                    "employee_role": employee.get("role", "employee"),
                    "employee_status": employee.get("status", "pending"),
                }
        except Exception:  # noqa: BLE001
            auth_status = "employee_identity_unavailable"

    return {
        "logged_in": True,
        "allowed": allowed,
        "auth_status": auth_status,
        "user": user,
        "employee": employee,
        "identity": identity,
    }


def is_admin(user: dict | None) -> bool:
    if not user:
        return False
    if user.get("employee_role") == "admin":
        return True
    open_id = user.get("open_id") or ""
    return open_id in DEFAULT_ADMIN_OPEN_IDS


def write_json(handler: BaseHTTPRequestHandler, status: HTTPStatus, body: dict) -> None:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def require_login(handler: BaseHTTPRequestHandler) -> dict | None:
    """统一处理登录和员工状态。返回 active user 或 None。"""
    auth = resolve_auth(handler.headers)
    if not auth["logged_in"]:
        write_json(handler, HTTPStatus.UNAUTHORIZED, {"error": "not_logged_in"})
        return None
    if not auth["allowed"]:
        write_json(
            handler,
            HTTPStatus.FORBIDDEN,
            {
                "error": "employee_not_allowed",
                "auth_status": auth["auth_status"],
                "employee": auth["employee"],
            },
        )
        return None
    return auth["user"]


def require_admin(handler: BaseHTTPRequestHandler) -> dict | None:
    user = require_login(handler)
    if user is None:
        return None
    if not is_admin(user):
        write_json(handler, HTTPStatus.FORBIDDEN, {"error": "not_admin"})
        return None
    return user
