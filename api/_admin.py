"""巅池管理后台鉴权。"""

from __future__ import annotations

import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._employee_access import has_permission, resolve_employee
from api._feishu import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    cookie_value,
    env,
    verify_payload,
)


def resolve_user(headers) -> dict | None:
    auth = resolve_auth(headers)
    return auth["user"] if auth["logged_in"] else None


def resolve_auth(
    headers,
    *,
    cookie_name: str = SESSION_COOKIE,
    max_age: int = SESSION_MAX_AGE,
) -> dict:
    signed = cookie_value(headers.get("Cookie"), cookie_name)
    payload = verify_payload(signed or "", max_age=max_age)
    if not payload or payload.get("exp", 0) < time.time():
        return {
            "logged_in": False,
            "allowed": False,
            "auth_status": "not_logged_in",
            "user": None,
            "employee": None,
            "identity": None,
            "permissions": [],
        }

    user = payload.get("user") or {}
    employee = None
    identity = None
    permissions = []
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
            permissions = resolved.get("permissions") or []
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
        "permissions": permissions,
    }


def is_admin(user: dict | None, permissions: list[dict] | None = None) -> bool:
    """Return whether the current employee has company-global DC admin access."""
    return bool(user) and has_permission(permissions or [], "dc_admin", scope="*")


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
    if not is_admin(auth["user"], auth["permissions"]):
        write_json(handler, HTTPStatus.FORBIDDEN, {"error": "not_admin"})
        return None
    return auth["user"]
