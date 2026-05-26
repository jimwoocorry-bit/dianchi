"""巅池管理后台鉴权。

M1 v0：admin 白名单写死（蔡挺 = product owner / 最高管理员）。
M3：管理员名单挪到 KV，由蔡挺通过管理后台增删。
"""

from __future__ import annotations

import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._feishu import SESSION_COOKIE, SESSION_MAX_AGE, cookie_value, verify_payload


# v0 硬编码 admin（蔡挺）。后续从 KV 读。
DEFAULT_ADMIN_OPEN_IDS = {
    "ou_129defaa7d62fdb15ffc1eab436791d6",  # 蔡挺
}


def resolve_user(headers) -> dict | None:
    signed = cookie_value(headers.get("Cookie"), SESSION_COOKIE)
    payload = verify_payload(signed or "", max_age=SESSION_MAX_AGE)
    if not payload or payload.get("exp", 0) < time.time():
        return None
    return payload.get("user")


def is_admin(user: dict | None) -> bool:
    if not user:
        return False
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
    """统一处理 401。返回 user 或 None（None 时已经写了响应）。"""
    user = resolve_user(handler.headers)
    if user is None:
        write_json(handler, HTTPStatus.UNAUTHORIZED, {"error": "not_logged_in"})
        return None
    return user


def require_admin(handler: BaseHTTPRequestHandler) -> dict | None:
    user = require_login(handler)
    if user is None:
        return None
    if not is_admin(user):
        write_json(handler, HTTPStatus.FORBIDDEN, {"error": "not_admin"})
        return None
    return user
