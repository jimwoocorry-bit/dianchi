"""GET /api/workspace/conversations — list workspace conversations.

v1 returns a hard-coded set of conversations. The list is shared with
``messages.py`` so both endpoints agree on the available IDs.
"""

from __future__ import annotations

import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._feishu import SESSION_COOKIE, SESSION_MAX_AGE, cookie_value, verify_payload


# Conversations the user can interact with. ``read_only=True`` means the
# front-end disables the input box for that conversation (it's a one-way
# notification channel, not a chat).
CONVERSATIONS: list[dict] = [
    {
        "id": "dc-agent",
        "title": "DC-Agent",
        "type": "agent",
        "avatar": "AI",
        "tag": "智能助手",
        "tag_color": "blue",
        "subtitle": "把客户需求、飞书消息、项目节点转成可执行任务。",
        "read_only": False,
    },
    {
        "id": "pet",
        "title": "小楠（宠物系统）",
        "type": "pet",
        "avatar": "P",
        "tag": "陪伴",
        "tag_color": "yellow",
        "subtitle": "巅池办公室宠物系统的轻互动入口。",
        "read_only": False,
    },
    {
        "id": "tech-daily",
        "title": "巅池-技术",
        "type": "report",
        "avatar": "技",
        "tag": "DevOps",
        "tag_color": "blue",
        "subtitle": "每天 09:00 推送昨日技术日报与异常摘要。",
        "read_only": False,
    },
    {
        "id": "feishu-bot",
        "title": "飞书机器人聚合",
        "type": "bot",
        "avatar": "飞",
        "tag": "机器人",
        "tag_color": "yellow",
        "subtitle": "审批、应用通知、安全告警等机器人事件入口。",
        "read_only": True,
    },
    {
        "id": "system",
        "title": "系统通知",
        "type": "system",
        "avatar": "系",
        "tag": "通知",
        "tag_color": "yellow",
        "subtitle": "巅池工作台的系统级提醒与变更说明。",
        "read_only": True,
    },
]


def resolve_user(headers) -> dict | None:
    signed = cookie_value(headers.get("Cookie"), SESSION_COOKIE)
    payload = verify_payload(signed or "", max_age=SESSION_MAX_AGE)
    if not payload or payload.get("exp", 0) < time.time():
        return None
    return payload.get("user")


def _view(c: dict) -> dict:
    # Last-message / unread are not materialised from storage on the list
    # endpoint (would require one LRANGE per conversation per request).
    # The detail endpoint fills the active conversation; list shows subtitle.
    return {
        **c,
        "last_message": c.get("subtitle", ""),
        "updated_at": "",
        "unread": 0,
    }


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        user = resolve_user(self.headers)
        if user is None:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "not_logged_in"})
            return

        body = {
            "conversations": [_view(c) for c in CONVERSATIONS],
            "user": user,
        }
        self._json(HTTPStatus.OK, body)

    def _json(self, status: HTTPStatus, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args) -> None:  # noqa: A002 - signature from stdlib
        # Vercel captures stderr; suppress the default per-request access log.
        return
