"""GET / POST /api/workspace/messages — read and send workspace messages.

Storage layout (Upstash Redis list, one per (user, conversation)):

    dianchi:msg:{open_id}:{conversation_id}  →  [json_message, ...]   # newest first

Reads use ``LRANGE 0 99`` and reverse so the front-end gets chronological order.
Writes ``LPUSH`` + ``LTRIM 0 99`` to cap history at ~100 messages per channel.
"""

from __future__ import annotations

import json
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from api import _kv
from api.workspace.conversations import CONVERSATIONS, resolve_user


CONVERSATION_INDEX = {c["id"]: c for c in CONVERSATIONS}

# Shown once when a conversation has no stored history yet.
INITIAL_GREETING = {
    "dc-agent": "你好，我是 DC-Agent。今天想让我帮你整理任务、生成脚本，还是检索一下知识库？",
    "pet": "小楠摇了摇尾巴，凑过来等你说话。",
    "tech-daily": "巅池-技术昨日报到，09:00 前会推送昨日异常与发布摘要。",
    "feishu-bot": "这里聚合飞书机器人事件。当前还未接入真实事件源。",
    "system": "巅池工作台系统通知。如有维护或变更会显示在这里。",
}

# Conversation-aware mock reply templates. Read-only conversations are not
# present here — they're rejected before reaching the reply step.
REPLY_TEMPLATES = {
    "dc-agent": "收到「{content}」。我会把这条记进今日任务，整理好回头告诉你。",
    "pet": "小楠歪着头听你说「{content}」，蹭了你一下。",
    "tech-daily": "已记录你对今日技术日报的备注：「{content}」。",
}

MAX_HISTORY = 100
MAX_CONTENT_LEN = 2000


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


def _user_key(user: dict, conversation_id: str) -> str:
    open_id = (user.get("open_id") or user.get("user_id") or "anon").strip() or "anon"
    return f"dianchi:msg:{open_id}:{conversation_id}"


def _make_message(role: str, content: str) -> dict:
    return {
        "id": uuid.uuid4().hex,
        "role": role,
        "content": content,
        "created_at": _now_iso(),
    }


def _load_messages(user: dict, conversation_id: str) -> list[dict]:
    key = _user_key(user, conversation_id)
    raw_items = _kv.lrange(key, 0, MAX_HISTORY - 1)
    out: list[dict] = []
    # Stored newest-first via LPUSH; reverse for chronological display.
    for raw in reversed(raw_items):
        try:
            out.append(json.loads(raw))
        except (ValueError, TypeError):
            continue
    if not out:
        out = [
            {
                "id": f"greeting-{conversation_id}",
                "role": "assistant",
                "content": INITIAL_GREETING.get(conversation_id, "暂无历史消息。"),
                "created_at": _now_iso(),
            }
        ]
    return out


def _append_message(user: dict, conversation_id: str, message: dict) -> None:
    key = _user_key(user, conversation_id)
    _kv.lpush(key, json.dumps(message, ensure_ascii=False))
    _kv.ltrim(key, 0, MAX_HISTORY - 1)


def _make_reply(conversation_id: str, content: str) -> dict | None:
    template = REPLY_TEMPLATES.get(conversation_id)
    if template is None:
        return None
    snippet = content if len(content) <= 120 else content[:117] + "…"
    return _make_message("assistant", template.format(content=snippet))


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        user = resolve_user(self.headers)
        if user is None:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "not_logged_in"})
            return

        params = parse_qs(urlparse(self.path).query)
        conversation_id = (params.get("conversation_id") or [""])[0].strip()
        if conversation_id not in CONVERSATION_INDEX:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unknown_conversation"})
            return

        self._json(HTTPStatus.OK, {
            "conversation_id": conversation_id,
            "messages": _load_messages(user, conversation_id),
            "persistent": _kv.is_persistent(),
        })

    def do_POST(self) -> None:
        user = resolve_user(self.headers)
        if user is None:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "not_logged_in"})
            return

        length = int(self.headers.get("Content-Length") or "0")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except (ValueError, UnicodeDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        conversation_id = (payload.get("conversation_id") or "").strip()
        content = (payload.get("content") or "").strip()
        conv = CONVERSATION_INDEX.get(conversation_id)

        if conv is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unknown_conversation"})
            return
        if conv.get("read_only"):
            self._json(HTTPStatus.FORBIDDEN, {"error": "conversation_read_only"})
            return
        if not content:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "empty_content"})
            return
        if len(content) > MAX_CONTENT_LEN:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "content_too_long"})
            return

        user_msg = _make_message("user", content)
        _append_message(user, conversation_id, user_msg)

        reply = _make_reply(conversation_id, content)
        if reply is not None:
            _append_message(user, conversation_id, reply)

        self._json(HTTPStatus.OK, {
            "message": user_msg,
            "reply": reply,
            "persistent": _kv.is_persistent(),
        })

    def _json(self, status: HTTPStatus, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
