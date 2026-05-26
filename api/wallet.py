"""GET /api/wallet — 当前登录用户的钱包余额 + 流水概览。"""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import require_login, write_json


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        user = require_login(self)
        if user is None:
            return
        wallet = _wallet.get_wallet(user["open_id"])
        write_json(self, HTTPStatus.OK, {
            "user": {"open_id": user["open_id"], "name": user.get("name", "")},
            "wallet": wallet,
        })

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
