"""POST /api/buy — 购买商品（永久解锁）。

请求 body: {"item_id": "char_naxida"}
返回 200 + 新钱包余额；400 余额不足 / 已购买；404 商品不存在。
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import require_login, write_json
from api._shop_catalog import find


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        user = require_login(self)
        if user is None:
            return
        length = int(self.headers.get("Content-Length") or "0")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except (ValueError, UnicodeDecodeError):
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        item_id = (payload.get("item_id") or "").strip()
        item = find(item_id)
        if item is None:
            write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown_item"})
            return

        open_id = user["open_id"]
        if item_id in _wallet.get_purchases(open_id):
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "already_purchased"})
            return

        wallet = _wallet.get_wallet(open_id)
        price = int(item["price"])
        if wallet["coins"] < price:
            write_json(self, HTTPStatus.BAD_REQUEST, {
                "error": "insufficient_coins",
                "required": price,
                "balance": wallet["coins"],
            })
            return

        wallet["coins"] -= price
        wallet["total_spent"] = wallet.get("total_spent", 0) + price
        _wallet.set_wallet(open_id, wallet)
        _wallet.add_purchase(open_id, item_id)

        write_json(self, HTTPStatus.OK, {
            "ok": True,
            "item": {"id": item_id, "name": item["name"], "type": item["type"]},
            "wallet": wallet,
        })

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
