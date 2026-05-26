"""巅池试用接口。

POST /api/trial  body: {"item_id": "char_naxida"}
  → 扣 trial_price，开启 30 分钟试用。
GET  /api/trial  → 当前用户所有 active trial（含剩余秒数）。
"""

from __future__ import annotations

import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import require_login, write_json
from api._shop_catalog import find


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        user = require_login(self)
        if user is None:
            return
        trials = _wallet.get_active_trials(user["open_id"])
        now = time.time()
        view = [
            {
                "item_id": t["item_id"],
                "start_ts": t["start_ts"],
                "end_ts": t["end_ts"],
                "seconds_left": max(0, int(t["end_ts"] - now)),
            }
            for t in trials
        ]
        write_json(self, HTTPStatus.OK, {"trials": view})

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

        # 已永久拥有就不能"试用"了
        if item_id in _wallet.get_purchases(open_id):
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "already_owned"})
            return

        # 已经在试用中
        for t in _wallet.get_active_trials(open_id):
            if t["item_id"] == item_id:
                write_json(self, HTTPStatus.BAD_REQUEST, {
                    "error": "trial_already_active",
                    "seconds_left": max(0, int(t["end_ts"] - time.time())),
                })
                return

        wallet = _wallet.get_wallet(open_id)
        cost = int(item.get("trial_price", 0))
        if wallet["coins"] < cost:
            write_json(self, HTTPStatus.BAD_REQUEST, {
                "error": "insufficient_coins",
                "required": cost,
                "balance": wallet["coins"],
            })
            return

        wallet["coins"] -= cost
        wallet["total_spent"] = wallet.get("total_spent", 0) + cost
        _wallet.set_wallet(open_id, wallet)
        trial = _wallet.add_trial(open_id, item_id, int(item.get("trial_minutes", 30)))

        write_json(self, HTTPStatus.OK, {
            "ok": True,
            "trial": trial,
            "wallet": wallet,
        })

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
