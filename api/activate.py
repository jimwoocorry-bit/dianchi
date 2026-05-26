"""POST /api/activate — 激活员工宠物系统 onboarding 奖励。"""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import require_login, write_json


STARTER_PET_ID = "char_ChrisKitty"


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        user = require_login(self)
        if user is None:
            return

        open_id = user["open_id"]
        if _wallet.is_activated(open_id):
            write_json(self, HTTPStatus.OK, {
                "ok": True,
                "status": "already_activated",
                "wallet": _wallet.get_wallet(open_id),
                "purchases": _wallet.get_purchases(open_id),
            })
            return

        wallet = _wallet.create_wallet(open_id)
        _wallet.add_purchase(open_id, STARTER_PET_ID)
        _wallet.set_activated(open_id, True)

        write_json(self, HTTPStatus.OK, {
            "ok": True,
            "status": "activated",
            "wallet": wallet,
            "purchases": _wallet.get_purchases(open_id),
            "starter_pet": STARTER_PET_ID,
        })

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
