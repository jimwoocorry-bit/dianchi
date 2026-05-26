"""GET /api/shop — 商品列表 + 当前用户的解锁状态。

返回每个商品的：基础信息 + status (locked/unlocked/trial) + 剩余试用秒数。
桌面端 / 管理后台 都用这一个接口。
"""

from __future__ import annotations

import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import require_login, write_json
from api._shop_catalog import CATALOG


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        user = require_login(self)
        if user is None:
            return
        open_id = user["open_id"]
        purchases = set(_wallet.get_purchases(open_id))
        trials = _wallet.get_active_trials(open_id)
        trial_map = {t["item_id"]: t for t in trials}
        wallet = _wallet.get_wallet(open_id)
        now = time.time()

        items_out = []
        for item in CATALOG:
            iid = item["id"]
            status: str
            extra: dict = {}
            if iid in purchases:
                status = "purchased"
            elif iid in trial_map:
                status = "trial"
                t = trial_map[iid]
                extra["trial_seconds_left"] = max(0, int(t["end_ts"] - now))
            else:
                status = "locked"
            items_out.append({**item, "status": status, **extra})

        write_json(self, HTTPStatus.OK, {
            "items": items_out,
            "wallet": wallet,
        })

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
