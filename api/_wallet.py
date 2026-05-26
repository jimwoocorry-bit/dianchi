"""巅池钱包 / 购买 / 试用 的 KV 数据层。

KV schema（key 前缀 dianchi:）：
- user:{open_id}:wallet      JSON {coins, total_earned, total_spent}
- user:{open_id}:purchases   JSON [item_id, item_id, ...]
- user:{open_id}:trials      JSON [{item_id, start_ts, end_ts}]
- user:{open_id}:activated   JSON true/false
"""

from __future__ import annotations

import json
import time
from typing import Any

from api import _kv
from api._shop_catalog import DEFAULT_UNLOCKED


DEFAULT_NEW_USER_COINS = 1000  # 新员工注册赠送金币
TRIAL_GRACE_SECONDS = 5  # 试用结束后宽限期（避免边界精度）


def _key(open_id: str, suffix: str) -> str:
    return f"dianchi:user:{open_id}:{suffix}"


def _read_json(key: str, default: Any) -> Any:
    raw = _kv.get_value(key)
    if raw is not None:
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            pass

    # M1 v0 wrote single values as a one-item Redis list. Keep read compatibility
    # while all new writes use proper SET/GET cells.
    legacy = _kv.lrange(key, 0, 0)
    if legacy:
        try:
            return json.loads(legacy[0])
        except (ValueError, TypeError):
            pass
    return default


def _write_json(key: str, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False)
    _kv.set_value(key, payload)


def default_wallet() -> dict:
    return {
        "coins": DEFAULT_NEW_USER_COINS,
        "total_earned": DEFAULT_NEW_USER_COINS,
        "total_spent": 0,
    }


def get_wallet(open_id: str) -> dict:
    data = _read_json(_key(open_id, "wallet"), default_wallet())
    return data


def set_wallet(open_id: str, wallet: dict) -> None:
    _write_json(_key(open_id, "wallet"), wallet)


def create_wallet(open_id: str) -> dict:
    wallet = default_wallet()
    set_wallet(open_id, wallet)
    return wallet


def get_purchases(open_id: str) -> list[str]:
    """已永久解锁的商品 id 列表（含默认免费的）。"""
    purchased = _read_json(_key(open_id, "purchases"), [])
    # 始终包含默认免费商品
    full = list(set(purchased) | set(DEFAULT_UNLOCKED))
    return full


def add_purchase(open_id: str, item_id: str) -> None:
    current = _read_json(_key(open_id, "purchases"), [])
    if item_id not in current:
        current.append(item_id)
        _write_json(_key(open_id, "purchases"), current)


def get_active_trials(open_id: str) -> list[dict]:
    """当前正在生效的试用列表（自动过滤过期的）。"""
    trials = _read_json(_key(open_id, "trials"), [])
    now = time.time()
    active = [t for t in trials if t.get("end_ts", 0) > now - TRIAL_GRACE_SECONDS]
    if len(active) != len(trials):
        _write_json(_key(open_id, "trials"), active)
    return active


def add_trial(open_id: str, item_id: str, minutes: int) -> dict:
    now = time.time()
    trial = {
        "item_id": item_id,
        "start_ts": now,
        "end_ts": now + minutes * 60,
        "minutes": minutes,
    }
    active = get_active_trials(open_id)
    active.append(trial)
    _write_json(_key(open_id, "trials"), active)
    return trial


def is_activated(open_id: str) -> bool:
    return bool(_read_json(_key(open_id, "activated"), False))


def set_activated(open_id: str, activated: bool) -> None:
    _write_json(_key(open_id, "activated"), activated)


def is_unlocked(open_id: str, item_id: str) -> tuple[bool, str]:
    """检查商品是否对该用户解锁（含购买 / 试用 / 默认免费）。

    Returns (is_unlocked, reason)：reason 是 "purchased" / "trial" / "default" / "locked"。
    """
    if item_id in DEFAULT_UNLOCKED:
        return True, "default"
    if item_id in get_purchases(open_id):
        return True, "purchased"
    for t in get_active_trials(open_id):
        if t.get("item_id") == item_id:
            return True, "trial"
    return False, "locked"
