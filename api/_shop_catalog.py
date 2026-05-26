"""巅池 M1 商品目录（hardcoded v0，将来移到 KV / admin 配置）。

13 个主角色 + 6 个 mini pet，价格 / 试用价 / 好感度门槛集中在此。
"""

from __future__ import annotations


# 商品类型
TYPE_CHARACTER = "character"  # 主角色
TYPE_SUBPET = "subpet"  # 跟随小宠物


# 默认免费解锁的商品（新员工注册时即拥有）
DEFAULT_UNLOCKED = ["char_ChrisKitty", "char_Kitty"]


# 商品定义。试用价默认 = 永久价 10%，试用时长 30 分钟。
def _char(role: str, price: int, fv_lock: int = 0) -> dict:
    return {
        "id": f"char_{role}",
        "name": role,
        "type": TYPE_CHARACTER,
        "price": price,
        "trial_price": max(50, price // 10),
        "trial_minutes": 30,
        "fv_lock": fv_lock,
        "preview": f"/static/shop/role/{role}.png",
        "default_unlocked": role in {"ChrisKitty", "Kitty"},
    }


def _subpet(name: str, price: int, fv_lock: int = 1) -> dict:
    return {
        "id": f"pet_{name}",
        "name": name,
        "type": TYPE_SUBPET,
        "price": price,
        "trial_price": max(20, price // 10),
        "trial_minutes": 30,
        "fv_lock": fv_lock,
        "preview": f"/static/shop/pet/{name}.png",
        "default_unlocked": False,
    }


CATALOG: list[dict] = [
    # 主角色（按 DyberPet 帧数复杂度排价）
    _char("ChrisKitty", 0),  # 免费
    _char("Kitty", 0),  # 免费
    _char("小呆", 1000),
    _char("像素四妹", 1500),
    _char("像素猫meme", 1500),
    _char("流萤", 2000),
    _char("流萤Firefly", 3000, fv_lock=2),
    _char("椿", 3000, fv_lock=2),
    _char("守岸人", 3500, fv_lock=2),
    _char("魈", 5000, fv_lock=3),
    _char("纳西妲", 5000, fv_lock=3),
    _char("露西亚·深红囚影", 6000, fv_lock=4),
    _char("流浪者", 8000, fv_lock=5),
    _char("流浪者(日配)", 8000, fv_lock=5),
    _char("饮月", 10000, fv_lock=6),
    # mini pet（DyberPet items_config 已有 cost，这里跟一下）
    _subpet("派蒙", 1250),
    _subpet("散猫猫", 1000),
    _subpet("蕈兽", 1000),
    _subpet("魈鸟", 1000),
    _subpet("兰纳罗", 1000),
    _subpet("皮克啾", 150),
]


def find(item_id: str) -> dict | None:
    for it in CATALOG:
        if it["id"] == item_id:
            return it
    return None
