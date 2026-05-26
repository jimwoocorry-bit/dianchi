# 巅池 M1 Server 设计

巅池企业养成 SaaS 的后端 / 管理后台基础。**当前 M1 v0：最小可用骨架**。

## 架构

```
[员工桌面端 (PySide6+DyberPet)]      [管理后台 WebUI (dianchi/admin.html)]
            │                                   │
            └──────────┬────────────────────────┘
                       │ HTTPS · 飞书 OAuth cookie
                       ▼
        ┌────────────────────────────────────┐
        │ Vercel Python functions             │
        │  dianchi/api/                       │
        │   ├─ auth/feishu/* (M0 已有)        │
        │   ├─ me           (M0 已有)         │
        │   ├─ workspace/*  (M0 已有)         │
        │   ├─ wallet       ← M1 新           │
        │   ├─ shop         ← M1 新           │
        │   ├─ buy          ← M1 新           │
        │   ├─ trial        ← M1 新           │
        │   └─ admin/* (M3 加)                │
        └─────────┬──────────────────────────┘
                  │ HTTP REST
                  ▼
        ┌────────────────────────────────────┐
        │ KV 数据层（_kv.py 抽象）            │
        │ Vercel KV / Upstash Redis (主存储) │
        │ 内存兜底（dev / 未配 KV 时）        │
        └────────────────────────────────────┘
                  │
                  │ (M2+ 接入)
                  ▼
        ┌────────────────────────────────────┐
        │ 公司 NAS                           │
        │  · Hermes / DC-Agent (已跑着)      │
        │  · 业务事件源 webhook → 奖励金币   │
        └────────────────────────────────────┘
```

## KV 数据 schema

所有 key 以 `dianchi:` 开头。

| Key 模式 | 类型 | 内容 |
|---|---|---|
| `user:{open_id}:wallet` | JSON `{coins, total_earned, total_spent}` | 用户钱包，默认新员工 1000 金币 |
| `user:{open_id}:purchases` | JSON `[item_id, ...]` | 已永久解锁的商品 id 列表 |
| `user:{open_id}:trials` | JSON `[{item_id, start_ts, end_ts, minutes}]` | 进行中的试用（过期自动清理）|
| `user:{open_id}:activated` | JSON `true/false` | 是否已通过 DC-Agent onboarding 领取宠物 |
| `admin:users` | JSON `[open_id, ...]`（M3 加）| admin 白名单（M1 v0 写死在 `_admin.py`）|
| `admin:config` | JSON 配置（M3 加）| 默认初始金币 / 试用折扣 / 等 |

商品目录（`_shop_catalog.py`）M1 v0 硬编码 21 个商品：13 主角色 + 6 mini pet + 2 个默认免费（ChrisKitty / Kitty）。M2 移到 KV 让 admin 改。

## API endpoint

### 用户端（任何已登录飞书的员工）

| Method | Path | 说明 |
|---|---|---|
| `GET` | `/api/me` | 当前用户 + 登录态 + `activated` |
| `POST` | `/api/activate` | 幂等激活宠物系统：创建钱包、解锁 ChrisKitty、标记 activated |
| `GET` | `/api/wallet` | 当前用户钱包余额 + 流水概览 |
| `GET` | `/api/shop` | 商品列表 + 当前用户每个商品的解锁状态（purchased / trial / locked + 剩余试用秒数）|
| `POST` | `/api/buy` | body `{item_id}`，扣 price 永久解锁 |
| `POST` | `/api/trial` | body `{item_id}`，扣 trial_price，开 trial_minutes 分钟试用 |
| `GET` | `/api/trial` | 当前 active trials 列表 + 剩余秒数 |

### 管理后台端（仅 admin）

> M1 v0 占位，M3 实装

| Method | Path | 说明 |
|---|---|---|
| `GET` | `/api/admin/users` | 员工列表 + 钱包 + 活跃度 |
| `POST` | `/api/admin/grant` | 给员工发金币（节日礼包 / 业务奖励）|
| `GET/PUT` | `/api/admin/shop` | 商品 CRUD |
| `GET/PUT` | `/api/admin/config` | 系统配置（初始金币 / 试用折扣 / admin 名单）|
| `GET` | `/api/admin/audit` | 审计日志（所有 admin 操作）|

## 解锁逻辑（`_wallet.is_unlocked`）

某商品对某用户是否解锁的判定顺序：

1. `item_id in DEFAULT_UNLOCKED` → `(True, "default")`
2. `item_id in user purchases` → `(True, "purchased")`
3. 任何 active trial 的 `item_id == item_id` → `(True, "trial")`
4. → `(False, "locked")`

桌面端切换角色 / 召唤宠物前调 `is_unlocked` 校验。

## Milestone

| Phase | 内容 | 状态 |
|---|---|---|
| **M1 v0**（今晚）| 5 个核心 API + admin.html 占位 + KV schema | ⏳ 进行中 |
| **M1 v1**（本周）| `POST /api/activate` + `/api/me.activated` + KV SET/GET helpers + curl 验证 | ✅ |
| **M2**（2-3 周后）| 桌面端 fork DyberPet + 真接 server（替换本地 userdata.json）| ⏳ |
| **M3**（M2 之后）| admin/* API + 管理后台真功能 | ⏳ |
| **M4**（M3 之后）| DC-Agent / 飞书 webhook → 业务事件奖励金币 | ⏳ |
| **M5**（最后）| 跨平台打包 + 跟 dianchi-desktop M3 跨平台打包对齐 | ⏳ |

## 风控 & 防作弊

- 所有 state（钱包 / 已购 / 试用计时）以 **server 为唯一来源**，桌面端只 cache
- 桌面端"购买"动作走 `POST /api/buy`，server 校验金币 + 写入；本地不存可改 JSON 的 wallet
- 试用结束时间 server 端记录，桌面端**仅展示**剩余时间。试用过期，server 端 `is_unlocked` 返回 false，桌面端强制切回默认角色
- M1 v0 没有签名 / token 校验额外加固，依赖飞书 OAuth cookie（HttpOnly + Secure）
- M3 加 audit log 记录所有 wallet 变动

## 当前限制（M1 v0 的妥协）

| 限制 | 何时解决 |
|---|---|
| 商品目录硬编码（改了要 deploy）| M2 移到 KV，admin 可在管理后台增删改 |
| admin 白名单硬编码（蔡挺）| M3 移到 KV |
| 没有 audit log | M3 |
| 没有 webhook 接业务事件 | M4 |
| 没有跨员工互动（送礼物 / 排行榜）| 暂不规划 |
