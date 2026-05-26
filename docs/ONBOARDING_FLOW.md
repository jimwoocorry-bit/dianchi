# 巅池企业养成 SaaS · 员工 onboarding 完整流程

蔡挺 2026-05-26 设计定稿。M2-M3 上线。

## 完整链路（员工首次接入）

```
① 公司主页 dianchi2026.vercel.app
   └─ 员工点「员工登录」→ 飞书 OAuth 扫码
                              ↓
② 登录后页面变成：欢迎 + 「下载桌面端」大按钮
   └─ 自动检测 OS 给对应 .dmg / .exe (D5)
                              ↓
③ 员工双击安装包 + 输 admin 密码 (D5)
                              ↓
④ 安装完成 → 自动启动桌面端（installer config）
                              ↓
⑤ 桌面端首次启动 → 飞书 OAuth 扫码（webview profile）
                              ↓
⑥ ★ server 检测「新用户首次飞书登录」事件
   触发 DC-Agent bot 开始 onboarding（DC-Agent 现有 state machine 已实现）
                              ↓
⑦ DC-Agent bot 自动推：
   ├─ 部门选择卡 (select_dept)
   ├─ 角色选择卡 (select_role)
   ├─ 姓名输入 prompt
   ├─ 教程清单卡 (tutorial_list)
   ├─ 6 节 lesson 自动推进 (60 秒一节)
   ├─ 测试题 (start_quiz / 多轮)
   └─ 测试结果卡 (build_quiz_result_card)
                              ↓
⑧ ★ 通过测试 → 结果卡有 2 按钮：
   ┌─────────────────────────────────────┐
   │ [🎁 继续私聊并领取宠物一只] [🚀 进入内测群] │  ← 第一个按钮是改造点
   └─────────────────────────────────────┘
                              ↓
⑨ 员工点「🎁 继续私聊并领取宠物一只」
   ├─ DC-Agent 触发 action: activate_pet_system
   ├─ server 收到激活：
   │   · 创建钱包（默认 1000 金币）
   │   · 解锁 ChrisKitty（员工初始宠物）
   │   · 标记用户 activated = true
   ├─ DC-Agent 回复"领取成功"卡片：
   │   · "🎉 你的 ChrisKitty 已经在桌面等你"
   │   · 列出基础玩法（钱包 / 商店 / 试用）
   │   · 「打开桌面端」按钮（dianchi:// URL scheme）
   └─ 桌面端检测到激活状态变化 → 显示 ChrisKitty 悬浮宠物
                              ↓
⑩ 员工跟着卡片操作，宠物系统正式开始使用
```

## 关键设计点

### 安装 ≠ 激活

- **安装完成**：桌面端窗口能开、能切「工作台」「飞书」「文档」tab、能用 dianchi web
- **未激活**：**桌面没有悬浮宠物**、商店进不去 / 显示「先去 DC-Agent 私聊激活」、钱包是 null
- **激活后**：悬浮宠物出现、商店可用、钱包初始 1000、ChrisKitty 已解锁

桌面端启动时调 `GET /api/me`，检查响应里 `activated` 字段：

```json
{
  "logged_in": true,
  "user": {...},
  "activated": false   // ← 未激活，桌面端不启动宠物层
}
```

激活后变 true，桌面端轮询发现 → 启动 DyberPet 显示 ChrisKitty。

### 复用 DC-Agent 现有 onboarding state machine

不重写 onboarding 流程，**只在结果卡按钮处插入"激活"动作**：

| 文件 | 改动 | 工作量 |
|---|---|---|
| `dc_engines/feishu_card_streamer/templates.py:1779-1826` | 按钮文案 + action: `noop` → `activate_pet_system`，type: `default` → `primary` | 5 分钟 |
| `data/plugins/employee_onboarding/main.py:ONBOARDING_CARD_ACTIONS` | 加 `activate_pet_system` 到白名单 | 1 分钟 |
| `data/plugins/employee_onboarding/main.py` | 加 handler：调 dianchi `/api/activate` + 回复"领取成功"卡片 | 半天 |
| `dc_engines/feishu_card_streamer/templates.py` | 加 `build_pet_received_card(display_name, pet_name)` | 1 小时 |
| `dianchi/api/activate.py` | 新 endpoint：POST → 创建钱包 + 解锁默认角色 + 标记 activated | 半天 |
| `dianchi/api/me.py` | 响应加 `activated` 字段（读 KV `dianchi:user:{open_id}:activated`） | 10 分钟 |
| 桌面端 `dianchi-desktop` | 启动时调 `/api/me` 检查 activated；轮询每 30 秒检查（首次激活后立即响应）| 1 天 (M2 阶段) |

**总：2-3 天**，完整 onboarding 流程可端到端跑通。

### 业务事件 → 金币奖励（M4 内容，跟激活独立）

激活后员工就拿到 1000 初始金币 + ChrisKitty。日常**通过业务行为赚更多金币**：

- 完成飞书周报 → +50 金币（M4 飞书 webhook）
- 完成 DC-Agent 任务 → +N 金币（DC-Agent 内部触发）
- 连续登录 → +10 金币（cron job）
- 节日礼包 → 老板在管理后台手动发（M3）

奖励规则由 admin 在管理后台配（M3）+ DC-Agent / 飞书 webhook 触发（M4）。

### 跟 DC-Agent 测试通过的关系

| 场景 | 行为 |
|---|---|
| 未通过测试 | 看不到「领取宠物」按钮，要先复习重做（已实现） |
| 通过测试但没点「领取宠物」 | 钱包不存在 + 桌面端没悬浮宠物。员工后续随时回 DC-Agent 私聊点按钮也能领 |
| 通过测试 + 点了「领取宠物」 | 一次性激活，幂等。重复点 server 返回 `already_activated` |
| 已激活但桌面端没装 | 钱包 + 解锁记录都在 server，员工以后装桌面端立刻看到悬浮 ChrisKitty + 1000 金币 |

## 状态 / 路线图

| 阶段 | 内容 | 状态 |
|---|---|---|
| 当前 | DC-Agent onboarding state machine + 测试通过结果卡（双按钮）| ✅ 已上线 |
| M1 v0 | dianchi server 核心 API（钱包 / 商店 / 购买 / 试用）| ✅ 今天上线 |
| M1 v1 | 加 `POST /api/activate` + `/api/me` 响应加 activated 字段 | ⏳ 这周 |
| M2 | 桌面端 fork DyberPet + 接 server + 激活态轮询 + dianchi:// URL scheme | ⏳ 2-3 周 |
| M3 | DC-Agent 改 templates.py 按钮 + main.py handler 接 dianchi 激活 API | ⏳ 跟 M2 同期或之后 |
| M4 | 飞书 webhook / DC-Agent 触发 → 金币奖励 | ⏳ |
