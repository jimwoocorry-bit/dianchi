# dianchi

巅池文化传媒官网原型与飞书 OAuth 员工入口。

## 内容

- `independent-website/dianchi-homepage-prototype.html`: 官网页面原型
- `independent-website/feishu_auth_server.py`: 本地官网服务与飞书 OAuth 回调接口
- `independent-website/feishu-auth.env.example`: 飞书应用环境变量示例
- `docs/grey_test_video/`: 页面引用的 logo、视频与预览素材

## 本地运行

```bash
python3 independent-website/feishu_auth_server.py
```

打开 `http://127.0.0.1:8032/`。

## 飞书登录配置

启动服务前设置：

```bash
export FEISHU_APP_ID=cli_xxx
export FEISHU_APP_SECRET=xxx
export FEISHU_REDIRECT_URI=http://127.0.0.1:8032/auth/feishu/callback
export SITE_SESSION_SECRET=change-this-to-a-long-random-string
```

飞书开发者后台也需要添加同一个重定向 URL。

也可以从本机私有 JSON 配置读取凭证，避免把密钥写进仓库：

```bash
export FEISHU_CREDENTIALS_FILE=/path/to/private/cmd_config.json
export FEISHU_CREDENTIALS_APP_ID=cli_xxx
```

## 工作台消息中心

`/workspace.html` 的「消息」面板是真交互的工作台消息中心，左侧会话列表 + 右侧消息流 + 底部输入框（Enter 发送 / Shift+Enter 换行）。**不再嵌入飞书网页版，也不再触发二次扫码**。

### 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/workspace/conversations` | 返回当前用户的会话清单 |
| `GET` | `/api/workspace/messages?conversation_id=<id>` | 拉取某会话的消息历史 |
| `POST` | `/api/workspace/messages` | body `{conversation_id, content}`，返回 `{message, reply}` |

所有接口要求飞书登录态（`/api/me` 返回 `logged_in: true`），未登录返回 `401`，前端自动跳 `/api/auth/feishu/start?app=agent`。

### 会话清单（v1 hardcoded）

- `dc-agent` — DC-Agent 智能助手（可发消息）
- `pet` — 小楠 / 宠物系统（可发消息）
- `tech-daily` — 巅池-技术 DevOps 日报（可发备注）
- `feishu-bot` — 飞书机器人事件聚合（只读）
- `system` — 系统通知（只读）

定义在 [api/workspace/conversations.py](api/workspace/conversations.py:21)。改这里 + 在 [api/workspace/messages.py](api/workspace/messages.py:26) 加对应 `INITIAL_GREETING` / `REPLY_TEMPLATES` 条目就能加新会话。

### 存储

按 `(open_id, conversation_id)` 维度隔离，key 形如 `dianchi:msg:<open_id>:<conversation_id>`，存为 Redis list（`LPUSH` 新消息 + `LTRIM` 保留最近 100 条）。

兼容 Vercel KV 和 Upstash REST API，**任选其一**：

**Vercel KV**（在 Vercel Dashboard → Storage → Create KV，绑到项目后自动注入这 4 个变量）：

```
KV_REST_API_URL=https://...-upstash.io
KV_REST_API_TOKEN=...
KV_REST_API_READ_ONLY_TOKEN=...      # 未使用
KV_URL=redis://...                    # 未使用（走 HTTP REST）
```

**Upstash 直连**（在 [upstash.com](https://upstash.com) 建一个 Redis 实例，取 REST URL/Token）：

```
UPSTASH_REDIS_REST_URL=https://...-upstash.io
UPSTASH_REDIS_REST_TOKEN=...
```

**没配 KV 也能跑** —— 降级到函数实例内存 dict，前端右上角会显示「本机临时」黄色徽章；配上以后变成「云端同步」绿色徽章。

### 后续

当前 `POST /api/workspace/messages` 的 `reply` 是按 `conversation_id` 取的固定模板（见 [api/workspace/messages.py:32](api/workspace/messages.py:32)）。接真 DC-Agent / 宠物系统时只需把那个 `_make_reply()` 改成调远端接口即可，存储层和前端协议都不用动。

