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
