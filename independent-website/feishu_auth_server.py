from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import mimetypes
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOMEPAGE = ROOT / "independent-website" / "dianchi-homepage-prototype.html"

FEISHU_AUTHORIZE_URL = (
    "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
)
FEISHU_TOKEN_URL = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
FEISHU_USER_INFO_URL = "https://open.feishu.cn/open-apis/authen/v1/user_info"

STATE_COOKIE = "dc_feishu_oauth_state"
SESSION_COOKIE = "dc_feishu_session"
SESSION_MAX_AGE = 8 * 60 * 60
STATE_MAX_AGE = 10 * 60


def _env(name: str, fallback: str = "") -> str:
    return os.environ.get(name, fallback).strip()


def _secret() -> bytes:
    raw = _env("SITE_SESSION_SECRET") or _env("FEISHU_SESSION_SECRET")
    if not raw:
        raw = "dc-agent-local-dev-secret-change-me"
    return raw.encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def sign_payload(payload: dict) -> str:
    body = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64(sig)}"


def verify_payload(value: str, *, max_age: int | None = None) -> dict | None:
    try:
        body, sig = value.split(".", 1)
        expected = hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_unb64(sig), expected):
            return None
        payload = json.loads(_unb64(body).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None

    issued_at = int(payload.get("iat", 0))
    if max_age is not None and (not issued_at or time.time() - issued_at > max_age):
        return None
    return payload


def cookie_value(cookie_header: str | None, name: str) -> str | None:
    if not cookie_header:
        return None
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    item = cookie.get(name)
    return item.value if item else None


def build_redirect_uri(handler: BaseHTTPRequestHandler) -> str:
    configured = _env("FEISHU_REDIRECT_URI")
    if configured:
        return configured
    proto = handler.headers.get("X-Forwarded-Proto", "http").split(",", 1)[0]
    host = handler.headers.get("Host", f"127.0.0.1:{handler.server.server_port}")
    return f"{proto}://{host}/auth/feishu/callback"


def _walk_credentials(obj: object) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        app_id = str(obj.get("app_id") or "").strip()
        app_secret = str(obj.get("app_secret") or "").strip()
        if app_id and app_secret:
            pairs.append((app_id, app_secret))
        for value in obj.values():
            pairs.extend(_walk_credentials(value))
    elif isinstance(obj, list):
        for value in obj:
            pairs.extend(_walk_credentials(value))
    return pairs


def _credentials_from_file() -> tuple[str, str] | None:
    raw_path = _env("FEISHU_CREDENTIALS_FILE")
    if not raw_path:
        return None
    path = Path(raw_path).expanduser()
    if not path.is_file():
        return None

    preferred_app_id = _env("FEISHU_CREDENTIALS_APP_ID") or _env("FEISHU_APP_ID")
    try:
        pairs = _walk_credentials(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        pairs = []

    if preferred_app_id:
        for app_id, app_secret in pairs:
            if app_id == preferred_app_id:
                return app_id, app_secret
    return pairs[0] if pairs else None


def feishu_config() -> tuple[str, str, str]:
    app_id = _env("FEISHU_APP_ID") or _env("LARK_APP_ID")
    app_secret = _env("FEISHU_APP_SECRET") or _env("LARK_APP_SECRET")
    if not (app_id and app_secret):
        loaded = _credentials_from_file()
        if loaded:
            app_id = app_id or loaded[0]
            app_secret = app_secret or loaded[1]
    scope = _env("FEISHU_OAUTH_SCOPE", "contact:user.base:readonly")
    return app_id, app_secret, scope


def request_json(url: str, *, method: str, headers: dict, body: dict | None = None) -> dict:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Feishu HTTP {exc.code}: {raw}") from exc


def exchange_code(code: str, redirect_uri: str) -> dict:
    app_id, app_secret, scope = feishu_config()
    payload = {
        "grant_type": "authorization_code",
        "client_id": app_id,
        "client_secret": app_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if scope:
        payload["scope"] = scope
    result = request_json(FEISHU_TOKEN_URL, method="POST", headers={}, body=payload)
    if result.get("code") not in (0, None):
        raise RuntimeError(f"Feishu token error: {result}")
    data = result.get("data") or result
    access_token = data.get("access_token")
    if not access_token:
        raise RuntimeError(f"Feishu token response missing access_token: {result}")
    return data


def fetch_user_info(access_token: str) -> dict:
    result = request_json(
        FEISHU_USER_INFO_URL,
        method="GET",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if result.get("code") not in (0, None):
        raise RuntimeError(f"Feishu user_info error: {result}")
    return result.get("data") or result


def public_user(raw: dict) -> dict:
    return {
        "name": raw.get("name") or raw.get("en_name") or "飞书员工",
        "open_id": raw.get("open_id", ""),
        "union_id": raw.get("union_id", ""),
        "user_id": raw.get("user_id", ""),
        "email": raw.get("enterprise_email") or raw.get("email") or "",
        "avatar_url": raw.get("avatar_url") or raw.get("avatar_thumb") or "",
        "tenant_key": raw.get("tenant_key", ""),
    }


class FeishuHomepageHandler(BaseHTTPRequestHandler):
    server_version = "DCFeishuHomepage/0.1"

    def do_GET(self) -> None:
        self.route(head_only=False)

    def do_HEAD(self) -> None:
        self.route(head_only=True)

    def route(self, *, head_only: bool) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.serve_file(HOMEPAGE, head_only=head_only)
        elif parsed.path == "/auth/feishu/start":
            self.start_feishu_login()
        elif parsed.path == "/auth/feishu/callback":
            self.finish_feishu_login(parsed)
        elif parsed.path == "/auth/logout":
            self.logout()
        elif parsed.path == "/api/me":
            self.api_me()
        elif parsed.path == "/favicon.ico":
            self.serve_file(
                ROOT / "docs" / "grey_test_video" / "dianchi_logo_cutout.png",
                head_only=head_only,
            )
        elif parsed.path.startswith(("/independent-website/", "/docs/")):
            self.serve_file(
                ROOT / urllib.parse.unquote(parsed.path).lstrip("/"),
                head_only=head_only,
            )
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def serve_file(self, path: Path, *, head_only: bool = False) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if ROOT not in resolved.parents and resolved != ROOT:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not resolved.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        mime, _ = mimetypes.guess_type(str(resolved))
        data = resolved.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def start_feishu_login(self) -> None:
        app_id, app_secret, scope = feishu_config()
        if not app_id or not app_secret:
            self.render_message(
                "飞书登录未配置",
                "请先设置 FEISHU_APP_ID 和 FEISHU_APP_SECRET，然后重启官网服务。",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            )
            return

        state = secrets.token_urlsafe(32)
        redirect_uri = build_redirect_uri(self)
        params = {
            "client_id": app_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        if scope:
            params["scope"] = scope
        location = FEISHU_AUTHORIZE_URL + "?" + urllib.parse.urlencode(params)

        self.send_response(HTTPStatus.FOUND)
        self.set_cookie(
            STATE_COOKIE,
            sign_payload({"state": state, "iat": int(time.time())}),
            max_age=STATE_MAX_AGE,
        )
        self.send_header("Location", location)
        self.end_headers()

    def finish_feishu_login(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        code = query.get("code", [""])[0]
        state = query.get("state", [""])[0]
        signed_state = cookie_value(self.headers.get("Cookie"), STATE_COOKIE)
        payload = verify_payload(signed_state or "", max_age=STATE_MAX_AGE)
        if not code or not state or not payload or payload.get("state") != state:
            self.render_message("飞书登录失败", "授权状态已过期或不匹配，请重新发起登录。")
            return

        try:
            token_data = exchange_code(code, build_redirect_uri(self))
            user = public_user(fetch_user_info(token_data["access_token"]))
        except Exception as exc:  # noqa: BLE001
            self.render_message("飞书登录失败", html.escape(str(exc)))
            return

        session = sign_payload(
            {"user": user, "iat": int(time.time()), "exp": int(time.time()) + SESSION_MAX_AGE}
        )
        self.send_response(HTTPStatus.FOUND)
        self.clear_cookie(STATE_COOKIE)
        self.set_cookie(SESSION_COOKIE, session, max_age=SESSION_MAX_AGE)
        self.send_header("Location", "/?login=success")
        self.end_headers()

    def logout(self) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.clear_cookie(SESSION_COOKIE)
        self.send_header("Location", "/")
        self.end_headers()

    def api_me(self) -> None:
        signed = cookie_value(self.headers.get("Cookie"), SESSION_COOKIE)
        payload = verify_payload(signed or "", max_age=SESSION_MAX_AGE)
        logged_in = bool(payload and payload.get("exp", 0) >= time.time())
        body = {"logged_in": logged_in, "user": payload.get("user") if logged_in else None}
        self.send_json(body)

    def send_json(self, body: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def render_message(
        self, title: str, message: str, *, status: HTTPStatus = HTTPStatus.BAD_REQUEST
    ) -> None:
        body = f"""<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<body style="font-family:system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background:#f7f5ee;color:#101421;padding:48px">
  <h1>{html.escape(title)}</h1>
  <p>{message}</p>
  <p><a href="/">返回首页</a></p>
</body>
</html>"""
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def set_cookie(self, name: str, value: str, *, max_age: int) -> None:
        self.send_header(
            "Set-Cookie",
            f"{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax",
        )

    def clear_cookie(self, name: str) -> None:
        self.send_header(
            "Set-Cookie",
            f"{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        )


def main() -> None:
    host = _env("DC_HOMEPAGE_HOST", "127.0.0.1")
    port = int(_env("DC_HOMEPAGE_PORT", "8032"))
    server = ThreadingHTTPServer((host, port), FeishuHomepageHandler)
    print(f"Serving DC homepage at http://{host}:{port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
