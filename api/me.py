from __future__ import annotations

import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._feishu import SESSION_COOKIE, SESSION_MAX_AGE, cookie_value, verify_payload


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        signed = cookie_value(self.headers.get("Cookie"), SESSION_COOKIE)
        payload = verify_payload(signed or "", max_age=SESSION_MAX_AGE)
        logged_in = bool(payload and payload.get("exp", 0) >= time.time())
        body = {
            "logged_in": logged_in,
            "user": payload.get("user") if logged_in else None,
        }
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
