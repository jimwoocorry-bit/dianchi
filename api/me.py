from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import resolve_user


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        user = resolve_user(self.headers)
        logged_in = user is not None
        body = {
            "logged_in": logged_in,
            "user": user if logged_in else None,
            "activated": _wallet.is_activated(user["open_id"]) if logged_in else False,
        }
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
