from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import resolve_auth


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        auth = resolve_auth(self.headers)
        user = auth["user"] if auth["logged_in"] else None
        body = {
            "logged_in": auth["logged_in"],
            "allowed": auth["allowed"],
            "auth_status": auth["auth_status"],
            "user": user,
            "employee": auth["employee"],
            "identity": auth["identity"],
            "permissions": auth["permissions"],
            "activated": _wallet.is_activated(user["open_id"])
            if auth["allowed"] and user
            else False,
        }
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
