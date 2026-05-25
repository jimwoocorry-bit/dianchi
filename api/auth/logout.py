from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._feishu import SESSION_COOKIE, clear_cookie_header


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Set-Cookie", clear_cookie_header(SESSION_COOKIE))
        self.send_header("Location", "/")
        self.end_headers()
