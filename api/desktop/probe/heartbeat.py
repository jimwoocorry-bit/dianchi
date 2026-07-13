from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._admin import write_json
from api._desktop_probe import record_probe_heartbeat


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0
        if content_length <= 0 or content_length > 8 * 1024:
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_body_size"})
            return
        try:
            body = json.loads(self.rfile.read(content_length).decode("utf-8"))
            recorded = record_probe_heartbeat(str(body.get("probe_id") or ""))
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except RuntimeError:
            write_json(
                self,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "probe_store_unavailable"},
            )
            return
        if not recorded:
            write_json(self, HTTPStatus.NOT_FOUND, {"error": "probe_expired"})
            return
        write_json(self, HTTPStatus.OK, {"ok": True, "status": "installed"})

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
