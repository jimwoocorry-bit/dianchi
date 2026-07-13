from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._admin import require_login, write_json
from api._desktop_probe import start_probe


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if require_login(self) is None:
            return
        try:
            probe_id = start_probe()
        except RuntimeError:
            write_json(
                self,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "probe_store_unavailable"},
            )
            return
        write_json(self, HTTPStatus.OK, {"ok": True, "probe_id": probe_id})

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
