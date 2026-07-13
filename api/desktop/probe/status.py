from __future__ import annotations

import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._admin import require_login, write_json
from api._desktop_probe import probe_status


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if require_login(self) is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        probe_id = query.get("probe_id", [""])[0]
        try:
            status = probe_status(probe_id)
        except RuntimeError:
            write_json(
                self,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "probe_store_unavailable"},
            )
            return
        write_json(self, HTTPStatus.OK, {"ok": True, "status": status})

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
