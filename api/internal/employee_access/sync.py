from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._employee_access import (
    EmployeeAccessError,
    store_snapshot,
    verify_snapshot_sync,
)


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0
        if content_length <= 0 or content_length > 1024 * 1024:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_body_size"})
            return

        body = self.rfile.read(content_length)
        try:
            snapshot = verify_snapshot_sync(
                body,
                self.headers.get("X-Dianchi-Timestamp", ""),
                self.headers.get("X-Dianchi-Signature", ""),
                os.environ.get("DESKTOP_EMPLOYEE_SYNC_SECRET", "").strip(),
            )
            store_snapshot(snapshot)
        except EmployeeAccessError as exc:
            status = (
                HTTPStatus.UNAUTHORIZED
                if "signature" in exc.code or "secret" in exc.code
                else HTTPStatus.BAD_REQUEST
            )
            self._write_json(status, {"error": exc.code})
            return
        except RuntimeError:
            self._write_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "authorization_store_unavailable"},
            )
            return

        self._write_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "version": snapshot["schema_version"],
                "count": len(snapshot["records"]),
                "digest": snapshot["digest"],
            },
        )

    def _write_json(self, status: HTTPStatus, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
