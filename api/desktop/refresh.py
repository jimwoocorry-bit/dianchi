from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._admin import write_json
from api._desktop_auth import DesktopAuthError, rotate_refresh


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0
        if content_length <= 0 or content_length > 16 * 1024:
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_body_size"})
            return
        try:
            body = json.loads(self.rfile.read(content_length).decode("utf-8"))
            result = rotate_refresh(
                str(body.get("refresh_token") or ""),
                installation_id=str(body.get("installation_id") or ""),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return
        except DesktopAuthError as exc:
            status = (
                HTTPStatus.FORBIDDEN
                if exc.code.startswith("status_")
                or exc.code in {"employee_not_allowed", "employee_identity_mismatch"}
                else HTTPStatus.BAD_REQUEST
            )
            write_json(self, status, {"error": exc.code})
            return
        except RuntimeError:
            write_json(
                self,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "authorization_store_unavailable"},
            )
            return

        write_json(self, HTTPStatus.OK, {"ok": True, **result})

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
