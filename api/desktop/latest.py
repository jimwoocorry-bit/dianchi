from __future__ import annotations

import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api._admin import require_login, write_json
from api._desktop_release import DesktopReleaseError, artifact_for


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if require_login(self) is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        platform = query.get("platform", [""])[0]
        architecture = query.get("arch", [""])[0]
        try:
            release = artifact_for(platform, architecture)
        except DesktopReleaseError as exc:
            status = (
                HTTPStatus.NOT_FOUND
                if exc.code.startswith("release_missing")
                else HTTPStatus.BAD_REQUEST
            )
            write_json(self, status, {"error": exc.code})
            return
        except RuntimeError:
            write_json(
                self,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "release_store_unavailable"},
            )
            return
        write_json(self, HTTPStatus.OK, {"ok": True, **release})

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
