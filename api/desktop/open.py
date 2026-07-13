"""GET /api/desktop/open — activate account and open the desktop app."""

from __future__ import annotations

import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import resolve_auth
from api._desktop_auth import desktop_authorize_url, issue_handoff


STARTER_PET_ID = "char_ChrisKitty"


def _redirect(handler: BaseHTTPRequestHandler, location: str) -> None:
    handler.send_response(HTTPStatus.FOUND)
    handler.send_header("Location", location)
    handler.end_headers()


def _activate_if_needed(open_id: str) -> None:
    if _wallet.is_activated(open_id):
        return
    _wallet.create_wallet(open_id)
    _wallet.add_purchase(open_id, STARTER_PET_ID)
    _wallet.set_activated(open_id, True)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        auth = resolve_auth(self.headers)
        if not auth["logged_in"]:
            _redirect(self, "/api/auth/feishu/start?app=agent&next=/desktop.html")
            return
        if not auth["allowed"]:
            reason = urllib.parse.quote(str(auth["auth_status"]), safe="")
            _redirect(self, f"/desktop.html?auth={reason}")
            return

        user = auth["user"]
        open_id = (user or {}).get("open_id") or ""
        if not open_id:
            _redirect(self, "/api/auth/feishu/start?app=agent&next=/desktop.html")
            return

        _activate_if_needed(open_id)
        try:
            code = issue_handoff(auth)
        except RuntimeError:
            _redirect(self, "/desktop.html?auth=authorization_unavailable")
            return
        _redirect(self, desktop_authorize_url(code))

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
