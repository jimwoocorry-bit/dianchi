"""Single Vercel function for desktop onboarding and internal sync routes."""

from __future__ import annotations

import json
import os
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from api import _wallet
from api._admin import require_login, resolve_auth, write_json
from api._desktop_auth import (
    DesktopAuthError,
    desktop_authorize_url,
    exchange_handoff,
    issue_handoff,
    rotate_refresh,
)
from api._desktop_probe import probe_status, record_probe_heartbeat, start_probe
from api._desktop_release import (
    DesktopReleaseError,
    artifact_for,
    store_release_manifest,
    verify_release_sync,
)
from api._feishu import (
    DESKTOP_BOOTSTRAP_COOKIE,
    DESKTOP_BOOTSTRAP_MAX_AGE,
    clear_cookie_header,
)
from api._oauth_connector import (
    OAuthConnectorError,
    check_cloud_docs_grant,
    exchange_cloud_docs_handoff,
    refresh_cloud_docs_grant,
    revoke_cloud_docs_grant,
)
from api._employee_access import (
    EmployeeAccessError,
    snapshot_health,
    store_snapshot,
    verify_snapshot_sync,
)


STARTER_PET_ID = "char_ChrisKitty"


class handler(BaseHTTPRequestHandler):
    """Dispatch desktop endpoints while consuming one Vercel Function slot."""

    def do_GET(self) -> None:
        route = self._route()
        if route == "open":
            self._open_desktop()
        elif route == "latest":
            self._latest_release()
        elif route == "probe-status":
            self._probe_status()
        elif route == "employee-health":
            write_json(self, HTTPStatus.OK, snapshot_health())
        else:
            write_json(self, HTTPStatus.NOT_FOUND, {"error": "route_not_found"})

    def do_POST(self) -> None:
        route = self._route()
        if route == "exchange":
            self._exchange()
        elif route == "refresh":
            self._refresh()
        elif route == "probe-start":
            self._probe_start()
        elif route == "probe-heartbeat":
            self._probe_heartbeat()
        elif route == "release-sync":
            self._release_sync()
        elif route == "employee-sync":
            self._employee_sync()
        elif route == "oauth-handoff-exchange":
            self._oauth_handoff_exchange()
        elif route == "oauth-grant-check":
            self._oauth_grant_check()
        elif route == "oauth-grant-refresh":
            self._oauth_grant_refresh()
        elif route == "oauth-grant-revoke":
            self._oauth_grant_revoke()
        else:
            write_json(self, HTTPStatus.NOT_FOUND, {"error": "route_not_found"})

    def _route(self) -> str:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return str(query.get("route", [""])[0]).strip()

    def _read_body(self, max_size: int) -> bytes | None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0
        if content_length <= 0 or content_length > max_size:
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_body_size"})
            return None
        return self.rfile.read(content_length)

    def _read_json(self, max_size: int) -> dict | None:
        body = self._read_body(max_size)
        if body is None:
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return None
        if not isinstance(payload, dict):
            write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return None
        return payload

    def _open_desktop(self) -> None:
        auth = resolve_auth(
            self.headers,
            cookie_name=DESKTOP_BOOTSTRAP_COOKIE,
            max_age=DESKTOP_BOOTSTRAP_MAX_AGE,
        )
        if not auth["logged_in"]:
            self._redirect(
                "/api/auth/feishu/start?app=agent&purpose=desktop_login"
                "&next=/api/desktop/open"
            )
            return
        if not auth["allowed"]:
            reason = urllib.parse.quote(str(auth["auth_status"]), safe="")
            self._redirect(f"/desktop.html?auth={reason}")
            return

        user = auth["user"]
        open_id = (user or {}).get("open_id") or ""
        if not open_id:
            self._redirect(
                "/api/auth/feishu/start?app=agent&purpose=desktop_login"
                "&next=/api/desktop/open"
            )
            return
        if not _wallet.is_activated(open_id):
            _wallet.create_wallet(open_id)
            _wallet.add_purchase(open_id, STARTER_PET_ID)
            _wallet.set_activated(open_id, True)
        try:
            code = issue_handoff(auth)
        except RuntimeError:
            self._redirect("/desktop.html?auth=authorization_unavailable")
            return
        self._redirect(
            desktop_authorize_url(code),
            clear_cookie=DESKTOP_BOOTSTRAP_COOKIE,
        )

    def _oauth_handoff_exchange(self) -> None:
        payload = self._read_json(8 * 1024)
        if payload is None:
            return
        self._oauth_result(
            lambda: exchange_cloud_docs_handoff(str(payload.get("code") or ""))
        )

    def _oauth_grant_check(self) -> None:
        payload = self._read_json(8 * 1024)
        if payload is None:
            return
        self._oauth_result(
            lambda: check_cloud_docs_grant(str(payload.get("grant_token") or ""))
        )

    def _oauth_grant_refresh(self) -> None:
        payload = self._read_json(8 * 1024)
        if payload is None:
            return
        self._oauth_result(
            lambda: refresh_cloud_docs_grant(str(payload.get("grant_token") or ""))
        )

    def _oauth_grant_revoke(self) -> None:
        payload = self._read_json(8 * 1024)
        if payload is None:
            return
        self._oauth_result(
            lambda: {
                "revoked": revoke_cloud_docs_grant(
                    str(payload.get("grant_token") or "")
                )
            }
        )

    def _oauth_result(self, operation) -> None:
        try:
            result = operation()
        except OAuthConnectorError as exc:
            if exc.code.startswith("status_") or exc.code in {
                "employee_identity_mismatch",
                "employee_not_allowed",
            }:
                status = HTTPStatus.FORBIDDEN
            elif exc.code.endswith("_failed"):
                status = HTTPStatus.SERVICE_UNAVAILABLE
            elif exc.code.endswith("_reauth_required"):
                status = HTTPStatus.UNAUTHORIZED
            else:
                status = HTTPStatus.BAD_REQUEST
            write_json(self, status, {"error": exc.code})
            return
        except RuntimeError:
            write_json(
                self,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "oauth_connector_unavailable"},
            )
            return
        write_json(self, HTTPStatus.OK, {"ok": True, **result})

    def _latest_release(self) -> None:
        if require_login(self) is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            release = artifact_for(
                query.get("platform", [""])[0],
                query.get("arch", [""])[0],
            )
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

    def _exchange(self) -> None:
        payload = self._read_json(16 * 1024)
        if payload is None:
            return
        try:
            result = exchange_handoff(
                str(payload.get("code") or ""),
                installation_id=str(payload.get("installation_id") or ""),
            )
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

    def _refresh(self) -> None:
        payload = self._read_json(16 * 1024)
        if payload is None:
            return
        try:
            result = rotate_refresh(
                str(payload.get("refresh_token") or ""),
                installation_id=str(payload.get("installation_id") or ""),
            )
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

    def _probe_start(self) -> None:
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

    def _probe_status(self) -> None:
        if require_login(self) is None:
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            status = probe_status(query.get("probe_id", [""])[0])
        except RuntimeError:
            write_json(
                self,
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "probe_store_unavailable"},
            )
            return
        write_json(self, HTTPStatus.OK, {"ok": True, "status": status})

    def _probe_heartbeat(self) -> None:
        payload = self._read_json(8 * 1024)
        if payload is None:
            return
        try:
            recorded = record_probe_heartbeat(str(payload.get("probe_id") or ""))
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

    def _release_sync(self) -> None:
        body = self._read_body(64 * 1024)
        if body is None:
            return
        try:
            manifest = verify_release_sync(
                body,
                self.headers.get("X-Dianchi-Timestamp", ""),
                self.headers.get("X-Dianchi-Signature", ""),
                os.environ.get("DESKTOP_RELEASE_SECRET", "").strip(),
            )
            store_release_manifest(manifest)
        except DesktopReleaseError as exc:
            status = (
                HTTPStatus.UNAUTHORIZED
                if "signature" in exc.code or "secret" in exc.code
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
        write_json(
            self,
            HTTPStatus.OK,
            {
                "ok": True,
                "version": manifest["version"],
                "channel": manifest["channel"],
            },
        )

    def _employee_sync(self) -> None:
        body = self._read_body(1024 * 1024)
        if body is None:
            return
        try:
            snapshot = verify_snapshot_sync(
                body,
                self.headers.get("X-Dianchi-Timestamp", ""),
                self.headers.get("X-Dianchi-Signature", ""),
                os.environ.get("DESKTOP_EMPLOYEE_SYNC_SECRET", "").strip(),
            )
            store_result = store_snapshot(snapshot)
        except EmployeeAccessError as exc:
            status = (
                HTTPStatus.UNAUTHORIZED
                if "signature" in exc.code or "secret" in exc.code
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
        write_json(
            self,
            HTTPStatus.OK,
            {
                "ok": True,
                "version": snapshot["schema_version"],
                "count": len(snapshot["records"]),
                "digest": snapshot["digest"],
                "store_result": store_result,
            },
        )

    def _redirect(self, location: str, *, clear_cookie: str = "") -> None:
        self.send_response(HTTPStatus.FOUND)
        if clear_cookie:
            self.send_header("Set-Cookie", clear_cookie_header(clear_cookie))
        self.send_header("Location", location)
        self.end_headers()

    def log_message(self, format, *args) -> None:  # noqa: A002
        return
