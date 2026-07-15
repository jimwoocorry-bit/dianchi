from __future__ import annotations

import io
import json
import os
import unittest
import urllib.parse
from unittest import mock

from api import _oauth_connector
from api._oauth_connector import (
    OAuthConnectorError,
    check_cloud_docs_grant,
    consume_oauth_transaction,
    create_oauth_transaction,
    exchange_cloud_docs_handoff,
    issue_cloud_docs_handoff,
    refresh_cloud_docs_grant,
    revoke_cloud_docs_grant,
    validate_return_url,
)
from api import desktop
from api._feishu import (
    DESKTOP_BOOTSTRAP_COOKIE,
    DESKTOP_BOOTSTRAP_MAX_AGE,
    FeishuRequestError,
)
from api.auth.feishu import callback, start

USER = {
    "name": "Employee One",
    "open_id": "ou_1",
    "union_id": "on_1",
    "user_id": "u_1",
    "tenant_key": "tenant_company",
}
EMPLOYEE = {
    "employee_id": "emp_1",
    "display_name": "Employee One",
    "department": "AI应用部",
    "title": "负责人",
    "role": "admin",
    "status": "active",
    "relation_type": "manager",
    "tenant_key": "tenant_company",
}
IDENTITY = {
    "employee_id": "emp_1",
    "tenant_key": "tenant_company",
    "feishu_open_id": "ou_1",
    "feishu_union_id": "on_1",
    "feishu_user_id": "u_1",
}
PERMISSIONS = [
    {
        "subject_id": "ou_1",
        "subject_type": "user",
        "permission": "dc_admin",
        "scope": "*",
        "source": "manual",
        "enabled": True,
        "updated_at": "2026-07-15T00:00:00+00:00",
    }
]


def active_authorization() -> dict:
    return {
        "allowed": True,
        "reason": "ok",
        "employee": EMPLOYEE,
        "identity": IDENTITY,
        "permissions": PERMISSIONS,
    }


class MemoryKv:
    def __init__(self) -> None:
        self.values = {}

    def set_value(self, key, value, *, ttl_seconds=None, strict=False) -> None:
        self.values[key] = value

    def get_value(self, key, default=None, *, strict=False):
        return self.values.get(key, default)

    def getdel_value(self, key, default=None, *, strict=False):
        return self.values.pop(key, default)


class CallbackHarness:
    def __init__(self) -> None:
        self.path = "/api/auth/feishu/callback?code=code-1&state=state-1"
        self.headers = {"Cookie": "dc_feishu_oauth_state=signed-state"}
        self.wfile = io.BytesIO()
        self.status = None
        self.response_headers = []

    def send_response(self, status) -> None:
        self.status = status

    def send_header(self, name, value) -> None:
        self.response_headers.append((name, value))

    def end_headers(self) -> None:
        return None

    def header_values(self, name: str) -> list[str]:
        return [value for key, value in self.response_headers if key == name]


class StartHarness(CallbackHarness):
    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path
        self.headers = {
            "Cookie": "dc_feishu_session=employee-session",
            "Host": "company.example.test",
            "X-Forwarded-Proto": "https",
        }


class DesktopOpenHarness:
    def __init__(self) -> None:
        self.headers = {"Cookie": "dc_feishu_session=employee-session"}
        self.redirects = []

    def _redirect(self, location: str, **kwargs) -> None:
        self.redirects.append((location, kwargs))


class OAuthConnectorTests(unittest.TestCase):
    def test_desktop_entry_ignores_employee_session_cookie(self) -> None:
        request = DesktopOpenHarness()
        unauthenticated = {
            "logged_in": False,
            "allowed": False,
            "auth_status": "not_logged_in",
        }
        with mock.patch.object(
            desktop,
            "resolve_auth",
            return_value=unauthenticated,
        ) as resolve_auth:
            desktop.handler._open_desktop(request)

        resolve_auth.assert_called_once_with(
            request.headers,
            cookie_name=DESKTOP_BOOTSTRAP_COOKIE,
            max_age=DESKTOP_BOOTSTRAP_MAX_AGE,
        )
        self.assertIn("purpose=desktop_login", request.redirects[0][0])

    def test_desktop_start_uses_its_isolated_bootstrap_cookie(self) -> None:
        request = StartHarness(
            "/api/auth/feishu/start?app=agent&purpose=desktop_login"
            "&next=/api/desktop/open"
        )
        transaction = {
            "state": "desktop-state",
            "purpose": "desktop_login",
            "app": "agent",
            "next": "/api/desktop/open",
            "return_to": "",
            "nonce": "nonce",
            "iat": 1000,
            "exp": 1600,
        }
        with (
            mock.patch.object(start, "cookie_value", return_value=None) as cookie,
            mock.patch.object(start, "verify_payload", return_value=None),
            mock.patch.object(
                start,
                "feishu_config",
                return_value=("agent", "app-id", "app-secret", "scope"),
            ),
            mock.patch.object(
                start,
                "create_oauth_transaction",
                return_value=("desktop-state", transaction),
            ),
            mock.patch.object(start, "sign_payload", return_value="signed-state"),
        ):
            start.handler.do_GET(request)

        self.assertEqual(request.status, 302)
        cookie.assert_called_once_with(
            "dc_feishu_session=employee-session",
            DESKTOP_BOOTSTRAP_COOKIE,
        )
        location = urllib.parse.urlsplit(request.header_values("Location")[0])
        query = urllib.parse.parse_qs(location.query)
        self.assertEqual(query["state"], ["desktop-state"])

    def test_transaction_is_allowlisted_signed_and_consumed_once(self) -> None:
        kv = MemoryKv()
        with (
            mock.patch.object(_oauth_connector._kv, "set_value", kv.set_value),
            mock.patch.object(_oauth_connector._kv, "getdel_value", kv.getdel_value),
            mock.patch.object(
                _oauth_connector.secrets,
                "token_urlsafe",
                side_effect=["state-1", "nonce-1"],
            ),
            mock.patch.dict(
                os.environ,
                {
                    "FEISHU_OAUTH_RETURN_ORIGINS": (
                        "http://192.168.2.162:6185,https://work.example.test"
                    )
                },
                clear=False,
            ),
        ):
            state, payload = create_oauth_transaction(
                purpose="cloud_docs",
                app_key="agent",
                next_path="/agent.html",
                return_to=(
                    "http://192.168.2.162:6185/api/assistant-attachments/"
                    "draft/oauth/callback?state=draft-state"
                ),
            )
            consumed = consume_oauth_transaction(state, payload)

            self.assertEqual(consumed["purpose"], "cloud_docs")
            self.assertEqual(consumed["nonce"], "nonce-1")
            with self.assertRaisesRegex(OAuthConnectorError, "expired"):
                consume_oauth_transaction(state, payload)

    def test_return_url_rejects_open_redirect_and_credentials(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"FEISHU_OAUTH_RETURN_ORIGINS": "https://work.example.test"},
            clear=False,
        ):
            self.assertEqual(
                validate_return_url(
                    "https://work.example.test/task/callback?state=one"
                ),
                "https://work.example.test/task/callback?state=one",
            )
            with self.assertRaisesRegex(OAuthConnectorError, "not_allowed"):
                validate_return_url("https://evil.example/task")
            with self.assertRaisesRegex(OAuthConnectorError, "invalid"):
                validate_return_url("https://user:pass@work.example.test/task")

    def test_cloud_grant_handoff_refresh_check_and_revoke_are_rotated(self) -> None:
        kv = MemoryKv()
        token_data = {
            "access_token": "access-one",
            "expires_in": 7200,
            "refresh_token": "refresh-one",
            "refresh_token_expires_in": 86400,
        }
        refreshed = {
            "access_token": "access-two",
            "expires_in": 7200,
            "refresh_token": "refresh-two",
            "refresh_token_expires_in": 86400,
        }
        with (
            mock.patch.object(_oauth_connector._kv, "set_value", kv.set_value),
            mock.patch.object(_oauth_connector._kv, "get_value", kv.get_value),
            mock.patch.object(_oauth_connector._kv, "getdel_value", kv.getdel_value),
            mock.patch.object(
                _oauth_connector.secrets,
                "token_urlsafe",
                side_effect=["handoff-one", "grant-one", "grant-two"],
            ),
            mock.patch.object(
                _oauth_connector,
                "resolve_employee",
                return_value=active_authorization(),
            ),
            mock.patch.object(
                _oauth_connector,
                "refresh_user_token",
                return_value=refreshed,
            ) as refresh,
            mock.patch.object(_oauth_connector, "revoke_user_token") as revoke,
        ):
            handoff = issue_cloud_docs_handoff(
                token_data=token_data,
                user=USER,
                authorization=active_authorization(),
                app_key="agent",
            )
            first = exchange_cloud_docs_handoff(handoff)
            checked = check_cloud_docs_grant(first["grant_token"])
            second = refresh_cloud_docs_grant(first["grant_token"])
            revoked = revoke_cloud_docs_grant(second["grant_token"])

        self.assertEqual(first["access_token"], "access-one")
        self.assertEqual(first["grant_token"], "grant-one")
        self.assertNotIn("refresh_token", first)
        self.assertTrue(checked["allowed"])
        self.assertEqual(checked["permissions"], PERMISSIONS)
        self.assertEqual(second["access_token"], "access-two")
        self.assertEqual(second["grant_token"], "grant-two")
        self.assertTrue(revoked)
        refresh.assert_called_once_with("refresh-one", "agent")
        self.assertEqual(
            [call.kwargs["token_type_hint"] for call in revoke.call_args_list],
            ["refresh_token", "access_token"],
        )

    def test_transient_refresh_failure_preserves_existing_grant(self) -> None:
        kv = MemoryKv()
        record = {
            "purpose": "cloud_docs",
            "app": "agent",
            "user": USER,
            "employee_id": "emp_1",
            "access_token": "access-one",
            "access_token_expires_at": 9999999999,
            "refresh_token": "refresh-one",
            "refresh_token_expires_at": 9999999999,
            "grant_expires_at": 9999999999,
        }
        grant = "grant-retryable"
        key = _oauth_connector._token_key("grant", grant)
        kv.values[key] = json.dumps(record)
        with (
            mock.patch.object(_oauth_connector._kv, "set_value", kv.set_value),
            mock.patch.object(_oauth_connector._kv, "get_value", kv.get_value),
            mock.patch.object(_oauth_connector._kv, "getdel_value", kv.getdel_value),
            mock.patch.object(
                _oauth_connector,
                "resolve_employee",
                return_value=active_authorization(),
            ),
            mock.patch.object(
                _oauth_connector,
                "refresh_user_token",
                side_effect=RuntimeError("upstream timeout"),
            ),
        ):
            with self.assertRaisesRegex(
                OAuthConnectorError,
                "cloud_docs_refresh_failed",
            ):
                refresh_cloud_docs_grant(grant)
            checked = check_cloud_docs_grant(grant)

        self.assertTrue(checked["allowed"])
        self.assertIn(key, kv.values)

    def test_rejected_refresh_requires_reauth_and_consumes_grant(self) -> None:
        kv = MemoryKv()
        record = {
            "purpose": "cloud_docs",
            "app": "agent",
            "user": USER,
            "employee_id": "emp_1",
            "access_token": "access-one",
            "access_token_expires_at": 9999999999,
            "refresh_token": "refresh-rejected",
            "refresh_token_expires_at": 9999999999,
            "grant_expires_at": 9999999999,
        }
        grant = "grant-rejected"
        key = _oauth_connector._token_key("grant", grant)
        kv.values[key] = json.dumps(record)
        with (
            mock.patch.object(_oauth_connector._kv, "getdel_value", kv.getdel_value),
            mock.patch.object(
                _oauth_connector,
                "resolve_employee",
                return_value=active_authorization(),
            ),
            mock.patch.object(
                _oauth_connector,
                "refresh_user_token",
                side_effect=FeishuRequestError(
                    "feishu_token_rejected_20030",
                    retryable=False,
                ),
            ),
        ):
            with self.assertRaisesRegex(
                OAuthConnectorError,
                "cloud_docs_reauth_required",
            ):
                refresh_cloud_docs_grant(grant)

        self.assertNotIn(key, kv.values)

    def test_disabled_employee_cannot_check_or_refresh_existing_grant(self) -> None:
        kv = MemoryKv()
        disabled = {
            **active_authorization(),
            "allowed": False,
            "reason": "status_disabled",
            "employee": {**EMPLOYEE, "status": "disabled"},
        }
        record = {
            "purpose": "cloud_docs",
            "app": "agent",
            "user": USER,
            "employee_id": "emp_1",
            "access_token": "access-one",
            "access_token_expires_at": 9999999999,
            "refresh_token": "refresh-one",
            "refresh_token_expires_at": 9999999999,
            "grant_expires_at": 9999999999,
        }
        grant = "grant-disabled"
        kv.values[_oauth_connector._token_key("grant", grant)] = json.dumps(record)
        with (
            mock.patch.object(_oauth_connector._kv, "get_value", kv.get_value),
            mock.patch.object(_oauth_connector._kv, "getdel_value", kv.getdel_value),
            mock.patch.object(
                _oauth_connector,
                "resolve_employee",
                return_value=disabled,
            ),
        ):
            with self.assertRaisesRegex(OAuthConnectorError, "status_disabled"):
                check_cloud_docs_grant(grant)
            with self.assertRaisesRegex(OAuthConnectorError, "status_disabled"):
                refresh_cloud_docs_grant(grant)

    def test_cloud_docs_callback_returns_handoff_without_employee_cookie(self) -> None:
        request = CallbackHarness()
        transaction = {
            "state": "state-1",
            "purpose": "cloud_docs",
            "app": "agent",
            "next": "/agent.html",
            "return_to": (
                "http://192.168.2.162:6185/api/assistant-attachments/"
                "draft/oauth/callback?state=draft-state"
            ),
            "nonce": "nonce",
            "iat": 1000,
            "exp": 1600,
        }
        token_data = {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 7200,
        }
        with (
            mock.patch.object(callback, "cookie_value", return_value="signed-state"),
            mock.patch.object(callback, "verify_payload", return_value=transaction),
            mock.patch.object(
                callback,
                "consume_oauth_transaction",
                return_value=transaction,
            ),
            mock.patch.object(callback, "exchange_code", return_value=token_data),
            mock.patch.object(callback, "fetch_user_info", return_value=USER),
            mock.patch.object(callback, "public_user", return_value=USER),
            mock.patch.object(
                callback,
                "resolve_employee",
                return_value=active_authorization(),
            ),
            mock.patch.object(
                callback,
                "issue_cloud_docs_handoff",
                return_value="handoff-code",
            ),
        ):
            callback.handler.do_GET(request)

        self.assertEqual(request.status, 302)
        location = request.header_values("Location")[0]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
        self.assertEqual(query["state"], ["draft-state"])
        self.assertEqual(query["handoff_code"], ["handoff-code"])
        self.assertFalse(
            any(
                value.startswith("dc_feishu_session=")
                for value in request.header_values("Set-Cookie")
            )
        )

    def test_desktop_callback_sets_only_short_lived_bootstrap_cookie(self) -> None:
        request = CallbackHarness()
        transaction = {
            "state": "state-1",
            "purpose": "desktop_login",
            "app": "agent",
            "next": "/api/desktop/open",
            "return_to": "",
            "nonce": "nonce",
            "iat": 1000,
            "exp": 1600,
        }
        with (
            mock.patch.object(callback, "cookie_value", return_value="signed-state"),
            mock.patch.object(callback, "verify_payload", return_value=transaction),
            mock.patch.object(
                callback,
                "consume_oauth_transaction",
                return_value=transaction,
            ),
            mock.patch.object(
                callback,
                "exchange_code",
                return_value={"access_token": "desktop-access"},
            ),
            mock.patch.object(callback, "fetch_user_info", return_value=USER),
            mock.patch.object(callback, "public_user", return_value=USER),
            mock.patch.object(
                callback,
                "resolve_employee",
                return_value=active_authorization(),
            ),
            mock.patch.object(
                callback, "sign_payload", return_value="desktop-session"
            ) as sign,
        ):
            callback.handler.do_GET(request)

        self.assertEqual(request.status, 302)
        cookies = request.header_values("Set-Cookie")
        self.assertTrue(
            any(
                value.startswith("dc_feishu_desktop_bootstrap=desktop-session")
                for value in cookies
            )
        )
        self.assertFalse(
            any(value.startswith("dc_feishu_session=") for value in cookies)
        )
        self.assertEqual(sign.call_args.args[0]["permissions"], PERMISSIONS)
        self.assertEqual(
            sign.call_args.args[0]["session_purpose"],
            "desktop_login",
        )

    def test_invalid_cloud_state_never_falls_into_desktop_login(self) -> None:
        request = CallbackHarness()
        with (
            mock.patch.object(callback, "cookie_value", return_value="signed-state"),
            mock.patch.object(callback, "verify_payload", return_value={}),
            mock.patch.object(
                callback,
                "consume_oauth_transaction",
                side_effect=OAuthConnectorError("oauth_state_invalid"),
            ),
        ):
            callback.handler.do_GET(request)

        self.assertEqual(request.status, 400)
        self.assertEqual(request.header_values("Location"), [])
        self.assertIn("oauth_state_invalid", request.wfile.getvalue().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
