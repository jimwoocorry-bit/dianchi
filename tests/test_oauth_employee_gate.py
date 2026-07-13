from __future__ import annotations

import io
import os
import unittest
from unittest import mock

from api import _admin
from api.auth.feishu import callback


ACTIVE_EMPLOYEE = {
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
PUBLIC_USER = {
    "name": "Employee One",
    "open_id": "ou_1",
    "union_id": "on_1",
    "user_id": "u_1",
    "tenant_key": "tenant_company",
}


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


class OAuthEmployeeGateTests(unittest.TestCase):
    def run_callback(self, decision: dict) -> CallbackHarness:
        request = CallbackHarness()
        with (
            mock.patch.object(callback, "cookie_value", return_value="signed-state"),
            mock.patch.object(
                callback,
                "verify_payload",
                return_value={
                    "state": "state-1",
                    "app": "agent",
                    "next": "/desktop.html",
                },
            ),
            mock.patch.object(
                callback, "exchange_code", return_value={"access_token": "x"}
            ),
            mock.patch.object(callback, "fetch_user_info", return_value=PUBLIC_USER),
            mock.patch.object(callback, "public_user", return_value=PUBLIC_USER),
            mock.patch.object(
                callback, "resolve_employee", return_value=decision
            ) as resolver,
            mock.patch.object(callback, "sign_payload", return_value="signed-session"),
            mock.patch.dict(
                os.environ,
                {"FEISHU_COMPANY_TENANT_KEY": "tenant_company"},
                clear=False,
            ),
        ):
            callback.handler.do_GET(request)

        resolver.assert_called_once_with(
            PUBLIC_USER,
            expected_tenant="tenant_company",
        )
        return request

    def test_active_employee_receives_session_and_desktop_redirect(self) -> None:
        response = self.run_callback(
            {
                "allowed": True,
                "reason": "ok",
                "employee": ACTIVE_EMPLOYEE,
                "identity": IDENTITY,
            }
        )

        self.assertEqual(response.status, 302)
        self.assertEqual(response.header_values("Location"), ["/desktop.html"])
        self.assertTrue(
            any(
                value.startswith("dc_feishu_session=signed-session")
                for value in response.header_values("Set-Cookie")
            )
        )

    def test_rejected_identity_receives_403_without_session_cookie(self) -> None:
        decisions = {
            "employee_not_found": "不是公司内部员工",
            "status_pending": "员工账号尚未启用",
            "status_disabled": "员工账号已停用",
            "tenant_mismatch": "不是公司内部员工",
            "snapshot_missing": "员工身份服务暂不可用",
            "authorization_unavailable": "员工身份服务暂不可用",
        }
        for reason, message in decisions.items():
            with self.subTest(reason=reason):
                response = self.run_callback(
                    {
                        "allowed": False,
                        "reason": reason,
                        "employee": None,
                        "identity": None,
                    }
                )

                self.assertEqual(response.status, 403)
                self.assertIn(message, response.wfile.getvalue().decode("utf-8"))
                self.assertFalse(
                    any(
                        value.startswith("dc_feishu_session=")
                        for value in response.header_values("Set-Cookie")
                    )
                )

    def test_existing_session_is_rechecked_and_disabled_immediately(self) -> None:
        signed_payload = {
            "user": {**PUBLIC_USER, "employee_role": "admin"},
            "employee": ACTIVE_EMPLOYEE,
            "identity": IDENTITY,
            "auth_status": "ok",
            "exp": 9999999999,
        }
        disabled = {
            "allowed": False,
            "reason": "status_disabled",
            "employee": {**ACTIVE_EMPLOYEE, "status": "disabled"},
            "identity": IDENTITY,
        }
        with (
            mock.patch.object(_admin, "cookie_value", return_value="session"),
            mock.patch.object(_admin, "verify_payload", return_value=signed_payload),
            mock.patch.object(
                _admin, "resolve_employee", return_value=disabled
            ) as resolver,
            mock.patch.dict(
                os.environ,
                {"FEISHU_COMPANY_TENANT_KEY": "tenant_company"},
                clear=False,
            ),
        ):
            result = _admin.resolve_auth({"Cookie": "session"})

        self.assertTrue(result["logged_in"])
        self.assertFalse(result["allowed"])
        self.assertEqual(result["auth_status"], "status_disabled")
        self.assertEqual(result["employee"]["status"], "disabled")
        resolver.assert_called_once_with(
            signed_payload["user"],
            expected_tenant="tenant_company",
        )


if __name__ == "__main__":
    unittest.main()
