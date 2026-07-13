from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import unittest
from unittest import mock

from api._desktop_auth import (
    DesktopAuthError,
    desktop_authorize_url,
    exchange_handoff,
    issue_desktop_binding_assertion,
    issue_handoff,
    rotate_refresh,
)


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
ACTIVE_AUTH = {
    "logged_in": True,
    "allowed": True,
    "auth_status": "ok",
    "user": USER,
    "employee": EMPLOYEE,
    "identity": IDENTITY,
}


class MemoryKv:
    def __init__(self) -> None:
        self.values = {}

    def set_value(self, key, value, *, ttl_seconds=None, strict=False) -> None:
        self.values[key] = value

    def getdel_value(self, key, default=None, *, strict=False):
        return self.values.pop(key, default)


def active_resolution() -> dict:
    return {
        "allowed": True,
        "reason": "ok",
        "employee": EMPLOYEE,
        "identity": IDENTITY,
    }


class DesktopAuthTests(unittest.TestCase):
    def test_binding_assertion_contains_signed_stable_employee_identity(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {"DESKTOP_BINDING_SECRET": "binding-secret"},
                clear=False,
            ),
            mock.patch("api._desktop_auth.secrets.token_hex", return_value="nonce-1"),
            mock.patch("api._desktop_auth.time.time", return_value=1000),
        ):
            result = issue_desktop_binding_assertion(
                EMPLOYEE,
                IDENTITY,
                installation_id="install-a",
            )

        body, signature = result["desktop_assertion"].split(".", 1)
        expected = hmac.new(
            b"binding-secret",
            body.encode("ascii"),
            hashlib.sha256,
        ).digest()
        payload = json.loads(
            base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        )
        self.assertTrue(
            hmac.compare_digest(
                base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
                expected,
            )
        )
        self.assertEqual(payload["employee_id"], "emp_1")
        self.assertEqual(payload["feishu_open_id"], "ou_1")
        self.assertEqual(payload["desktop_session_id"], result["desktop_session_id"])
        self.assertEqual(payload["nonce"], "nonce-1")
        self.assertEqual(payload["exp"] - payload["iat"], 60)

    def test_handoff_is_one_time_and_refresh_rotates(self) -> None:
        kv = MemoryKv()
        with (
            mock.patch("api._desktop_auth._kv.set_value", kv.set_value),
            mock.patch("api._desktop_auth._kv.getdel_value", kv.getdel_value),
            mock.patch(
                "api._desktop_auth.secrets.token_urlsafe",
                side_effect=["handoff-code", "refresh-one", "refresh-two"],
            ),
            mock.patch(
                "api._desktop_auth.resolve_employee",
                return_value=active_resolution(),
            ),
            mock.patch(
                "api._desktop_auth.sign_payload",
                side_effect=["session-one", "session-two"],
            ),
            mock.patch.dict(
                os.environ,
                {
                    "FEISHU_COMPANY_TENANT_KEY": "tenant_company",
                    "DESKTOP_PET_API_URL": "http://192.168.1.35/pet",
                },
                clear=False,
            ),
        ):
            code = issue_handoff(ACTIVE_AUTH)
            first = exchange_handoff(code, installation_id="install-a")
            with self.assertRaisesRegex(
                DesktopAuthError,
                "invalid_or_expired_code",
            ):
                exchange_handoff(code, installation_id="install-a")
            rotated = rotate_refresh(
                first["refresh_token"],
                installation_id="install-a",
            )

        self.assertEqual(first["session"], "session-one")
        self.assertEqual(first["refresh_token"], "refresh-one")
        self.assertEqual(first["employee"]["employee_id"], "emp_1")
        self.assertEqual(first["pet_api_url"], "http://192.168.1.35/pet")
        self.assertEqual(rotated["session"], "session-two")
        self.assertEqual(rotated["refresh_token"], "refresh-two")

    def test_expired_handoff_is_rejected(self) -> None:
        kv = MemoryKv()
        with (
            mock.patch("api._desktop_auth._kv.set_value", kv.set_value),
            mock.patch("api._desktop_auth._kv.getdel_value", kv.getdel_value),
            mock.patch(
                "api._desktop_auth.secrets.token_urlsafe",
                return_value="expired-code",
            ),
        ):
            code = issue_handoff(ACTIVE_AUTH)
            key = next(iter(kv.values))
            record = json.loads(kv.values[key])
            record["expires_at"] = time.time() - 1
            kv.values[key] = json.dumps(record)

            with self.assertRaisesRegex(
                DesktopAuthError,
                "invalid_or_expired_code",
            ):
                exchange_handoff(code, installation_id="install-a")

    def test_refresh_rejects_installation_mismatch_and_expiry(self) -> None:
        kv = MemoryKv()
        with (
            mock.patch("api._desktop_auth._kv.set_value", kv.set_value),
            mock.patch("api._desktop_auth._kv.getdel_value", kv.getdel_value),
            mock.patch(
                "api._desktop_auth.secrets.token_urlsafe",
                side_effect=["handoff-a", "refresh-a", "handoff-b", "refresh-b"],
            ),
            mock.patch(
                "api._desktop_auth.resolve_employee",
                return_value=active_resolution(),
            ),
            mock.patch("api._desktop_auth.sign_payload", return_value="session"),
        ):
            first = exchange_handoff(
                issue_handoff(ACTIVE_AUTH),
                installation_id="install-a",
            )
            with self.assertRaisesRegex(
                DesktopAuthError,
                "installation_mismatch",
            ):
                rotate_refresh(
                    first["refresh_token"],
                    installation_id="install-b",
                )

            second = exchange_handoff(
                issue_handoff(ACTIVE_AUTH),
                installation_id="install-a",
            )
            refresh_key = next(key for key in kv.values if ":refresh:" in key)
            refresh_record = json.loads(kv.values[refresh_key])
            refresh_record["expires_at"] = time.time() - 1
            kv.values[refresh_key] = json.dumps(refresh_record)
            with self.assertRaisesRegex(
                DesktopAuthError,
                "invalid_or_expired_refresh",
            ):
                rotate_refresh(
                    second["refresh_token"],
                    installation_id="install-a",
                )

    def test_disabled_employee_cannot_exchange_handoff(self) -> None:
        kv = MemoryKv()
        with (
            mock.patch("api._desktop_auth._kv.set_value", kv.set_value),
            mock.patch("api._desktop_auth._kv.getdel_value", kv.getdel_value),
            mock.patch(
                "api._desktop_auth.secrets.token_urlsafe",
                return_value="handoff-code",
            ),
            mock.patch(
                "api._desktop_auth.resolve_employee",
                return_value={
                    "allowed": False,
                    "reason": "status_disabled",
                    "employee": {**EMPLOYEE, "status": "disabled"},
                    "identity": IDENTITY,
                },
            ),
        ):
            code = issue_handoff(ACTIVE_AUTH)
            with self.assertRaisesRegex(DesktopAuthError, "status_disabled"):
                exchange_handoff(code, installation_id="install-a")

    def test_authorize_url_contains_only_the_one_time_code(self) -> None:
        url = desktop_authorize_url("one-time-code")

        self.assertEqual(url, "dianchi://authorize?code=one-time-code")
        self.assertNotIn("session=", url)
        self.assertNotIn("access_token", url)


if __name__ == "__main__":
    unittest.main()
