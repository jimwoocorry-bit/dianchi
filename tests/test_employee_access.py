from __future__ import annotations

import hashlib
import hmac
import json
import os
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from api import _kv
from api._employee_access import (
    EmployeeAccessError,
    has_permission,
    resolve_employee,
    snapshot_health,
    snapshot_digest,
    store_snapshot,
    verify_snapshot_sync,
)


def snapshot_for(
    *,
    status: str = "active",
    generated_at: str | None = None,
) -> dict:
    records = [
        {
            "employee_id": "emp_1",
            "display_name": "Employee One",
            "department": "AI应用部",
            "title": "负责人",
            "role": "admin",
            "status": status,
            "relation_type": "manager",
            "tenant_key": "tenant_company",
            "feishu_open_id": "ou_1",
            "feishu_union_id": "on_1",
            "feishu_user_id": "u_1",
        }
    ]
    return {
        "schema_version": 1,
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "records": records,
        "digest": snapshot_digest(records),
    }


def snapshot_v2_for(
    *,
    status: str = "active",
    generated_at: str | None = None,
) -> dict:
    identities = [
        {
            "app_key": "agent",
            "provider": "feishu:agent",
            "provider_subject": "ou_agent",
            "tenant_key": "tenant_company",
            "feishu_open_id": "ou_agent",
            "feishu_union_id": "on_1",
            "feishu_user_id": "u_1",
        },
        {
            "app_key": "promo",
            "provider": "feishu:promo",
            "provider_subject": "ou_promo",
            "tenant_key": "tenant_company",
            "feishu_open_id": "ou_promo",
            "feishu_union_id": "on_1",
            "feishu_user_id": "u_1",
        },
    ]
    permissions = [
        {
            "subject_id": "ou_agent",
            "subject_type": "user",
            "permission": "dc_admin",
            "scope": "*",
            "source": "manual",
            "enabled": True,
            "updated_at": "2026-07-15T00:00:00+00:00",
        },
        {
            "subject_id": "ou_agent",
            "subject_type": "user",
            "permission": "office_ops",
            "scope": "AI应用部",
            "source": "manual",
            "enabled": False,
            "updated_at": "2026-07-15T00:00:00+00:00",
        },
    ]
    records = [
        {
            "employee_id": "emp_1",
            "display_name": "Employee One",
            "department": "AI应用部",
            "title": "负责人",
            "role": "admin",
            "status": status,
            "relation_type": "manager",
            "tenant_key": "tenant_company",
            "feishu_open_id": "ou_agent",
            "feishu_union_id": "on_1",
            "feishu_user_id": "u_1",
            "principal_key": "feishu:tenant_company:union:on_1",
            "identities": identities,
            "permissions": permissions,
        }
    ]
    return {
        "schema_version": 2,
        "snapshot_id": "snap_test",
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "sync_reason": "manual_recovery",
        "records": records,
        "stats": {
            "record_count": 1,
            "identity_count": 2,
            "identity_fallback_count": 0,
            "permission_count": 2,
            "unbound_permission_count": 0,
        },
        "digest": snapshot_digest(records),
    }


class EmployeeAccessTests(unittest.TestCase):
    def test_v2_resolves_cross_app_identity_and_company_permissions(self) -> None:
        result = resolve_employee(
            {
                "tenant_key": "tenant_company",
                "union_id": "on_1",
                "open_id": "ou_promo",
            },
            snapshot=snapshot_v2_for(),
            expected_tenant="tenant_company",
        )

        self.assertTrue(result["allowed"])
        self.assertEqual(
            result["employee"]["principal_key"],
            "feishu:tenant_company:union:on_1",
        )
        self.assertEqual(result["identity"]["app_key"], "promo")
        self.assertTrue(has_permission(result["permissions"], "dc_admin"))
        self.assertFalse(
            has_permission(result["permissions"], "office_ops", scope="AI应用部")
        )

    def test_resolves_active_employee_by_feishu_identity(self) -> None:
        result = resolve_employee(
            {
                "tenant_key": "tenant_company",
                "user_id": "u_1",
                "union_id": "",
                "open_id": "ou_1",
            },
            snapshot=snapshot_for(),
            expected_tenant="tenant_company",
        )

        self.assertTrue(result["allowed"])
        self.assertEqual(result["reason"], "ok")
        self.assertEqual(result["employee"]["employee_id"], "emp_1")
        self.assertEqual(result["identity"]["feishu_open_id"], "ou_1")
        self.assertNotIn("feishu_open_id", result["employee"])

    def test_denies_tenant_unknown_pending_and_disabled_identities(self) -> None:
        external = resolve_employee(
            {"tenant_key": "tenant_external", "open_id": "ou_1"},
            snapshot=snapshot_for(),
            expected_tenant="tenant_company",
        )
        unknown = resolve_employee(
            {"tenant_key": "tenant_company", "open_id": "ou_unknown"},
            snapshot=snapshot_for(),
            expected_tenant="tenant_company",
        )
        pending = resolve_employee(
            {"tenant_key": "tenant_company", "open_id": "ou_1"},
            snapshot=snapshot_for(status="pending"),
            expected_tenant="tenant_company",
        )
        disabled = resolve_employee(
            {"tenant_key": "tenant_company", "open_id": "ou_1"},
            snapshot=snapshot_for(status="disabled"),
            expected_tenant="tenant_company",
        )

        self.assertEqual(external["reason"], "tenant_mismatch")
        self.assertEqual(unknown["reason"], "employee_not_found")
        self.assertEqual(pending["reason"], "status_pending")
        self.assertEqual(disabled["reason"], "status_disabled")

    def test_rejects_stale_or_unsupported_snapshot(self) -> None:
        stale = snapshot_for(
            generated_at=(datetime.now(UTC) - timedelta(hours=31)).isoformat()
        )
        unsupported = snapshot_for()
        unsupported["schema_version"] = 2

        self.assertEqual(
            resolve_employee(
                {"tenant_key": "tenant_company", "open_id": "ou_1"},
                snapshot=stale,
                expected_tenant="tenant_company",
            )["reason"],
            "snapshot_stale",
        )
        self.assertEqual(
            resolve_employee(
                {"tenant_key": "tenant_company", "open_id": "ou_1"},
                snapshot=unsupported,
                expected_tenant="tenant_company",
            )["reason"],
            "snapshot_invalid",
        )

    def test_snapshot_sync_signature_and_timestamp_are_verified(self) -> None:
        snapshot = snapshot_for()
        body = json.dumps(
            snapshot,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        signature = hmac.new(b"sync-secret", body, hashlib.sha256).hexdigest()

        self.assertEqual(
            verify_snapshot_sync(
                body,
                snapshot["generated_at"],
                signature,
                "sync-secret",
            )["digest"],
            snapshot["digest"],
        )
        with self.assertRaisesRegex(EmployeeAccessError, "signature"):
            verify_snapshot_sync(
                body,
                snapshot["generated_at"],
                "0" * 64,
                "sync-secret",
            )
        with self.assertRaisesRegex(EmployeeAccessError, "timestamp"):
            verify_snapshot_sync(
                body,
                (datetime.now(UTC) - timedelta(minutes=6)).isoformat(),
                signature,
                "sync-secret",
            )

    def test_store_snapshot_requires_persistent_kv(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "KV REST API"):
                store_snapshot(snapshot_for())

    def test_snapshot_health_distinguishes_healthy_delayed_and_stale(self) -> None:
        healthy = snapshot_health(snapshot_v2_for())
        delayed = snapshot_health(
            snapshot_v2_for(
                generated_at=(datetime.now(UTC) - timedelta(hours=25)).isoformat()
            )
        )
        stale = snapshot_health(
            snapshot_v2_for(
                generated_at=(datetime.now(UTC) - timedelta(hours=31)).isoformat()
            )
        )

        self.assertEqual(healthy["status"], "healthy")
        self.assertEqual(healthy["permission_count"], 2)
        self.assertEqual(delayed["status"], "degraded")
        self.assertEqual(delayed["reason"], "snapshot_delayed")
        self.assertEqual(stale["status"], "unavailable")
        self.assertEqual(stale["reason"], "snapshot_stale")

    def test_store_snapshot_rejects_rollback_and_accepts_idempotent_replay(
        self,
    ) -> None:
        current = snapshot_v2_for()
        older = snapshot_v2_for(
            generated_at=(datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        )
        with (
            mock.patch.object(_kv, "get_value", return_value=json.dumps(current)),
            mock.patch.object(_kv, "set_value") as setter,
        ):
            self.assertEqual(store_snapshot(current), "unchanged")
            with self.assertRaisesRegex(EmployeeAccessError, "out_of_order"):
                store_snapshot(older)

        setter.assert_not_called()


class StrictKvTests(unittest.TestCase):
    def test_ttl_set_and_getdel_use_redis_commands(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {"KV_REST_API_URL": "https://kv.test", "KV_REST_API_TOKEN": "x"},
                clear=True,
            ),
            mock.patch.object(
                _kv,
                "_rest_call",
                side_effect=[{"result": "OK"}, {"result": "value"}],
            ) as rest_call,
        ):
            _kv.set_value("key", "value", ttl_seconds=60, strict=True)
            value = _kv.getdel_value("key", strict=True)

        self.assertEqual(value, "value")
        self.assertEqual(
            rest_call.call_args_list,
            [
                mock.call(["SET", "key", "value", "EX", "60"]),
                mock.call(["GETDEL", "key"]),
            ],
        )

    def test_strict_mode_never_falls_back_to_process_memory(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "KV REST API"):
                _kv.set_value("strict-key", "value", strict=True)
            with self.assertRaisesRegex(RuntimeError, "KV REST API"):
                _kv.get_value("strict-key", strict=True)

    def test_local_memory_getdel_consumes_the_value_once(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            _kv.set_value("memory-pop", "value")
            self.assertEqual(_kv.getdel_value("memory-pop"), "value")
            self.assertIsNone(_kv.getdel_value("memory-pop"))


if __name__ == "__main__":
    unittest.main()
