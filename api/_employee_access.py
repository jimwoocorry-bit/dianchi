"""Read-only employee authorization mirror for Vercel functions."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from api import _kv


SNAPSHOT_KEY = "dianchi:employee-access:snapshot"
SCHEMA_VERSION = 1
MAX_SNAPSHOT_AGE_SECONDS = 24 * 60 * 60
MAX_SYNC_SKEW_SECONDS = 5 * 60
IDENTITY_FIELDS = (
    "feishu_open_id",
    "feishu_union_id",
    "feishu_user_id",
)
RECORD_FIELDS = {
    "employee_id",
    "display_name",
    "department",
    "title",
    "role",
    "status",
    "relation_type",
    "tenant_key",
    *IDENTITY_FIELDS,
}


class EmployeeAccessError(ValueError):
    """Represent a rejected employee snapshot or synchronization request."""

    def __init__(self, code: str) -> None:
        """Initialize an employee access error.

        Args:
            code: Stable machine-readable rejection code.
        """
        super().__init__(code)
        self.code = code


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validate_snapshot(
    snapshot: dict[str, Any],
    *,
    max_age_seconds: int | None = None,
) -> None:
    if snapshot.get("schema_version") != SCHEMA_VERSION:
        raise EmployeeAccessError("invalid_snapshot_version")

    records = snapshot.get("records")
    if not isinstance(records, list):
        raise EmployeeAccessError("invalid_snapshot_records")
    if snapshot.get("digest") != snapshot_digest(records):
        raise EmployeeAccessError("invalid_snapshot_digest")

    employee_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
            raise EmployeeAccessError("invalid_snapshot_record_fields")
        employee_id = str(record.get("employee_id") or "")
        if not employee_id or employee_id in employee_ids:
            raise EmployeeAccessError("invalid_snapshot_employee_id")
        employee_ids.add(employee_id)
        if record.get("status") not in {"active", "disabled", "pending"}:
            raise EmployeeAccessError("invalid_snapshot_status")
        if record.get("role") not in {"employee", "manager", "admin"}:
            raise EmployeeAccessError("invalid_snapshot_role")
        if not any(str(record.get(field) or "") for field in IDENTITY_FIELDS):
            raise EmployeeAccessError("invalid_snapshot_identity")

    timestamp = str(snapshot.get("generated_at") or "")
    try:
        generated_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EmployeeAccessError("invalid_snapshot_timestamp") from exc
    if generated_at.tzinfo is None:
        raise EmployeeAccessError("invalid_snapshot_timestamp")
    age_seconds = (datetime.now(UTC) - generated_at.astimezone(UTC)).total_seconds()
    if age_seconds < -MAX_SYNC_SKEW_SECONDS:
        raise EmployeeAccessError("snapshot_from_future")
    if max_age_seconds is not None and age_seconds > max_age_seconds:
        raise EmployeeAccessError("snapshot_stale")


def snapshot_digest(records: list[dict[str, Any]]) -> str:
    """Return the SHA-256 digest for canonical employee records.

    Args:
        records: Employee authorization records.

    Returns:
        Lowercase hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(_canonical_json(records).encode("utf-8")).hexdigest()


def resolve_employee(
    user: dict[str, Any],
    *,
    snapshot: dict[str, Any] | None = None,
    expected_tenant: str | None = None,
) -> dict[str, Any]:
    """Resolve one Feishu OAuth identity against the read-only employee mirror.

    Args:
        user: Public Feishu OAuth identity.
        snapshot: Optional in-memory snapshot used by tests or callers with a cache.
        expected_tenant: Optional company tenant key.

    Returns:
        Authorization decision with public employee and identity records.
    """
    tenant_key = str(user.get("tenant_key") or "").strip()
    company_tenant = str(expected_tenant or "").strip()
    if company_tenant and tenant_key != company_tenant:
        return {
            "allowed": False,
            "reason": "tenant_mismatch",
            "employee": None,
            "identity": None,
        }

    if snapshot is None:
        try:
            raw_snapshot = _kv.get_value(SNAPSHOT_KEY, strict=True)
        except RuntimeError:
            return {
                "allowed": False,
                "reason": "authorization_unavailable",
                "employee": None,
                "identity": None,
            }
        if not raw_snapshot:
            return {
                "allowed": False,
                "reason": "snapshot_missing",
                "employee": None,
                "identity": None,
            }
        try:
            snapshot = json.loads(str(raw_snapshot))
        except json.JSONDecodeError:
            return {
                "allowed": False,
                "reason": "snapshot_invalid",
                "employee": None,
                "identity": None,
            }

    try:
        _validate_snapshot(snapshot, max_age_seconds=MAX_SNAPSHOT_AGE_SECONDS)
    except EmployeeAccessError as exc:
        reason = (
            "snapshot_stale" if exc.code == "snapshot_stale" else "snapshot_invalid"
        )
        return {
            "allowed": False,
            "reason": reason,
            "employee": None,
            "identity": None,
        }

    matched: dict[str, Any] | None = None
    for record in snapshot["records"]:
        record_tenant = str(record.get("tenant_key") or "").strip()
        if record_tenant and tenant_key and record_tenant != tenant_key:
            continue
        if any(
            str(user.get(field.removeprefix("feishu_")) or "").strip()
            and str(user.get(field.removeprefix("feishu_")) or "").strip()
            == str(record.get(field) or "").strip()
            for field in IDENTITY_FIELDS
        ):
            matched = record
            break

    if matched is None:
        return {
            "allowed": False,
            "reason": "employee_not_found",
            "employee": None,
            "identity": None,
        }

    employee = {
        key: value for key, value in matched.items() if key not in IDENTITY_FIELDS
    }
    identity = {
        "employee_id": matched["employee_id"],
        "tenant_key": matched["tenant_key"],
        **{field: matched[field] for field in IDENTITY_FIELDS},
    }
    status = str(matched["status"])
    return {
        "allowed": status == "active",
        "reason": "ok" if status == "active" else f"status_{status}",
        "employee": employee,
        "identity": identity,
    }


def store_snapshot(snapshot: dict[str, Any]) -> None:
    """Atomically replace the authorization snapshot after validation.

    Args:
        snapshot: Complete employee authorization snapshot.

    Raises:
        EmployeeAccessError: If snapshot validation fails.
        RuntimeError: If persistent Redis is unavailable.
    """
    _validate_snapshot(snapshot, max_age_seconds=MAX_SNAPSHOT_AGE_SECONDS)
    _kv.set_value(SNAPSHOT_KEY, _canonical_json(snapshot), strict=True)


def verify_snapshot_sync(
    body: bytes,
    timestamp: str,
    signature: str,
    secret: str,
) -> dict[str, Any]:
    """Verify and decode one employee authorization synchronization request.

    Args:
        body: Raw canonical JSON request body.
        timestamp: ISO-8601 timestamp sent by the exporter.
        signature: Hex HMAC-SHA256 signature over the raw body.
        secret: Shared synchronization secret.

    Returns:
        Validated employee authorization snapshot.

    Raises:
        EmployeeAccessError: If authentication, freshness, or schema checks fail.
    """
    if not secret:
        raise EmployeeAccessError("sync_secret_missing")
    try:
        sync_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EmployeeAccessError("invalid_sync_timestamp") from exc
    if sync_time.tzinfo is None:
        raise EmployeeAccessError("invalid_sync_timestamp")
    skew = abs((datetime.now(UTC) - sync_time.astimezone(UTC)).total_seconds())
    if skew > MAX_SYNC_SKEW_SECONDS:
        raise EmployeeAccessError("sync_timestamp_expired")

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise EmployeeAccessError("invalid_sync_signature")
    try:
        snapshot = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EmployeeAccessError("invalid_snapshot_json") from exc
    if not isinstance(snapshot, dict):
        raise EmployeeAccessError("invalid_snapshot_root")
    if str(snapshot.get("generated_at") or "") != timestamp:
        raise EmployeeAccessError("sync_timestamp_mismatch")
    _validate_snapshot(snapshot, max_age_seconds=MAX_SYNC_SKEW_SECONDS)
    return snapshot
