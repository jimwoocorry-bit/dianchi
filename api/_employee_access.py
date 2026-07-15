"""Read-only employee identity and authorization mirror for Vercel functions."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from api import _kv


SNAPSHOT_KEY = "dianchi:employee-access:snapshot"
CURRENT_SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = {1, CURRENT_SCHEMA_VERSION}
MAX_SNAPSHOT_AGE_SECONDS = 30 * 60 * 60
DEGRADED_SNAPSHOT_AGE_SECONDS = 24 * 60 * 60
MAX_SYNC_SKEW_SECONDS = 5 * 60
IDENTITY_FIELDS = (
    "feishu_open_id",
    "feishu_union_id",
    "feishu_user_id",
)
CORE_RECORD_FIELDS = {
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
V2_RECORD_FIELDS = {
    *CORE_RECORD_FIELDS,
    "principal_key",
    "identities",
    "permissions",
}
IDENTITY_RECORD_FIELDS = {
    "app_key",
    "provider",
    "provider_subject",
    "tenant_key",
    *IDENTITY_FIELDS,
}
PERMISSION_RECORD_FIELDS = {
    "subject_id",
    "subject_type",
    "permission",
    "scope",
    "source",
    "enabled",
    "updated_at",
}
SYNC_REASONS = {
    "scheduled_reconcile",
    "identity_changed",
    "permission_changed",
    "manual_recovery",
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


def _timestamp(value: Any, error_code: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise EmployeeAccessError(error_code) from exc
    if parsed.tzinfo is None:
        raise EmployeeAccessError(error_code)
    return parsed.astimezone(UTC)


def _snapshot_age_seconds(snapshot: dict[str, Any]) -> float:
    return (
        datetime.now(UTC)
        - _timestamp(snapshot.get("generated_at"), "invalid_snapshot_timestamp")
    ).total_seconds()


def _record_identities(record: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(record.get("identities"), list):
        return list(record["identities"])
    return [
        {
            "app_key": "legacy",
            "provider": "feishu",
            "provider_subject": record.get("feishu_open_id", ""),
            "tenant_key": record.get("tenant_key", ""),
            **{field: record.get(field, "") for field in IDENTITY_FIELDS},
        }
    ]


def _expected_principal_key(record: dict[str, Any]) -> str:
    tenant_key = str(record.get("tenant_key") or "").strip()
    for kind, field in (
        ("union", "feishu_union_id"),
        ("user", "feishu_user_id"),
        ("open", "feishu_open_id"),
        ("employee", "employee_id"),
    ):
        value = str(record.get(field) or "").strip()
        if value:
            return f"feishu:{tenant_key or 'unknown'}:{kind}:{value}"
    raise EmployeeAccessError("invalid_snapshot_identity")


def _validate_snapshot(
    snapshot: dict[str, Any],
    *,
    max_age_seconds: int | None = None,
) -> None:
    version = snapshot.get("schema_version")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise EmployeeAccessError("invalid_snapshot_version")

    records = snapshot.get("records")
    if not isinstance(records, list):
        raise EmployeeAccessError("invalid_snapshot_records")
    if snapshot.get("digest") != snapshot_digest(records):
        raise EmployeeAccessError("invalid_snapshot_digest")
    if version == CURRENT_SCHEMA_VERSION:
        if not str(snapshot.get("snapshot_id") or "").startswith("snap_"):
            raise EmployeeAccessError("invalid_snapshot_id")
        if snapshot.get("sync_reason") not in SYNC_REASONS:
            raise EmployeeAccessError("invalid_snapshot_sync_reason")
        if not isinstance(snapshot.get("stats"), dict):
            raise EmployeeAccessError("invalid_snapshot_stats")

    employee_ids: set[str] = set()
    principal_keys: set[str] = set()
    for record in records:
        expected_fields = (
            V2_RECORD_FIELDS
            if version == CURRENT_SCHEMA_VERSION
            else CORE_RECORD_FIELDS
        )
        if not isinstance(record, dict) or set(record) != expected_fields:
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

        if version != CURRENT_SCHEMA_VERSION:
            continue
        principal_key = str(record.get("principal_key") or "")
        if (
            principal_key != _expected_principal_key(record)
            or principal_key in principal_keys
        ):
            raise EmployeeAccessError("invalid_snapshot_principal_key")
        principal_keys.add(principal_key)
        identities = record.get("identities")
        if not isinstance(identities, list) or not identities:
            raise EmployeeAccessError("invalid_snapshot_identities")
        candidate_subjects = {employee_id}
        for identity in identities:
            if (
                not isinstance(identity, dict)
                or set(identity) != IDENTITY_RECORD_FIELDS
            ):
                raise EmployeeAccessError("invalid_snapshot_identity_fields")
            if not any(str(identity.get(field) or "") for field in IDENTITY_FIELDS):
                raise EmployeeAccessError("invalid_snapshot_identity")
            candidate_subjects.update(
                str(identity.get(field) or "").strip()
                for field in ("provider_subject", *IDENTITY_FIELDS)
                if str(identity.get(field) or "").strip()
            )
        permissions = record.get("permissions")
        if not isinstance(permissions, list):
            raise EmployeeAccessError("invalid_snapshot_permissions")
        for permission in permissions:
            if (
                not isinstance(permission, dict)
                or set(permission) != PERMISSION_RECORD_FIELDS
            ):
                raise EmployeeAccessError("invalid_snapshot_permission_fields")
            if permission.get("subject_type") != "user":
                raise EmployeeAccessError("invalid_snapshot_permission_subject")
            if str(permission.get("subject_id") or "") not in candidate_subjects:
                raise EmployeeAccessError("invalid_snapshot_permission_subject")
            if not str(permission.get("permission") or ""):
                raise EmployeeAccessError("invalid_snapshot_permission")
            if not str(permission.get("scope") or ""):
                raise EmployeeAccessError("invalid_snapshot_permission_scope")
            if not str(permission.get("source") or ""):
                raise EmployeeAccessError("invalid_snapshot_permission_source")
            if type(permission.get("enabled")) is not bool:
                raise EmployeeAccessError("invalid_snapshot_permission_enabled")

    age_seconds = _snapshot_age_seconds(snapshot)
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


def has_permission(
    records: Any,
    permission: str,
    *,
    scope: str = "*",
) -> bool:
    """Check one exact enabled company permission assignment.

    Args:
        records: Permission projection returned by employee resolution.
        permission: Exact company permission required by the caller.
        scope: Required scope. A global assignment grants narrower scopes.

    Returns:
        Whether a valid assignment grants the requested authority.
    """
    if not isinstance(records, list | tuple):
        return False
    required_permission = str(permission or "").strip()
    required_scope = str(scope or "*").strip() or "*"
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("subject_type") != "user" or record.get("enabled") is not True:
            continue
        if str(record.get("permission") or "").strip() != required_permission:
            continue
        assignment_scope = str(record.get("scope") or "").strip()
        if assignment_scope == "*" or assignment_scope == required_scope:
            return True
    return False


def resolve_employee(
    user: dict[str, Any],
    *,
    snapshot: dict[str, Any] | None = None,
    expected_tenant: str | None = None,
) -> dict[str, Any]:
    """Resolve a Feishu identity and current company permission context.

    Args:
        user: Public Feishu OAuth identity.
        snapshot: Optional in-memory snapshot for tests or cached callers.
        expected_tenant: Optional company tenant key.

    Returns:
        Authorization decision with employee, identity, and permission records.
    """
    tenant_key = str(user.get("tenant_key") or "").strip()
    company_tenant = str(expected_tenant or "").strip()
    if company_tenant and tenant_key != company_tenant:
        return _decision(False, "tenant_mismatch")

    if snapshot is None:
        try:
            raw_snapshot = _kv.get_value(SNAPSHOT_KEY, strict=True)
        except RuntimeError:
            return _decision(False, "authorization_unavailable")
        if not raw_snapshot:
            return _decision(False, "snapshot_missing")
        try:
            snapshot = json.loads(str(raw_snapshot))
        except json.JSONDecodeError:
            return _decision(False, "snapshot_invalid")

    try:
        _validate_snapshot(snapshot, max_age_seconds=MAX_SNAPSHOT_AGE_SECONDS)
    except EmployeeAccessError as exc:
        reason = (
            "snapshot_stale" if exc.code == "snapshot_stale" else "snapshot_invalid"
        )
        return _decision(False, reason)

    matched: dict[str, Any] | None = None
    matched_identity: dict[str, Any] | None = None
    for user_field, record_field in (
        ("union_id", "feishu_union_id"),
        ("user_id", "feishu_user_id"),
        ("open_id", "feishu_open_id"),
    ):
        value = str(user.get(user_field) or "").strip()
        if not value:
            continue
        matches: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        for record in snapshot["records"]:
            record_tenant = str(record.get("tenant_key") or "").strip()
            if record_tenant and tenant_key and record_tenant != tenant_key:
                continue
            for identity in _record_identities(record):
                identity_tenant = str(
                    identity.get("tenant_key") or record_tenant
                ).strip()
                if identity_tenant and tenant_key and identity_tenant != tenant_key:
                    continue
                if str(identity.get(record_field) or "").strip() == value:
                    matches[str(record["employee_id"])] = (record, identity)
        if len(matches) > 1:
            return _decision(False, "identity_conflict")
        if matches:
            matched, matched_identity = next(iter(matches.values()))
            break

    if matched is None or matched_identity is None:
        return _decision(False, "employee_not_found")

    oauth_open_id = str(user.get("open_id") or "").strip()
    if oauth_open_id:
        for identity in _record_identities(matched):
            if str(identity.get("feishu_open_id") or "").strip() == oauth_open_id:
                matched_identity = identity
                break

    employee = {
        key: matched[key]
        for key in (
            "employee_id",
            "display_name",
            "department",
            "title",
            "role",
            "status",
            "relation_type",
            "tenant_key",
        )
    }
    if snapshot.get("schema_version") == CURRENT_SCHEMA_VERSION:
        employee["principal_key"] = matched["principal_key"]
    identity = {
        "employee_id": matched["employee_id"],
        "tenant_key": matched_identity.get("tenant_key") or matched["tenant_key"],
        **{field: matched_identity.get(field, "") for field in IDENTITY_FIELDS},
    }
    if snapshot.get("schema_version") == CURRENT_SCHEMA_VERSION:
        identity.update(
            {
                "app_key": matched_identity.get("app_key", ""),
                "provider": matched_identity.get("provider", "feishu"),
                "provider_subject": matched_identity.get("provider_subject", ""),
                "principal_key": matched["principal_key"],
            }
        )
    permissions = (
        list(matched.get("permissions") or [])
        if snapshot.get("schema_version") == CURRENT_SCHEMA_VERSION
        else []
    )
    status = str(matched["status"])
    return {
        "allowed": status == "active",
        "reason": "ok" if status == "active" else f"status_{status}",
        "employee": employee,
        "identity": identity,
        "permissions": permissions,
    }


def _decision(allowed: bool, reason: str) -> dict[str, Any]:
    return {
        "allowed": allowed,
        "reason": reason,
        "employee": None,
        "identity": None,
        "permissions": [],
    }


def snapshot_health(snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a non-PII health summary for monitoring and release checks.

    Args:
        snapshot: Optional in-memory snapshot used by tests.

    Returns:
        Health state, structured reason, age, counts, and digest prefix.
    """
    if snapshot is None:
        try:
            raw_snapshot = _kv.get_value(SNAPSHOT_KEY, strict=True)
        except RuntimeError:
            return {"status": "unavailable", "reason": "authorization_unavailable"}
        if not raw_snapshot:
            return {"status": "unavailable", "reason": "snapshot_missing"}
        try:
            snapshot = json.loads(str(raw_snapshot))
        except json.JSONDecodeError:
            return {"status": "unavailable", "reason": "snapshot_invalid"}
    try:
        _validate_snapshot(snapshot)
    except EmployeeAccessError as exc:
        return {"status": "unavailable", "reason": exc.code}

    age_seconds = max(0, int(_snapshot_age_seconds(snapshot)))
    if age_seconds > MAX_SNAPSHOT_AGE_SECONDS:
        status = "unavailable"
        reason = "snapshot_stale"
    elif age_seconds > DEGRADED_SNAPSHOT_AGE_SECONDS:
        status = "degraded"
        reason = "snapshot_delayed"
    else:
        status = "healthy"
        reason = "ok"
    permissions = sum(
        len(record.get("permissions") or []) for record in snapshot["records"]
    )
    return {
        "status": status,
        "reason": reason,
        "schema_version": snapshot["schema_version"],
        "age_seconds": age_seconds,
        "record_count": len(snapshot["records"]),
        "permission_count": permissions,
        "digest_prefix": str(snapshot["digest"])[:12],
        "sync_reason": str(snapshot.get("sync_reason") or "legacy"),
    }


def store_snapshot(snapshot: dict[str, Any]) -> str:
    """Atomically replace the mirror while rejecting version rollback.

    Args:
        snapshot: Complete employee authorization snapshot.

    Returns:
        ``stored`` or ``unchanged`` for an idempotent replay.

    Raises:
        EmployeeAccessError: If validation or ordering checks fail.
        RuntimeError: If persistent Redis is unavailable.
    """
    _validate_snapshot(snapshot, max_age_seconds=MAX_SNAPSHOT_AGE_SECONDS)
    existing_raw = _kv.get_value(SNAPSHOT_KEY, strict=True)
    if existing_raw:
        try:
            existing = json.loads(str(existing_raw))
            _validate_snapshot(existing)
        except (json.JSONDecodeError, EmployeeAccessError):
            existing = None
        if existing is not None:
            incoming_time = _timestamp(
                snapshot.get("generated_at"), "invalid_snapshot_timestamp"
            )
            existing_time = _timestamp(
                existing.get("generated_at"), "invalid_snapshot_timestamp"
            )
            if incoming_time < existing_time:
                raise EmployeeAccessError("snapshot_out_of_order")
            if incoming_time == existing_time:
                if snapshot.get("digest") == existing.get("digest"):
                    return "unchanged"
                raise EmployeeAccessError("snapshot_version_conflict")
    _kv.set_value(SNAPSHOT_KEY, _canonical_json(snapshot), strict=True)
    return "stored"


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
    sync_time = _timestamp(timestamp, "invalid_sync_timestamp")
    skew = abs((datetime.now(UTC) - sync_time).total_seconds())
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
