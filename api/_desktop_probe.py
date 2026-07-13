"""Short-lived URL-protocol probe state for installed desktop detection."""

from __future__ import annotations

import secrets

from api import _kv


PROBE_TTL_SECONDS = 90
PROBE_KEY_PREFIX = "dianchi:desktop:probe:"


def start_probe() -> str:
    """Create a short-lived pending desktop probe.

    Returns:
        Opaque probe identifier.

    Raises:
        RuntimeError: If persistent Redis is unavailable.
    """
    probe_id = secrets.token_urlsafe(24)
    _kv.set_value(
        f"{PROBE_KEY_PREFIX}{probe_id}",
        "pending",
        ttl_seconds=PROBE_TTL_SECONDS,
        strict=True,
    )
    return probe_id


def record_probe_heartbeat(probe_id: str) -> bool:
    """Mark an existing probe as installed.

    Args:
        probe_id: Opaque probe identifier received through the URL protocol.

    Returns:
        Whether a live pending or installed probe was found.

    Raises:
        RuntimeError: If persistent Redis is unavailable.
    """
    if not probe_id or len(probe_id) > 256:
        return False
    key = f"{PROBE_KEY_PREFIX}{probe_id}"
    current = _kv.get_value(key, strict=True)
    if current not in {"pending", "installed"}:
        return False
    _kv.set_value(
        key,
        "installed",
        ttl_seconds=PROBE_TTL_SECONDS,
        strict=True,
    )
    return True


def probe_status(probe_id: str) -> str:
    """Return pending, installed, or expired for one probe.

    Args:
        probe_id: Opaque probe identifier.

    Returns:
        Stable probe state string.

    Raises:
        RuntimeError: If persistent Redis is unavailable.
    """
    if not probe_id or len(probe_id) > 256:
        return "expired"
    current = _kv.get_value(f"{PROBE_KEY_PREFIX}{probe_id}", strict=True)
    return str(current) if current in {"pending", "installed"} else "expired"
