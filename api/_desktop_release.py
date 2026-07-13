"""Validated Vercel Blob release manifests for desktop installers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from api import _kv


RELEASE_KEY_PREFIX = "dianchi:desktop:release:"
MAX_RELEASE_SYNC_SKEW_SECONDS = 5 * 60
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PLATFORM_ARTIFACTS = {
    "windows-x64": ("desktop/windows/x64", "DianchiDesktopAssistantSetup.exe"),
    "macos-arm64": ("desktop/macos/arm64", "DianchiDesktopAssistant.dmg"),
}


class DesktopReleaseError(ValueError):
    """Represent a rejected desktop release manifest or request."""

    def __init__(self, code: str) -> None:
        """Initialize a desktop release error.

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


def validate_release_manifest(manifest: dict[str, Any]) -> None:
    """Validate a complete immutable desktop release manifest.

    Args:
        manifest: Candidate desktop release manifest.

    Raises:
        DesktopReleaseError: If version, channel, artifact, or integrity fails.
    """
    if not isinstance(manifest, dict) or set(manifest) != {
        "version",
        "channel",
        "published_at",
        "artifacts",
    }:
        raise DesktopReleaseError("invalid_manifest_fields")
    version = str(manifest.get("version") or "")
    if not VERSION_PATTERN.fullmatch(version):
        raise DesktopReleaseError("invalid_release_version")
    channel = str(manifest.get("channel") or "")
    if channel not in {"stable", "gray"}:
        raise DesktopReleaseError("invalid_release_channel")
    try:
        published_at = datetime.fromisoformat(
            str(manifest.get("published_at") or "").replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise DesktopReleaseError("invalid_release_timestamp") from exc
    if published_at.tzinfo is None:
        raise DesktopReleaseError("invalid_release_timestamp")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise DesktopReleaseError("invalid_release_artifacts")
    if channel == "stable" and set(artifacts) != set(PLATFORM_ARTIFACTS):
        raise DesktopReleaseError("stable_artifacts_incomplete")
    if not set(artifacts).issubset(PLATFORM_ARTIFACTS):
        raise DesktopReleaseError("unsupported_release_artifact")

    for artifact_key, artifact in artifacts.items():
        if not isinstance(artifact, dict) or set(artifact) != {
            "url",
            "size",
            "sha256",
            "signed",
        }:
            raise DesktopReleaseError("invalid_artifact_fields")
        if not isinstance(artifact.get("size"), int) or artifact["size"] <= 0:
            raise DesktopReleaseError("invalid_artifact_size")
        if not SHA256_PATTERN.fullmatch(str(artifact.get("sha256") or "")):
            raise DesktopReleaseError("invalid_artifact_sha256")
        if not isinstance(artifact.get("signed"), bool):
            raise DesktopReleaseError("invalid_artifact_signature_state")
        if channel == "stable" and not artifact["signed"]:
            raise DesktopReleaseError("stable_artifact_unsigned")

        parsed_url = urlparse(str(artifact.get("url") or ""))
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or not parsed_url.hostname.endswith("blob.vercel-storage.com")
        ):
            raise DesktopReleaseError("invalid_artifact_url")
        expected_prefix, expected_filename = PLATFORM_ARTIFACTS[artifact_key]
        expected_suffix = f"/{expected_prefix}/{version}/{expected_filename}"
        if not parsed_url.path.endswith(expected_suffix):
            raise DesktopReleaseError("artifact_path_not_immutable")


def artifact_for(
    platform: str,
    architecture: str,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Select one platform artifact from the stable release manifest.

    Args:
        platform: Normalized operating system name.
        architecture: Normalized CPU architecture.
        manifest: Optional manifest supplied by tests or a cached caller.

    Returns:
        Version metadata and the matching artifact.

    Raises:
        DesktopReleaseError: If no valid matching release is available.
        RuntimeError: If persistent Redis is unavailable.
    """
    artifact_key = f"{platform.strip().lower()}-{architecture.strip().lower()}"
    if artifact_key not in PLATFORM_ARTIFACTS:
        raise DesktopReleaseError("unsupported_platform")
    if manifest is None:
        raw_manifest = _kv.get_value(f"{RELEASE_KEY_PREFIX}stable", strict=True)
        if not raw_manifest:
            raise DesktopReleaseError("release_missing")
        try:
            manifest = json.loads(str(raw_manifest))
        except json.JSONDecodeError as exc:
            raise DesktopReleaseError("release_invalid") from exc
    validate_release_manifest(manifest)
    artifact = manifest["artifacts"].get(artifact_key)
    if not artifact:
        raise DesktopReleaseError("release_missing_for_platform")
    return {
        "version": manifest["version"],
        "channel": manifest["channel"],
        "published_at": manifest["published_at"],
        "platform": artifact_key,
        "artifact": artifact,
    }


def store_release_manifest(manifest: dict[str, Any]) -> None:
    """Store one validated stable or gray release manifest.

    Args:
        manifest: Validated release manifest.

    Raises:
        DesktopReleaseError: If manifest validation fails.
        RuntimeError: If persistent Redis is unavailable.
    """
    validate_release_manifest(manifest)
    _kv.set_value(
        f"{RELEASE_KEY_PREFIX}{manifest['channel']}",
        _canonical_json(manifest),
        strict=True,
    )


def verify_release_sync(
    body: bytes,
    timestamp: str,
    signature: str,
    secret: str,
) -> dict[str, Any]:
    """Verify and decode an internal desktop release publication request.

    Args:
        body: Raw canonical release JSON.
        timestamp: ISO-8601 publication timestamp.
        signature: Hex HMAC-SHA256 signature over the raw body.
        secret: Shared release publication secret.

    Returns:
        Validated release manifest.

    Raises:
        DesktopReleaseError: If authentication, freshness, or manifest fails.
    """
    if not secret:
        raise DesktopReleaseError("release_secret_missing")
    try:
        sync_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DesktopReleaseError("invalid_release_sync_timestamp") from exc
    if sync_time.tzinfo is None:
        raise DesktopReleaseError("invalid_release_sync_timestamp")
    skew = abs((datetime.now(UTC) - sync_time.astimezone(UTC)).total_seconds())
    if skew > MAX_RELEASE_SYNC_SKEW_SECONDS:
        raise DesktopReleaseError("release_sync_timestamp_expired")
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise DesktopReleaseError("invalid_release_signature")
    try:
        manifest = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DesktopReleaseError("invalid_release_json") from exc
    if not isinstance(manifest, dict):
        raise DesktopReleaseError("invalid_release_root")
    if str(manifest.get("published_at") or "") != timestamp:
        raise DesktopReleaseError("release_sync_timestamp_mismatch")
    validate_release_manifest(manifest)
    return manifest
