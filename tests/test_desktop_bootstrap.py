from __future__ import annotations

import hashlib
import hmac
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from api._desktop_probe import probe_status, record_probe_heartbeat, start_probe
from api._desktop_release import (
    DesktopReleaseError,
    artifact_for,
    validate_release_manifest,
    verify_release_sync,
)


class MemoryKv:
    def __init__(self) -> None:
        self.values = {}

    def set_value(self, key, value, *, ttl_seconds=None, strict=False) -> None:
        self.values[key] = value

    def get_value(self, key, default=None, *, strict=False):
        return self.values.get(key, default)


def release_manifest(*, signed: bool = True) -> dict:
    version = "0.2.0"
    return {
        "version": version,
        "channel": "stable",
        "published_at": datetime.now(UTC).isoformat(),
        "artifacts": {
            "windows-x64": {
                "url": "https://dianchi.public.blob.vercel-storage.com/desktop/windows/x64/0.2.0/DianchiDesktopAssistantSetup.exe",
                "size": 1024,
                "sha256": "a" * 64,
                "signed": signed,
            },
            "macos-arm64": {
                "url": "https://dianchi.public.blob.vercel-storage.com/desktop/macos/arm64/0.2.0/DianchiDesktopAssistant.dmg",
                "size": 2048,
                "sha256": "b" * 64,
                "signed": signed,
            },
        },
    }


class DesktopProbeTests(unittest.TestCase):
    def test_probe_moves_from_pending_to_installed(self) -> None:
        kv = MemoryKv()
        with (
            mock.patch("api._desktop_probe._kv.set_value", kv.set_value),
            mock.patch("api._desktop_probe._kv.get_value", kv.get_value),
            mock.patch(
                "api._desktop_probe.secrets.token_urlsafe",
                return_value="probe-1",
            ),
        ):
            probe_id = start_probe()
            self.assertEqual(probe_status(probe_id), "pending")
            self.assertTrue(record_probe_heartbeat(probe_id))
            self.assertEqual(probe_status(probe_id), "installed")
            self.assertEqual(probe_status(probe_id), "installed")

    def test_missing_probe_is_expired(self) -> None:
        kv = MemoryKv()
        with mock.patch("api._desktop_probe._kv.get_value", kv.get_value):
            self.assertEqual(probe_status("missing"), "expired")
            self.assertFalse(record_probe_heartbeat("missing"))


class DesktopReleaseTests(unittest.TestCase):
    def test_manifest_selects_the_matching_platform_artifact(self) -> None:
        manifest = release_manifest()

        validate_release_manifest(manifest)
        result = artifact_for("windows", "x64", manifest=manifest)

        self.assertEqual(result["version"], "0.2.0")
        self.assertTrue(result["artifact"]["url"].endswith("Setup.exe"))

    def test_configured_gray_channel_is_loaded_from_redis(self) -> None:
        manifest = release_manifest()
        manifest["channel"] = "gray"

        with (
            mock.patch.dict("os.environ", {"DESKTOP_RELEASE_CHANNEL": "gray"}),
            mock.patch(
                "api._desktop_release._kv.get_value",
                return_value=json.dumps(manifest),
            ) as get_value,
        ):
            result = artifact_for("macos", "arm64")

        get_value.assert_called_once_with(
            "dianchi:desktop:release:gray",
            strict=True,
        )
        self.assertEqual(result["channel"], "gray")

    def test_manifest_rejects_integrity_path_and_signature_errors(self) -> None:
        invalid_sha = release_manifest()
        invalid_sha["artifacts"]["windows-x64"]["sha256"] = "bad"
        invalid_path = release_manifest()
        invalid_path["artifacts"]["windows-x64"]["url"] = (
            "https://dianchi.public.blob.vercel-storage.com/desktop/windows/x64/latest/setup.exe"
        )
        unsigned = release_manifest(signed=False)
        invalid_version = release_manifest()
        invalid_version["version"] = "latest"

        for manifest in [invalid_sha, invalid_path, unsigned, invalid_version]:
            with self.subTest(manifest=manifest):
                with self.assertRaises(DesktopReleaseError):
                    validate_release_manifest(manifest)

    def test_release_sync_requires_valid_hmac(self) -> None:
        manifest = release_manifest()
        body = json.dumps(
            manifest,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        timestamp = manifest["published_at"]
        signature = hmac.new(b"release-secret", body, hashlib.sha256).hexdigest()

        self.assertEqual(
            verify_release_sync(body, timestamp, signature, "release-secret"),
            manifest,
        )
        with self.assertRaisesRegex(DesktopReleaseError, "signature"):
            verify_release_sync(body, timestamp, "0" * 64, "release-secret")

    def test_desktop_page_contains_only_truthful_bootstrap_states(self) -> None:
        source = Path("desktop.html").read_text(encoding="utf-8")

        for state in [
            "checking-login",
            "probing",
            "opening-installed",
            "downloading-installer",
            "download-ready",
            "download-blocked",
            "service-unavailable",
        ]:
            self.assertIn(state, source)
        self.assertIn("dianchi://probe?probe_id=", source)
        self.assertNotIn("downloadLink.click()", source)
        self.assertNotIn("扫描已安装程序", source)
        self.assertNotIn("自动运行安装包", source)


if __name__ == "__main__":
    unittest.main()
