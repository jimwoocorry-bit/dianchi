from __future__ import annotations

import base64
import json
import unittest
import urllib.parse

from api.auth.feishu.callback import attachment_redirect_url


def attachment_state(return_url: str) -> str:
    """Encode the same OAuth state shape produced by DC-Agent.

    Args:
        return_url: LAN callback URL embedded in the state.

    Returns:
        Unpadded base64url state value.
    """
    payload = json.dumps(
        {"return_url": return_url, "nonce": "test"}, separators=(",", ":")
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


class AttachmentRedirectTest(unittest.TestCase):
    def test_valid_attachment_state_redirects_to_bound_lan_callback(self) -> None:
        state = attachment_state(
            "http://192.168.2.162:6185/api/v1/assistant-attachments/"
            "draft_123/oauth/callback"
        )

        location = attachment_redirect_url(state, "oauth-code", "")

        self.assertIsNotNone(location)
        parsed = urllib.parse.urlparse(location or "")
        self.assertEqual(parsed.hostname, "192.168.2.162")
        self.assertEqual(parsed.port, 6185)
        self.assertEqual(
            urllib.parse.parse_qs(parsed.query),
            {"state": [state], "code": ["oauth-code"]},
        )

    def test_denied_consent_forwards_error_without_code(self) -> None:
        state = attachment_state(
            "http://192.168.1.55:6185/api/v1/assistant-attachments/"
            "draft_456/oauth/callback"
        )

        location = attachment_redirect_url(state, "", "access_denied")

        parsed = urllib.parse.urlparse(location or "")
        self.assertEqual(
            urllib.parse.parse_qs(parsed.query),
            {"state": [state], "error": ["access_denied"]},
        )

    def test_normal_website_state_is_not_intercepted(self) -> None:
        self.assertIsNone(attachment_redirect_url("normal-random-state", "code", ""))

    def test_untrusted_return_target_is_rejected(self) -> None:
        state = attachment_state(
            "https://attacker.example/api/v1/assistant-attachments/"
            "draft_123/oauth/callback"
        )

        self.assertIsNone(attachment_redirect_url(state, "code", ""))


if __name__ == "__main__":
    unittest.main()
