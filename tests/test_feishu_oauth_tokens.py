from __future__ import annotations

import os
import unittest
import urllib.parse
from unittest import mock

from api import _feishu


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None


class FeishuOAuthTokenTests(unittest.TestCase):
    def test_cloud_docs_scope_is_purpose_specific_and_refreshable(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            cloud_scope = set(_feishu.oauth_scope("agent", "cloud_docs").split())

        self.assertIn("offline_access", cloud_scope)
        self.assertIn("drive:drive:readonly", cloud_scope)

    def test_refresh_uses_v2_endpoint_and_rotated_refresh_token(self) -> None:
        response = {
            "access_token": "access-new",
            "expires_in": 7200,
            "refresh_token": "refresh-new",
            "refresh_token_expires_in": 86400,
        }
        with (
            mock.patch.object(
                _feishu,
                "feishu_config",
                return_value=("agent", "app-id", "app-secret", "scope"),
            ),
            mock.patch.object(
                _feishu,
                "request_json",
                return_value=response,
            ) as request_json,
        ):
            result = _feishu.refresh_user_token("refresh-old", "agent")

        self.assertEqual(result["refresh_token"], "refresh-new")
        self.assertEqual(request_json.call_args.args[0], _feishu.FEISHU_TOKEN_URL)
        self.assertEqual(
            request_json.call_args.kwargs["body"],
            {
                "grant_type": "refresh_token",
                "client_id": "app-id",
                "client_secret": "app-secret",
                "refresh_token": "refresh-old",
            },
        )

    def test_refresh_business_rejection_is_non_retryable(self) -> None:
        with (
            mock.patch.object(
                _feishu,
                "feishu_config",
                return_value=("agent", "app-id", "app-secret", "scope"),
            ),
            mock.patch.object(
                _feishu,
                "request_json",
                return_value={"code": 20030, "msg": "invalid refresh token"},
            ),
            self.assertRaises(_feishu.FeishuRequestError) as error,
        ):
            _feishu.refresh_user_token("refresh-old", "agent")

        self.assertFalse(error.exception.retryable)
        self.assertEqual(error.exception.code, "feishu_token_rejected_20030")

    def test_revoke_uses_form_encoded_rfc7009_request(self) -> None:
        with (
            mock.patch.object(
                _feishu,
                "feishu_config",
                return_value=("agent", "app-id", "app-secret", "scope"),
            ),
            mock.patch.object(
                _feishu.urllib.request,
                "urlopen",
                return_value=_Response(),
            ) as urlopen,
        ):
            _feishu.revoke_user_token(
                "refresh-value",
                "agent",
                token_type_hint="refresh_token",
            )

        request = urlopen.call_args.args[0]
        form = urllib.parse.parse_qs(request.data.decode("utf-8"))
        self.assertEqual(request.full_url, _feishu.FEISHU_REVOKE_URL)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(form["token"], ["refresh-value"])
        self.assertEqual(form["token_type_hint"], ["refresh_token"])
        self.assertEqual(
            request.headers["Content-type"],
            "application/x-www-form-urlencoded",
        )


if __name__ == "__main__":
    unittest.main()
