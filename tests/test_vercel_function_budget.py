from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


class VercelFunctionBudgetTests(unittest.TestCase):
    def test_hobby_deployment_stays_within_twelve_python_functions(self) -> None:
        tracked = subprocess.check_output(
            ["git", "ls-files", "--cached", "api"], text=True
        ).splitlines()
        handlers = []
        for filename in tracked:
            path = Path(filename)
            if path.suffix != ".py":
                continue
            if path.name == "__init__.py" or any(
                part.startswith("_") for part in path.relative_to("api").parts
            ):
                continue
            handlers.append(path.as_posix())

        self.assertLessEqual(len(handlers), 12, handlers)

    def test_desktop_routes_share_one_vercel_function(self) -> None:
        config = json.loads(Path("vercel.json").read_text(encoding="utf-8"))
        rewrites = {item["source"]: item["destination"] for item in config["rewrites"]}
        expected = {
            "/api/desktop/exchange": "/api/desktop?route=exchange",
            "/api/desktop/latest": "/api/desktop?route=latest",
            "/api/desktop/open": "/api/desktop?route=open",
            "/api/desktop/probe/start": "/api/desktop?route=probe-start",
            "/api/desktop/probe/status": "/api/desktop?route=probe-status",
            "/api/desktop/probe/heartbeat": "/api/desktop?route=probe-heartbeat",
            "/api/desktop/refresh": "/api/desktop?route=refresh",
            "/api/internal/desktop/release": "/api/desktop?route=release-sync",
            "/api/internal/employee-access/sync": ("/api/desktop?route=employee-sync"),
            "/api/internal/employee-access/health": (
                "/api/desktop?route=employee-health"
            ),
            "/api/oauth/handoff/exchange": (
                "/api/desktop?route=oauth-handoff-exchange"
            ),
            "/api/oauth/grant/check": "/api/desktop?route=oauth-grant-check",
            "/api/oauth/grant/refresh": ("/api/desktop?route=oauth-grant-refresh"),
            "/api/oauth/grant/revoke": "/api/desktop?route=oauth-grant-revoke",
        }

        self.assertEqual({route: rewrites.get(route) for route in expected}, expected)


if __name__ == "__main__":
    unittest.main()
