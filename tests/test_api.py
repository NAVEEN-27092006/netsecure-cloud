from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.monitor import ProbeResult


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class NetSecureApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        settings = Settings(
            database_path=Path(self.temporary_directory.name) / "test.db",
            session_secret="test-secret",
            session_hours=1,
            allow_private_targets=True,
            cookie_secure=False,
            environment="test",
            frontend_path=PROJECT_ROOT / "frontend",
        )
        self.client_context = TestClient(create_app(settings))
        self.client = self.client_context.__enter__()

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)
        self.temporary_directory.cleanup()

    def bootstrap(self) -> None:
        response = self.client.post(
            "/api/auth/bootstrap",
            json={"username": "admin", "password": "a-very-long-test-password"},
        )
        self.assertEqual(response.status_code, 201)

    def test_setup_bootstrap_and_authenticated_dashboard(self) -> None:
        self.assertEqual(self.client.get("/api/setup-status").json(), {"needs_bootstrap": True})
        self.assertEqual(self.client.get("/api/dashboard").status_code, 401)

        self.bootstrap()

        self.assertEqual(self.client.get("/api/auth/me").json()["username"], "admin")
        dashboard = self.client.get("/api/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.json()["unknown_count"], 0)
        self.assertFalse(self.client.get("/api/setup-status").json()["needs_bootstrap"])

    def test_target_lifecycle_and_history(self) -> None:
        self.bootstrap()
        created = self.client.post(
            "/api/targets",
            json={"name": "Local lab", "host": "127.0.0.1", "port": 443},
        )
        self.assertEqual(created.status_code, 201)
        target_id = created.json()["id"]

        with patch(
            "app.main.probe_tcp",
            return_value=ProbeResult(status="online", response_ms=11.4, error_message=None),
        ):
            checked = self.client.post(f"/api/targets/{target_id}/check")

        self.assertEqual(checked.status_code, 200)
        self.assertEqual(checked.json()["status"], "online")
        dashboard = self.client.get("/api/dashboard").json()
        self.assertEqual(dashboard["online_count"], 1)
        self.assertEqual(dashboard["targets"][0]["latest_response_ms"], 11.4)
        history = self.client.get(f"/api/targets/{target_id}/history").json()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "online")
        self.assertEqual(self.client.delete(f"/api/targets/{target_id}").status_code, 204)

    def test_private_target_is_rejected_when_disabled(self) -> None:
        self.client_context.__exit__(None, None, None)
        self.temporary_directory.cleanup()
        self.temporary_directory = tempfile.TemporaryDirectory()
        settings = Settings(
            database_path=Path(self.temporary_directory.name) / "test.db",
            session_secret="test-secret",
            session_hours=1,
            allow_private_targets=False,
            cookie_secure=False,
            environment="test",
            frontend_path=PROJECT_ROOT / "frontend",
        )
        self.client_context = TestClient(create_app(settings))
        self.client = self.client_context.__enter__()
        self.bootstrap()

        response = self.client.post(
            "/api/targets",
            json={"name": "Blocked local host", "host": "127.0.0.1", "port": 443},
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("private or restricted", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
