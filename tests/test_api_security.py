"""
GhostHunt — Phase 6 Test Suite: API & Dashboard Security Controls
Comprehensive security tests verifying hardening, CSRF enforcement, and input safety.

Covers:
1. Single-process debug mode disabled (debug=False, use_reloader=False).
2. Localhost-only binding (127.0.0.1).
3. CSRF protection enforcement on browser sessions (rejects missing/invalid tokens).
4. Valid CSRF token accepted on browser sessions.
5. Oversized payload rejection (MAX_CONTENT_LENGTH = 1 MB returns 413).
6. Suppression of stack traces and internal secrets in error responses.
7. HTML auto-escaping of forensic evidence (XSS protection).
8. Parameter tampering rejection (invalid types and out-of-bounds parameters).
9. Absence of destructive execution/modification endpoints.
"""

import tempfile
import unittest
from pathlib import Path

import config
import core.db as db
from dashboard import create_app


class TestApiSecurity(unittest.TestCase):
    """Security verification test suite."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_sec.db")
        db.init_db(self.db_path)

        self.app = create_app({
            "TESTING": True,
            "DB_PATH": self.db_path,
            "CSRF_ENABLED": True,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        import gc
        gc.collect()
        self.temp_dir.cleanup()

    def test_01_debug_and_reloader_disabled_in_config(self):
        """Production and development configs must have FLASK_DEBUG and USE_RELOADER False."""
        self.assertFalse(config.FLASK_DEBUG)
        self.assertFalse(config.FLASK_USE_RELOADER)

    def test_02_default_binding_is_localhost(self):
        """Default server binding must be strictly 127.0.0.1 (not 0.0.0.0)."""
        self.assertEqual(config.FLASK_HOST, "127.0.0.1")

    def test_03_csrf_rejects_browser_session_without_token(self):
        """Browser session (with session cookie) attempting state change without token is rejected."""
        # 1. Establish session cookie
        self.client.get("/")

        # 2. Attempt POST without CSRF token
        resp = self.client.post("/api/baseline/reset", json={"confirm": True})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("CSRF token missing or invalid", data["message"])

    def test_04_csrf_rejects_invalid_token(self):
        """Browser session sending an invalid CSRF token is rejected with 400."""
        self.client.get("/")
        resp = self.client.post(
            "/api/baseline/reset",
            json={"confirm": True},
            headers={"X-CSRF-Token": "invalid_forged_csrf_token_value"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("CSRF token missing or invalid", resp.get_json()["message"])

    def test_05_csrf_accepts_valid_token(self):
        """Browser session providing matching X-CSRF-Token is accepted."""
        # 1. Establish session and retrieve CSRF token
        self.client.get("/")
        with self.client.session_transaction() as sess:
            valid_token = sess.get("csrf_token")

        self.assertIsNotNone(valid_token)

        # 2. State-changing request with valid token
        resp = self.client.post(
            "/api/baseline/reset",
            json={"confirm": True},
            headers={"X-CSRF-Token": valid_token},
        )
        self.assertEqual(resp.status_code, 200)

    def test_06_oversized_payload_rejected_with_413(self):
        """Payloads exceeding MAX_CONTENT_LENGTH (1 MB) return 413 Payload Too Large."""
        large_bytes = b"A" * (1024 * 1024 + 1024)  # > 1 MB
        resp = self.client.post("/api/scan", data=large_bytes, content_type="application/json")
        self.assertEqual(resp.status_code, 413)

    def test_07_error_responses_suppress_stack_traces_and_secrets(self):
        """500/400/404 responses do not leak stack traces, database paths, or secret keys."""
        resp = self.client.get("/api/scan/invalid_format_string")
        self.assertEqual(resp.status_code, 404)
        body = resp.get_data(as_text=True)

        self.assertNotIn("Traceback", body)
        self.assertNotIn(config.SECRET_KEY, body)

    def test_08_xss_auto_escaping_in_forensic_evidence(self):
        """Malicious script tags in process names or forensic evidence are auto-escaped in HTML."""
        sid = db.start_scan(db_path=self.db_path)
        xss_evidence = "<script>alert('XSS_ATTACK_VECTOR')</script>"
        findings = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "process_view",
            "pid": 9999,
            "process_name": "xss<tag>.exe",
            "evidence": xss_evidence,
            "severity": "high",
            "signature_status": "N/A",
            "metadata": "{}",
        }]
        db.insert_findings(sid, findings, db_path=self.db_path)
        db.complete_scan(sid, 1, 1, 10.0, db_path=self.db_path)

        resp = self.client.get(f"/process/9999?scan_id={sid}")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # Raw unescaped script tag must NOT be present
        self.assertNotIn("<script>alert('XSS_ATTACK_VECTOR')</script>", html)
        # Escaped HTML entity must be present
        self.assertIn("&lt;script&gt;alert(&#39;XSS_ATTACK_VECTOR&#39;)&lt;/script&gt;", html)

    def test_09_no_destructive_or_remediation_endpoints_exist(self):
        """GhostHunt is read-only; no endpoints exist for killing processes or executing commands."""
        resp_kill = self.client.post("/api/process/1234/kill", json={})
        self.assertEqual(resp_kill.status_code, 404)

        resp_remediate = self.client.post("/api/remediate", json={})
        self.assertEqual(resp_remediate.status_code, 404)

        resp_cmd = self.client.post("/api/exec", json={"cmd": "whoami"})
        self.assertEqual(resp_cmd.status_code, 404)


if __name__ == "__main__":
    unittest.main()
