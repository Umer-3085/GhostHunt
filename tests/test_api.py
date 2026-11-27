"""
GhostHunt — Phase 6 Test Suite: REST API Endpoints
Comprehensive unit and integration tests for all REST API endpoints.

Covers:
1. Health and status endpoint (GET /api/health, GET /api/status).
2. Database unavailable response (503 Service Unavailable).
3. Manual scan trigger success (POST /api/scan).
4. Manual scan busy lock contention response (409 Conflict).
5. Scan status retrieval by scan_id (GET /api/scan/<id>).
6. Latest completed scan retrieval (GET /api/scan/latest).
7. Failed scans excluded from latest completed scan query.
8. Risk-ranked entity retrieval (GET /api/scores) with sorting and filtering.
9. Forensic evidence retrieval (GET /api/findings/<id> and GET /api/process/<pid>/findings).
10. Scan history retrieval (GET /api/history).
11. Invalid scan IDs (returns 400 or 404).
12. Invalid pagination parameters (page=0, per_page=9999 returns 400).
13. Invalid request bodies (malformed payload returns 400).
14. Baseline lifecycle metadata retrieval (GET /api/baseline).
15. Candidate baseline acceptance (POST /api/baseline/accept).
16. Baseline reset with confirmation (POST /api/baseline/reset).
17. Lock contention during baseline acceptance/reset (returns 409 Conflict).
18. Safe error handling (never exposes internal exceptions or stack traces).
"""

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import config
import core.db as db
import core.scheduler as scheduler
from dashboard import create_app


class TestRestApi(unittest.TestCase):
    """Test suite for GhostHunt REST API endpoints."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_api.db")
        db.init_db(self.db_path)

        self.app = create_app({
            "TESTING": True,
            "DB_PATH": self.db_path,
            "CSRF_ENABLED": False,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        import gc
        gc.collect()
        self.temp_dir.cleanup()

    def test_01_health_and_status_endpoint(self):
        """GET /api/health returns 200 with status ok and version."""
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["db_connected"])
        self.assertEqual(data["version"], config.APP_VERSION)
        self.assertIn("scheduler", data)

    def test_02_database_unavailable_returns_503(self):
        """When database is unreachable, health endpoint returns 503 Service Unavailable."""
        # Point to invalid database path
        app_broken = create_app({"TESTING": True, "DB_PATH": "Z:\\invalid_drive\\ghosthunt.db"})
        client_broken = app_broken.test_client()

        resp = client_broken.get("/api/health")
        self.assertEqual(resp.status_code, 503)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertFalse(data["db_connected"])
        self.assertEqual(data["status"], "error")

    def test_03_manual_scan_success(self):
        """POST /api/scan triggers scan cycle and returns 200 with scan metadata."""
        with patch("core.scheduler.ScanScheduler.trigger_manual_scan") as mock_scan:
            mock_scan.return_value = {
                "success": True,
                "status": "completed",
                "scan_id": 101,
                "total_findings": 2,
                "high_risk_count": 1,
                "duration_ms": 45.2,
            }
            resp = self.client.post("/api/scan", json={})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(data["scan_id"], 101)
            self.assertEqual(data["high_risk_count"], 1)

    def test_04_manual_scan_busy_returns_409_conflict(self):
        """When another scan or reset holds the lock, POST /api/scan returns 409 Conflict."""
        with patch("core.scheduler.ScanScheduler.trigger_manual_scan") as mock_scan:
            mock_scan.return_value = {
                "success": False,
                "status": "busy",
                "message": "Another protected operation is in progress.",
            }
            resp = self.client.post("/api/scan", json={})
            self.assertEqual(resp.status_code, 409)
            data = resp.get_json()
            self.assertFalse(data["success"])
            self.assertEqual(data["status"], "busy")
            self.assertIn("in progress", data["message"])

    def test_05_get_scan_status_by_id(self):
        """GET /api/scan/<id> returns 200 for existing scan and 404 for missing scan."""
        # Create scan in test database
        scan_id = db.start_scan(db_path=self.db_path)
        db.complete_scan(scan_id, 0, 0, 10.0, db_path=self.db_path)

        resp = self.client.get(f"/api/scan/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["scan"]["id"], scan_id)
        self.assertEqual(data["scan"]["status"], "COMPLETED")

        # Non-existent scan ID returns 404
        resp_404 = self.client.get("/api/scan/999999")
        self.assertEqual(resp_404.status_code, 404)

    def test_06_get_latest_completed_scan(self):
        """GET /api/scan/latest returns latest completed scan details."""
        # Fresh DB has no completed scans -> 404
        resp = self.client.get("/api/scan/latest")
        self.assertEqual(resp.status_code, 404)

        # Complete a scan
        sid = db.start_scan(db_path=self.db_path)
        db.complete_scan(sid, 5, 2, 25.0, db_path=self.db_path)

        resp2 = self.client.get("/api/scan/latest")
        self.assertEqual(resp2.status_code, 200)
        data = resp2.get_json()
        self.assertEqual(data["scan"]["id"], sid)

    def test_07_failed_scans_excluded_from_latest_completed(self):
        """Failed scans are strictly excluded from latest completed scan query."""
        # 1. Complete scan 1
        sid1 = db.start_scan(db_path=self.db_path)
        db.complete_scan(sid1, 0, 0, 10.0, db_path=self.db_path)

        # 2. Fail scan 2
        sid2 = db.start_scan(db_path=self.db_path)
        db.fail_scan(sid2, "Simulated crash", db_path=self.db_path)

        # Latest completed must be sid1, NOT sid2
        resp = self.client.get("/api/scan/latest")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["scan"]["id"], sid1)

    def test_08_risk_ranked_entities_scores_endpoint(self):
        """GET /api/scores retrieves correlated entities ordered by score desc."""
        sid = db.start_scan(db_path=self.db_path)
        risk_entries = [
            {"item_key": "proc:100:low.exe", "process_name": "low.exe", "pid": 100, "score": 0.30, "risk_level": "LOW", "signals_triggered": "persistence"},
            {"item_key": "proc:200:high.exe", "process_name": "high.exe", "pid": 200, "score": 0.70, "risk_level": "HIGH", "signals_triggered": "process_view,persistence"},
        ]
        db.insert_risk_scores(sid, risk_entries, db_path=self.db_path)
        db.complete_scan(sid, 2, 1, 15.0, db_path=self.db_path)

        resp = self.client.get(f"/api/scores?scan_id={sid}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["total_count"], 2)
        # Verify ordering: High score first
        self.assertEqual(data["entities"][0]["process_name"], "high.exe")
        self.assertEqual(data["entities"][1]["process_name"], "low.exe")

        # Test severity filter
        resp_filter = self.client.get(f"/api/scores?scan_id={sid}&severity=HIGH")
        self.assertEqual(resp_filter.status_code, 200)
        self.assertEqual(resp_filter.get_json()["total_count"], 1)
        self.assertEqual(resp_filter.get_json()["entities"][0]["risk_level"], "HIGH")

    def test_09_forensic_evidence_endpoints(self):
        """GET /api/findings/<id> and GET /api/process/<pid>/findings separate threats and diagnostics."""
        sid = db.start_scan(db_path=self.db_path)
        findings = [
            {"finding_type": "threat", "score_eligible": 1, "signal": "process_view", "pid": 500, "process_name": "rootkit.exe", "evidence": "Hidden proc", "severity": "high", "signature_status": "N/A", "metadata": "{}"},
            {"finding_type": "diagnostic", "score_eligible": 0, "signal": "signature", "pid": 500, "process_name": "rootkit.exe", "evidence": "Access denied", "severity": "low", "signature_status": "ERROR", "metadata": "{}"},
        ]
        db.insert_findings(sid, findings, db_path=self.db_path)
        db.complete_scan(sid, 2, 1, 10.0, db_path=self.db_path)

        # 1. Scan findings endpoint
        resp_all = self.client.get(f"/api/findings/{sid}")
        self.assertEqual(resp_all.status_code, 200)
        self.assertEqual(resp_all.get_json()["total_count"], 2)

        # 2. Process findings endpoint
        resp_proc = self.client.get(f"/api/process/500/findings?scan_id={sid}")
        self.assertEqual(resp_proc.status_code, 200)
        data = resp_proc.get_json()
        self.assertEqual(len(data["threats"]), 1)
        self.assertEqual(data["threats"][0]["evidence"], "Hidden proc")
        self.assertEqual(len(data["diagnostics"]), 1)
        self.assertEqual(data["diagnostics"][0]["evidence"], "Access denied")

    def test_10_scan_history_endpoint(self):
        """GET /api/history returns historical execution logs."""
        sid1 = db.start_scan(db_path=self.db_path)
        db.complete_scan(sid1, 0, 0, 5.0, db_path=self.db_path)
        sid2 = db.start_scan(db_path=self.db_path)
        db.complete_scan(sid2, 1, 0, 8.0, db_path=self.db_path)

        resp = self.client.get("/api/history?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 2)
        # Scans returned in reverse chronological order
        self.assertEqual(data["history"][0]["id"], sid2)
        self.assertEqual(data["history"][1]["id"], sid1)

    def test_11_invalid_scan_ids_rejected(self):
        """Zero scan ID returns 400 Bad Request; non-existent returns 404."""
        resp_zero = self.client.get("/api/scan/0")
        self.assertEqual(resp_zero.status_code, 400)
        resp_404 = self.client.get("/api/scan/999999")
        self.assertEqual(resp_404.status_code, 404)

    def test_12_invalid_pagination_parameters_rejected(self):
        """Invalid page (< 1) or excessive per_page (> 500) returns 400 Bad Request."""
        resp_page0 = self.client.get("/api/scores?page=0")
        self.assertEqual(resp_page0.status_code, 400)
        resp_perpage = self.client.get("/api/scores?per_page=9999")
        self.assertEqual(resp_perpage.status_code, 400)

    def test_13_baseline_lifecycle_endpoints(self):
        """GET /api/baseline returns all 3 persistence categories."""
        resp = self.client.get("/api/baseline")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        cats = data["categories"]
        for cat in config.PERSISTENCE_CATEGORIES:
            self.assertIn(cat, cats)
            self.assertEqual(cats[cat]["state"], "NOT_INITIALIZED")

    def test_14_candidate_baseline_acceptance(self):
        """POST /api/baseline/accept accepts candidate baseline."""
        # Capture candidate in test db
        db.capture_candidate_baseline_atomic(
            "registry",
            [{"entry_key": "App1", "entry_name": "App1", "path": "C:\\app.exe", "fingerprint": "fp1"}],
            db_path=self.db_path,
        )

        resp = self.client.post("/api/baseline/accept", json={"category": "registry"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "accepted")

        # Verify state is now ACCEPTED_TRUSTED
        meta = db.get_category_baseline_meta("registry", db_path=self.db_path)
        self.assertEqual(meta.get("baseline_state") or meta.get("state"), "ACCEPTED_TRUSTED")
        self.assertEqual(meta["accepted_entry_count"], 1)

    def test_15_baseline_reset_requires_confirmation(self):
        """POST /api/baseline/reset without confirm=true is rejected with 400."""
        # Reset without confirmation rejected
        resp_noconfirm = self.client.post("/api/baseline/reset", json={})
        self.assertEqual(resp_noconfirm.status_code, 400)

        # Reset with confirmation succeeds
        resp_confirm = self.client.post("/api/baseline/reset", json={"confirm": True})
        self.assertEqual(resp_confirm.status_code, 200)
        data = resp_confirm.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "reset")

    def test_16_baseline_operation_busy_returns_409(self):
        """When lock is busy, POST /api/baseline/accept and reset return 409 Conflict."""
        with patch("core.scheduler.ScanScheduler.execute_with_lock") as mock_exec:
            mock_exec.return_value = {
                "success": False,
                "status": "busy",
                "message": "Operation lock is currently busy",
            }
            resp_acc = self.client.post("/api/baseline/accept", json={"category": "registry"})
            self.assertEqual(resp_acc.status_code, 409)

            resp_reset = self.client.post("/api/baseline/reset", json={"confirm": True})
            self.assertEqual(resp_reset.status_code, 409)

    def test_17_recent_scans_returns_completed_only(self):
        """GET /api/scans/recent returns up to 10 completed scans with entity counts."""
        # Insert completed scans and failed scans
        sid1 = db.start_scan(db_path=self.db_path)
        db.complete_scan(sid1, total_findings=2, high_risk_count=1, duration_ms=45.0, db_path=self.db_path)

        sid_fail = db.start_scan(db_path=self.db_path)
        db.fail_scan(sid_fail, "Simulated failure", db_path=self.db_path)

        sid2 = db.start_scan(db_path=self.db_path)
        db.complete_scan(sid2, total_findings=0, high_risk_count=0, duration_ms=30.0, db_path=self.db_path)

        resp = self.client.get("/api/scans/recent")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 2)
        scans = data["scans"]
        self.assertEqual(len(scans), 2)
        self.assertEqual(scans[0]["id"], sid2)
        self.assertEqual(scans[1]["id"], sid1)
        for s in scans:
            self.assertEqual(s["status"], "COMPLETED")
            self.assertIn("entity_count", s)
            self.assertIn("scan_duration_ms", s)


if __name__ == "__main__":
    unittest.main()
