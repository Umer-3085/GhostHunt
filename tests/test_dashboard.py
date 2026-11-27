"""
GhostHunt — Phase 6 Test Suite: Dashboard HTML Views & Template Rendering
Comprehensive unit and integration tests for all HTML presentation pages.

Covers:
1. Overview page renders successfully (GET /).
2. Clean empty state renders when no completed scans exist.
3. Risk-ranked entities table renders when a scan exists.
4. HIGH, MEDIUM, and LOW risk categories are properly styled with distinct badges.
5. Threat findings and operational diagnostics rendered in separate sections.
6. Scan history timeline renders (GET /history).
7. Historical scan snapshot renders (GET /history/<id>).
8. Process forensic detail page renders (GET /process/<pid>).
9. Candidate baseline review banner appears when category in CANDIDATE_REVIEW.
10. Baseline reset confirmation modal is present in DOM.
11. System findings page renders (GET /system-findings).
"""

import tempfile
import unittest
from pathlib import Path

import config
import core.db as db
from dashboard import create_app


class TestDashboardViews(unittest.TestCase):
    """Test suite for GhostHunt HTML dashboard views."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_views.db")
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

    def test_01_empty_state_renders_when_no_scans_exist(self):
        """When no scans have completed, GET / renders a clear empty state."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("No Completed Scans Recorded", html)
        self.assertIn("Initiate Initial Scan Cycle", html)
        self.assertIn("GhostHunt", html)

    def test_02_overview_renders_with_completed_scan(self):
        """When a completed scan exists, GET / renders metrics cards and entity table."""
        sid = db.start_scan(db_path=self.db_path)
        risk_entries = [
            {"item_key": "proc:1234:malware.exe", "process_name": "malware.exe", "pid": 1234, "score": 0.70, "risk_level": "HIGH", "signals_triggered": "process_view,persistence"},
            {"item_key": "proc:5678:clean.exe", "process_name": "clean.exe", "pid": 5678, "score": 0.0, "risk_level": "LOW", "signals_triggered": ""},
        ]
        db.insert_risk_scores(sid, risk_entries, db_path=self.db_path)
        db.complete_scan(sid, total_findings=2, high_risk_count=1, duration_ms=42.0, db_path=self.db_path)

        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # Check metrics and entity content
        self.assertIn(f"Latest Completed Scan", html)
        self.assertIn(f"#{sid}", html)
        self.assertIn("malware.exe", html)
        self.assertIn("1234", html)
        self.assertIn("HIGH", html)
        self.assertIn("LOW", html)
        self.assertIn("badge-high", html)
        self.assertIn("timeline-card", html)
        self.assertIn("timeline-container", html)
        self.assertIn("Scheduler Activity Timeline", html)
        self.assertIn("waterfall-row", html)
        self.assertIn("waterfall-panel", html)
        self.assertIn("signal-bar", html)
        self.assertIn("signal-bar-fill", html)

    def test_03_candidate_baseline_review_banner(self):
        """When a persistence category is in CANDIDATE_REVIEW, a review banner is displayed."""
        # Transition registry to CANDIDATE_REVIEW
        db.capture_candidate_baseline_atomic(
            "registry",
            [{"entry_key": "Autorun1", "entry_name": "Autorun1", "path": "C:\\run.exe", "fingerprint": "fp1"}],
            db_path=self.db_path,
        )

        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Candidate Baseline Review Required", html)
        self.assertIn("Accept Baseline", html)

    def test_04_process_detail_view_separates_threats_and_diagnostics(self):
        """GET /process/<pid> clearly separates threat evidence from operational diagnostics."""
        sid = db.start_scan(db_path=self.db_path)
        findings = [
            {"finding_type": "threat", "score_eligible": 1, "signal": "process_view", "pid": 3000, "process_name": "stealth.exe", "evidence": "Confirmed discrepancy: hidden from Toolhelp32", "severity": "high", "signature_status": "N/A", "metadata": "{\"technique\": \"DKOM\"}"},
            {"finding_type": "diagnostic", "score_eligible": 0, "signal": "signature", "pid": 3000, "process_name": "stealth.exe", "evidence": "Operational diagnostic: access denied", "severity": "low", "signature_status": "ERROR", "metadata": "{}"},
        ]
        db.insert_findings(sid, findings, db_path=self.db_path)
        db.insert_risk_scores(sid, [{"item_key": "proc:3000:stealth.exe", "process_name": "stealth.exe", "pid": 3000, "score": 0.40, "risk_level": "MEDIUM", "signals_triggered": "process_view"}], db_path=self.db_path)
        db.complete_scan(sid, total_findings=2, high_risk_count=0, duration_ms=18.0, db_path=self.db_path)

        resp = self.client.get(f"/process/3000?scan_id={sid}")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertIn("stealth.exe", html)
        self.assertIn("PID 3000", html)
        self.assertIn("Threat Evidence", html)
        self.assertIn("Confirmed discrepancy", html)
        self.assertIn("Operational Diagnostics", html)
        self.assertIn("Operational diagnostic: access denied", html)
        self.assertIn("Score Eligible: 0.0 (Isolated)", html)

    def test_05_system_findings_view(self):
        """GET /system-findings renders dormant persistence findings (pid=None)."""
        sid = db.start_scan(db_path=self.db_path)
        findings = [
            {"finding_type": "threat", "score_eligible": 1, "signal": "persistence", "pid": None, "process_name": "system:service:EvilSvc", "evidence": "Unauthorized service registered", "severity": "medium", "signature_status": "N/A", "metadata": "{}"},
        ]
        db.insert_findings(sid, findings, db_path=self.db_path)
        db.complete_scan(sid, total_findings=1, high_risk_count=0, duration_ms=12.0, db_path=self.db_path)

        resp = self.client.get(f"/system-findings?scan_id={sid}")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("System Persistence Findings", html)
        self.assertIn("Unauthorized service registered", html)

    def test_06_history_view_renders_table_and_snapshots(self):
        """GET /history and GET /history/<scan_id> render audit log and snapshot cards."""
        sid1 = db.start_scan(db_path=self.db_path)
        db.complete_scan(sid1, total_findings=0, high_risk_count=0, duration_ms=15.0, db_path=self.db_path)

        # 1. Main history log
        resp_hist = self.client.get("/history")
        self.assertEqual(resp_hist.status_code, 200)
        html_hist = resp_hist.get_data(as_text=True)
        self.assertIn("Historical Scan Audit Log", html_hist)
        self.assertIn(f"#{sid1}", html_hist)

        # 2. Snapshot drilldown
        resp_snap = self.client.get(f"/history/{sid1}")
        self.assertEqual(resp_snap.status_code, 200)
        html_snap = resp_snap.get_data(as_text=True)
        self.assertIn(f"Scan Snapshot #{sid1}", html_snap)

    def test_07_reset_modal_present_in_dom(self):
        """The reset confirmation modal is present in the DOM for user safety."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn('id="reset-modal"', html)
        self.assertIn("Confirm Persistence Baseline Reset", html)

    def test_08_signal_waterfall_per_entity_visualization(self):
        """Signal Waterfall accordion rows and bars render per entity with exact weights and labels."""
        sid = db.start_scan(db_path=self.db_path)
        risk_entries = [
            {
                "item_key": "proc:1234:malware.exe",
                "process_name": "malware.exe",
                "pid": 1234,
                "score": 0.70,
                "risk_level": "HIGH",
                "signals_triggered": "process_view,persistence",
            },
            {
                "item_key": "proc:9999:clean.exe",
                "process_name": "clean.exe",
                "pid": 9999,
                "score": 0.0,
                "risk_level": "LOW",
                "signals_triggered": "",
            },
        ]
        db.insert_risk_scores(sid, risk_entries, db_path=self.db_path)
        db.complete_scan(sid, total_findings=2, high_risk_count=1, duration_ms=50.0, db_path=self.db_path)

        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # 1. Structure and accessibility
        self.assertIn('aria-controls="waterfall-panel-1"', html)
        self.assertIn('role="button"', html)
        self.assertIn('aria-expanded="false"', html)
        self.assertIn('class="waterfall-chevron-btn"', html)
        self.assertIn('class="waterfall-row hidden"', html)
        self.assertIn('class="waterfall-panel"', html)

        # 2. 3 Signals and weights
        self.assertIn("Process Views", html)
        self.assertIn("(weight 0.40)", html)
        self.assertIn("Persistence", html)
        self.assertIn("(weight 0.30)", html)
        self.assertIn("Signature", html)
        self.assertIn("(weight 0.30)", html)

        # 3. Bar styling and raw/contrib metrics
        self.assertIn("signal-bar", html)
        self.assertIn("signal-bar-fill", html)
        self.assertIn("Contrib: <strong>+0.40</strong>", html)
        self.assertIn("Contrib: <strong>+0.30</strong>", html)
        self.assertIn("SIGNAL RISK BREAKDOWN", html)

    def test_09_system_findings_candidate_review_diff_button_and_modal(self):
        """When a persistence category is in CANDIDATE_REVIEW, /system-findings renders 'Review Diff' button and modal."""
        # 1. Transition registry category to CANDIDATE_REVIEW
        db.capture_candidate_baseline_atomic(
            "registry",
            [{"entry_key": "RunKey1", "entry_name": "RunKey1", "entry_value": "C:\\run.exe", "fingerprint": "fp1"}],
            db_path=self.db_path,
        )

        resp = self.client.get("/system-findings")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # 2. Check Candidate Review section on /system-findings
        self.assertIn("Candidate Baseline Review Required", html)
        self.assertIn("btn-review-diff", html)
        self.assertIn("Review Diff", html)
        self.assertIn("BaselineVisualDiff.openDiff('registry')", html)
        self.assertIn("Accept Baseline", html)

        # 3. Check Baseline Visual Diff Modal present in DOM
        self.assertIn('id="baseline-diff-modal"', html)
        self.assertIn('class="diff-panel"', html)
        self.assertIn('class="diff-side diff-side-left"', html)
        self.assertIn('class="diff-side diff-side-right"', html)
        self.assertIn("Current System State", html)
        self.assertIn("Proposed Baseline", html)
        self.assertIn('id="btn-accept-diff-baseline"', html)


if __name__ == "__main__":
    unittest.main()
