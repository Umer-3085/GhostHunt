"""
GhostHunt — Phase 5 Test Suite: Scan Coordinator & Orchestration
Comprehensive unit and integration tests for the 9-step scan lifecycle.

Covers:
1. Successful scan execution with zero findings.
2. Successful scan execution with multi-signal findings.
3. Individual engine operational failure handling (fails scan cleanly, records reason).
4. Database insertion failure handling.
5. Risk correlation failure handling.
6. Risk-score persistence failure handling.
7. Incomplete and failed scans never appear as completed scans in DAL queries.
8. Unique sequential scan_id generation.
9. Historical scan retention across successive scans.
10. Diagnostic findings persistence with complete score exclusion.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import config
import core.db as db
import core.scheduler as scheduler


class TestScanCoordinator(unittest.TestCase):
    """Integration and unit tests for execute_scan_cycle."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_coordinator.db")
        db.init_db(self.db_path)

    def tearDown(self):
        import gc
        gc.collect()
        self.temp_dir.cleanup()

    def test_01_successful_scan_with_no_findings(self):
        """A clean scan with zero findings completes successfully with status COMPLETED."""
        res = scheduler.execute_scan_cycle(
            db_path=self.db_path,
            pv_runner=lambda **kw: [],
            persistence_runner=lambda **kw: [],
            signature_runner=lambda **kw: [],
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["total_findings"], 0)
        self.assertEqual(res["high_risk_count"], 0)
        self.assertGreaterEqual(res["duration_ms"], 0.0)

        # Verify database state
        scan_row = db.get_scan_status(res["scan_id"], db_path=self.db_path)
        self.assertIsNotNone(scan_row)
        self.assertEqual(scan_row["status"], "COMPLETED")
        self.assertEqual(scan_row["total_findings"], 0)
        self.assertEqual(scan_row["high_risk_count"], 0)

        # Verify latest completed scan ID matches
        latest_id = db.get_latest_completed_scan_id(db_path=self.db_path)
        self.assertEqual(latest_id, res["scan_id"])

    def test_02_successful_scan_with_multi_signal_findings(self):
        """A scan with findings from all 3 signals persists findings and risk scores."""
        pv_findings = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "process_view",
            "pid": 1111,
            "process_name": "stealth.exe",
            "evidence": "Hidden from Toolhelp32",
            "severity": "high",
            "signature_status": "N/A",
            "metadata": "{}",
        }]
        per_findings = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "persistence",
            "pid": 1111,
            "process_name": "stealth.exe",
            "evidence": "Unauthorized registry key",
            "severity": "medium",
            "signature_status": "N/A",
            "metadata": "{}",
        }]
        sig_findings = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "signature",
            "pid": 1111,
            "process_name": "stealth.exe",
            "evidence": "Unsigned DLL in %TEMP%",
            "severity": "high",
            "signature_status": "UNSIGNED",
            "metadata": "{}",
        }]

        res = scheduler.execute_scan_cycle(
            db_path=self.db_path,
            pv_runner=lambda **kw: pv_findings,
            persistence_runner=lambda **kw: per_findings,
            signature_runner=lambda **kw: sig_findings,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["total_findings"], 3)
        self.assertEqual(res["high_risk_count"], 1)

        # Verify database findings
        db_findings = db.get_findings_for_scan(res["scan_id"], db_path=self.db_path)
        self.assertEqual(len(db_findings), 3)

        # Verify database risk scores
        scores = db.get_risk_scores_for_scan(res["scan_id"], db_path=self.db_path)
        self.assertEqual(len(scores), 1)
        self.assertAlmostEqual(scores[0]["score"], 1.0, places=4)
        self.assertEqual(scores[0]["risk_level"], "HIGH")
        self.assertEqual(scores[0]["pid"], 1111)

    def test_03_engine_failure_marks_scan_failed(self):
        """When a detection engine raises an exception, scan is marked FAILED in DB."""
        def failing_pv(**kw):
            raise ConnectionError("Simulated WMI/Toolhelp provider crash")

        with self.assertRaises(RuntimeError) as ctx:
            scheduler.execute_scan_cycle(
                db_path=self.db_path,
                pv_runner=failing_pv,
                persistence_runner=lambda **kw: [],
                signature_runner=lambda **kw: [],
            )

        self.assertIn("Process-view enumeration failed", str(ctx.exception))

        # Verify the scan was recorded as FAILED in database
        history = db.get_scan_history(limit=1, db_path=self.db_path)
        self.assertEqual(len(history), 1)
        failed_scan = history[0]
        self.assertEqual(failed_scan["status"], "FAILED")
        self.assertIn("Process-view enumeration failed", failed_scan["error_message"])

        # Latest completed scan ID must be None
        latest_id = db.get_latest_completed_scan_id(db_path=self.db_path)
        self.assertIsNone(latest_id)

    def test_04_database_insertion_failure_marks_scan_failed(self):
        """When db.insert_findings fails, scan is marked FAILED."""
        pv_findings = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "process_view",
            "pid": 2222,
            "process_name": "app.exe",
            "evidence": "Discrepancy",
            "severity": "low",
            "signature_status": "N/A",
            "metadata": "{}",
        }]

        with patch("core.db.insert_findings", side_effect=OSError("Disk write error")):
            with self.assertRaises(OSError):
                scheduler.execute_scan_cycle(
                    db_path=self.db_path,
                    pv_runner=lambda **kw: pv_findings,
                    persistence_runner=lambda **kw: [],
                    signature_runner=lambda **kw: [],
                )

        # Scan should be marked FAILED
        history = db.get_scan_history(limit=1, db_path=self.db_path)
        self.assertEqual(history[0]["status"], "FAILED")
        self.assertIn("Disk write error", history[0]["error_message"])

    def test_05_correlation_failure_marks_scan_failed(self):
        """When correlator raises an exception, scan is marked FAILED."""
        pv_findings = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "process_view",
            "pid": 3333,
            "process_name": "app.exe",
            "evidence": "Discrepancy",
            "severity": "low",
            "signature_status": "N/A",
            "metadata": "{}",
        }]

        with patch("core.correlator.correlate_all", side_effect=ValueError("Correlator fault")):
            with self.assertRaises(ValueError):
                scheduler.execute_scan_cycle(
                    db_path=self.db_path,
                    pv_runner=lambda **kw: pv_findings,
                    persistence_runner=lambda **kw: [],
                    signature_runner=lambda **kw: [],
                )

        history = db.get_scan_history(limit=1, db_path=self.db_path)
        self.assertEqual(history[0]["status"], "FAILED")
        self.assertIn("Correlator fault", history[0]["error_message"])

    def test_06_risk_score_persistence_failure_marks_scan_failed(self):
        """When db.insert_risk_scores fails, scan is marked FAILED."""
        pv_findings = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "process_view",
            "pid": 4444,
            "process_name": "app.exe",
            "evidence": "Discrepancy",
            "severity": "low",
            "signature_status": "N/A",
            "metadata": "{}",
        }]

        with patch("core.db.insert_risk_scores", side_effect=Exception("DB constraint error")):
            with self.assertRaises(Exception):
                scheduler.execute_scan_cycle(
                    db_path=self.db_path,
                    pv_runner=lambda **kw: pv_findings,
                    persistence_runner=lambda **kw: [],
                    signature_runner=lambda **kw: [],
                )

        history = db.get_scan_history(limit=1, db_path=self.db_path)
        self.assertEqual(history[0]["status"], "FAILED")
        self.assertIn("DB constraint error", history[0]["error_message"])

    def test_07_incomplete_scans_never_appear_as_completed(self):
        """A failed scan never overwrites or shadows previous completed scans."""
        # 1. Run a successful scan
        res1 = scheduler.execute_scan_cycle(
            db_path=self.db_path,
            pv_runner=lambda **kw: [],
            persistence_runner=lambda **kw: [],
            signature_runner=lambda **kw: [],
        )
        self.assertEqual(res1["status"], "COMPLETED")
        self.assertEqual(db.get_latest_completed_scan_id(db_path=self.db_path), res1["scan_id"])

        # 2. Run a failing scan
        try:
            scheduler.execute_scan_cycle(
                db_path=self.db_path,
                pv_runner=lambda **kw: (_ for _ in ()).throw(RuntimeError("Crash")),
                persistence_runner=lambda **kw: [],
                signature_runner=lambda **kw: [],
            )
        except RuntimeError:
            pass

        # 3. Latest completed scan ID MUST still be res1["scan_id"], NOT the failed scan
        latest_id = db.get_latest_completed_scan_id(db_path=self.db_path)
        self.assertEqual(latest_id, res1["scan_id"])

    def test_08_unique_scan_ids_maintained(self):
        """Sequential scans obtain distinct, strictly increasing scan IDs."""
        res1 = scheduler.execute_scan_cycle(
            db_path=self.db_path,
            pv_runner=lambda **kw: [],
            persistence_runner=lambda **kw: [],
            signature_runner=lambda **kw: [],
        )
        res2 = scheduler.execute_scan_cycle(
            db_path=self.db_path,
            pv_runner=lambda **kw: [],
            persistence_runner=lambda **kw: [],
            signature_runner=lambda **kw: [],
        )
        self.assertGreater(res2["scan_id"], res1["scan_id"])

    def test_09_historical_scan_results_remain_intact(self):
        """Running multiple scans preserves all historical findings and risk scores."""
        # Scan 1 with finding
        f1 = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "process_view",
            "pid": 100,
            "process_name": "p1.exe",
            "evidence": "Hidden",
            "severity": "low",
            "signature_status": "N/A",
            "metadata": "{}",
        }]
        res1 = scheduler.execute_scan_cycle(
            db_path=self.db_path,
            pv_runner=lambda **kw: f1,
            persistence_runner=lambda **kw: [],
            signature_runner=lambda **kw: [],
        )

        # Scan 2 with different finding
        f2 = [{
            "finding_type": "threat",
            "score_eligible": 1,
            "signal": "persistence",
            "pid": None,
            "process_name": "system:service:p2",
            "evidence": "New service",
            "severity": "medium",
            "signature_status": "N/A",
            "metadata": "{}",
        }]
        res2 = scheduler.execute_scan_cycle(
            db_path=self.db_path,
            pv_runner=lambda **kw: [],
            persistence_runner=lambda **kw: f2,
            signature_runner=lambda **kw: [],
        )

        # Verify Scan 1 findings still intact in DB
        findings1 = db.get_findings_for_scan(res1["scan_id"], db_path=self.db_path)
        self.assertEqual(len(findings1), 1)
        self.assertEqual(findings1[0]["process_name"], "p1.exe")

        # Verify Scan 2 findings intact in DB
        findings2 = db.get_findings_for_scan(res2["scan_id"], db_path=self.db_path)
        self.assertEqual(len(findings2), 1)
        self.assertEqual(findings2[0]["process_name"], "system:service:p2")

    def test_10_diagnostics_persisted_but_excluded_from_risk(self):
        """Operational diagnostics are stored in findings table but yield score=0.0 / LOW."""
        diag_findings = [{
            "finding_type": "diagnostic",
            "score_eligible": 0,
            "signal": "process_view",
            "pid": 5555,
            "process_name": "protected.exe",
            "evidence": "Access denied enumerating process",
            "severity": "low",
            "signature_status": "N/A",
            "metadata": "{}",
        }]

        res = scheduler.execute_scan_cycle(
            db_path=self.db_path,
            pv_runner=lambda **kw: diag_findings,
            persistence_runner=lambda **kw: [],
            signature_runner=lambda **kw: [],
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["total_findings"], 1)
        self.assertEqual(res["high_risk_count"], 0)

        # Stored in findings table
        stored = db.get_findings_for_scan(res["scan_id"], db_path=self.db_path)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["finding_type"], "diagnostic")
        self.assertEqual(stored[0]["score_eligible"], 0)

        # Stored in risk_scores table with score 0.0 and LOW
        scores = db.get_risk_scores_for_scan(res["scan_id"], db_path=self.db_path)
        self.assertEqual(len(scores), 1)
        self.assertEqual(scores[0]["score"], 0.0)
        self.assertEqual(scores[0]["risk_level"], "LOW")
        self.assertEqual(scores[0]["signals_triggered"], "")


if __name__ == "__main__":
    unittest.main()
