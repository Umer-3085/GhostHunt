"""
GhostHunt — Phase 1 Test Suite: Database Foundation & Data Access Layer
Comprehensive tests for SQLite DAL, fail-safe finding classification,
restrictive foreign-key retention, baseline lifecycle state management,
and audit corrections.
"""

import math
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Generator

import core.db as db


class TestGhostHuntDatabaseFoundation(unittest.TestCase):
    """
    Unit and integration tests for the GhostHunt SQLite foundation (Phase 1).
    All tests execute against temporary, isolated SQLite databases.
    """

    def setUp(self) -> None:
        """Create a temporary database file for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_ghosthunt.db")
        db.init_db(self.db_path)

    def tearDown(self) -> None:
        """Clean up the temporary directory."""
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except PermissionError:
            pass

    # -----------------------------------------------------------------------
    # 1. Database Initialization on Fresh Database
    # -----------------------------------------------------------------------
    def test_01_init_db_creates_all_tables_and_metadata(self) -> None:
        """Verify all required tables, indexes, and seed rows exist on fresh database."""
        with db.get_connection(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            )
            tables = {row["name"] for row in cursor.fetchall()}
            expected_tables = {
                "scan_history",
                "findings",
                "risk_scores",
                "persistence_baseline_meta",
                "persistence_baseline",
            }
            self.assertTrue(expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}")

            cursor = conn.execute("SELECT category, baseline_state FROM persistence_baseline_meta;")
            categories = {row["category"]: row["baseline_state"] for row in cursor.fetchall()}
            self.assertEqual(
                categories,
                {
                    "registry": "NOT_INITIALIZED",
                    "task": "NOT_INITIALIZED",
                    "service": "NOT_INITIALIZED",
                },
            )

    # -----------------------------------------------------------------------
    # 2. Repeated Initialization Idempotency
    # -----------------------------------------------------------------------
    def test_02_repeated_init_db_is_idempotent(self) -> None:
        """Verify repeated calls to init_db do not corrupt schema or duplicate data."""
        scan_id = db.start_scan(self.db_path)

        db.init_db(self.db_path)
        db.init_db(self.db_path)

        status = db.get_scan_status(scan_id, self.db_path)
        self.assertIsNotNone(status)
        self.assertEqual(status["id"], scan_id)
        self.assertEqual(status["status"], "IN_PROGRESS")

        with db.get_connection(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) AS cnt FROM persistence_baseline_meta;").fetchone()["cnt"]
            self.assertEqual(count, 3)

    # -----------------------------------------------------------------------
    # 3. Foreign Key Enforcement
    # -----------------------------------------------------------------------
    def test_03_foreign_keys_are_enforced(self) -> None:
        """Verify PRAGMA foreign_keys is enabled and rejects orphaned child records."""
        with db.get_connection(self.db_path) as conn:
            fk_status = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
            self.assertEqual(fk_status, 1, "Foreign keys must be enabled on every connection")

        non_existent_scan_id = 99999
        finding = {
            "scan_id": non_existent_scan_id,
            "pid": 1234,
            "process_name": "orphaned.exe",
            "signal": "process_view",
            "evidence": "Orphaned finding test",
            "severity": "medium",
            "finding_type": "threat",
            "score_eligible": 1,
        }
        with self.assertRaises(sqlite3.IntegrityError):
            db.insert_findings(non_existent_scan_id, [finding], self.db_path)

        risk_score = {
            "item_key": "pid:1234",
            "pid": 1234,
            "process_name": "orphaned.exe",
            "score": 0.40,
            "risk_level": "MEDIUM",
            "signals_triggered": "process_view",
        }
        with self.assertRaises(sqlite3.IntegrityError):
            db.insert_risk_scores(non_existent_scan_id, [risk_score], self.db_path)

    # -----------------------------------------------------------------------
    # 4. WAL Mode and Busy Timeout
    # -----------------------------------------------------------------------
    def test_04_wal_mode_and_busy_timeout(self) -> None:
        """Verify journal_mode is WAL and busy_timeout is set."""
        with db.get_connection(self.db_path) as conn:
            journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            self.assertEqual(journal_mode.lower(), "wal")

            busy_timeout = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
            self.assertEqual(busy_timeout, 5000)

    # -----------------------------------------------------------------------
    # 5. Scan History Insertion and Status Updates
    # -----------------------------------------------------------------------
    def test_05_scan_lifecycle_and_latest_completed_query(self) -> None:
        """Verify scan creation, completion, failure, and completed scan query filtering."""
        scan1 = db.start_scan(self.db_path)
        self.assertIsInstance(scan1, int)
        self.assertGreater(scan1, 0)
        self.assertIsNone(db.get_latest_completed_scan_id(self.db_path))

        db.complete_scan(
            scan_id=scan1,
            total_findings=5,
            high_risk_count=1,
            duration_ms=125.5,
            cache_hits=40,
            cache_misses=2,
            db_path=self.db_path,
        )
        self.assertEqual(db.get_latest_completed_scan_id(self.db_path), scan1)

        status1 = db.get_scan_status(scan1, self.db_path)
        self.assertEqual(status1["status"], "COMPLETED")
        self.assertEqual(status1["total_findings"], 5)
        self.assertEqual(status1["high_risk_count"], 1)
        self.assertEqual(status1["cache_hits"], 40)
        self.assertEqual(status1["cache_misses"], 2)

        scan2 = db.start_scan(self.db_path)
        db.fail_scan(scan_id=scan2, error_message="WMI connection failed", duration_ms=50.0, db_path=self.db_path)

        status2 = db.get_scan_status(scan2, self.db_path)
        self.assertEqual(status2["status"], "FAILED")
        self.assertEqual(status2["error_message"], "WMI connection failed")

        self.assertEqual(db.get_latest_completed_scan_id(self.db_path), scan1)

        scan3 = db.start_scan(self.db_path)
        self.assertEqual(db.get_latest_completed_scan_id(self.db_path), scan1)

        db.complete_scan(scan3, 0, 0, 80.0, db_path=self.db_path)
        self.assertEqual(db.get_latest_completed_scan_id(self.db_path), scan3)

    # -----------------------------------------------------------------------
    # 6. Finding Insertion and Retrieval
    # -----------------------------------------------------------------------
    def test_06_finding_insertion_and_retrieval(self) -> None:
        """Verify inserting and querying findings by scan, PID, and system."""
        scan_id = db.start_scan(self.db_path)

        findings = [
            {
                "pid": 2048,
                "process_name": "target.exe",
                "signal": "process_view",
                "evidence": "Hidden from Toolhelp32",
                "severity": "high",
                "finding_type": "threat",
                "score_eligible": 1,
            },
            {
                "pid": 2048,
                "process_name": "target.exe",
                "signal": "signature",
                "evidence": "Access denied inspecting modules",
                "severity": "low",
                "finding_type": "diagnostic",
                "score_eligible": 0,
            },
            {
                "pid": None,
                "process_name": "RunOnceKey",
                "signal": "persistence",
                "evidence": "New autorun entry added",
                "severity": "medium",
                "finding_type": "threat",
                "score_eligible": 1,
            },
        ]
        inserted = db.insert_findings(scan_id, findings, self.db_path)
        self.assertEqual(inserted, 3)

        all_findings = db.get_findings_for_scan(scan_id, include_diagnostics=True, db_path=self.db_path)
        self.assertEqual(len(all_findings), 3)

        threats_only = db.get_findings_for_scan(scan_id, include_diagnostics=False, db_path=self.db_path)
        self.assertEqual(len(threats_only), 2)
        for f in threats_only:
            self.assertEqual(f["finding_type"], "threat")

        pid_findings = db.get_findings_for_process(scan_id, 2048, include_diagnostics=True, db_path=self.db_path)
        self.assertEqual(len(pid_findings), 2)

        sys_findings = db.get_system_findings(scan_id, include_diagnostics=True, db_path=self.db_path)
        self.assertEqual(len(sys_findings), 1)
        self.assertEqual(sys_findings[0]["process_name"], "RunOnceKey")

    # -----------------------------------------------------------------------
    # 7. Missing Classification Fields Rejected
    # -----------------------------------------------------------------------
    def test_07_missing_classification_fields_rejected(self) -> None:
        """Verify omitting finding_type or score_eligible is rejected."""
        scan_id = db.start_scan(self.db_path)

        bad_f1 = {
            "pid": 100,
            "process_name": "test.exe",
            "signal": "process_view",
            "evidence": "Evidence",
            "severity": "high",
            "score_eligible": 1,
        }
        with self.assertRaises(ValueError):
            db.validate_finding(bad_f1)
        with self.assertRaises(ValueError):
            db.insert_findings(scan_id, [bad_f1], self.db_path)

        bad_f2 = {
            "pid": 100,
            "process_name": "test.exe",
            "signal": "process_view",
            "evidence": "Evidence",
            "severity": "high",
            "finding_type": "threat",
        }
        with self.assertRaises(ValueError):
            db.validate_finding(bad_f2)
        with self.assertRaises(ValueError):
            db.insert_findings(scan_id, [bad_f2], self.db_path)

    # -----------------------------------------------------------------------
    # 8. Invalid Classification Values Rejected
    # -----------------------------------------------------------------------
    def test_08_invalid_classification_values_rejected(self) -> None:
        """Verify invalid values for finding_type or score_eligible are rejected."""
        scan_id = db.start_scan(self.db_path)

        bad_f1 = {
            "scan_id": scan_id,
            "pid": 100,
            "process_name": "test.exe",
            "signal": "process_view",
            "evidence": "Evidence",
            "severity": "high",
            "finding_type": "malware",
            "score_eligible": 1,
        }
        with self.assertRaises(ValueError):
            db.validate_finding(bad_f1)

        bad_f2 = {
            "scan_id": scan_id,
            "pid": 100,
            "process_name": "test.exe",
            "signal": "process_view",
            "evidence": "Evidence",
            "severity": "high",
            "finding_type": "threat",
            "score_eligible": 2,
        }
        with self.assertRaises(ValueError):
            db.validate_finding(bad_f2)

    # -----------------------------------------------------------------------
    # 9. Diagnostic with score_eligible=1 Rejected
    # -----------------------------------------------------------------------
    def test_09_diagnostic_with_score_eligible_1_rejected(self) -> None:
        """
        Verify the core invariant:
            finding_type == 'diagnostic' => score_eligible == 0
        Attempting finding_type='diagnostic' with score_eligible=1 must fail in DAL validation
        and fail at the SQLite CHECK constraint level.
        """
        scan_id = db.start_scan(self.db_path)

        violating_finding = {
            "scan_id": scan_id,
            "pid": 100,
            "process_name": "test.exe",
            "signal": "process_view",
            "evidence": "Access denied error",
            "severity": "low",
            "finding_type": "diagnostic",
            "score_eligible": 1,
        }

        with self.assertRaises(ValueError) as ctx:
            db.validate_finding(violating_finding)
        self.assertIn("invariant", str(ctx.exception).lower())

        with self.assertRaises(sqlite3.IntegrityError):
            with db.get_connection(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO findings (
                        scan_id, pid, process_name, signal, evidence,
                        severity, finding_type, score_eligible
                    ) VALUES (?, 100, 'test.exe', 'process_view', 'Error', 'low', 'diagnostic', 1);
                    """,
                    (scan_id,),
                )

    # -----------------------------------------------------------------------
    # 10. Threat with score_eligible=0 Accepted as Ineligible Threat
    # -----------------------------------------------------------------------
    def test_10_threat_with_score_eligible_0_accepted(self) -> None:
        """Verify that a threat finding may be explicitly deactivated (score_eligible=0)."""
        scan_id = db.start_scan(self.db_path)

        deactivated_threat = {
            "pid": 100,
            "process_name": "test.exe",
            "signal": "signature",
            "evidence": "Unsigned DLL in whitelisted path (suppressed)",
            "severity": "low",
            "finding_type": "threat",
            "score_eligible": 0,
        }
        validated = db.validate_finding({**deactivated_threat, "scan_id": scan_id})
        self.assertEqual(validated["score_eligible"], 0)

        db.insert_findings(scan_id, [deactivated_threat], self.db_path)
        stored = db.get_findings_for_scan(scan_id, db_path=self.db_path)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["finding_type"], "threat")
        self.assertEqual(stored[0]["score_eligible"], 0)

    # -----------------------------------------------------------------------
    # 11. Diagnostic with score_eligible=0 Stored Correctly
    # -----------------------------------------------------------------------
    def test_11_diagnostic_with_score_eligible_0_stored(self) -> None:
        """Verify valid operational diagnostic is stored cleanly."""
        scan_id = db.start_scan(self.db_path)

        diag = {
            "pid": 4,
            "process_name": "System",
            "signal": "process_view",
            "evidence": "Access denied opening process",
            "severity": "low",
            "finding_type": "diagnostic",
            "score_eligible": 0,
        }
        db.insert_findings(scan_id, [diag], self.db_path)

        stored = db.get_findings_for_scan(scan_id, db_path=self.db_path)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["finding_type"], "diagnostic")
        self.assertEqual(stored[0]["score_eligible"], 0)

    # -----------------------------------------------------------------------
    # 12. Historical Records Protected from Cascade Deletion
    # -----------------------------------------------------------------------
    def test_12_historical_records_protected_from_cascade_deletion(self) -> None:
        """
        Verify ON DELETE RESTRICT prevents deleting scan_history rows that contain
        findings or risk scores, preserving historical forensic integrity.
        """
        scan_id = db.start_scan(self.db_path)

        db.insert_findings(
            scan_id,
            [
                {
                    "pid": 500,
                    "process_name": "app.exe",
                    "signal": "process_view",
                    "evidence": "Evidence",
                    "severity": "high",
                    "finding_type": "threat",
                    "score_eligible": 1,
                }
            ],
            self.db_path,
        )
        db.insert_risk_scores(
            scan_id,
            [
                {
                    "item_key": "pid:500",
                    "pid": 500,
                    "process_name": "app.exe",
                    "score": 0.40,
                    "risk_level": "MEDIUM",
                    "signals_triggered": "process_view",
                }
            ],
            self.db_path,
        )

        with self.assertRaises(sqlite3.IntegrityError):
            with db.get_connection(self.db_path) as conn:
                conn.execute("DELETE FROM scan_history WHERE id = ?;", (scan_id,))

        status = db.get_scan_status(scan_id, self.db_path)
        self.assertIsNotNone(status)
        findings = db.get_findings_for_scan(scan_id, db_path=self.db_path)
        self.assertEqual(len(findings), 1)
        scores = db.get_risk_scores_for_scan(scan_id, self.db_path)
        self.assertEqual(len(scores), 1)

    # -----------------------------------------------------------------------
    # 13. Failed Transactions Roll Back Cleanly
    # -----------------------------------------------------------------------
    def test_13_failed_transactions_rollback_cleanly(self) -> None:
        """Verify multi-statement write failures do not leave partial state."""
        scan_id = db.start_scan(self.db_path)

        valid_finding = {
            "pid": 101,
            "process_name": "first.exe",
            "signal": "process_view",
            "evidence": "First",
            "severity": "high",
            "finding_type": "threat",
            "score_eligible": 1,
        }
        invalid_finding = {
            "pid": 102,
            "process_name": "second.exe",
            "signal": "process_view",
            "evidence": "Second",
            "severity": "low",
            "finding_type": "diagnostic",
            "score_eligible": 1,
        }

        with self.assertRaises(ValueError):
            db.insert_findings(scan_id, [valid_finding, invalid_finding], self.db_path)

        findings = db.get_findings_for_scan(scan_id, db_path=self.db_path)
        self.assertEqual(len(findings), 0)

    # -----------------------------------------------------------------------
    # 14. Candidate and Accepted Baseline Records Distinguishable
    # -----------------------------------------------------------------------
    def test_14_candidate_and_accepted_records_distinguishable(self) -> None:
        """
        Verify candidate records (is_candidate=1) and accepted records (is_candidate=0)
        are properly isolated and transition atomically upon acceptance.
        """
        entries = [
            {
                "entry_key": r"HKCU:Run:TestApp",
                "entry_value": r"C:\app.exe",
                "fingerprint": "hash123",
                "structured_data": {"command": r"C:\app.exe"},
            },
            {
                "entry_key": r"HKLM:Run:SecurityAgent",
                "entry_value": r"C:\sec.exe",
                "fingerprint": "hash456",
                "structured_data": {"command": r"C:\sec.exe"},
            },
        ]

        db.capture_candidate_baseline_atomic("registry", entries, self.db_path)

        candidates = db.get_candidate_baseline("registry", db_path=self.db_path)
        self.assertEqual(len(candidates), 2)
        accepted = db.get_persistence_baseline("registry", only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(accepted), 0)

        meta = db.get_category_baseline_meta("registry", self.db_path)
        self.assertEqual(meta["baseline_state"], "CANDIDATE_REVIEW")
        self.assertEqual(meta["candidate_entry_count"], 2)
        self.assertEqual(meta["accepted_entry_count"], 0)

        result = db.accept_baseline_atomic("registry", self.db_path)
        self.assertEqual(result["promoted_entries"], 2)
        self.assertIn("registry", result["accepted_categories"])

        candidates_after = db.get_candidate_baseline("registry", db_path=self.db_path)
        self.assertEqual(len(candidates_after), 0)
        accepted_after = db.get_persistence_baseline("registry", only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(accepted_after), 2)

        meta_after = db.get_category_baseline_meta("registry", self.db_path)
        self.assertEqual(meta_after["baseline_state"], "ACCEPTED_TRUSTED")
        self.assertEqual(meta_after["accepted_entry_count"], 2)
        self.assertIsNotNone(meta_after["accepted_at"])

    # -----------------------------------------------------------------------
    # 15. Candidate Operations Cannot Overwrite Accepted Baseline
    # -----------------------------------------------------------------------
    def test_15_candidate_capture_cannot_overwrite_accepted_baseline(self) -> None:
        """
        Verify that once a category is in ACCEPTED_TRUSTED state, attempting to capture
        a candidate baseline is strictly rejected to protect the reference standard.
        """
        entries = [
            {
                "entry_key": r"Task:CleanJob",
                "entry_value": r"C:\task.exe",
                "fingerprint": "taskhash",
            }
        ]
        db.capture_candidate_baseline_atomic("task", entries, self.db_path)
        db.accept_baseline_atomic("task", self.db_path)

        new_entries = [
            {
                "entry_key": r"Task:InjectedMalware",
                "entry_value": r"C:\malware.exe",
                "fingerprint": "badhash",
            }
        ]
        with self.assertRaises(ValueError) as ctx:
            db.capture_candidate_baseline_atomic("task", new_entries, self.db_path)
        self.assertIn("already accepted_trusted", str(ctx.exception).lower())

        accepted = db.get_persistence_baseline("task", only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(accepted), 1)
        self.assertIn(r"Task:CleanJob", accepted)

    # -----------------------------------------------------------------------
    # 16. Enumeration Failure Does Not Erase Accepted Baseline
    # -----------------------------------------------------------------------
    def test_16_enumeration_failure_does_not_erase_accepted_baseline(self) -> None:
        """
        Verify that when an accepted category suffers a transient enumeration failure,
        the accepted reference baseline and records are completely preserved.
        """
        entries = [
            {
                "entry_key": "service:AuditSvc",
                "entry_value": r"C:\svc.exe",
                "fingerprint": "svchash",
            }
        ]
        db.capture_candidate_baseline_atomic("service", entries, self.db_path)
        db.accept_baseline_atomic("service", self.db_path)

        db.record_enumeration_failure("service", "Access denied querying service manager", self.db_path)

        meta = db.get_category_baseline_meta("service", self.db_path)
        self.assertEqual(meta["baseline_state"], "ACCEPTED_TRUSTED")
        self.assertEqual(meta["last_enumeration_status"], "FAILED")
        self.assertEqual(meta["last_error"], "Access denied querying service manager")

        accepted = db.get_persistence_baseline("service", only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(accepted), 1)
        self.assertIn("service:AuditSvc", accepted)

    # -----------------------------------------------------------------------
    # 17. Atomic Reset Clears Baselines and Re-arms Candidate Workflow
    # -----------------------------------------------------------------------
    def test_17_atomic_reset_clears_all_and_requires_new_acceptance(self) -> None:
        """Verify reset_all_baselines_atomic wipes all records and returns to NOT_INITIALIZED."""
        db.capture_candidate_baseline_atomic(
            "registry",
            [{"entry_key": "reg:1", "entry_value": "val1", "fingerprint": "fp1"}],
            self.db_path,
        )
        db.accept_baseline_atomic("registry", self.db_path)

        db.capture_candidate_baseline_atomic(
            "service",
            [{"entry_key": "svc:1", "entry_value": "val2", "fingerprint": "fp2"}],
            self.db_path,
        )

        db.reset_all_baselines_atomic(self.db_path)

        all_entries = db.get_persistence_baseline(only_accepted=False, db_path=self.db_path)
        self.assertEqual(len(all_entries), 0)

        all_meta = db.get_all_baseline_meta(self.db_path)
        for cat in ("registry", "task", "service"):
            self.assertEqual(all_meta[cat]["baseline_state"], "NOT_INITIALIZED")
            self.assertEqual(all_meta[cat]["candidate_entry_count"], 0)
            self.assertEqual(all_meta[cat]["accepted_entry_count"], 0)
            self.assertIsNotNone(all_meta[cat]["last_reset_at"])

    # =======================================================================
    # REGRESSION TESTS (AUDIT CORRECTIONS)
    # =======================================================================

    # -----------------------------------------------------------------------
    # Regression 1: Acceptance Rejected from NOT_INITIALIZED
    # -----------------------------------------------------------------------
    def test_reg_01_acceptance_rejected_from_not_initialized(self) -> None:
        """Verify accept_baseline_atomic raises ValueError when category is NOT_INITIALIZED."""
        meta = db.get_category_baseline_meta("registry", self.db_path)
        self.assertEqual(meta["baseline_state"], "NOT_INITIALIZED")

        with self.assertRaises(ValueError) as ctx:
            db.accept_baseline_atomic("registry", self.db_path)
        self.assertIn("cannot be accepted", str(ctx.exception))
        self.assertIn("NOT_INITIALIZED", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Regression 2: Acceptance Rejected from ENUMERATION_FAILED
    # -----------------------------------------------------------------------
    def test_reg_02_acceptance_rejected_from_enumeration_failed(self) -> None:
        """Verify accept_baseline_atomic raises ValueError when category is ENUMERATION_FAILED."""
        db.record_enumeration_failure("task", "Access Denied", self.db_path)
        meta = db.get_category_baseline_meta("task", self.db_path)
        self.assertEqual(meta["baseline_state"], "ENUMERATION_FAILED")

        with self.assertRaises(ValueError) as ctx:
            db.accept_baseline_atomic("task", self.db_path)
        self.assertIn("cannot be accepted", str(ctx.exception))
        self.assertIn("ENUMERATION_FAILED", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Regression 3: Acceptance Rejected from ACCEPTED_TRUSTED
    # -----------------------------------------------------------------------
    def test_reg_03_acceptance_rejected_from_accepted_trusted(self) -> None:
        """Verify accept_baseline_atomic raises ValueError when category is already ACCEPTED_TRUSTED."""
        db.capture_candidate_baseline_atomic(
            "service",
            [{"entry_key": "svc:init", "entry_value": "cmd", "fingerprint": "fp"}],
            self.db_path,
        )
        db.accept_baseline_atomic("service", self.db_path)

        meta = db.get_category_baseline_meta("service", self.db_path)
        self.assertEqual(meta["baseline_state"], "ACCEPTED_TRUSTED")

        # Second acceptance attempt must be rejected
        with self.assertRaises(ValueError) as ctx:
            db.accept_baseline_atomic("service", self.db_path)
        self.assertIn("cannot be accepted", str(ctx.exception))
        self.assertIn("ACCEPTED_TRUSTED", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Regression 4: Successful Candidate Acceptance
    # -----------------------------------------------------------------------
    def test_reg_04_successful_candidate_acceptance(self) -> None:
        """Verify successful promotion and transition from CANDIDATE_REVIEW to ACCEPTED_TRUSTED."""
        entries = [
            {"entry_key": "reg:key1", "entry_value": "val1", "fingerprint": "fp1"},
            {"entry_key": "reg:key2", "entry_value": "val2", "fingerprint": "fp2"},
        ]
        db.capture_candidate_baseline_atomic("registry", entries, self.db_path)
        res = db.accept_baseline_atomic("registry", self.db_path)

        self.assertEqual(res["accepted_categories"], ["registry"])
        self.assertEqual(res["promoted_entries"], 2)

        meta = db.get_category_baseline_meta("registry", self.db_path)
        self.assertEqual(meta["baseline_state"], "ACCEPTED_TRUSTED")
        self.assertEqual(meta["accepted_entry_count"], 2)

    # -----------------------------------------------------------------------
    # Regression 5: Valid Empty Candidate Acceptance
    # -----------------------------------------------------------------------
    def test_reg_05_valid_empty_candidate_acceptance(self) -> None:
        """Verify that a legitimate empty candidate inventory can be accepted."""
        # Capture 0 entries (e.g. system with zero autoruns in monitored hive)
        db.capture_candidate_baseline_atomic("registry", [], self.db_path)

        meta = db.get_category_baseline_meta("registry", self.db_path)
        self.assertEqual(meta["baseline_state"], "CANDIDATE_REVIEW")
        self.assertEqual(meta["candidate_entry_count"], 0)

        # Explicit acceptance of empty candidate baseline must succeed
        res = db.accept_baseline_atomic("registry", self.db_path)
        self.assertEqual(res["accepted_categories"], ["registry"])
        self.assertEqual(res["promoted_entries"], 0)

        meta_after = db.get_category_baseline_meta("registry", self.db_path)
        self.assertEqual(meta_after["baseline_state"], "ACCEPTED_TRUSTED")
        self.assertEqual(meta_after["accepted_entry_count"], 0)

    # -----------------------------------------------------------------------
    # Regression 6: Missing Category Metadata Rejected During Candidate Capture
    # -----------------------------------------------------------------------
    def test_reg_06_missing_category_metadata_rejected(self) -> None:
        """Verify capture_candidate_baseline_atomic rejects category without metadata row."""
        with db.get_connection(self.db_path) as conn:
            conn.execute("DELETE FROM persistence_baseline_meta WHERE category = 'task';")

        with self.assertRaises(ValueError) as ctx:
            db.capture_candidate_baseline_atomic(
                "task",
                [{"entry_key": "t1", "entry_value": "cmd", "fingerprint": "fp"}],
                self.db_path,
            )
        self.assertIn("does not exist", str(ctx.exception))

    # -----------------------------------------------------------------------
    # Regression 7: Failed Candidate Replacement Rolls Back Cleanly
    # -----------------------------------------------------------------------
    def test_reg_07_failed_candidate_replacement_rolls_back(self) -> None:
        """Verify that an invalid candidate batch does not wipe existing candidate records."""
        # Initial valid candidate snapshot
        db.capture_candidate_baseline_atomic(
            "registry",
            [{"entry_key": "reg:orig", "entry_value": "v1", "fingerprint": "fp1"}],
            self.db_path,
        )
        self.assertEqual(len(db.get_candidate_baseline("registry", db_path=self.db_path)), 1)

        # Attempt to capture batch containing an invalid entry (empty entry_key)
        invalid_batch = [
            {"entry_key": "reg:good", "entry_value": "v2", "fingerprint": "fp2"},
            {"entry_key": "", "entry_value": "v3", "fingerprint": "fp3"},  # Invalid!
        ]
        with self.assertRaises(ValueError):
            db.capture_candidate_baseline_atomic("registry", invalid_batch, self.db_path)

        # Original snapshot must still exist intact
        candidates = db.get_candidate_baseline("registry", db_path=self.db_path)
        self.assertEqual(len(candidates), 1)
        self.assertIn("reg:orig", candidates)

    # -----------------------------------------------------------------------
    # Regression 8: WAL Initialization and Per-Connection Foreign Keys
    # -----------------------------------------------------------------------
    def test_reg_08_wal_initialization_and_per_connection_foreign_keys(self) -> None:
        """Verify WAL mode is confirmed on init_db and foreign_keys enabled on new connection."""
        with db.get_connection(self.db_path) as conn:
            fk = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
            self.assertEqual(fk, 1)
            wal = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            self.assertEqual(wal.lower(), "wal")

    # -----------------------------------------------------------------------
    # Regression 9: Same Entry Key Permitted Across Different Categories & Identity Preserved
    # -----------------------------------------------------------------------
    def test_reg_09_same_entry_key_permitted_across_different_categories(self) -> None:
        """
        Verify identical entry_key is allowed in different categories under composite PK,
        and that retrieval across all categories preserves category identity without collisions.
        """
        shared_key = "SharedIdentifier"

        # Capture in registry
        db.capture_candidate_baseline_atomic(
            "registry",
            [{"entry_key": shared_key, "entry_value": "reg_val", "fingerprint": "fp_reg"}],
            self.db_path,
        )
        # Capture in task
        db.capture_candidate_baseline_atomic(
            "task",
            [{"entry_key": shared_key, "entry_value": "task_val", "fingerprint": "fp_task"}],
            self.db_path,
        )

        # Scoped retrieval preserves single-key access
        reg_candidates = db.get_candidate_baseline("registry", db_path=self.db_path)
        task_candidates = db.get_candidate_baseline("task", db_path=self.db_path)

        self.assertIn(shared_key, reg_candidates)
        self.assertIn(shared_key, task_candidates)
        self.assertEqual(reg_candidates[shared_key]["entry_value"], "reg_val")
        self.assertEqual(task_candidates[shared_key]["entry_value"], "task_val")

        # Unscoped retrieval across all categories (category=None) must preserve both records
        all_candidates = db.get_candidate_baseline(db_path=self.db_path)
        self.assertEqual(len(all_candidates), 2, "Both records must be preserved across categories without collision")
        self.assertIn(("registry", shared_key), all_candidates)
        self.assertIn(("task", shared_key), all_candidates)
        self.assertEqual(all_candidates[("registry", shared_key)]["entry_value"], "reg_val")
        self.assertEqual(all_candidates[("task", shared_key)]["entry_value"], "task_val")

        # Ambiguous unscoped string lookup must raise KeyError
        with self.assertRaises(KeyError) as ctx:
            _ = all_candidates[shared_key]
        self.assertIn("ambiguous", str(ctx.exception).lower())

        # Grouping helper works as expected
        grouped = all_candidates.by_category()
        self.assertEqual(grouped["registry"][shared_key]["entry_value"], "reg_val")
        self.assertEqual(grouped["task"][shared_key]["entry_value"], "task_val")

        # Accept both and verify get_persistence_baseline also preserves both records
        db.accept_baseline_atomic("registry", self.db_path)
        db.accept_baseline_atomic("task", self.db_path)

        all_accepted = db.get_persistence_baseline(only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(all_accepted), 2)
        self.assertEqual(all_accepted[("registry", shared_key)]["entry_value"], "reg_val")
        self.assertEqual(all_accepted[("task", shared_key)]["entry_value"], "task_val")

    # -----------------------------------------------------------------------
    # Regression 10: Duplicate Key Rejected Within Same Category and Snapshot
    # -----------------------------------------------------------------------
    def test_reg_10_duplicate_key_rejected_within_same_category(self) -> None:
        """Verify duplicate entry_key within the same snapshot is rejected."""
        batch_with_duplicates = [
            {"entry_key": "DuplicateKey", "entry_value": "val1", "fingerprint": "fp1"},
            {"entry_key": "DuplicateKey", "entry_value": "val2", "fingerprint": "fp2"},
        ]
        with self.assertRaises(ValueError) as ctx:
            db.capture_candidate_baseline_atomic("registry", batch_with_duplicates, self.db_path)
        self.assertIn("duplicate entry_key", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # Regression 11: Invalid Metadata JSON Rejected
    # -----------------------------------------------------------------------
    def test_reg_11_invalid_metadata_json_rejected(self) -> None:
        """Verify unparseable metadata JSON strings or unsupported types are rejected."""
        scan_id = db.start_scan(self.db_path)

        # Malformed JSON string
        bad_f1 = {
            "scan_id": scan_id,
            "pid": 100,
            "process_name": "proc.exe",
            "signal": "process_view",
            "evidence": "Evidence",
            "severity": "low",
            "finding_type": "threat",
            "score_eligible": 1,
            "metadata": "{invalid_json: 123",  # Malformed
        }
        with self.assertRaises(ValueError):
            db.validate_finding(bad_f1)

        # Unsupported metadata type (e.g. integer)
        bad_f2 = {
            "scan_id": scan_id,
            "pid": 100,
            "process_name": "proc.exe",
            "signal": "process_view",
            "evidence": "Evidence",
            "severity": "low",
            "finding_type": "threat",
            "score_eligible": 1,
            "metadata": 12345,  # Invalid type
        }
        with self.assertRaises(TypeError):
            db.validate_finding(bad_f2)

    # -----------------------------------------------------------------------
    # Regression 12: None Process Name and Evidence Rejected
    # -----------------------------------------------------------------------
    def test_reg_12_none_process_name_and_evidence_rejected(self) -> None:
        """Verify process_name=None or evidence=None are rejected without silent str() conversion."""
        scan_id = db.start_scan(self.db_path)

        # process_name is None
        bad_f1 = {
            "scan_id": scan_id,
            "pid": 100,
            "process_name": None,
            "signal": "process_view",
            "evidence": "Valid evidence",
            "severity": "low",
            "finding_type": "threat",
            "score_eligible": 1,
        }
        with self.assertRaises(ValueError):
            db.validate_finding(bad_f1)

        # evidence is None
        bad_f2 = {
            "scan_id": scan_id,
            "pid": 100,
            "process_name": "valid.exe",
            "signal": "process_view",
            "evidence": None,
            "severity": "low",
            "finding_type": "threat",
            "score_eligible": 1,
        }
        with self.assertRaises(ValueError):
            db.validate_finding(bad_f2)

        # Integer instead of string
        bad_f3 = {
            "scan_id": scan_id,
            "pid": 100,
            "process_name": 12345,
            "signal": "process_view",
            "evidence": "Valid evidence",
            "severity": "low",
            "finding_type": "threat",
            "score_eligible": 1,
        }
        with self.assertRaises(ValueError):
            db.validate_finding(bad_f3)

    # -----------------------------------------------------------------------
    # Regression 13: Conflicting Scan IDs, Non-Dict Findings, and Booleans Rejected
    # -----------------------------------------------------------------------
    def test_reg_13_conflicting_scan_ids_rejected(self) -> None:
        """Verify insert_findings validates finding type and rejects conflicting/boolean scan_ids."""
        scan1 = db.start_scan(self.db_path)
        scan2 = db.start_scan(self.db_path)

        finding = {
            "scan_id": scan1,  # Conflicts with target scan2
            "pid": 100,
            "process_name": "proc.exe",
            "signal": "process_view",
            "evidence": "Evidence",
            "severity": "low",
            "finding_type": "threat",
            "score_eligible": 1,
        }
        with self.assertRaises(ValueError) as ctx:
            db.insert_findings(scan2, [finding], self.db_path)
        self.assertIn("conflicts", str(ctx.exception).lower())

        # Boolean scan_id (True == 1) must be strictly rejected
        bad_bool_finding = {
            "scan_id": True,
            "pid": 100,
            "process_name": "proc.exe",
            "signal": "process_view",
            "evidence": "Evidence",
            "severity": "low",
            "finding_type": "threat",
            "score_eligible": 1,
        }
        with self.assertRaises(ValueError) as ctx:
            db.insert_findings(1, [bad_bool_finding], self.db_path)
        self.assertIn("positive integer", str(ctx.exception).lower())

        # Non-dict item inside findings list must raise TypeError
        with self.assertRaises(TypeError) as ctx:
            db.insert_findings(scan1, ["not_a_dictionary"], self.db_path)  # type: ignore
        self.assertIn("must be a dictionary", str(ctx.exception).lower())

        # Non-list findings argument must raise TypeError
        with self.assertRaises(TypeError) as ctx:
            db.insert_findings(scan1, "not_a_list", self.db_path)  # type: ignore
        self.assertIn("must be a list", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # Regression 14: Completed Scan Cannot Be Completed Again
    # -----------------------------------------------------------------------
    def test_reg_14_completed_scan_cannot_be_completed_again(self) -> None:
        """Verify attempting to complete an already COMPLETED scan raises ValueError."""
        scan_id = db.start_scan(self.db_path)
        db.complete_scan(scan_id, 0, 0, 10.0, db_path=self.db_path)

        with self.assertRaises(ValueError) as ctx:
            db.complete_scan(scan_id, 0, 0, 10.0, db_path=self.db_path)
        self.assertIn("cannot complete", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # Regression 15: Failed Scan Cannot Be Completed
    # -----------------------------------------------------------------------
    def test_reg_15_failed_scan_cannot_be_completed(self) -> None:
        """Verify attempting to complete an already FAILED scan raises ValueError."""
        scan_id = db.start_scan(self.db_path)
        db.fail_scan(scan_id, "Error", 10.0, db_path=self.db_path)

        with self.assertRaises(ValueError) as ctx:
            db.complete_scan(scan_id, 0, 0, 10.0, db_path=self.db_path)
        self.assertIn("cannot complete", str(ctx.exception).lower())

        with self.assertRaises(ValueError) as ctx:
            db.fail_scan(scan_id, "Second Error", 10.0, db_path=self.db_path)
        self.assertIn("cannot fail", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # Regression 16: Nonexistent Scan Updates Rejected
    # -----------------------------------------------------------------------
    def test_reg_16_nonexistent_scan_updates_rejected(self) -> None:
        """Verify updating a non-existent scan_id raises ValueError."""
        non_existent_id = 888888
        with self.assertRaises(ValueError) as ctx:
            db.complete_scan(non_existent_id, 0, 0, 10.0, db_path=self.db_path)
        self.assertIn("does not exist", str(ctx.exception).lower())

        with self.assertRaises(ValueError) as ctx:
            db.fail_scan(non_existent_id, "Error", 10.0, db_path=self.db_path)
        self.assertIn("does not exist", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # Regression 17: NaN and Infinity Scores Rejected
    # -----------------------------------------------------------------------
    def test_reg_17_nan_and_infinity_scores_rejected(self) -> None:
        """Verify NaN, inf, and -inf risk scores are rejected in insert_risk_scores."""
        scan_id = db.start_scan(self.db_path)

        # NaN
        with self.assertRaises(ValueError):
            db.insert_risk_scores(
                scan_id,
                [{"item_key": "pid:1", "process_name": "p.exe", "score": float("nan"), "risk_level": "LOW"}],
                self.db_path,
            )

        # +Infinity
        with self.assertRaises(ValueError):
            db.insert_risk_scores(
                scan_id,
                [{"item_key": "pid:1", "process_name": "p.exe", "score": float("inf"), "risk_level": "HIGH"}],
                self.db_path,
            )

        # -Infinity
        with self.assertRaises(ValueError):
            db.insert_risk_scores(
                scan_id,
                [{"item_key": "pid:1", "process_name": "p.exe", "score": float("-inf"), "risk_level": "LOW"}],
                self.db_path,
            )

    # -----------------------------------------------------------------------
    # Regression 18: Incorrect Risk-Level / Score Combinations Rejected
    # -----------------------------------------------------------------------
    def test_reg_18_incorrect_risk_level_score_combinations_rejected(self) -> None:
        """Verify risk_level must strictly match configured thresholds for score."""
        scan_id = db.start_scan(self.db_path)

        # Score 0.80 is HIGH, but labeled LOW
        with self.assertRaises(ValueError) as ctx:
            db.insert_risk_scores(
                scan_id,
                [{"item_key": "pid:1", "process_name": "p.exe", "score": 0.80, "risk_level": "LOW"}],
                self.db_path,
            )
        self.assertIn("does not match", str(ctx.exception).lower())

        # Score 0.20 is LOW, but labeled HIGH
        with self.assertRaises(ValueError) as ctx:
            db.insert_risk_scores(
                scan_id,
                [{"item_key": "pid:1", "process_name": "p.exe", "score": 0.20, "risk_level": "HIGH"}],
                self.db_path,
            )
        self.assertIn("does not match", str(ctx.exception).lower())

        # Score 0.50 is MEDIUM, but labeled LOW
        with self.assertRaises(ValueError) as ctx:
            db.insert_risk_scores(
                scan_id,
                [{"item_key": "pid:1", "process_name": "p.exe", "score": 0.50, "risk_level": "LOW"}],
                self.db_path,
            )
        self.assertIn("does not match", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # Regression 19: Safe Legacy Schema Migration Succeeds When Data Valid
    # -----------------------------------------------------------------------
    def test_reg_19_legacy_migration_succeeds_when_valid(self) -> None:
        """Verify older schema with single-column PK migrates safely to composite PK."""
        legacy_dir = tempfile.TemporaryDirectory()
        legacy_db = str(Path(legacy_dir.name) / "legacy.db")
        try:
            # Set up a legacy database with old single-column PK on entry_key
            conn = sqlite3.connect(legacy_db)
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("""
            CREATE TABLE persistence_baseline (
                entry_type TEXT NOT NULL,
                entry_key TEXT PRIMARY KEY,
                entry_value TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                structured_data TEXT NOT NULL DEFAULT '{}',
                is_candidate INTEGER NOT NULL,
                captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                accepted_at DATETIME DEFAULT NULL
            );
            """)
            conn.execute("""
            INSERT INTO persistence_baseline (entry_type, entry_key, entry_value, fingerprint, is_candidate)
            VALUES ('registry', 'App1', 'val1', 'fp1', 0),
                   ('service', 'Svc1', 'val2', 'fp2', 0);
            """)
            conn.commit()
            conn.close()

            # Run init_db which must perform the migration
            db.init_db(legacy_db)

            # Verify table info has composite PK
            with db.get_connection(legacy_db) as conn2:
                table_info = conn2.execute("PRAGMA table_info(persistence_baseline);").fetchall()
                pk_cols = {r["name"] for r in table_info if r["pk"] > 0}
                self.assertEqual(pk_cols, {"entry_type", "entry_key", "is_candidate"})

                # Verify all records migrated
                count = conn2.execute("SELECT COUNT(*) AS cnt FROM persistence_baseline;").fetchone()["cnt"]
                self.assertEqual(count, 2)

                # Verify legacy table was dropped
                legacy_tbl = conn2.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='persistence_baseline_legacy';"
                ).fetchone()
                self.assertIsNone(legacy_tbl)
        finally:
            import gc
            gc.collect()
            try:
                legacy_dir.cleanup()
            except PermissionError:
                pass

    # -----------------------------------------------------------------------
    # Regression 20: Legacy Schema Migration Detects Conflicts and Rolls Back
    # -----------------------------------------------------------------------
    def test_reg_20_legacy_migration_detects_conflicts_and_rolls_back(self) -> None:
        """Verify migration detects duplicate composite keys and aborts without silent data loss."""
        conflict_dir = tempfile.TemporaryDirectory()
        conflict_db = str(Path(conflict_dir.name) / "conflict.db")
        try:
            # Set up a legacy table without PK constraint containing duplicates
            conn = sqlite3.connect(conflict_db)
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("""
            CREATE TABLE persistence_baseline (
                entry_type TEXT NOT NULL,
                entry_key TEXT NOT NULL,
                entry_value TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                structured_data TEXT NOT NULL DEFAULT '{}',
                is_candidate INTEGER NOT NULL,
                captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                accepted_at DATETIME DEFAULT NULL
            );
            """)
            # Insert two identical rows that would conflict under the new composite PK
            conn.execute("""
            INSERT INTO persistence_baseline (entry_type, entry_key, entry_value, fingerprint, is_candidate)
            VALUES ('registry', 'DupKey', 'val1', 'fp1', 1),
                   ('registry', 'DupKey', 'val2', 'fp2', 1);
            """)
            conn.commit()
            conn.close()

            # Attempt init_db, which must detect the conflict and abort
            with self.assertRaises(RuntimeError) as ctx:
                db.init_db(conflict_db)
            self.assertIn("duplicate primary keys", str(ctx.exception).lower())
        finally:
            import gc
            gc.collect()
            try:
                conflict_dir.cleanup()
            except PermissionError:
                pass


if __name__ == "__main__":
    unittest.main()
