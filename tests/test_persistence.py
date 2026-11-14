"""
GhostHunt — Phase 3 Test Suite: Persistence Monitoring Engine
Comprehensive unit and integration tests for Signal 2 persistence monitoring.

Covers:
1. Category enumerators: Registry, Scheduled Tasks, Windows Services (live & mocked).
2. Failure isolation, no empty-list spoofing, and error handling.
3. Baseline lifecycle state machine:
   - NOT_INITIALIZED -> CANDIDATE_REVIEW on first successful enumeration.
   - Neutral candidate capture (pre-existing mechanisms are candidate entries, not additions).
   - Diffing suppression while in CANDIDATE_REVIEW.
   - Explicit acceptance transition to ACCEPTED_TRUSTED.
   - Fixed reference baseline semantics (ordinary scans never silently advance baseline).
   - Failure preservation (failed enumeration never erases accepted baseline; zero false removals).
   - Atomic reset wipes candidate & accepted baselines, returning to NOT_INITIALIZED.
4. Diffing & deviation detection: added, modified, removed, and unchanged entries.
5. Cross-category key collision resistance.
6. Schema and classification invariant conformance:
   - finding_type == 'threat' => score_eligible in (0, 1)
   - finding_type == 'diagnostic' => score_eligible == 0
   - pid == None supported for system-level persistence items.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import config
import core.db as db
import core.persistence as cp


class TestPersistenceEngine(unittest.TestCase):
    """
    Test suite for Phase 3 Persistence Monitoring Engine.
    All tests execute against isolated, temporary SQLite databases.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_persistence.db")
        db.init_db(self.db_path)

    def tearDown(self) -> None:
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except PermissionError:
            pass

    # =======================================================================
    # 1. REGISTRY ENUMERATION TESTS
    # =======================================================================

    def test_01_registry_live_or_handled_enumeration(self) -> None:
        """Verify registry enumerator returns structured result on live host."""
        if not cp.IS_WINDOWS:
            self.skipTest("Registry test requires Windows host")
        success, entries, err = cp.read_registry_run_keys()
        self.assertIsInstance(success, bool)
        self.assertIsInstance(entries, dict)
        if success:
            # On Windows host, HKLM typically has at least 1 autorun entry or is empty
            for k, item in entries.items():
                self.assertEqual(item["entry_type"], "registry")
                self.assertTrue(k.startswith("registry:"))
                self.assertTrue(len(item["fingerprint"]) == 64)
                self.assertIn("value_name", item["structured_data"])

    def test_02_registry_mocked_populated_and_empty(self) -> None:
        """Verify registry parsing of mocked entries and legitimate empty keys."""
        mock_entries = {
            "registry:hklm:64bit:run:testapp": {
                "entry_type": "registry",
                "entry_key": "registry:hklm:64bit:run:testapp",
                "entry_value": "C:\\test\\app.exe",
                "fingerprint": "a" * 64,
                "structured_data": {"value_name": "TestApp", "value_data": "C:\\test\\app.exe"},
            }
        }
        success, entries, err = cp.read_registry_run_keys(caller=lambda: (True, mock_entries, None))
        self.assertTrue(success)
        self.assertEqual(len(entries), 1)
        self.assertIsNone(err)

        # Empty key enumeration
        success_empty, entries_empty, err_empty = cp.read_registry_run_keys(caller=lambda: (True, {}, None))
        self.assertTrue(success_empty)
        self.assertEqual(len(entries_empty), 0)
        self.assertIsNone(err_empty)

    def test_03_registry_mocked_access_denied_failure(self) -> None:
        """Verify registry failure reports explicit error without empty-list spoofing."""
        fail_caller = lambda: (False, {}, "Access denied opening registry keys")
        success, entries, err = cp.read_registry_run_keys(caller=fail_caller)
        self.assertFalse(success)
        self.assertEqual(entries, {})
        self.assertIn("Access denied", err)

    def test_04_registry_deterministic_fingerprint(self) -> None:
        """Verify deterministic fingerprint computation regardless of dictionary key order."""
        d1 = {"hive": "HKLM", "path": "SOFTWARE\\Run", "name": "App", "value": "C:\\app.exe", "view": "64bit"}
        d2 = {"view": "64bit", "name": "App", "path": "SOFTWARE\\Run", "value": "C:\\app.exe", "hive": "HKLM"}
        fp1 = cp.compute_fingerprint(d1)
        fp2 = cp.compute_fingerprint(d2)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

    # =======================================================================
    # 2. SCHEDULED TASK ENUMERATION TESTS
    # =======================================================================

    def test_05_tasks_mocked_populated_and_empty(self) -> None:
        """Verify task enumeration handles populated inventory and legitimate empty lists."""
        mock_tasks = {
            "task:\\microsoft\\windows\\backup": {
                "entry_type": "task",
                "entry_key": "task:\\microsoft\\windows\\backup",
                "entry_value": "C:\\Windows\\System32\\backup.exe /auto",
                "fingerprint": "b" * 64,
                "structured_data": {
                    "task_name": "\\Microsoft\\Windows\\Backup",
                    "status": "Ready",
                    "action": "C:\\Windows\\System32\\backup.exe /auto",
                    "author": "Microsoft",
                },
            }
        }
        success, entries, err = cp.read_scheduled_tasks(caller=lambda: (True, mock_tasks, None))
        self.assertTrue(success)
        self.assertEqual(len(entries), 1)
        self.assertIn("task:\\microsoft\\windows\\backup", entries)

        # Legitimate empty
        success_empty, entries_empty, err_empty = cp.read_scheduled_tasks(caller=lambda: (True, {}, None))
        self.assertTrue(success_empty)
        self.assertEqual(len(entries_empty), 0)

    def test_06_tasks_mocked_failure_handling(self) -> None:
        """Verify scheduled task failure returns explicit error details."""
        fail_caller = lambda: (False, {}, "Task Scheduler service unavailable")
        success, entries, err = cp.read_scheduled_tasks(caller=fail_caller)
        self.assertFalse(success)
        self.assertEqual(entries, {})
        self.assertIn("Task Scheduler service unavailable", err)

    def test_07_tasks_preserves_disabled_and_no_action_tasks(self) -> None:
        """Verify disabled tasks and tasks with N/A actions are preserved in inventory."""
        mock_tasks = {
            "task:\\maintenance\\task1": {
                "entry_type": "task",
                "entry_key": "task:\\maintenance\\task1",
                "entry_value": "N/A",
                "fingerprint": "c" * 64,
                "structured_data": {"task_name": "\\Maintenance\\Task1", "status": "Disabled", "action": "N/A"},
            }
        }
        success, entries, err = cp.read_scheduled_tasks(caller=lambda: (True, mock_tasks, None))
        self.assertTrue(success)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries["task:\\maintenance\\task1"]["structured_data"]["status"], "Disabled")

    # =======================================================================
    # 3. WINDOWS SERVICE ENUMERATION TESTS
    # =======================================================================

    def test_08_services_mocked_populated_and_empty(self) -> None:
        """Verify service enumerator parses installed services cleanly."""
        mock_services = {
            "service:wuauserv": {
                "entry_type": "service",
                "entry_key": "service:wuauserv",
                "entry_value": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                "fingerprint": "d" * 64,
                "structured_data": {
                    "service_name": "wuauserv",
                    "display_name": "Windows Update",
                    "binary_path": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                    "start_mode": "AUTO_START",
                    "state": "RUNNING",
                    "account": "LocalSystem",
                },
            }
        }
        success, entries, err = cp.read_windows_services(caller=lambda: (True, mock_services, None))
        self.assertTrue(success)
        self.assertEqual(len(entries), 1)
        self.assertIn("service:wuauserv", entries)

        # Empty
        success_empty, entries_empty, err_empty = cp.read_windows_services(caller=lambda: (True, {}, None))
        self.assertTrue(success_empty)
        self.assertEqual(len(entries_empty), 0)

    def test_09_services_mocked_scm_failure(self) -> None:
        """Verify service failure returns explicit error details without empty-list spoofing."""
        fail_caller = lambda: (False, {}, "OpenSCManagerW failed with Win32 error 5 (Access is denied)")
        success, entries, err = cp.read_windows_services(caller=fail_caller)
        self.assertFalse(success)
        self.assertEqual(entries, {})
        self.assertIn("OpenSCManagerW failed", err)

    def test_10_services_preserves_stopped_and_disabled_services(self) -> None:
        """Verify stopped and disabled services are retained in inventory."""
        mock_services = {
            "service:stoppedsvc": {
                "entry_type": "service",
                "entry_key": "service:stoppedsvc",
                "entry_value": "C:\\stopped\\service.exe",
                "fingerprint": "e" * 64,
                "structured_data": {
                    "service_name": "stoppedsvc",
                    "display_name": "Stopped Service",
                    "binary_path": "C:\\stopped\\service.exe",
                    "start_mode": "DISABLED",
                    "state": "STOPPED",
                    "account": "LocalSystem",
                },
            }
        }
        success, entries, err = cp.read_windows_services(caller=lambda: (True, mock_services, None))
        self.assertTrue(success)
        self.assertEqual(entries["service:stoppedsvc"]["structured_data"]["state"], "STOPPED")
        self.assertEqual(entries["service:stoppedsvc"]["structured_data"]["start_mode"], "DISABLED")

    # =======================================================================
    # 4. BASELINE LIFECYCLE TESTS (FIXED REFERENCE BASELINE)
    # =======================================================================

    def test_11_first_scan_captures_candidate_baseline_cleanly(self) -> None:
        """Verify first successful scan captures candidate baseline in CANDIDATE_REVIEW with 0 threats."""
        reg_entries = {
            "registry:hklm:64bit:run:app1": {
                "entry_type": "registry",
                "entry_key": "registry:hklm:64bit:run:app1",
                "entry_value": "C:\\app1.exe",
                "fingerprint": "1" * 64,
                "structured_data": {"val": 1},
            }
        }

        # Scan 1: initial capture
        findings = cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        # Check metadata state transitioned to CANDIDATE_REVIEW
        meta = db.get_category_baseline_meta("registry", db_path=self.db_path)
        self.assertEqual(meta["baseline_state"], "CANDIDATE_REVIEW")
        self.assertEqual(meta["candidate_entry_count"], 1)
        self.assertEqual(meta["accepted_entry_count"], 0)

        # Zero threat findings emitted; only operational diagnostics
        threats = [f for f in findings if f["finding_type"] == "threat"]
        diags = [f for f in findings if f["finding_type"] == "diagnostic"]
        self.assertEqual(len(threats), 0, "Initial candidate capture must emit zero threat findings")
        self.assertGreater(len(diags), 0, "Diagnostic must be emitted notifying operator that review is required")

    def test_12_diffing_suppressed_while_in_candidate_review(self) -> None:
        """Verify baseline diffing is suppressed while in CANDIDATE_REVIEW state."""
        reg_entries_p1 = {
            "registry:k1": {
                "entry_type": "registry",
                "entry_key": "registry:k1",
                "entry_value": "val1",
                "fingerprint": "1" * 64,
                "structured_data": {},
            }
        }
        # First scan captures candidate
        cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entries_p1, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        # Second scan introduces a new entry before operator acceptance
        reg_entries_p2 = dict(reg_entries_p1)
        reg_entries_p2["registry:k2"] = {
            "entry_type": "registry",
            "entry_key": "registry:k2",
            "entry_value": "val2",
            "fingerprint": "2" * 64,
            "structured_data": {},
        }

        findings_p2 = cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entries_p2, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        # Still in CANDIDATE_REVIEW, so zero threats should be emitted
        threats = [f for f in findings_p2 if f["finding_type"] == "threat"]
        self.assertEqual(len(threats), 0, "Diffing must be suppressed pending operator acceptance")

    def test_13_explicit_acceptance_promotes_candidate_to_accepted(self) -> None:
        """Verify explicit acceptance promotes candidate records to ACCEPTED_TRUSTED."""
        reg_entries = {
            "registry:k1": {
                "entry_type": "registry",
                "entry_key": "registry:k1",
                "entry_value": "val1",
                "fingerprint": "1" * 64,
                "structured_data": {},
            }
        }
        cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        # Explicit acceptance
        accept_res = cp.accept_baseline("registry", db_path=self.db_path)
        self.assertEqual(accept_res["promoted_entries"], 1)

        meta = db.get_category_baseline_meta("registry", db_path=self.db_path)
        self.assertEqual(meta["baseline_state"], "ACCEPTED_TRUSTED")
        self.assertEqual(meta["accepted_entry_count"], 1)

        candidates_after = db.get_candidate_baseline("registry", db_path=self.db_path)
        self.assertEqual(len(candidates_after), 0)

        accepted_after = db.get_persistence_baseline("registry", only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(accepted_after), 1)

    def test_14_accepted_baseline_remains_fixed_during_normal_scans(self) -> None:
        """Verify ordinary scans never silently update or overwrite the accepted baseline."""
        reg_entries = {
            "registry:k1": {
                "entry_type": "registry",
                "entry_key": "registry:k1",
                "entry_value": "val1",
                "fingerprint": "1" * 64,
                "structured_data": {},
            }
        }
        cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )
        cp.accept_baseline("registry", db_path=self.db_path)

        accepted_before = db.get_persistence_baseline("registry", only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(accepted_before), 1)

        # Subsequent scan with new entries
        reg_entries_modified = dict(reg_entries)
        reg_entries_modified["registry:k2_added"] = {
            "entry_type": "registry",
            "entry_key": "registry:k2_added",
            "entry_value": "malware.exe",
            "fingerprint": "9" * 64,
            "structured_data": {},
        }
        findings = cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entries_modified, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        # Threat finding emitted for added entry
        threats = [f for f in findings if f["finding_type"] == "threat"]
        self.assertEqual(len(threats), 1)
        self.assertIn("added", threats[0]["evidence"].lower())

        # Verify accepted baseline was NOT silently updated
        accepted_after = db.get_persistence_baseline("registry", only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(accepted_after), 1, "Accepted baseline must remain strictly fixed")
        self.assertNotIn("registry:k2_added", accepted_after)

    def test_15_enumeration_failure_preserves_accepted_baseline_and_zero_false_removals(self) -> None:
        """Verify failed enumeration preserves accepted baseline and never emits false removed findings."""
        reg_entries = {
            "registry:k1": {
                "entry_type": "registry",
                "entry_key": "registry:k1",
                "entry_value": "val1",
                "fingerprint": "1" * 64,
                "structured_data": {},
            }
        }
        cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )
        cp.accept_baseline("registry", db_path=self.db_path)

        # Next scan encounters an operational failure
        findings_fail = cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (False, {}, "Access Denied querying registry"),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        # Zero threat findings (especially no false 'removed' findings!)
        threats = [f for f in findings_fail if f["finding_type"] == "threat"]
        self.assertEqual(len(threats), 0, "Must never emit false removed findings on enumeration failure")

        # Operational diagnostic must be emitted
        diags = [f for f in findings_fail if f["finding_type"] == "diagnostic"]
        self.assertTrue(any("Access Denied" in d["evidence"] for d in diags))

        # Verify accepted baseline records are still 100% intact
        accepted = db.get_persistence_baseline("registry", only_accepted=True, db_path=self.db_path)
        self.assertEqual(len(accepted), 1)
        self.assertIn("registry:k1", accepted)

    def test_16_atomic_reset_wipes_all_and_requires_new_acceptance(self) -> None:
        """Verify atomic reset wipes candidate and accepted baselines returning to NOT_INITIALIZED."""
        reg_entries = {
            "registry:k1": {
                "entry_type": "registry",
                "entry_key": "registry:k1",
                "entry_value": "val1",
                "fingerprint": "1" * 64,
                "structured_data": {},
            }
        }
        cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )
        cp.accept_baseline("registry", db_path=self.db_path)

        # Reset all
        cp.reset_all_baselines(db_path=self.db_path)

        all_meta = db.get_all_baseline_meta(db_path=self.db_path)
        for cat in ("registry", "task", "service"):
            self.assertEqual(all_meta[cat]["baseline_state"], "NOT_INITIALIZED")
            self.assertEqual(all_meta[cat]["candidate_entry_count"], 0)
            self.assertEqual(all_meta[cat]["accepted_entry_count"], 0)

        all_records = db.get_persistence_baseline(only_accepted=False, db_path=self.db_path)
        self.assertEqual(len(all_records), 0)

    # =======================================================================
    # 5. DIFFING & DEVIATION DETECTION TESTS
    # =======================================================================

    def test_17_diff_identifies_added_modified_removed(self) -> None:
        """Verify diff_persistence_category identifies additions, modifications, and removals."""
        baseline = {
            "key1": {"entry_key": "key1", "entry_value": "old_val", "fingerprint": "fp_old", "structured_data": {}},
            "key2_to_remove": {"entry_key": "key2_to_remove", "entry_value": "val2", "fingerprint": "fp2", "structured_data": {}},
            "key3_unchanged": {"entry_key": "key3_unchanged", "entry_value": "val3", "fingerprint": "fp3", "structured_data": {}},
        }
        current = {
            "key1": {"entry_key": "key1", "entry_value": "new_val", "fingerprint": "fp_new", "structured_data": {}},  # Modified
            "key3_unchanged": {"entry_key": "key3_unchanged", "entry_value": "val3", "fingerprint": "fp3", "structured_data": {}},  # Unchanged
            "key4_added": {"entry_key": "key4_added", "entry_value": "val4", "fingerprint": "fp4", "structured_data": {}},  # Added
        }

        diff = cp.diff_persistence_category("service", current, baseline)
        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(diff["added"][0]["entry_key"], "key4_added")

        self.assertEqual(len(diff["removed"]), 1)
        self.assertEqual(diff["removed"][0]["entry_key"], "key2_to_remove")

        self.assertEqual(len(diff["modified"]), 1)
        self.assertEqual(diff["modified"][0]["entry_key"], "key1")

        self.assertEqual(len(diff["unchanged"]), 1)
        self.assertEqual(diff["unchanged"][0]["entry_key"], "key3_unchanged")
        self.assertEqual(diff["total_deviations"], 3)

    def test_18_cross_category_same_key_preserved_without_collision(self) -> None:
        """Verify identical keys in different categories are tracked independently."""
        shared_key = "SharedApp"
        reg_entry = {
            shared_key: {
                "entry_type": "registry",
                "entry_key": shared_key,
                "entry_value": "reg.exe",
                "fingerprint": "fp_reg",
                "structured_data": {},
            }
        }
        task_entry = {
            shared_key: {
                "entry_type": "task",
                "entry_key": shared_key,
                "entry_value": "task.exe",
                "fingerprint": "fp_task",
                "structured_data": {},
            }
        }

        # Initialize and accept both
        cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entry, None),
            tasks_caller=lambda: (True, task_entry, None),
            services_caller=lambda: (True, {}, None),
        )
        cp.accept_baseline("registry", db_path=self.db_path)
        cp.accept_baseline("task", db_path=self.db_path)

        reg_baseline = db.get_persistence_baseline("registry", only_accepted=True, db_path=self.db_path)
        task_baseline = db.get_persistence_baseline("task", only_accepted=True, db_path=self.db_path)

        self.assertIn(shared_key, reg_baseline)
        self.assertIn(shared_key, task_baseline)
        self.assertEqual(reg_baseline[shared_key]["entry_value"], "reg.exe")
        self.assertEqual(task_baseline[shared_key]["entry_value"], "task.exe")

    def test_19_failed_category_does_not_affect_other_categories(self) -> None:
        """Verify failure in one category leaves other categories' baseline diffing active."""
        # Initialize and accept registry and service
        reg_entry = {
            "reg1": {"entry_type": "registry", "entry_key": "reg1", "entry_value": "reg.exe", "fingerprint": "1" * 64, "structured_data": {}}
        }
        svc_entry = {
            "svc1": {"entry_type": "service", "entry_key": "svc1", "entry_value": "svc.exe", "fingerprint": "2" * 64, "structured_data": {}}
        }

        cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entry, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, svc_entry, None),
        )
        cp.accept_baseline("registry", db_path=self.db_path)
        cp.accept_baseline("service", db_path=self.db_path)

        # Next scan: task fails, registry adds a deviation, service unchanged
        reg_entry_modified = dict(reg_entry)
        reg_entry_modified["reg2_threat"] = {
            "entry_type": "registry", "entry_key": "reg2_threat", "entry_value": "evil.exe", "fingerprint": "9" * 64, "structured_data": {}
        }

        findings = cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entry_modified, None),
            tasks_caller=lambda: (False, {}, "Task Scheduler crashed"),  # Category failure
            services_caller=lambda: (True, svc_entry, None),  # Unchanged
        )

        threats = [f for f in findings if f["finding_type"] == "threat"]
        diags = [f for f in findings if f["finding_type"] == "diagnostic"]

        # Threat detected for registry addition despite task failure
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["signal"], "persistence")
        self.assertIn("reg2_threat", threats[0]["evidence"])

        # Diagnostic logged for task failure
        self.assertTrue(any("Task Scheduler crashed" in d["evidence"] for d in diags))

    # =======================================================================
    # 6. FINDING CLASSIFICATION & DATABASE INTEGRATION TESTS
    # =======================================================================

    def test_20_findings_follow_phase1_schema_and_support_none_pid(self) -> None:
        """Verify generated findings strictly follow Phase 1 schema, invariants, and pid=None."""
        reg_entry = {
            "reg1": {"entry_type": "registry", "entry_key": "reg1", "entry_value": "reg.exe", "fingerprint": "1" * 64, "structured_data": {}}
        }
        cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entry, None),
            tasks_caller=lambda: (False, {}, "Error"),
            services_caller=lambda: (True, {}, None),
        )
        cp.accept_baseline("registry", db_path=self.db_path)

        # Trigger added threat
        reg_entry_new = dict(reg_entry)
        reg_entry_new["reg2"] = {"entry_type": "registry", "entry_key": "reg2", "entry_value": "new.exe", "fingerprint": "2" * 64, "structured_data": {}}

        findings = cp.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entry_new, None),
            tasks_caller=lambda: (False, {}, "Error"),
            services_caller=lambda: (True, {}, None),
        )

        for f in findings:
            validated = db.validate_finding(f)
            self.assertEqual(validated["signal"], "persistence")
            self.assertIsNone(validated["pid"])  # Persistence findings have pid=None

            if validated["finding_type"] == "diagnostic":
                self.assertEqual(validated["score_eligible"], 0)
            elif validated["finding_type"] == "threat":
                self.assertIn(validated["score_eligible"], (0, 1))

    def test_21_run_scan_persists_to_database_with_scan_id(self) -> None:
        """Verify run_scan successfully persists findings into SQLite database with scan_id."""
        scan_id = db.start_scan(self.db_path)

        reg_entry = {
            "reg1": {"entry_type": "registry", "entry_key": "reg1", "entry_value": "reg.exe", "fingerprint": "1" * 64, "structured_data": {}}
        }
        cp.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_entry, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )
        cp.accept_baseline("registry", db_path=self.db_path)

        # Scan 2: with deviation
        scan2_id = db.start_scan(self.db_path)
        reg_new = dict(reg_entry)
        reg_new["added"] = {"entry_type": "registry", "entry_key": "added", "entry_value": "backdoor.exe", "fingerprint": "9" * 64, "structured_data": {}}

        findings = cp.run_scan(
            scan_id=scan2_id,
            db_path=self.db_path,
            registry_caller=lambda: (True, reg_new, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )
        db.complete_scan(scan2_id, total_findings=len(findings), high_risk_count=1, duration_ms=20.0, db_path=self.db_path)

        stored_threats = db.get_findings_for_scan(scan2_id, include_diagnostics=False, db_path=self.db_path)
        self.assertEqual(len(stored_threats), 1)
        self.assertEqual(stored_threats[0]["signal"], "persistence")
        self.assertEqual(stored_threats[0]["finding_type"], "threat")
        self.assertEqual(stored_threats[0]["score_eligible"], 1)
        self.assertIsNone(stored_threats[0]["pid"])


if __name__ == "__main__":
    unittest.main()
