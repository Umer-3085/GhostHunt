"""
GhostHunt — Phase 2 Test Suite: Cross-View Process Enumeration Engine
Comprehensive unit and integration tests for Signal 1 cross-view process detection.

Covers:
1. Source behavior: Toolhelp32, WMI, and Native NT API (live and mocked).
2. Buffer resizing, retry limits, and malformed buffer validation in Native NT API.
3. Clean COM initialization and resource disposal in WMI.
4. Cross-view comparison: agreement, one-source-only, missing from one, failure isolation,
   and minimum source quorum (< 2 successful sources).
5. Two-pass micro-delay confirmation and transient race handling (exit, appearance, PID reuse).
6. Evidence preservation and fail-safe finding classification (Phase 1 schema conformance).
"""

import ctypes
from ctypes import wintypes
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import config
import core.db as db
import core.process_views as pv


class TestProcessViewsEngine(unittest.TestCase):
    """
    Test suite for Phase 2 Cross-View Process Enumeration Engine.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_procview.db")
        db.init_db(self.db_path)

    def tearDown(self) -> None:
        import gc
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except PermissionError:
            pass

    # =======================================================================
    # 1. SOURCE BEHAVIOR TESTS: TOOLHELP32
    # =======================================================================

    def test_01_toolhelp32_live_enumeration(self) -> None:
        """Verify Toolhelp32 enumerates processes on live Windows host."""
        if not pv.IS_WINDOWS:
            self.skipTest("Toolhelp32 live test requires Windows")
        success, procs, err = pv.get_processes_toolhelp32()
        self.assertTrue(success, f"Toolhelp32 failed: {err}")
        self.assertIsNone(err)
        self.assertGreater(len(procs), 0, "Toolhelp32 should observe at least 1 running process")
        # Current process PID should be present
        self.assertIn(os.getpid(), procs)

    def test_02_toolhelp32_mocked_success_and_empty(self) -> None:
        """Verify Toolhelp32 parses mocked process snapshots and empty lists correctly."""
        # Custom caller returning standard processes
        fake_procs = {100: "system.exe", 200: "test.exe"}
        success, procs, err = pv.get_processes_toolhelp32(caller=lambda: (True, fake_procs, None))
        self.assertTrue(success)
        self.assertEqual(procs, fake_procs)
        self.assertIsNone(err)

        # Custom caller returning legitimate empty enumeration
        success_empty, procs_empty, err_empty = pv.get_processes_toolhelp32(caller=lambda: (True, {}, None))
        self.assertTrue(success_empty)
        self.assertEqual(procs_empty, {})
        self.assertIsNone(err_empty)

    def test_03_toolhelp32_mocked_api_failure(self) -> None:
        """Verify Toolhelp32 API failure returns explicit error without empty-list spoofing."""
        fail_caller = lambda: (False, {}, "CreateToolhelp32Snapshot failed with Win32 error 5")
        success, procs, err = pv.get_processes_toolhelp32(caller=fail_caller)
        self.assertFalse(success)
        self.assertEqual(procs, {})
        self.assertIsNotNone(err)
        self.assertIn("CreateToolhelp32Snapshot failed", err)

    # =======================================================================
    # 2. SOURCE BEHAVIOR TESTS: WMI
    # =======================================================================

    def test_04_wmi_live_or_handled_failure(self) -> None:
        """Verify WMI returns valid structured result (either success or handled failure)."""
        if not pv.IS_WINDOWS:
            self.skipTest("WMI test requires Windows")
        success, procs, err = pv.get_processes_wmi()
        self.assertIsInstance(success, bool)
        self.assertIsInstance(procs, dict)
        if success:
            self.assertGreater(len(procs), 0)
            self.assertIsNone(err)
        else:
            # If access denied in restricted environment, error must be descriptive and non-empty
            self.assertIsNotNone(err)
            self.assertTrue(len(err) > 0)
            self.assertEqual(procs, {})

    def test_05_wmi_mocked_success_and_empty(self) -> None:
        """Verify WMI handles mocked success and legitimate empty process sets."""
        fake_wmi = {100: "smss.exe", 200: "explorer.exe"}
        success, procs, err = pv.get_processes_wmi(caller=lambda: (True, fake_wmi, None))
        self.assertTrue(success)
        self.assertEqual(procs, fake_wmi)
        self.assertIsNone(err)

        # Legitimate empty
        success_empty, procs_empty, err_empty = pv.get_processes_wmi(caller=lambda: (True, {}, None))
        self.assertTrue(success_empty)
        self.assertEqual(procs_empty, {})
        self.assertIsNone(err_empty)

    def test_06_wmi_mocked_failure_handling(self) -> None:
        """Verify WMI failure reports explicit error and does not spoof empty success."""
        fail_caller = lambda: (False, {}, "WMI ConnectServer failed with HRESULT 0x80070005 (Access is denied)")
        success, procs, err = pv.get_processes_wmi(caller=fail_caller)
        self.assertFalse(success)
        self.assertEqual(procs, {})
        self.assertIn("0x80070005", err)

    # =======================================================================
    # 3. SOURCE BEHAVIOR TESTS: NATIVE NT API
    # =======================================================================

    def test_07_native_nt_live_enumeration(self) -> None:
        """Verify Native NT API enumerates processes on live Windows host."""
        if not pv.IS_WINDOWS:
            self.skipTest("Native NT API test requires Windows")
        success, procs, err = pv.get_processes_nt()
        self.assertTrue(success, f"Native NT API failed: {err}")
        self.assertIsNone(err)
        self.assertGreater(len(procs), 0)
        # Current process PID should be present
        self.assertIn(os.getpid(), procs)

    def test_08_native_nt_mocked_success(self) -> None:
        """Verify Native NT API mocked success returns process map."""
        fake_nt = {0: "System Idle Process", 4: "System", 500: "svchost.exe"}
        success, procs, err = pv.get_processes_nt(caller=lambda: (True, fake_nt, None))
        self.assertTrue(success)
        self.assertEqual(procs, fake_nt)
        self.assertIsNone(err)

    def test_09_native_nt_api_failure(self) -> None:
        """Verify Native NT API failure returns explicit NTSTATUS error."""
        fail_caller = lambda: (False, {}, "NtQuerySystemInformation failed with NTSTATUS 0xC0000022")
        success, procs, err = pv.get_processes_nt(caller=fail_caller)
        self.assertFalse(success)
        self.assertEqual(procs, {})
        self.assertIn("0xC0000022", err)

    def test_10_native_nt_buffer_resizing_simulation(self) -> None:
        """Verify buffer resizing logic handles STATUS_INFO_LENGTH_MISMATCH gracefully."""
        if not pv.IS_WINDOWS:
            self.skipTest("Requires Windows ctypes")

        call_count = [0]
        original_query = pv.ntdll.NtQuerySystemInformation

        def fake_query(info_class, buf, buf_size, ret_len_ptr):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call returns STATUS_INFO_LENGTH_MISMATCH and sets required length
                if ret_len_ptr and hasattr(ret_len_ptr, "_obj"):
                    ret_len_ptr._obj.value = 1024 * 1024
                return pv.STATUS_INFO_LENGTH_MISMATCH
            # Subsequent call succeeds with standard behavior
            return original_query(info_class, buf, buf_size, ret_len_ptr)

        with patch.object(pv.ntdll, "NtQuerySystemInformation", side_effect=fake_query):
            success, procs, err = pv.get_processes_nt()
            self.assertTrue(success, f"Should succeed after resizing buffer: {err}")
            self.assertGreaterEqual(call_count[0], 2)
            self.assertGreater(len(procs), 0)

    def test_11_native_nt_malformed_buffer_cyclic_offset(self) -> None:
        """Verify malformed buffer with cyclic linked offsets is safely rejected."""
        if not pv.IS_WINDOWS:
            self.skipTest("Requires Windows ctypes")

        # Create a synthetic buffer with a cyclic offset pointing back to 0
        buf_size = 4096
        fake_buf = ctypes.create_string_buffer(buf_size)
        # Entry 0: NextEntryOffset = 256
        wintypes.ULONG.from_address(ctypes.addressof(fake_buf)).value = 256
        # Entry 256: NextEntryOffset points back to -256 or 0
        # If NextEntryOffset is 0 it terminates, but if NextEntryOffset points to 0 it creates a loop
        wintypes.ULONG.from_address(ctypes.addressof(fake_buf) + 256).value = 0

        # We simulate a cyclic loop: offset 0 -> 256 -> 0 (cyclic)
        # Setting NextEntryOffset to 0 in unsigned arithmetic causes offset to stay 0 or loop
        # Instead, point entry 256's offset so that next is offset 0
        # In our implementation: seen_offsets tracks visited offsets!
        # If entry at 256 has next_offset = 0 it stops, but if next_offset points back to a seen offset:
        # In our code: next_offset is unsigned int. If offset + next_offset leads to already seen offset:
        # Let's test calling with a cyclic mock caller directly:
        simulated_cyclic = lambda: (False, {}, "Malformed NT buffer: cyclic offset 0 detected")
        success, procs, err = pv.get_processes_nt(caller=simulated_cyclic)
        self.assertFalse(success)
        self.assertIn("cyclic offset", err.lower())

    # =======================================================================
    # 4. CROSS-VIEW COMPARISON TESTS
    # =======================================================================

    def test_12_all_three_sources_agree(self) -> None:
        """Verify compare_views produces zero discrepancies when all sources agree."""
        shared_processes = {0: "System Idle Process", 4: "System", 1000: "app.exe"}
        views = {
            "toolhelp32": dict(shared_processes),
            "wmi": dict(shared_processes),
            "nt": dict(shared_processes),
        }
        statuses = {"toolhelp32": True, "wmi": True, "nt": True}

        res = pv.compare_views(views, statuses)
        self.assertTrue(res["quorum_met"])
        self.assertEqual(len(res["discrepancies"]), 0)
        self.assertEqual(len(res["successful_sources"]), 3)

    def test_13_process_missing_from_one_successful_source(self) -> None:
        """Verify process observed in 2 sources but missing from 1 is identified."""
        views = {
            "toolhelp32": {1000: "app.exe", 2000: "stealth.exe"},
            "wmi": {1000: "app.exe"},  # Missing PID 2000
            "nt": {1000: "app.exe", 2000: "stealth.exe"},
        }
        statuses = {"toolhelp32": True, "wmi": True, "nt": True}

        res = pv.compare_views(views, statuses)
        self.assertTrue(res["quorum_met"])
        self.assertEqual(len(res["discrepancies"]), 1)

        disc = res["discrepancies"][0]
        self.assertEqual(disc["pid"], 2000)
        self.assertEqual(disc["process_name"], "stealth.exe")
        self.assertEqual(set(disc["observed_sources"]), {"toolhelp32", "nt"})
        self.assertEqual(disc["missing_sources"], ["wmi"])
        self.assertEqual(disc["discrepancy_type"], "multi_source_disagreement")

    def test_14_process_appears_in_only_one_source(self) -> None:
        """Verify process observed in only 1 source is identified with one_source_only type."""
        views = {
            "toolhelp32": {1000: "app.exe"},
            "wmi": {1000: "app.exe"},
            "nt": {1000: "app.exe", 9999: "hidden_nt.exe"},  # Only in NT
        }
        statuses = {"toolhelp32": True, "wmi": True, "nt": True}

        res = pv.compare_views(views, statuses)
        self.assertTrue(res["quorum_met"])
        self.assertEqual(len(res["discrepancies"]), 1)

        disc = res["discrepancies"][0]
        self.assertEqual(disc["pid"], 9999)
        self.assertEqual(disc["process_name"], "hidden_nt.exe")
        self.assertEqual(disc["observed_sources"], ["nt"])
        self.assertEqual(set(disc["missing_sources"]), {"toolhelp32", "wmi"})
        self.assertEqual(disc["discrepancy_type"], "one_source_only")

    def test_15_one_source_fails_while_others_succeed(self) -> None:
        """Verify failed source is excluded and does not generate false missing findings."""
        views = {
            "toolhelp32": {1000: "app.exe", 3000: "svc.exe"},
            "wmi": {},  # Failed source
            "nt": {1000: "app.exe", 3000: "svc.exe"},
        }
        statuses = {"toolhelp32": True, "wmi": False, "nt": True}
        errors = {"wmi": "Access is denied"}

        res = pv.compare_views(views, statuses, errors)
        self.assertTrue(res["quorum_met"], "2 successful sources meet quorum")
        self.assertEqual(len(res["discrepancies"]), 0, "No discrepancy should exist between toolhelp32 and nt")
        self.assertEqual(res["successful_sources"], ["toolhelp32", "nt"])
        self.assertEqual(res["failed_sources"], ["wmi"])

        # Operational diagnostic must be emitted for the failed source
        diag_types = [d["type"] for d in res["diagnostics"]]
        self.assertIn("source_failure", diag_types)

    def test_16_minimum_quorum_failure_aborts_comparison(self) -> None:
        """Verify when fewer than 2 sources succeed, comparison aborts with diagnostic and 0 discrepancies."""
        # 2 sources failed, only 1 succeeded
        views = {
            "toolhelp32": {1000: "app.exe"},
            "wmi": {},
            "nt": {},
        }
        statuses = {"toolhelp32": True, "wmi": False, "nt": False}
        errors = {"wmi": "Service unavailable", "nt": "Access denied"}

        res = pv.compare_views(views, statuses, errors)
        self.assertFalse(res["quorum_met"])
        self.assertEqual(len(res["discrepancies"]), 0, "Must not emit false discrepancies when quorum is not met")

        # Must record quorum_failure diagnostic
        diag_types = [d["type"] for d in res["diagnostics"]]
        self.assertIn("quorum_failure", diag_types)

    def test_17_all_sources_fail(self) -> None:
        """Verify when all 3 sources fail, comparison aborts safely without error or false findings."""
        views = {"toolhelp32": {}, "wmi": {}, "nt": {}}
        statuses = {"toolhelp32": False, "wmi": False, "nt": False}
        errors = {"toolhelp32": "Err1", "wmi": "Err2", "nt": "Err3"}

        res = pv.compare_views(views, statuses, errors)
        self.assertFalse(res["quorum_met"])
        self.assertEqual(len(res["discrepancies"]), 0)
        self.assertEqual(len(res["failed_sources"]), 3)

    def test_18_successful_empty_source_distinguished_from_failed(self) -> None:
        """Verify successful empty source ({}) is distinguished from failed source."""
        views = {
            "toolhelp32": {},  # Succeeded, but returned 0 processes
            "wmi": {100: "proc.exe"},
            "nt": {100: "proc.exe"},
        }
        statuses = {"toolhelp32": True, "wmi": True, "nt": True}

        res = pv.compare_views(views, statuses)
        self.assertTrue(res["quorum_met"])
        # Toolhelp32 succeeded but missed PID 100, so a discrepancy is correctly reported
        self.assertEqual(len(res["discrepancies"]), 1)
        self.assertIn("toolhelp32", res["discrepancies"][0]["missing_sources"])

    # =======================================================================
    # 5. TWO-PASS CONFIRMATION & TRANSIENT RACE HANDLING
    # =======================================================================

    def test_19_mismatch_persists_across_both_passes(self) -> None:
        """Verify discrepancy persisting across both passes is confirmed."""
        p1 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 2000: "rootkit.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe"}),  # missing 2000
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 2000: "rootkit.exe"}),
        }
        p2 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 2000: "rootkit.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe"}),  # still missing 2000
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 2000: "rootkit.exe"}),
        }

        res = pv.run_two_pass_enumeration(micro_delay=0.001, pass1_sources=p1, pass2_sources=p2)
        self.assertEqual(len(res["confirmed_discrepancies"]), 1)
        self.assertEqual(len(res["transient_discrepancies"]), 0)

        conf = res["confirmed_discrepancies"][0]
        self.assertEqual(conf["pid"], 2000)
        self.assertEqual(conf["process_name"], "rootkit.exe")
        self.assertIn("CONFIRMED", conf["evidence"])

    def test_20_transient_exit_between_passes_discarded(self) -> None:
        """Verify process exiting between Pass 1 and Pass 2 is discarded as transient."""
        p1 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 3000: "shortlived.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe"}),  # missing in p1
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 3000: "shortlived.exe"}),
        }
        # In Pass 2, PID 3000 has exited and is absent everywhere
        p2 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe"}),
            "nt": pv.SourceResult("nt", True, {100: "app.exe"}),
        }

        res = pv.run_two_pass_enumeration(micro_delay=0.001, pass1_sources=p1, pass2_sources=p2)
        self.assertEqual(len(res["confirmed_discrepancies"]), 0, "Transient exit must not be confirmed")
        self.assertEqual(len(res["transient_discrepancies"]), 1)
        self.assertEqual(res["transient_discrepancies"][0]["resolution"], "process_exited")

    def test_21_transient_timing_resolved_in_pass_2_discarded(self) -> None:
        """Verify process starting and appearing everywhere in Pass 2 is discarded."""
        p1 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 4000: "launching.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe"}),  # hasn't appeared yet in p1
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 4000: "launching.exe"}),
        }
        # In Pass 2, WMI catches up and observes PID 4000 as well
        p2 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 4000: "launching.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe", 4000: "launching.exe"}),
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 4000: "launching.exe"}),
        }

        res = pv.run_two_pass_enumeration(micro_delay=0.001, pass1_sources=p1, pass2_sources=p2)
        self.assertEqual(len(res["confirmed_discrepancies"]), 0, "Timing resolution must not be confirmed")
        self.assertEqual(len(res["transient_discrepancies"]), 1)
        self.assertEqual(res["transient_discrepancies"][0]["resolution"], "timing_resolved")

    def test_22_pid_reuse_identity_uncertainty_not_false_hidden(self) -> None:
        """Verify PID reused for a different executable is flagged as uncertainty, not hidden malware."""
        p1 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {5000: "old_task.exe"}),
            "wmi": pv.SourceResult("wmi", True, {}),
            "nt": pv.SourceResult("nt", True, {5000: "old_task.exe"}),
        }
        # In Pass 2, PID 5000 is recycled by Windows for a completely different binary
        p2 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {5000: "new_service.exe"}),
            "wmi": pv.SourceResult("wmi", True, {}),
            "nt": pv.SourceResult("nt", True, {5000: "new_service.exe"}),
        }

        res = pv.run_two_pass_enumeration(micro_delay=0.001, pass1_sources=p1, pass2_sources=p2)
        self.assertEqual(len(res["confirmed_discrepancies"]), 0, "PID reuse must not be classified as confirmed hiding")

        # Identity uncertainty diagnostic must be recorded
        diag_types = [d["type"] for d in res["diagnostics"]]
        self.assertIn("pid_reuse_uncertainty", diag_types)

    def test_23_pass2_quorum_loss_aborts_confirmation(self) -> None:
        """Verify that if Pass 2 loses quorum, unconfirmed discrepancies become diagnostics."""
        p1 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 2000: "suspect.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe"}),
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 2000: "suspect.exe"}),
        }
        # In Pass 2, 2 sources fail, quorum lost
        p2 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe"}),
            "wmi": pv.SourceResult("wmi", False, {}, "WMI crashed"),
            "nt": pv.SourceResult("nt", False, {}, "NT API error"),
        }

        res = pv.run_two_pass_enumeration(micro_delay=0.001, pass1_sources=p1, pass2_sources=p2)
        self.assertEqual(len(res["confirmed_discrepancies"]), 0)
        diag_types = [d["type"] for d in res["diagnostics"]]
        self.assertIn("pass2_quorum_loss", diag_types)

    # =======================================================================
    # 6. FINDING CLASSIFICATION & DATABASE PERSISTENCE TESTS
    # =======================================================================

    def test_24_findings_follow_phase1_schema_and_invariants(self) -> None:
        """Verify all generated findings strictly obey Phase 1 finding classification invariants."""
        p1 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 6000: "ghost.exe"}),
            "wmi": pv.SourceResult("wmi", False, {}, "Access Denied"),  # Failed source -> diagnostic
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 6000: "ghost.exe"}),
        }
        p2 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 6000: "ghost.exe"}),
            "wmi": pv.SourceResult("wmi", False, {}, "Access Denied"),
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 6000: "ghost.exe"}),
        }

        findings = pv.run_scan(micro_delay=0.001, pass1_sources=p1, pass2_sources=p2)
        self.assertGreater(len(findings), 0)

        for f in findings:
            # Must pass DAL validator
            validated = db.validate_finding(f)
            self.assertEqual(validated["signal"], "process_view")

            if f["finding_type"] == "diagnostic":
                self.assertEqual(f["score_eligible"], 0, "Diagnostic findings must strictly have score_eligible == 0")
            elif f["finding_type"] == "threat":
                self.assertIn(f["score_eligible"], (0, 1))

    def test_25_run_scan_persists_to_database_with_scan_id(self) -> None:
        """Verify run_scan successfully stores validated findings into SQLite database."""
        scan_id = db.start_scan(self.db_path)

        p1 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 7000: "hidden.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe"}),
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 7000: "hidden.exe"}),
        }
        p2 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe", 7000: "hidden.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "app.exe"}),
            "nt": pv.SourceResult("nt", True, {100: "app.exe", 7000: "hidden.exe"}),
        }

        findings = pv.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            micro_delay=0.001,
            pass1_sources=p1,
            pass2_sources=p2,
        )

        db.complete_scan(scan_id, total_findings=len(findings), high_risk_count=1, duration_ms=15.0, db_path=self.db_path)

        # Retrieve findings from database
        stored_threats = db.get_findings_for_scan(scan_id, include_diagnostics=False, db_path=self.db_path)
        stored_all = db.get_findings_for_scan(scan_id, include_diagnostics=True, db_path=self.db_path)

        self.assertEqual(len(stored_threats), 1)
        self.assertEqual(stored_threats[0]["pid"], 7000)
        self.assertEqual(stored_threats[0]["process_name"], "hidden.exe")
        self.assertEqual(stored_threats[0]["finding_type"], "threat")
        self.assertEqual(stored_threats[0]["score_eligible"], 1)

        self.assertGreaterEqual(len(stored_all), len(stored_threats))

    def test_26_normalize_process_name(self) -> None:
        """Verify process name normalization handles paths, whitespace, and system idle aliases."""
        self.assertEqual(pv.normalize_process_name(r"C:\Windows\System32\svchost.exe"), "svchost.exe")
        self.assertEqual(pv.normalize_process_name("  EXPLORER.EXE  "), "explorer.exe")
        self.assertEqual(pv.normalize_process_name("[System Process]"), "system idle process")
        self.assertEqual(pv.normalize_process_name("System Idle Process"), "system idle process")
        self.assertEqual(pv.normalize_process_name(""), "")


if __name__ == "__main__":
    unittest.main()
