"""
GhostHunt — Phase 5 Test Suite: Multi-Signal Risk Correlation Engine
Comprehensive unit and integration tests for Signal 1, 2, and 3 correlation.

Covers:
1. Signal weights validation (process_view: 0.40, persistence: 0.30, signature: 0.30).
2. All three signals combined produce exactly 1.00.
3. Strict signal deduplication: multiple findings for a single signal contribute weight only once.
4. Threat finding eligibility: only finding_type == 'threat' AND score_eligible in (1, True) contribute.
5. Operational diagnostic isolation: finding_type == 'diagnostic' contributes 0.0 to risk score.
6. score_eligible == 0 findings contribute 0.0 even if finding_type == 'threat'.
7. Quarantining/rejection of malformed findings and schema violations.
8. System-level persistence findings with PID=None are preserved and scored.
9. Entity grouping separation: distinct processes or persistence items are not merged.
10. PID reuse protection: distinct process creation times or exe paths yield separate entities.
11. Categorical severity threshold boundaries (0.3999, 0.40, 0.5999, 0.60, 1.00).
12. Empty finding input produces empty output.
13. Forensic evidence and metadata preservation.
14. Public re-export module verification (detectors.correlator).
"""

import json
import unittest

import config
import core.correlator as cc
import detectors.correlator as dc


class TestRiskCorrelationEngine(unittest.TestCase):
    """Unit tests for core/correlator.py and detectors/correlator.py."""

    def test_re_exports_in_detector_module(self):
        """Verifies detectors.correlator re-exports all required symbols."""
        required = [
            "SIGNAL_WEIGHTS",
            "VALID_SIGNALS",
            "classify_severity",
            "correlate_all",
            "get_entity_identity",
            "validate_finding_for_scoring",
            "validate_weights",
        ]
        for sym in required:
            self.assertTrue(hasattr(dc, sym), f"Missing re-export: {sym}")
            self.assertIs(getattr(dc, sym), getattr(cc, sym))

    def test_01_individual_signal_weights(self):
        """Each signal independently receives its exact configured weight."""
        # Test process_view alone: 0.40
        f_pv = [{"finding_type": "threat", "score_eligible": 1, "signal": "process_view", "pid": 100, "process_name": "proc_pv.exe"}]
        scores_pv, _ = cc.correlate_all(1, f_pv)
        self.assertEqual(len(scores_pv), 1)
        self.assertAlmostEqual(scores_pv[0]["score"], 0.40, places=4)
        self.assertEqual(scores_pv[0]["risk_level"], "MEDIUM")
        self.assertEqual(scores_pv[0]["signals_triggered"], "process_view")

        # Test persistence alone: 0.30
        f_per = [{"finding_type": "threat", "score_eligible": 1, "signal": "persistence", "pid": None, "process_name": "system:service:EvilSvc"}]
        scores_per, _ = cc.correlate_all(1, f_per)
        self.assertEqual(len(scores_per), 1)
        self.assertAlmostEqual(scores_per[0]["score"], 0.30, places=4)
        self.assertEqual(scores_per[0]["risk_level"], "LOW")
        self.assertEqual(scores_per[0]["signals_triggered"], "persistence")

        # Test signature alone: 0.30
        f_sig = [{"finding_type": "threat", "score_eligible": 1, "signal": "signature", "pid": 200, "process_name": "proc_sig.exe"}]
        scores_sig, _ = cc.correlate_all(1, f_sig)
        self.assertEqual(len(scores_sig), 1)
        self.assertAlmostEqual(scores_sig[0]["score"], 0.30, places=4)
        self.assertEqual(scores_sig[0]["risk_level"], "LOW")
        self.assertEqual(scores_sig[0]["signals_triggered"], "signature")

    def test_02_all_three_signals_produce_one_point_zero(self):
        """When all three signals are triggered on an entity, the score is exactly 1.00 (HIGH)."""
        findings = [
            {"finding_type": "threat", "score_eligible": 1, "signal": "process_view", "pid": 500, "process_name": "malware.exe"},
            {"finding_type": "threat", "score_eligible": 1, "signal": "persistence", "pid": 500, "process_name": "malware.exe"},
            {"finding_type": "threat", "score_eligible": 1, "signal": "signature", "pid": 500, "process_name": "malware.exe"},
        ]
        scores, quarantined = cc.correlate_all(1, findings)
        self.assertEqual(len(quarantined), 0)
        self.assertEqual(len(scores), 1)
        ent = scores[0]
        self.assertAlmostEqual(ent["score"], 1.00, places=4)
        self.assertEqual(ent["risk_level"], "HIGH")
        self.assertEqual(set(ent["contributing_signals"]), {"process_view", "persistence", "signature"})

    def test_03_duplicate_findings_from_one_signal_deduplicated(self):
        """Five eligible signature findings on a single entity result in 0.30, not 1.50."""
        findings = [
            {"finding_type": "threat", "score_eligible": 1, "signal": "signature", "pid": 600, "process_name": "host.exe", "metadata": json.dumps({"module": f"mod_{i}.dll"})}
            for i in range(5)
        ]
        scores, _ = cc.correlate_all(1, findings)
        self.assertEqual(len(scores), 1)
        self.assertAlmostEqual(scores[0]["score"], 0.30, places=4)
        self.assertEqual(scores[0]["risk_level"], "LOW")
        self.assertEqual(len(scores[0]["supporting_findings"]), 5)
        self.assertEqual(scores[0]["signals_triggered"], "signature")

    def test_04_multiple_signals_additive_without_score_inflation(self):
        """One process_view finding (0.40) + three persistence findings (0.30) produces 0.70."""
        findings = [
            {"finding_type": "threat", "score_eligible": 1, "signal": "process_view", "pid": 700, "process_name": "rootkit.exe"},
            {"finding_type": "threat", "score_eligible": 1, "signal": "persistence", "pid": 700, "process_name": "rootkit.exe", "metadata": '{"item": 1}'},
            {"finding_type": "threat", "score_eligible": 1, "signal": "persistence", "pid": 700, "process_name": "rootkit.exe", "metadata": '{"item": 2}'},
            {"finding_type": "threat", "score_eligible": 1, "signal": "persistence", "pid": 700, "process_name": "rootkit.exe", "metadata": '{"item": 3}'},
        ]
        scores, _ = cc.correlate_all(1, findings)
        self.assertEqual(len(scores), 1)
        self.assertAlmostEqual(scores[0]["score"], 0.70, places=4)
        self.assertEqual(scores[0]["risk_level"], "HIGH")
        self.assertEqual(set(scores[0]["contributing_signals"]), {"process_view", "persistence"})

    def test_05_diagnostic_findings_never_contribute_to_risk(self):
        """Operational diagnostic findings alone contribute 0.0 to risk score."""
        findings = [
            {"finding_type": "diagnostic", "score_eligible": 0, "signal": "process_view", "pid": 4, "process_name": "csrss.exe", "evidence": "Access denied"},
            {"finding_type": "diagnostic", "score_eligible": 0, "signal": "signature", "pid": 4, "process_name": "csrss.exe", "evidence": "File locked"},
        ]
        scores, _ = cc.correlate_all(1, findings)
        self.assertEqual(len(scores), 1)
        ent = scores[0]
        self.assertEqual(ent["score"], 0.0)
        self.assertEqual(ent["risk_level"], "LOW")
        self.assertEqual(ent["signals_triggered"], "")
        self.assertEqual(len(ent["contributing_signals"]), 0)
        self.assertEqual(len(ent["excluded_diagnostics"]), 2)
        self.assertEqual(len(ent["supporting_findings"]), 0)

    def test_06_deactivated_threat_finding_contributes_zero(self):
        """Threat findings with score_eligible == 0 do not increment the score."""
        findings = [
            {"finding_type": "threat", "score_eligible": 0, "signal": "process_view", "pid": 800, "process_name": "test.exe"},
            {"finding_type": "threat", "score_eligible": 1, "signal": "signature", "pid": 800, "process_name": "test.exe"},
        ]
        scores, _ = cc.correlate_all(1, findings)
        self.assertEqual(len(scores), 1)
        # Only signature (0.30) should be counted
        self.assertAlmostEqual(scores[0]["score"], 0.30, places=4)
        self.assertEqual(scores[0]["signals_triggered"], "signature")

    def test_07_invalid_or_malformed_findings_quarantined(self):
        """Malformed findings (e.g. diagnostic with score_eligible=1) are quarantined and excluded."""
        findings = [
            # Invariant violation: diagnostic cannot have score_eligible == 1
            {"finding_type": "diagnostic", "score_eligible": 1, "signal": "process_view", "pid": 900, "process_name": "bad.exe"},
            # Invalid finding_type
            {"finding_type": "unknown_type", "score_eligible": 1, "signal": "signature", "pid": 900, "process_name": "bad.exe"},
            # Non-dict finding
            "invalid_string_finding",
            # Legitimate finding
            {"finding_type": "threat", "score_eligible": 1, "signal": "persistence", "pid": 900, "process_name": "bad.exe"},
        ]
        scores, quarantined = cc.correlate_all(1, findings)
        self.assertEqual(len(quarantined), 3)
        self.assertEqual(len(scores), 1)
        self.assertAlmostEqual(scores[0]["score"], 0.30, places=4)
        self.assertEqual(scores[0]["signals_triggered"], "persistence")

    def test_08_system_level_persistence_with_pid_none_preserved(self):
        """System-level persistence findings with pid=None are preserved and properly scored."""
        findings = [
            {
                "finding_type": "threat",
                "score_eligible": 1,
                "signal": "persistence",
                "pid": None,
                "process_name": "system:service:EvilDriver",
                "evidence": "Unauthorized driver service installed",
                "metadata": json.dumps({"category": "service", "entry_key": "EvilDriver"}),
            }
        ]
        scores, _ = cc.correlate_all(1, findings)
        self.assertEqual(len(scores), 1)
        ent = scores[0]
        self.assertIsNone(ent["pid"])
        self.assertEqual(ent["entity_type"], "persistence")
        self.assertEqual(ent["process_name"], "system:service:EvilDriver")
        self.assertAlmostEqual(ent["score"], 0.30, places=4)
        self.assertEqual(ent["risk_level"], "LOW")

    def test_09_unrelated_entities_not_merged(self):
        """Different processes or entities are maintained in distinct risk score records."""
        findings = [
            {"finding_type": "threat", "score_eligible": 1, "signal": "process_view", "pid": 101, "process_name": "proc_a.exe"},
            {"finding_type": "threat", "score_eligible": 1, "signal": "process_view", "pid": 102, "process_name": "proc_b.exe"},
            {"finding_type": "threat", "score_eligible": 1, "signal": "persistence", "pid": None, "process_name": "system:task:TaskA"},
        ]
        scores, _ = cc.correlate_all(1, findings)
        self.assertEqual(len(scores), 3)
        keys = {s["item_key"] for s in scores}
        self.assertEqual(len(keys), 3)

    def test_10_pid_reuse_protection(self):
        """
        Two process instances sharing the same PID but having distinct creation times
        or executable paths are not merged into the same entity.
        """
        findings = [
            {
                "finding_type": "threat",
                "score_eligible": 1,
                "signal": "process_view",
                "pid": 2000,
                "process_name": "worker.exe",
                "metadata": json.dumps({"create_time": 1700000000.0, "exe_path": "C:\\app\\worker.exe"}),
            },
            {
                "finding_type": "threat",
                "score_eligible": 1,
                "signal": "signature",
                "pid": 2000,
                "process_name": "worker.exe",
                "metadata": json.dumps({"create_time": 1700009999.0, "exe_path": "C:\\temp\\worker.exe"}),
            },
        ]
        scores, _ = cc.correlate_all(1, findings)
        self.assertEqual(len(scores), 2)
        # Verify that because creation times differ, they have distinct item_keys
        self.assertNotEqual(scores[0]["item_key"], scores[1]["item_key"])

    def test_11_severity_boundary_thresholds(self):
        """
        Validates exact categorical severity boundaries without rounding:
        - 0.3999 -> LOW
        - 0.40   -> MEDIUM
        - 0.5999 -> MEDIUM
        - 0.60   -> HIGH
        - 1.00   -> HIGH
        """
        self.assertEqual(cc.classify_severity(0.0), "LOW")
        self.assertEqual(cc.classify_severity(0.3999), "LOW")
        self.assertEqual(cc.classify_severity(0.40), "MEDIUM")
        self.assertEqual(cc.classify_severity(0.50), "MEDIUM")
        self.assertEqual(cc.classify_severity(0.5999), "MEDIUM")
        self.assertEqual(cc.classify_severity(0.60), "HIGH")
        self.assertEqual(cc.classify_severity(0.70), "HIGH")
        self.assertEqual(cc.classify_severity(1.00), "HIGH")

    def test_12_empty_findings_produces_empty_output(self):
        """Empty input findings list produces empty output lists."""
        scores, quarantined = cc.correlate_all(1, [])
        self.assertEqual(scores, [])
        self.assertEqual(quarantined, [])

    def test_13_scan_id_validation(self):
        """Invalid scan_id raises ValueError."""
        with self.assertRaises(ValueError):
            cc.correlate_all(-1, [])
        with self.assertRaises(ValueError):
            cc.correlate_all(0, [])
        with self.assertRaises(ValueError):
            cc.correlate_all(True, [])  # Boolean must be rejected

    def test_14_preserves_forensic_evidence(self):
        """Entity risk score output preserves original findings and evidence strings."""
        findings = [
            {
                "finding_type": "threat",
                "score_eligible": 1,
                "signal": "process_view",
                "pid": 333,
                "process_name": "stealth.exe",
                "evidence": "Process hidden from Toolhelp32 view",
            },
            {
                "finding_type": "diagnostic",
                "score_eligible": 0,
                "signal": "signature",
                "pid": 333,
                "process_name": "stealth.exe",
                "evidence": "Verification error: file locked",
            },
        ]
        scores, _ = cc.correlate_all(42, findings)
        self.assertEqual(len(scores), 1)
        ent = scores[0]
        self.assertEqual(ent["scan_id"], 42)
        self.assertEqual(len(ent["supporting_findings"]), 1)
        self.assertEqual(ent["supporting_findings"][0]["evidence"], "Process hidden from Toolhelp32 view")
        self.assertEqual(len(ent["excluded_diagnostics"]), 1)
        self.assertEqual(ent["excluded_diagnostics"][0]["evidence"], "Verification error: file locked")


if __name__ == "__main__":
    unittest.main()
