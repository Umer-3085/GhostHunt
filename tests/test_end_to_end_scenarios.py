"""
GhostHunt — Phase 7 Tests: End-to-End Multi-Signal Correlation Scenarios
Validates authoritative Scenarios A through J verifying risk scores, risk levels,
and diagnostic invariants.
"""

import unittest

from simulators.scenario_runner import (
    AllThreeSignalsScenario,
    CleanSystemScenario,
    EnumerationQuorumFailureScenario,
    OperationalDiagnosticsOnlyScenario,
    PersistenceAndSignatureScenario,
    PersistenceOnlyScenario,
    ProcessViewAndPersistenceScenario,
    ProcessViewOnlyScenario,
    SignalDeduplicationScenario,
    SignatureOnlyScenario,
)


class TestEndToEndScenarios(unittest.TestCase):
    """Verifies Scenarios A through J produce exact authoritative scores and severities."""

    def test_scenario_a_clean_system(self):
        """Scenario A: Clean system baseline -> Score 0.00, LOW risk, 0 threats."""
        with CleanSystemScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario A failed: {res}")
            self.assertEqual(res["threat_count"], 0)

    def test_scenario_b_process_view_only(self):
        """Scenario B: Process-view discrepancy only -> Score 0.40, MEDIUM risk."""
        with ProcessViewOnlyScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario B failed: {res}")
            self.assertEqual(res["threat_count"], 1)

    def test_scenario_c_persistence_only(self):
        """Scenario C: Persistence deviation only -> Score 0.30, LOW risk."""
        with PersistenceOnlyScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario C failed: {res}")
            self.assertEqual(res["threat_count"], 1)

    def test_scenario_d_signature_only(self):
        """Scenario D: Signature anomaly only -> Score 0.30, LOW risk."""
        with SignatureOnlyScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario D failed: {res}")
            self.assertEqual(res["threat_count"], 1)

    def test_scenario_e_process_view_and_persistence(self):
        """Scenario E: Process-view (0.40) + persistence (0.30) -> Score 0.70, HIGH risk."""
        with ProcessViewAndPersistenceScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario E failed: {res}")

    def test_scenario_f_persistence_and_signature(self):
        """Scenario F: Persistence (0.30) + signature (0.30) -> Score 0.60, HIGH risk."""
        with PersistenceAndSignatureScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario F failed: {res}")

    def test_scenario_g_all_three_signals(self):
        """Scenario G: All 3 signals (0.40 + 0.30 + 0.30) -> Score 1.00, HIGH risk."""
        with AllThreeSignalsScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario G failed: {res}")

    def test_scenario_h_operational_diagnostics_only(self):
        """Scenario H: Diagnostics only -> Score 0.00, LOW risk, diagnostic invariant satisfied."""
        with OperationalDiagnosticsOnlyScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario H failed: {res}")
            self.assertEqual(res["threat_count"], 0)
            self.assertTrue(res["invariant_satisfied"])

    def test_scenario_i_quorum_failure(self):
        """Scenario I: Insufficient process quorum -> Score 0.00, LOW risk, diagnostic emitted."""
        with EnumerationQuorumFailureScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario I failed: {res}")
            self.assertEqual(res["threat_count"], 0)

    def test_scenario_j_signal_deduplication(self):
        """Scenario J: 2 threat findings under signature signal deduplicate to 0.30 (not 0.60)."""
        with SignalDeduplicationScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"Scenario J failed: {res}")
            self.assertEqual(res["threat_count"], 2)


if __name__ == "__main__":
    unittest.main()
