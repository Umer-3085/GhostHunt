"""
GhostHunt — Phase 7 Tests: Persistence Simulation Scenarios
Validates PER-1 through PER-4 using the standard scenario framework.
"""

import unittest

from simulators.persistence_scenarios import (
    AddedPersistenceThreatScenario,
    CandidateBaselineCaptureScenario,
    CategoryFailureIsolationScenario,
    ModifiedPersistenceScenario,
)


class TestPersistenceSimulationScenarios(unittest.TestCase):
    """Verifies Signal 2 persistence scenarios produce authoritative results."""

    def test_per1_candidate_capture(self):
        """PER-1: Candidate baseline capture enters CANDIDATE_REVIEW with 0 threats."""
        with CandidateBaselineCaptureScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PER-1 failed: {res}")
            self.assertEqual(res["threat_count"], 0)
            self.assertEqual(res["state"], "CANDIDATE_REVIEW")

    def test_per2_added_autorun_threat(self):
        """PER-2: Added persistence entry relative to accepted baseline emits threat."""
        with AddedPersistenceThreatScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PER-2 failed: {res}")
            self.assertEqual(res["threat_count"], 1)

    def test_per3_modified_autorun_threat(self):
        """PER-3: Modified persistence entry fingerprint emits threat."""
        with ModifiedPersistenceScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PER-3 failed: {res}")
            self.assertEqual(res["threat_count"], 1)

    def test_per4_failure_isolation(self):
        """PER-4: Query failure in accepted category skips diffing without false removals."""
        with CategoryFailureIsolationScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PER-4 failed: {res}")
            self.assertEqual(res["threat_count"], 0)
            self.assertGreaterEqual(res["diagnostic_count"], 1)


if __name__ == "__main__":
    unittest.main()
