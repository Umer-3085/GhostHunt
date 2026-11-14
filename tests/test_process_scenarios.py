"""
GhostHunt — Phase 7 Tests: Process-View Simulation Scenarios
Validates PV-1 through PV-5 using the standard scenario framework.
"""

import unittest

from simulators.process_scenarios import (
    ConsistentProcessScenario,
    InsufficientQuorumScenario,
    ProcessDiscrepancyScenario,
    SourceFailureQuorumScenario,
    TransientTerminationScenario,
)


class TestProcessSimulationScenarios(unittest.TestCase):
    """Verifies Signal 1 process-view scenarios produce authoritative results."""

    def test_pv1_consistent_enumeration(self):
        """PV-1: Consistent sources produce zero threats."""
        with ConsistentProcessScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PV-1 failed: {res}")
            self.assertEqual(res["threat_count"], 0)

    def test_pv2_confirmed_discrepancy(self):
        """PV-2: Toolhelp32 omission produces confirmed threat with score_eligible=1."""
        with ProcessDiscrepancyScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PV-2 failed: {res}")
            self.assertEqual(res["threat_count"], 1)

    def test_pv3_transient_termination(self):
        """PV-3: Process termination between passes is filtered as transient (0 threats)."""
        with TransientTerminationScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PV-3 failed: {res}")
            self.assertEqual(res["threat_count"], 0)

    def test_pv4_source_failure_isolation(self):
        """PV-4: Single source failure excludes failed source, emits diagnostic (0 threats)."""
        with SourceFailureQuorumScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PV-4 failed: {res}")
            self.assertEqual(res["threat_count"], 0)
            self.assertGreaterEqual(res["diagnostic_count"], 1)

    def test_pv5_insufficient_quorum(self):
        """PV-5: Insufficient quorum aborts comparison, emits diagnostic (0 threats)."""
        with InsufficientQuorumScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"PV-5 failed: {res}")
            self.assertEqual(res["threat_count"], 0)
            self.assertGreaterEqual(res["diagnostic_count"], 1)


if __name__ == "__main__":
    unittest.main()
