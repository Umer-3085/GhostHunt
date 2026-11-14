"""
GhostHunt — Phase 7 Tests: Scenario Runner & API Endpoints
Verifies scenario registry, execution APIs, and REST simulation endpoints.
"""

import unittest

from dashboard import create_app
from simulators import get_scenario, list_scenarios
from simulators.scenario_runner import run_all_scenarios, run_scenario


class TestScenarioRunnerAndApi(unittest.TestCase):
    """Verifies scenario registry, runner functions, and REST API simulation endpoints."""

    def setUp(self):
        self.app = create_app({"TESTING": True, "CSRF_ENABLED": False})
        self.client = self.app.test_client()

    def test_01_registry_contains_all_scenarios(self):
        """Registry contains all PV, PER, SIG, and Scenarios A through J."""
        scenarios = list_scenarios()
        ids = {s["scenario_id"] for s in scenarios}

        # Verify Signal 1 scenarios
        for expected in ["PV-1", "PV-2", "PV-3", "PV-4", "PV-5"]:
            self.assertIn(expected, ids)

        # Verify Signal 2 scenarios
        for expected in ["PER-1", "PER-2", "PER-3", "PER-4"]:
            self.assertIn(expected, ids)

        # Verify Signal 3 scenarios
        for expected in ["SIG-1", "SIG-2", "SIG-3", "SIG-4", "SIG-5"]:
            self.assertIn(expected, ids)

        # Verify End-to-End Scenarios A-J
        for ch in "ABCDEFGHIJ":
            self.assertIn(f"SCENARIO-{ch}", ids)

    def test_02_get_scenario_by_id(self):
        """get_scenario returns an instantiated scenario or None if missing."""
        s = get_scenario("PV-1")
        self.assertIsNotNone(s)
        self.assertEqual(s.scenario_id, "PV-1")

        missing = get_scenario("NON_EXISTENT_SCENARIO")
        self.assertIsNone(missing)

    def test_03_run_single_scenario(self):
        """run_scenario executes a single scenario safely with timing metadata."""
        res = run_scenario("PV-1")
        self.assertTrue(res.get("passed"))
        self.assertIn("duration_ms", res)
        self.assertGreater(res["duration_ms"], 0.0)

    def test_04_run_all_scenarios(self):
        """run_all_scenarios executes all scenarios and returns list of results."""
        results = run_all_scenarios()
        self.assertGreaterEqual(len(results), 24)
        for r in results:
            self.assertTrue(r.get("passed"), f"Scenario {r.get('scenario_id')} failed: {r}")

    def test_05_api_list_scenarios_endpoint(self):
        """GET /api/scenarios returns JSON list of all registered scenarios."""
        resp = self.client.get("/api/scenarios")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertGreaterEqual(data["count"], 24)
        self.assertIsInstance(data["scenarios"], list)

    def test_06_api_run_single_scenario_endpoint(self):
        """POST /api/scenarios/run with scenario_id executes single scenario."""
        resp = self.client.post("/api/scenarios/run", json={"scenario_id": "PV-1"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(len(data["results"]), 1)
        self.assertTrue(data["results"][0]["passed"])

    def test_07_api_run_all_scenarios_endpoint(self):
        """POST /api/scenarios/run with scenario_id='all' executes all scenarios."""
        resp = self.client.post("/api/scenarios/run", json={"scenario_id": "all"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["failed"], 0)
        self.assertGreaterEqual(data["total"], 24)

    def test_08_api_run_invalid_scenario_returns_404(self):
        """POST /api/scenarios/run with non-existent ID returns 404."""
        resp = self.client.post("/api/scenarios/run", json={"scenario_id": "INVALID_ID"})
        self.assertEqual(resp.status_code, 404)

    def test_09_simulations_page_renders(self):
        """GET /simulations renders HTML page with scenario catalog."""
        resp = self.client.get("/simulations")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Safe Malware-Behavior Simulations", resp.data)
        self.assertIn(b"SCENARIO-A", resp.data)
        self.assertIn(b"PV-1", resp.data)


if __name__ == "__main__":
    unittest.main()
