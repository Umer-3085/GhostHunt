"""
GhostHunt — Phase 1 Test Suite: Configuration Validation
Tests for centralized application configuration, startup validation,
risk weight validation, and project-relative database paths.
"""

import os
import unittest
from pathlib import Path
from unittest.mock import patch

import config


class TestGhostHuntConfiguration(unittest.TestCase):
    """
    Tests for GhostHunt centralized configuration and startup checks.
    """

    def test_01_config_loads_and_validates(self) -> None:
        """Verify the configuration validates successfully on standard settings."""
        self.assertTrue(config.validate_config())

    def test_02_database_path_is_relative_to_project_root(self) -> None:
        """Verify DB_PATH resolves relative to BASE_DIR without machine-specific hardcoding."""
        db_path = Path(config.DB_PATH)
        self.assertTrue(db_path.is_absolute())
        self.assertEqual(db_path.parent, config.BASE_DIR)
        self.assertEqual(db_path.name, "ghosthunt.db")

    def test_03_risk_weights_sum_to_one(self) -> None:
        """Verify the 3 documented risk weights sum to exactly 1.0."""
        expected_signals = {"process_view", "persistence", "signature"}
        self.assertEqual(set(config.RISK_WEIGHTS.keys()), expected_signals)
        self.assertAlmostEqual(sum(config.RISK_WEIGHTS.values()), 1.0, places=4)
        self.assertEqual(config.RISK_WEIGHTS["process_view"], 0.40)
        self.assertEqual(config.RISK_WEIGHTS["persistence"], 0.30)
        self.assertEqual(config.RISK_WEIGHTS["signature"], 0.30)

    def test_04_risk_thresholds_are_properly_ordered(self) -> None:
        """Verify categorical risk thresholds: 0.0 < LOW (< 0.40) < MEDIUM (< 0.60) <= HIGH."""
        self.assertGreater(config.RISK_THRESHOLD_MEDIUM, 0.0)
        self.assertLess(config.RISK_THRESHOLD_MEDIUM, config.RISK_THRESHOLD_HIGH)
        self.assertLessEqual(config.RISK_THRESHOLD_HIGH, 1.0)
        self.assertEqual(config.RISK_THRESHOLD_MEDIUM, 0.40)
        self.assertEqual(config.RISK_THRESHOLD_HIGH, 0.60)

    def test_05_single_process_flask_settings(self) -> None:
        """Verify single-process deployment guards: debug=False and use_reloader=False."""
        self.assertFalse(config.FLASK_DEBUG)
        self.assertFalse(config.FLASK_USE_RELOADER)
        self.assertEqual(config.FLASK_HOST, "127.0.0.1")

    def test_06_timing_and_concurrency_constants(self) -> None:
        """Verify scan interval, micro delay, and busy timeout values."""
        self.assertIn(config.SCAN_INTERVAL_SECONDS, (10, 300))
        self.assertEqual(config.MICRO_DELAY_SECONDS, 0.05)
        self.assertGreaterEqual(config.DB_BUSY_TIMEOUT_MS, 1000)

    def test_07_production_mode_rejects_fallback_secret(self) -> None:
        """Verify production mode strictly rejects the development fallback secret."""
        env = {
            "GHOSTHUNT_ENV": "production",
            "GHOSTHUNT_SECRET_KEY": "",
            "SECRET_KEY": "",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(ValueError) as ctx:
                config.validate_config()
            self.assertIn("development fallback secret key is strictly prohibited", str(ctx.exception))

    def test_08_production_mode_rejects_short_secret(self) -> None:
        """Verify production mode rejects secrets shorter than 32 characters."""
        env = {
            "GHOSTHUNT_ENV": "production",
            "GHOSTHUNT_SECRET_KEY": "short-secret-key-123",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(ValueError) as ctx:
                config.validate_config()
            self.assertIn("must be at least 32 characters", str(ctx.exception))

    def test_09_production_mode_accepts_valid_secret(self) -> None:
        """Verify production mode accepts an environment-provided secret of at least 32 characters."""
        env = {
            "GHOSTHUNT_ENV": "production",
            "GHOSTHUNT_SECRET_KEY": "super-secure-production-secret-key-32-chars!!",
        }
        with patch.dict(os.environ, env, clear=False):
            self.assertTrue(config.validate_config())


if __name__ == "__main__":
    unittest.main()
