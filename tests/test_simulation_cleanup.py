"""
GhostHunt — Phase 7 Tests: Simulation Cleanup & Isolation Manager
Verifies that SimulationCleanupManager safely confines test artifacts,
terminates test processes, purges temporary files, and guarantees idempotency.
"""

import os
import subprocess
import sys
import unittest

from simulators.cleanup import SimulationCleanupManager


class TestSimulationCleanupManager(unittest.TestCase):
    """Unit tests for SimulationCleanupManager safety and isolation guarantees."""

    def test_01_lazy_temp_dir_creation(self):
        """Temp directory is created only when accessed, with the given prefix."""
        mgr = SimulationCleanupManager(prefix="test_gh_clean_")
        self.assertIsNone(mgr._temp_dir)

        temp_dir = mgr.temp_dir
        self.assertTrue(os.path.isdir(temp_dir))
        self.assertTrue(os.path.basename(temp_dir).startswith("test_gh_clean_"))

        mgr.cleanup()
        self.assertFalse(os.path.exists(temp_dir))

    def test_02_tracked_file_cleanup(self):
        """Tracked files created inside temp directory are deleted on cleanup."""
        mgr = SimulationCleanupManager(prefix="test_gh_files_")
        fpath = mgr.get_temp_file_path("sample.txt")

        with open(fpath, "w") as f:
            f.write("harmless test content")

        self.assertTrue(os.path.exists(fpath))
        mgr.cleanup()
        self.assertFalse(os.path.exists(fpath))

    def test_03_tracked_process_termination(self):
        """Harmless test child processes are cleanly terminated by the manager."""
        mgr = SimulationCleanupManager(prefix="test_gh_proc_")

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        mgr.track_pid(proc.pid)

        # Process should be alive initially
        self.assertIsNone(proc.poll())

        mgr.cleanup()

        # Child process should now be terminated
        try:
            proc.wait(timeout=2.0)
        except Exception:
            pass
        self.assertIsNotNone(proc.poll())

    def test_04_idempotent_cleanup_safe_to_call_multiple_times(self):
        """Calling cleanup() repeatedly does not raise errors or alter state."""
        mgr = SimulationCleanupManager(prefix="test_gh_idempotent_")
        fpath = mgr.get_temp_file_path("temp.bin")
        with open(fpath, "wb") as f:
            f.write(b"12345")

        mgr.cleanup()
        self.assertTrue(mgr._is_cleaned)

        # Second and third calls must be completely safe
        mgr.cleanup()
        mgr.cleanup()
        self.assertTrue(mgr._is_cleaned)

    def test_05_context_manager_support(self):
        """Manager acts as a context manager and auto-cleans on exit."""
        temp_path = None
        with SimulationCleanupManager(prefix="test_gh_ctx_") as mgr:
            temp_path = mgr.get_temp_file_path("ctx_test.txt")
            with open(temp_path, "w") as f:
                f.write("auto-cleanup test")
            self.assertTrue(os.path.exists(temp_path))

        self.assertFalse(os.path.exists(temp_path))


if __name__ == "__main__":
    unittest.main()
