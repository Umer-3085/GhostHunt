"""
GhostHunt — Phase 5 Test Suite: Background Scan Scheduler & Concurrency Guard
Comprehensive unit tests for ScanScheduler, GLOBAL_OPERATION_LOCK, and in-process concurrency.

Covers:
1. Scheduler starts successfully (is_running == True).
2. Scheduler stops cleanly (is_running == False, thread terminated).
3. Repeated start does not create duplicate worker threads.
4. Scheduled scans execute periodically at configured interval.
5. Scheduled scan cannot overlap another scan (non-blocking lock acquisition skips if busy).
6. Manual scan cannot overlap an active operation (returns status 'busy').
7. Busy lock produces documented busy result dictionary.
8. Baseline reset and scan operations share the same lock (execute_with_lock).
9. Scheduler worker loop recovers gracefully from coordinator exceptions.
10. Graceful shutdown leaves zero active scheduler background threads.
"""

import threading
import time
import unittest
from unittest.mock import MagicMock

import config
import core.scheduler as scheduler


class TestBackgroundScheduler(unittest.TestCase):
    """Unit tests for ScanScheduler and in-process synchronization."""

    def setUp(self):
        self.lock = threading.RLock()
        self.coordinator_calls = 0
        self.coordinator_event = threading.Event()

    def mock_coordinator(self, **kwargs):
        self.coordinator_calls += 1
        self.coordinator_event.set()
        return {"success": True, "scan_id": self.coordinator_calls}

    def test_01_scheduler_starts_successfully(self):
        """Scheduler starts daemon thread and reports is_running=True."""
        sched = scheduler.ScanScheduler(
            interval_seconds=1.0,
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )
        try:
            started = sched.start()
            self.assertTrue(started)
            self.assertTrue(sched.is_running)
        finally:
            sched.stop(timeout=2.0)

    def test_02_scheduler_stops_cleanly(self):
        """Scheduler stop terminates thread cleanly within timeout."""
        sched = scheduler.ScanScheduler(
            interval_seconds=1.0,
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )
        sched.start()
        self.assertTrue(sched.is_running)

        stopped = sched.stop(timeout=2.0)
        self.assertTrue(stopped)
        self.assertFalse(sched.is_running)

    def test_03_repeated_start_does_not_create_duplicate_workers(self):
        """Calling start() on already-running scheduler returns False and creates no extra threads."""
        sched = scheduler.ScanScheduler(
            interval_seconds=1.0,
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )
        try:
            self.assertTrue(sched.start())
            initial_thread = sched._thread
            # Second call must be rejected
            self.assertFalse(sched.start())
            self.assertIs(sched._thread, initial_thread)
        finally:
            sched.stop(timeout=2.0)

    def test_04_scheduled_scans_execute_at_interval(self):
        """Scheduler executes coordinator periodically at the configured interval."""
        sched = scheduler.ScanScheduler(
            interval_seconds=0.05,  # 50 ms fast interval for deterministic test
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )
        try:
            sched.start()
            # Wait for at least 2 scan cycles
            time.sleep(0.18)
            self.assertGreaterEqual(sched.scan_count, 2)
            self.assertIsNotNone(sched.last_scan_time)
        finally:
            sched.stop(timeout=2.0)

    def test_05_scheduled_scan_skips_when_lock_is_busy(self):
        """When operation lock is held, scheduled scan skips non-blockingly without hanging."""
        sched = scheduler.ScanScheduler(
            interval_seconds=0.05,
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )
        # Acquire lock externally
        self.lock.acquire()
        try:
            sched.start()
            # Sleep longer than interval; scheduled scan cannot acquire lock
            time.sleep(0.12)
            # Scan count must be 0 because lock was busy
            self.assertEqual(sched.scan_count, 0)
        finally:
            self.lock.release()
            sched.stop(timeout=2.0)

    def test_06_manual_scan_cannot_overlap_active_operation(self):
        """When lock is held by another thread, manual scan reports status 'busy'."""
        sched = scheduler.ScanScheduler(
            interval_seconds=1.0,
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )
        lock_held = threading.Event()
        release_lock = threading.Event()

        def hold_lock_worker():
            with self.lock:
                lock_held.set()
                release_lock.wait(timeout=2.0)

        t = threading.Thread(target=hold_lock_worker)
        t.start()
        lock_held.wait(timeout=1.0)

        try:
            res = sched.trigger_manual_scan(timeout=0.0)
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "busy")
            self.assertIn("in progress", res["message"])
        finally:
            release_lock.set()
            t.join(timeout=2.0)

    def test_07_manual_scan_succeeds_when_lock_is_free(self):
        """When lock is free, manual scan executes and returns completed status."""
        sched = scheduler.ScanScheduler(
            interval_seconds=1.0,
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )
        res = sched.trigger_manual_scan(timeout=0.0)
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["scan_id"], 1)

    def test_08_reset_and_scan_share_same_lock(self):
        """execute_with_lock shares the same lock, blocking if another thread holds the lock."""
        sched = scheduler.ScanScheduler(
            interval_seconds=1.0,
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )

        dummy_action_called = False

        def dummy_reset():
            nonlocal dummy_action_called
            dummy_action_called = True
            return "reset_ok"

        lock_held = threading.Event()
        release_lock = threading.Event()

        def hold_lock_worker():
            with self.lock:
                lock_held.set()
                release_lock.wait(timeout=2.0)

        t = threading.Thread(target=hold_lock_worker)
        t.start()
        lock_held.wait(timeout=1.0)

        # When lock is held by another thread, execute_with_lock reports busy
        try:
            res = sched.execute_with_lock(dummy_reset, timeout=0.0)
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "busy")
            self.assertFalse(dummy_action_called)
        finally:
            release_lock.set()
            t.join(timeout=2.0)

        # When lock is free, execute_with_lock succeeds
        res_free = sched.execute_with_lock(dummy_reset, timeout=0.0)
        self.assertTrue(res_free["success"])
        self.assertEqual(res_free["result"], "reset_ok")
        self.assertTrue(dummy_action_called)

    def test_09_scheduler_recovers_from_exceptions(self):
        """Coordinator exceptions are caught, error_count is incremented, and scheduler continues."""
        failing_calls = 0

        def failing_coordinator(**kwargs):
            nonlocal failing_calls
            failing_calls += 1
            if failing_calls == 1:
                raise RuntimeError("Transient enumeration error")
            return {"success": True, "scan_id": 99}

        sched = scheduler.ScanScheduler(
            interval_seconds=0.05,
            operation_lock=self.lock,
            coordinator=failing_coordinator,
        )
        try:
            sched.start()
            # Wait for at least 2 cycles (first fails, second succeeds)
            time.sleep(0.18)
            self.assertGreaterEqual(sched.error_count, 1)
            self.assertGreaterEqual(sched.scan_count, 1)
            self.assertTrue(sched.is_running)
        finally:
            sched.stop(timeout=2.0)

    def test_10_shutdown_leaves_no_active_threads(self):
        """Stopping scheduler guarantees worker thread has fully exited."""
        sched = scheduler.ScanScheduler(
            interval_seconds=0.05,
            operation_lock=self.lock,
            coordinator=self.mock_coordinator,
        )
        sched.start()
        worker_thread = sched._thread
        self.assertIsNotNone(worker_thread)
        self.assertTrue(worker_thread.is_alive())

        sched.stop(timeout=2.0)
        self.assertFalse(worker_thread.is_alive())
        self.assertIsNone(sched._thread)


if __name__ == "__main__":
    unittest.main()
