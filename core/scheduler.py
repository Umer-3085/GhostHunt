"""
GhostHunt — Phase 5: Scan Orchestration & Background Scheduler
Authoritative implementation of the scan coordinator, in-process concurrency guard,
and background scheduler daemon specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Single-Process Concurrency Guarantee:
GhostHunt's initial deployment architecture is explicitly single-process.
The threading.RLock synchronization primitive defined here protects threads
within a single Python process only. It does NOT provide cross-process synchronization.
To maintain this guarantee, the web presentation layer in Phase 6 will be run with:
  debug=False
  use_reloader=False
Multiprocess deployments (e.g. multi-worker gunicorn or uWSGI) are outside the
architectural design of this single-process implementation.
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import config
import core.correlator as correlator
import core.db as db
import core.persistence as persistence_engine
import core.process_views as process_views_engine
import core.signatures as signatures_engine

logger = logging.getLogger("ghosthunt.scheduler")

# Shared in-process re-entrant lock protecting scan, accept, and reset operations
GLOBAL_OPERATION_LOCK = threading.RLock()

# Scan progress tracking (in-memory, single-process)
_SCAN_PROGRESS: Dict[str, Any] = {
    "scan_id": None,
    "phase": "idle",  # idle, process_views, persistence, signatures, correlation, complete
    "progress": 0,    # 0-100
    "started_at": None,
    "updated_at": None,
}
_SCAN_PROGRESS_LOCK = threading.Lock()


def _update_scan_progress(scan_id: Optional[int], phase: str, progress: int) -> None:
    """Update the in-memory scan progress tracker."""
    with _SCAN_PROGRESS_LOCK:
        _SCAN_PROGRESS["scan_id"] = scan_id
        _SCAN_PROGRESS["phase"] = phase
        _SCAN_PROGRESS["progress"] = max(0, min(100, progress))
        _SCAN_PROGRESS["updated_at"] = time.time()
        if phase != "idle" and _SCAN_PROGRESS["started_at"] is None:
            _SCAN_PROGRESS["started_at"] = time.time()
        if phase in ("complete", "idle"):
            _SCAN_PROGRESS["started_at"] = None


def get_scan_progress() -> Dict[str, Any]:
    """Return a copy of the current scan progress state."""
    with _SCAN_PROGRESS_LOCK:
        return dict(_SCAN_PROGRESS)


class ConcurrencyBusyError(Exception):
    """Raised when an operation cannot acquire the shared operation lock."""
    pass


# ---------------------------------------------------------------------------
# Scan Coordinator (Section 4)
# ---------------------------------------------------------------------------
def execute_scan_cycle(
    db_path: Optional[str] = None,
    # Custom injectors for unit testing & decoupled evaluation
    pv_runner: Optional[Callable[..., List[Dict[str, Any]]]] = None,
    persistence_runner: Optional[Callable[..., List[Dict[str, Any]]]] = None,
    signature_runner: Optional[Callable[..., List[Dict[str, Any]]]] = None,
    running_processes: Optional[Dict[int, Any]] = None,
) -> Dict[str, Any]:
    """
    Orchestrates the 9-step scan lifecycle in strict sequential order:
    1. Start a scan record in SQLite (status: 'IN_PROGRESS').
    2. Execute process-view enumeration.
    3. Execute persistence enumeration.
    4. Execute signature/module analysis.
    5. Collect findings and diagnostics.
    6. Validate and persist findings to SQLite.
    7. Run multi-signal risk correlation.
    8. Persist risk scores to SQLite.
    9. Mark the scan COMPLETED only after all operations succeed.

    On any failure: records meaningful error details via db.fail_scan(),
    never leaves the scan in 'IN_PROGRESS', and preserves forensic audit integrity.
    """
    start_time = time.perf_counter()
    effective_db = db_path or config.DB_PATH

    # Step 1: Start scan record
    scan_id = db.start_scan(db_path=effective_db)
    _update_scan_progress(scan_id, "process_views", 5)
    logger.info("Started scan cycle %d", scan_id)

    all_findings: List[Dict[str, Any]] = []

    try:
        # Step 2: Execute process-view enumeration
        _update_scan_progress(scan_id, "process_views", 15)
        pv_func = pv_runner or process_views_engine.run_scan
        try:
            # Pass scan_id=None so findings are collected in memory without early commit
            pv_findings = pv_func(scan_id=None, db_path=effective_db)
            all_findings.extend(pv_findings)
        except Exception as ex:
            raise RuntimeError(f"Process-view enumeration failed: {ex}") from ex
        _update_scan_progress(scan_id, "process_views", 25)

        # Step 3: Execute persistence enumeration
        _update_scan_progress(scan_id, "persistence", 35)
        per_func = persistence_runner or persistence_engine.run_scan
        try:
            per_findings = per_func(scan_id=None, db_path=effective_db)
            all_findings.extend(per_findings)
        except Exception as ex:
            raise RuntimeError(f"Persistence enumeration failed: {ex}") from ex
        _update_scan_progress(scan_id, "persistence", 50)

        # Step 4: Execute signature/module analysis
        _update_scan_progress(scan_id, "signatures", 60)
        sig_func = signature_runner or signatures_engine.run_scan
        try:
            sig_findings = sig_func(scan_id=None, db_path=effective_db)
            all_findings.extend(sig_findings)
        except Exception as ex:
            raise RuntimeError(f"Signature analysis failed: {ex}") from ex
        _update_scan_progress(scan_id, "signatures", 70)

        # Step 5: Collect and stamp findings with actual scan_id
        stamped_findings: List[Dict[str, Any]] = []
        for f in all_findings:
            f_copy = dict(f)
            f_copy["scan_id"] = scan_id
            stamped_findings.append(f_copy)

        # Step 6: Validate and persist findings
        _update_scan_progress(scan_id, "correlation", 75)
        if stamped_findings:
            db.insert_findings(scan_id, stamped_findings, db_path=effective_db)

        # Step 7: Run risk correlation
        _update_scan_progress(scan_id, "correlation", 85)
        risk_scores, quarantined = correlator.correlate_all(
            scan_id,
            stamped_findings,
            running_processes=running_processes,
        )

        # Step 8: Persist risk scores
        _update_scan_progress(scan_id, "correlation", 90)
        if risk_scores:
            db.insert_risk_scores(scan_id, risk_scores, db_path=effective_db)

        # Step 9: Mark scan COMPLETED
        _update_scan_progress(scan_id, "complete", 95)
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        high_risk_count = sum(1 for r in risk_scores if r.get("risk_level") == "HIGH")
        total_findings = len(stamped_findings)

        cache_hits = getattr(signatures_engine.GLOBAL_VERIFICATION_CACHE, "hits", 0)
        cache_misses = getattr(signatures_engine.GLOBAL_VERIFICATION_CACHE, "misses", 0)

        db.complete_scan(
            scan_id=scan_id,
            total_findings=total_findings,
            high_risk_count=high_risk_count,
            duration_ms=duration_ms,
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            db_path=effective_db,
        )

        _update_scan_progress(scan_id, "complete", 100)
        logger.info(
            "Scan %d completed in %.2f ms (total_findings=%d, high_risk=%d)",
            scan_id, duration_ms, total_findings, high_risk_count,
        )

        return {
            "success": True,
            "scan_id": scan_id,
            "status": "COMPLETED",
            "findings": stamped_findings,
            "risk_scores": risk_scores,
            "quarantined": quarantined,
            "duration_ms": duration_ms,
            "high_risk_count": high_risk_count,
            "total_findings": total_findings,
        }

    except Exception as ex:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        err_msg = f"{type(ex).__name__}: {str(ex)}"
        logger.error("Scan %d failed after %.2f ms: %s", scan_id, duration_ms, err_msg)
        _update_scan_progress(scan_id, "idle", 0)
        try:
            db.fail_scan(scan_id, error_message=err_msg, duration_ms=duration_ms, db_path=effective_db)
        except Exception as fail_err:
            logger.error("Failed to record scan failure in database: %s", fail_err)

        raise


# ---------------------------------------------------------------------------
# Background Scheduler Daemon & Concurrency Guard (Section 5)
# ---------------------------------------------------------------------------
class ScanScheduler:
    """
    Background scan scheduler managing periodic automated scan cycles.
    Guaranteed single instance within the application process.

    Uses the shared GLOBAL_OPERATION_LOCK to prevent overlapping execution
    between periodic scans, manual scans, and baseline operations.
    """

    def __init__(
        self,
        interval_seconds: float = config.SCAN_INTERVAL_SECONDS,
        db_path: Optional[str] = None,
        operation_lock: Optional[threading.RLock] = None,
        coordinator: Optional[Callable[..., Any]] = None,
    ):
        if isinstance(interval_seconds, bool) or not isinstance(interval_seconds, (int, float)) or interval_seconds <= 0:
            raise ValueError(f"interval_seconds must be a positive number, got {interval_seconds!r}")

        self.interval_seconds = float(interval_seconds)
        self.db_path = db_path or config.DB_PATH
        self.operation_lock = operation_lock or GLOBAL_OPERATION_LOCK
        self.coordinator = coordinator or execute_scan_cycle

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False
        self._lifecycle_lock = threading.Lock()
        self._scan_count = 0
        self._error_count = 0
        self._last_scan_time: Optional[float] = None

    @property
    def is_running(self) -> bool:
        """Returns True if the scheduler background thread is active."""
        with self._lifecycle_lock:
            return self._is_running and self._thread is not None and self._thread.is_alive()

    @property
    def scan_count(self) -> int:
        """Total number of successful scheduled scan cycles completed."""
        return self._scan_count

    @property
    def error_count(self) -> int:
        """Total number of exceptions encountered during scheduled scans."""
        return self._error_count

    @property
    def last_scan_time(self) -> Optional[float]:
        """Timestamp of the most recent completed scan cycle."""
        return self._last_scan_time

    def start(self) -> bool:
        """
        Starts the background scheduler daemon thread.
        Idempotent: calling start() on an already-running scheduler returns False.
        """
        with self._lifecycle_lock:
            if self._is_running and self._thread is not None and self._thread.is_alive():
                logger.warning("ScanScheduler is already running; start() ignored")
                return False

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._worker_loop,
                name="GhostHunt-SchedulerThread",
                daemon=True,
            )
            self._is_running = True
            self._thread.start()
            logger.info("ScanScheduler started (interval: %.1f s)", self.interval_seconds)
            return True

    def stop(self, timeout: float = 5.0) -> bool:
        """
        Gracefully stops the scheduler thread within the specified timeout.
        Leaves no lingering active background worker threads.
        """
        with self._lifecycle_lock:
            if not self._is_running or self._thread is None:
                return True

            self._stop_event.set()
            thread = self._thread

        thread.join(timeout=timeout)
        is_clean = not thread.is_alive()

        with self._lifecycle_lock:
            self._is_running = False
            self._thread = None

        if is_clean:
            logger.info("ScanScheduler stopped cleanly")
        else:
            logger.warning("ScanScheduler stop timed out after %.1f s", timeout)

        return is_clean

    def _worker_loop(self) -> None:
        """Worker thread executing scheduled scan cycles with error isolation."""
        logger.debug("Scheduler worker thread entered")
        while not self._stop_event.is_set():
            # Wait for the configured interval or until stop is requested
            if self._stop_event.wait(timeout=self.interval_seconds):
                break
            if self._stop_event.is_set():
                break

            # Attempt non-blocking lock acquisition
            acquired = self.operation_lock.acquire(blocking=False)
            if not acquired:
                logger.debug("Scheduled scan cycle skipped: operation lock is busy")
                continue

            try:
                self.coordinator(db_path=self.db_path)
                self._scan_count += 1
                self._last_scan_time = time.time()
            except Exception as ex:
                self._error_count += 1
                logger.error("Unhandled exception in scheduled scan cycle: %s", ex, exc_info=True)
            finally:
                self.operation_lock.release()

        logger.debug("Scheduler worker thread exiting")

    def trigger_manual_scan(self, timeout: float = 0.0) -> Dict[str, Any]:
        """
        Triggers an immediate scan cycle guarded by the shared operation lock.
        Performs non-blocking (or bounded timeout) lock acquisition.
        If the lock is busy, returns a structured busy response (status: 'busy').
        """
        blocking = timeout > 0.0
        acquired = self.operation_lock.acquire(blocking=blocking, timeout=timeout if blocking else -1)
        if not acquired:
            return {
                "success": False,
                "status": "busy",
                "message": "Another operation (scan, reset, or acceptance) is currently in progress",
                "scan_id": None,
            }

        try:
            result = self.coordinator(db_path=self.db_path)
            result["status"] = "completed"
            return result
        except Exception as ex:
            return {
                "success": False,
                "status": "failed",
                "message": str(ex),
                "scan_id": None,
            }
        finally:
            self.operation_lock.release()

    def execute_with_lock(
        self,
        action: Callable[..., Any],
        *args: Any,
        timeout: float = 0.0,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Executes an arbitrary baseline action (e.g. baseline acceptance or reset)
        under the shared operation lock with non-blocking acquisition.
        """
        blocking = timeout > 0.0
        acquired = self.operation_lock.acquire(blocking=blocking, timeout=timeout if blocking else -1)
        if not acquired:
            return {
                "success": False,
                "status": "busy",
                "message": "Operation lock is currently busy",
                "result": None,
            }

        try:
            res = action(*args, **kwargs)
            return {
                "success": True,
                "status": "completed",
                "result": res,
            }
        except Exception as ex:
            return {
                "success": False,
                "status": "failed",
                "message": str(ex),
                "result": None,
            }
        finally:
            self.operation_lock.release()


# Global default scheduler instance (not started by default)
GLOBAL_SCHEDULER = ScanScheduler()
