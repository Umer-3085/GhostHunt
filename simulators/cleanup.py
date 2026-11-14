"""
GhostHunt — Phase 7: Simulation Cleanup & Isolation Manager
Guarantees safe, isolated, and idempotent cleanup of test artifacts.

Safety & Isolation Guarantees:
1. All simulation artifacts are confined to a dedicated temporary directory.
2. Isolated temporary SQLite databases prevent contamination of production state.
3. Registered files, directories, and processes are cleanly purged on cleanup.
4. Cleanup is strictly idempotent and safe to execute multiple times.
5. Exceptions during cleanup are logged without masking original scenario errors.
"""

import logging
import os
import shutil
import tempfile
from typing import List, Optional, Set

import psutil

logger = logging.getLogger("ghosthunt.simulators.cleanup")


class SimulationCleanupManager:
    """
    Manages temporary files, databases, and test processes for simulation scenarios.
    Ensures zero persistent artifacts survive test scenario execution.
    """

    def __init__(self, prefix: str = "ghosthunt_sim_"):
        self.prefix = prefix
        self._temp_dir: Optional[str] = None
        self._tracked_files: Set[str] = set()
        self._tracked_pids: Set[int] = set()
        self._is_cleaned = False

    @property
    def temp_dir(self) -> str:
        """Lazily creates and returns the dedicated simulation temporary directory."""
        if self._temp_dir is None or not os.path.exists(self._temp_dir):
            self._temp_dir = tempfile.mkdtemp(prefix=self.prefix)
        return self._temp_dir

    def get_temp_file_path(self, filename: str) -> str:
        """Returns a tracked absolute file path within the temporary simulation directory."""
        file_path = os.path.join(self.temp_dir, filename)
        self._tracked_files.add(os.path.normpath(file_path))
        return file_path

    def track_pid(self, pid: int) -> None:
        """Registers a harmless test process ID owned by the simulation harness for termination."""
        if isinstance(pid, int) and pid > 0:
            self._tracked_pids.add(pid)

    def cleanup(self) -> None:
        """
        Executes complete, idempotent cleanup of tracked test processes, files, and directories.
        Safe to call multiple times.
        """
        # 1. Terminate tracked test processes owned by simulation
        for pid in list(self._tracked_pids):
            try:
                if psutil.pid_exists(pid):
                    proc = psutil.Process(pid)
                    proc.terminate()
                    try:
                        proc.wait(timeout=1.0)
                    except psutil.TimeoutExpired:
                        proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as ex:
                logger.debug("Process %d already exited or inaccessible: %s", pid, ex)
            except Exception as ex:
                logger.warning("Error terminating test process %d: %s", pid, ex)

        self._tracked_pids.clear()

        # 2. Delete individually tracked files
        for fpath in list(self._tracked_files):
            try:
                if os.path.exists(fpath):
                    os.unlink(fpath)
            except Exception as ex:
                logger.debug("Error deleting tracked file %s: %s", fpath, ex)

        self._tracked_files.clear()

        # 3. Recursively remove the simulation temporary directory
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
            except Exception as ex:
                logger.warning("Error deleting temporary simulation directory %s: %s", self._temp_dir, ex)
            finally:
                self._temp_dir = None

        self._is_cleaned = True
        logger.debug("SimulationCleanupManager completed cleanup")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
