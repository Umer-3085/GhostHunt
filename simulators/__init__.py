"""
GhostHunt — Phase 7: Safe Academic Simulators & Detection Validation
Authoritative simulation package specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Architectural & Safety Principles:
1. Strictly defensive, controlled, and harmless test scenarios.
2. Zero kernel modifications, zero API hooking, zero process injection.
3. Complete isolation: all scenarios execute against dedicated temporary databases
   and temporary sandboxes. Production databases and baselines remain untouched.
4. Idempotent cleanup guarantees no lingering files or processes.
5. Never executes automatically on application startup.
"""

import abc
import logging
from typing import Any, Dict, List, Optional, Type

from simulators.cleanup import SimulationCleanupManager

logger = logging.getLogger("ghosthunt.simulators")


class BaseScenario(abc.ABC):
    """Abstract base class for all GhostHunt simulation scenarios."""

    scenario_id: str
    name: str
    description: str
    target_signal: str  # 'process_view' | 'persistence' | 'signature' | 'multi_signal'
    is_synthetic: bool = True  # True if using mock/injection; False if using real harmless Windows artifacts

    def __init__(self, db_path: Optional[str] = None):
        self.cleanup_manager = SimulationCleanupManager(prefix=f"gh_sim_{self.scenario_id}_")
        self.db_path = db_path or self.cleanup_manager.get_temp_file_path("scenario.db")

    def setup(self) -> None:
        """Initializes test fixtures, temporary files, or isolated databases."""
        pass

    @abc.abstractmethod
    def run(self) -> Dict[str, Any]:
        """
        Executes the simulation scenario against detection engines.
        Returns a structured dictionary detailing:
          scenario_id, name, target_signal, is_synthetic,
          findings: List[Dict], risk_scores: List[Dict],
          expected_outcome: str, passed: bool, details: Dict.
        """
        pass

    def cleanup(self) -> None:
        """Purges all temporary files, processes, and databases."""
        self.cleanup_manager.cleanup()

    def __enter__(self):
        self.setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


# Global scenario registry
SCENARIO_REGISTRY: Dict[str, Type[BaseScenario]] = {}


def register_scenario(cls: Type[BaseScenario]) -> Type[BaseScenario]:
    """Decorator to register simulation scenario classes in the global catalogue."""
    SCENARIO_REGISTRY[cls.scenario_id] = cls
    return cls


def get_scenario(scenario_id: str, db_path: Optional[str] = None) -> Optional[BaseScenario]:
    """Instantiates a scenario by its unique identifier."""
    cls = SCENARIO_REGISTRY.get(scenario_id)
    if cls:
        return cls(db_path=db_path)
    return None


def list_scenarios() -> List[Dict[str, Any]]:
    """Returns metadata for all registered simulation scenarios."""
    return [
        {
            "scenario_id": cls.scenario_id,
            "name": cls.name,
            "description": cls.description,
            "target_signal": cls.target_signal,
            "is_synthetic": getattr(cls, "is_synthetic", True),
        }
        for cls in SCENARIO_REGISTRY.values()
    ]


# Auto-import scenario suites to populate SCENARIO_REGISTRY
import simulators.process_scenarios  # noqa: F401, E402
import simulators.persistence_scenarios  # noqa: F401, E402
import simulators.signature_scenarios  # noqa: F401, E402
import simulators.scenario_runner  # noqa: F401, E402


