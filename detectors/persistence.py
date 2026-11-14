"""
GhostHunt — Signal 2 Detector: Persistence Monitoring Engine
Authoritative detector module specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).
Re-exports functionality from core.persistence.
"""

from core.persistence import (
    ENUM_SERVICE_STATUS_PROCESSW,
    PersistenceEntry,
    PersistenceResult,
    QUERY_SERVICE_CONFIGW,
    accept_baseline,
    compute_fingerprint,
    diff_persistence_category,
    evaluate_category_persistence,
    read_registry_run_keys,
    read_scheduled_tasks,
    read_windows_services,
    reset_all_baselines,
    run_scan,
)

__all__ = [
    "ENUM_SERVICE_STATUS_PROCESSW",
    "PersistenceEntry",
    "PersistenceResult",
    "QUERY_SERVICE_CONFIGW",
    "accept_baseline",
    "compute_fingerprint",
    "diff_persistence_category",
    "evaluate_category_persistence",
    "read_registry_run_keys",
    "read_scheduled_tasks",
    "read_windows_services",
    "reset_all_baselines",
    "run_scan",
]
