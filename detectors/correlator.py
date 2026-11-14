"""
GhostHunt — Multi-Signal Risk Correlation Engine
Public detector re-export module specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).
Re-exports functionality from core.correlator.
"""

from core.correlator import (
    SIGNAL_WEIGHTS,
    VALID_SIGNALS,
    classify_severity,
    correlate_all,
    get_entity_identity,
    validate_finding_for_scoring,
    validate_weights,
)

__all__ = [
    "SIGNAL_WEIGHTS",
    "VALID_SIGNALS",
    "classify_severity",
    "correlate_all",
    "get_entity_identity",
    "validate_finding_for_scoring",
    "validate_weights",
]
