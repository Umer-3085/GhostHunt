"""
GhostHunt — Master Configuration Module
Authoritative configuration for the GhostHunt user-mode rootkit and stealth
malware detection system.

All paths are relative to the project root directory; machine-specific
absolute paths are strictly prohibited.
"""

import os
from pathlib import Path
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Project Paths & Filesystem
# ---------------------------------------------------------------------------
BASE_DIR: Path = Path(__file__).resolve().parent
DB_PATH: str = str(BASE_DIR / "ghosthunt.db")
LOG_FILE: str = str(BASE_DIR / "ghosthunt.log")

# ---------------------------------------------------------------------------
# Application Metadata
# ---------------------------------------------------------------------------
APP_NAME: str = "GhostHunt"
APP_VERSION: str = "1.4.3"

# ---------------------------------------------------------------------------
# Engine Scheduling & Performance Parameters
# ---------------------------------------------------------------------------
# Scheduling interval for background scanner (evaluation target, not bound)
# Increased from 10s to 300s (5 min) to allow full scans to complete.
# A full scan (process views + persistence + signatures + correlation)
# typically takes 2-5 minutes due to signature verification (Authenticode + Catalog).
SCAN_INTERVAL_SECONDS: int = 300

# Micro-delay (50 ms) for two-pass transient process confirmation
MICRO_DELAY_SECONDS: float = 0.05

# SQLite busy timeout (milliseconds) for concurrency lock contention
DB_BUSY_TIMEOUT_MS: int = 5000

# Signature verification cache maximum time-to-live (30 minutes)
CACHE_TTL_SECONDS: int = 1800

# ---------------------------------------------------------------------------
# Risk Scoring Weights & Thresholds
# Documented Linear Scoring Model:
# ThreatSignalsTriggered = Unique({ f['signal'] | f is score-eligible threat })
# Score = sum(RISK_WEIGHTS[s]) capped at 1.0
# ---------------------------------------------------------------------------
RISK_WEIGHTS: Dict[str, float] = {
    "process_view": 0.40,
    "persistence": 0.30,
    "signature": 0.30,
}

# Categorical Risk Classification Thresholds
# LOW:    score < 0.40
# MEDIUM: 0.40 <= score < 0.60
# HIGH:   score >= 0.60
RISK_THRESHOLD_MEDIUM: float = 0.40
RISK_THRESHOLD_HIGH: float = 0.60
HIGH_RISK_THRESHOLD: float = 0.60  # Backward-compatible alias

# ---------------------------------------------------------------------------
# Persistence Inspection Targets
# ---------------------------------------------------------------------------
STARTUP_REGISTRY_PATHS: List[str] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]

# Baseline categories tracked independently
PERSISTENCE_CATEGORIES: List[str] = ["registry", "task", "service"]

# ---------------------------------------------------------------------------
# Signature Verification & Path Heuristics
# ---------------------------------------------------------------------------
SYSTEM_WHITELIST_PATHS: List[str] = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\WinSxS",
]

SUSPICIOUS_PATH_PATTERNS: List[str] = [
    r"\AppData\Local\Temp",
    r"\AppData\Roaming",
    r"\AppData\Local",
    r"\Downloads",
    r"\Desktop",
]

# ---------------------------------------------------------------------------
# Presentation & REST API Configuration (Local Execution)
# Strict Single-Process Boundaries: debug=False and use_reloader=False
# ---------------------------------------------------------------------------
FLASK_HOST: str = "127.0.0.1"
FLASK_PORT: int = 5000
FLASK_DEBUG: bool = False
FLASK_USE_RELOADER: bool = False

# Environment-provided secret with a designated fallback for local development
DEV_SECRET_FALLBACK: str = "ghosthunt-dev-insecure-local-only-key"
GHOSTHUNT_ENV: str = os.environ.get("GHOSTHUNT_ENV", "development").lower()
IS_PRODUCTION: bool = (GHOSTHUNT_ENV == "production")

SECRET_KEY: str = (
    os.environ.get("GHOSTHUNT_SECRET_KEY")
    or os.environ.get("SECRET_KEY")
    or DEV_SECRET_FALLBACK
)

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
LOG_LEVEL: str = "INFO"
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s (%(threadName)s): %(message)s"


# ---------------------------------------------------------------------------
# Startup Configuration Validation
# ---------------------------------------------------------------------------
def validate_config() -> bool:
    """
    Validates configuration values at application startup.
    Raises ValueError if any configuration setting violates system constraints.
    Returns True when all checks pass.
    """
    if SCAN_INTERVAL_SECONDS <= 0:
        raise ValueError(f"SCAN_INTERVAL_SECONDS must be positive, got {SCAN_INTERVAL_SECONDS}")

    if MICRO_DELAY_SECONDS < 0.001 or MICRO_DELAY_SECONDS > 5.0:
        raise ValueError(f"MICRO_DELAY_SECONDS must be between 1ms and 5s, got {MICRO_DELAY_SECONDS}")

    if DB_BUSY_TIMEOUT_MS < 1000:
        raise ValueError(f"DB_BUSY_TIMEOUT_MS must be at least 1000 ms, got {DB_BUSY_TIMEOUT_MS}")

    if CACHE_TTL_SECONDS <= 0:
        raise ValueError(f"CACHE_TTL_SECONDS must be positive, got {CACHE_TTL_SECONDS}")

    # Verify risk weights
    expected_signals = {"process_view", "persistence", "signature"}
    if set(RISK_WEIGHTS.keys()) != expected_signals:
        raise ValueError(f"RISK_WEIGHTS keys must be {expected_signals}, got {set(RISK_WEIGHTS.keys())}")

    weights_sum = sum(RISK_WEIGHTS.values())
    if abs(weights_sum - 1.0) > 1e-6:
        raise ValueError(f"RISK_WEIGHTS must sum to 1.0, got {weights_sum:.4f}")

    for sig, w in RISK_WEIGHTS.items():
        if w < 0.0 or w > 1.0:
            raise ValueError(f"Weight for '{sig}' must be between 0.0 and 1.0, got {w}")

    # Verify threshold ordering
    if not (0.0 < RISK_THRESHOLD_MEDIUM < RISK_THRESHOLD_HIGH <= 1.0):
        raise ValueError(
            f"Thresholds must satisfy 0.0 < MEDIUM ({RISK_THRESHOLD_MEDIUM}) < HIGH ({RISK_THRESHOLD_HIGH}) <= 1.0"
        )

    # Verify database path validity
    db_parent = Path(DB_PATH).parent
    if not db_parent.exists():
        raise ValueError(f"Database directory does not exist: {db_parent}")

    # Environment-aware secret key protection
    is_prod = (os.environ.get("GHOSTHUNT_ENV", GHOSTHUNT_ENV).lower() == "production")
    active_key = os.environ.get("GHOSTHUNT_SECRET_KEY") or os.environ.get("SECRET_KEY") or SECRET_KEY
    if is_prod:
        if active_key == DEV_SECRET_FALLBACK:
            raise ValueError(
                "In production (GHOSTHUNT_ENV=production), development fallback secret key "
                "is strictly prohibited. Provide GHOSTHUNT_SECRET_KEY via environment variable."
            )
        if len(active_key) < 32:
            raise ValueError(
                f"In production (GHOSTHUNT_ENV=production), SECRET_KEY must be at least 32 characters, "
                f"got length {len(active_key)}"
            )

    return True


# Run validation on module import
validate_config()
