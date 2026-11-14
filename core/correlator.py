"""
GhostHunt — Phase 5: Multi-Signal Risk Correlation Engine
Authoritative implementation of the multi-signal risk correlation engine specified
in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Architectural Invariants & Safeguards:
1. Finding Eligibility & Separation:
   - Only findings where finding_type == 'threat' AND score_eligible in (1, True)
     contribute to the risk score.
   - Operational diagnostics (finding_type == 'diagnostic' OR score_eligible in (0, False))
     NEVER contribute to risk scores (score addition = 0.0).
   - Strict validation: findings violating schema invariants are quarantined and excluded.
2. Unique Signal Deduplication:
   - Each signal (process_view: 0.40, persistence: 0.30, signature: 0.30) counts at most
     once per entity regardless of finding count.
   - risk_score = min(1.0, sum(unique_eligible_signal_weights)).
3. Deterministic Entity Identity:
   - Active processes: identified by PID + process_name + creation_time/exe_path where
     available. Prevents accidental grouping under PID reuse.
   - Dormant persistence: identified by stable source identity (system:<category>:<key>).
   - System-level persistence findings with PID=None are preserved and scored.
4. Exact Categorical Severity:
   - LOW:    score < 0.40
   - MEDIUM: 0.40 <= score < 0.60
   - HIGH:   score >= 0.60
   - Evaluated without preliminary rounding.
5. Explainability & Evidence:
   - Preserves human-readable forensic evidence, supporting eligible findings, and
     excluded diagnostics for every entity.
"""

import copy
import json
import logging
import math
import os
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import config

logger = logging.getLogger("ghosthunt.correlator")

# Authoritative signal weights from configuration
VALID_SIGNALS: Set[str] = {"process_view", "persistence", "signature"}


def validate_weights() -> Dict[str, float]:
    """
    Validates that configured weights match the roadmap specification
    and sum to exactly 1.0 within floating point tolerance.
    """
    weights = config.RISK_WEIGHTS
    if not isinstance(weights, dict):
        raise TypeError("config.RISK_WEIGHTS must be a dictionary")

    for sig in VALID_SIGNALS:
        if sig not in weights:
            raise ValueError(f"Missing required signal weight in config: '{sig}'")
        val = weights[sig]
        if isinstance(val, bool) or not isinstance(val, (int, float)) or val <= 0:
            raise ValueError(f"Weight for '{sig}' must be a positive number, got {val!r}")

    total_weight = sum(weights[s] for s in VALID_SIGNALS)
    if abs(total_weight - 1.0) > 1e-6:
        raise ValueError(f"Signal weights must sum to 1.0, got {total_weight:.6f}")

    return {s: float(weights[s]) for s in VALID_SIGNALS}


# Validate weights on module import
SIGNAL_WEIGHTS = validate_weights()


def classify_severity(score: float) -> str:
    """
    Classifies risk score into categorical severity levels strictly adhering
    to roadmap thresholds without preliminary rounding:
      - score < 0.40: LOW
      - 0.40 <= score < 0.60: MEDIUM
      - score >= 0.60: HIGH
    """
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        raise ValueError(f"Score must be a finite float, got {score!r}")

    if score >= config.RISK_THRESHOLD_HIGH:
        return "HIGH"
    elif score >= config.RISK_THRESHOLD_MEDIUM:
        return "MEDIUM"
    else:
        return "LOW"


def validate_finding_for_scoring(finding: Any) -> Tuple[bool, Optional[str]]:
    """
    Validates finding schema and classification invariants before scoring.
    Returns: (is_valid: bool, rejection_reason: Optional[str])

    Invariants enforced:
    - Must be a non-empty dictionary.
    - finding_type must be exactly 'threat' or 'diagnostic'.
    - If finding_type == 'diagnostic', score_eligible MUST be exactly 0 (or False).
    - If finding_type == 'threat', score_eligible must be in (0, 1, False, True).
    - signal must be a non-empty string.
    """
    if not isinstance(finding, dict):
        return False, f"Finding must be a dictionary, got {type(finding).__name__}"

    raw_ft = finding.get("finding_type")
    if not isinstance(raw_ft, str) or raw_ft not in ("threat", "diagnostic"):
        return False, f"Invalid finding_type: {raw_ft!r}"

    raw_se = finding.get("score_eligible")
    # Disallow malformed non-boolean/non-int types
    if raw_se not in (0, 1, True, False):
        return False, f"Invalid score_eligible: {raw_se!r}"

    # Critical invariant: diagnostic must NEVER be score_eligible
    if raw_ft == "diagnostic" and (raw_se is True or raw_se == 1):
        return False, "Invariant violation: finding_type 'diagnostic' with score_eligible == 1"

    signal = finding.get("signal")
    if not isinstance(signal, str) or not signal.strip():
        return False, f"Missing or invalid signal field: {signal!r}"

    return True, None


def get_entity_identity(
    finding: Dict[str, Any],
    running_processes: Optional[Dict[int, Any]] = None,
) -> Tuple[str, str, Optional[int], str]:
    """
    Determines stable entity identity to group findings accurately while
    safeguarding against PID reuse and improper entity merging.

    Returns:
    (item_key: str, process_name: str, pid: Optional[int], entity_type: str)
      - item_key: unique identity key (e.g. 'proc:1234:app.exe:...' or 'system:registry:...')
      - process_name: human-readable name of process or persistence item
      - pid: integer PID or None
      - entity_type: 'process' or 'persistence'
    """
    pid = finding.get("pid")
    raw_proc = finding.get("process_name", "")
    proc_name = str(raw_proc).strip() if raw_proc else "unknown"

    meta: Dict[str, Any] = {}
    raw_meta = finding.get("metadata")
    if isinstance(raw_meta, str):
        try:
            meta = json.loads(raw_meta)
        except Exception:
            pass
    elif isinstance(raw_meta, dict):
        meta = raw_meta

    # Case 1: Active Process Entity (PID is an integer > 0)
    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
        entity_type = "process"

        # Check for creation time or instance token to protect against PID reuse
        create_time = meta.get("create_time") or meta.get("timestamp")
        exe_path = meta.get("exe_path") or meta.get("path") or meta.get("module_path")

        # Fallback to running_processes lookup if provided
        if running_processes and pid in running_processes:
            pinfo = running_processes[pid]
            if isinstance(pinfo, dict):
                create_time = create_time or pinfo.get("create_time")
                exe_path = exe_path or pinfo.get("exe") or pinfo.get("exe_path")
            elif hasattr(pinfo, "create_time"):
                create_time = create_time or getattr(pinfo, "create_time", None)

        key_parts = [f"proc:{pid}:{proc_name.lower()}"]
        if create_time is not None:
            key_parts.append(str(create_time))
        elif exe_path:
            norm_exe = os.path.normcase(os.path.normpath(str(exe_path)))
            key_parts.append(norm_exe)

        item_key = ":".join(key_parts)
        return item_key, proc_name, pid, entity_type

    # Case 2: Persistence / System Entity (PID is None or 0)
    entity_type = "persistence"
    category = meta.get("category") or "persistence"
    entry_key = meta.get("entry_key") or meta.get("entry_name") or proc_name

    # Normalize persistence item key: system:<category>:<entry_key>
    if proc_name.startswith("system:"):
        item_key = proc_name
    else:
        item_key = f"system:{category}:{entry_key}"

    # Ensure process_name conforms to database NOT NULL constraint
    effective_name = proc_name if proc_name and proc_name != "unknown" else item_key

    return item_key, effective_name, None, entity_type


def correlate_all(
    scan_id: int,
    findings: List[Dict[str, Any]],
    running_processes: Optional[Dict[int, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Correlates findings for a given scan_id across the three detection signals.
    Implements roadmap FR-4 and Section 3.

    Returns:
    (risk_scores: List[Dict[str, Any]], quarantined_findings: List[Dict[str, Any]])

    - risk_scores: List of structured entity risk dictionaries ready for db.insert_risk_scores.
      Each entry contains:
        item_key, pid, process_name, score, risk_level, signals_triggered,
        scan_id, entity_type, contributing_signals, supporting_findings,
        excluded_diagnostics, calculated_at.
    - quarantined_findings: Findings rejected due to schema or invariant violations.
    """
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
        raise ValueError(f"scan_id must be a positive integer, got {scan_id!r}")

    if not findings:
        return [], []

    # 1. Validation & Quarantining Phase
    valid_findings: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []

    for f in findings:
        ok, reason = validate_finding_for_scoring(f)
        if ok:
            valid_findings.append(f)
        else:
            q_copy = copy.deepcopy(f) if isinstance(f, dict) else {"raw": f}
            q_copy["quarantine_reason"] = reason
            quarantined.append(q_copy)
            logger.warning(
                "Quarantined malformed finding in scan %d: %s (finding: %r)",
                scan_id, reason, f,
            )

    # 2. Entity Grouping Phase
    # Group findings by deterministic item_key
    entities: Dict[str, Dict[str, Any]] = {}

    for f in valid_findings:
        item_key, proc_name, pid, entity_type = get_entity_identity(f, running_processes=running_processes)

        if item_key not in entities:
            entities[item_key] = {
                "scan_id": scan_id,
                "item_key": item_key,
                "pid": pid,
                "process_name": proc_name,
                "entity_type": entity_type,
                "threat_findings": [],
                "diagnostic_findings": [],
            }

        # Update process_name if a more specific name becomes available
        if entities[item_key]["process_name"] == "unknown" and proc_name != "unknown":
            entities[item_key]["process_name"] = proc_name

        ft = f.get("finding_type")
        se = f.get("score_eligible")

        # Threat evidence: finding_type == 'threat' AND score_eligible in (1, True)
        if ft == "threat" and (se is True or se == 1):
            entities[item_key]["threat_findings"].append(f)
        else:
            # Operational diagnostic or deactivated threat
            entities[item_key]["diagnostic_findings"].append(f)

    # 3. Risk Calculation & Severity Classification Phase
    risk_scores: List[Dict[str, Any]] = []
    calc_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    for item_key, ent in entities.items():
        threats: List[Dict[str, Any]] = ent["threat_findings"]
        diagnostics: List[Dict[str, Any]] = ent["diagnostic_findings"]

        # Deduplicate signals: each signal contributes at most once
        contributing_signals: List[str] = sorted(list({
            f["signal"] for f in threats
            if f.get("signal") in SIGNAL_WEIGHTS
        }))

        # Calculate explainable linear risk score
        raw_score = sum(SIGNAL_WEIGHTS[s] for s in contributing_signals)
        final_score = min(1.0, max(0.0, raw_score))

        # Classify categorical severity without preliminary rounding
        risk_level = classify_severity(final_score)

        signals_str = ",".join(contributing_signals)

        result_row = {
            "scan_id": scan_id,
            "item_key": item_key,
            "pid": ent["pid"],
            "process_name": ent["process_name"],
            "score": final_score,
            "risk_level": risk_level,
            "signals_triggered": signals_str,
            "entity_type": ent["entity_type"],
            "contributing_signals": contributing_signals,
            "supporting_findings": threats,
            "excluded_diagnostics": diagnostics,
            "calculated_at": calc_time,
        }
        risk_scores.append(result_row)

    # Sort risk scores descending by score, then ascending by item_key
    risk_scores.sort(key=lambda r: (-r["score"], r["item_key"]))

    return risk_scores, quarantined
