"""
GhostHunt — Phase 7: Signal 2 Persistence Simulation Scenarios
Validates baseline lifecycle state machine, candidate review, explicit acceptance,
added/modified/removed deviation detection, and category failure isolation.

Safety Principle:
Uses injectable category caller functions and an isolated temporary SQLite database.
Never touches real Windows registry autoruns, Windows services, or Task Scheduler.
"""

from typing import Any, Dict, List, Optional

import core.db as db
import core.persistence as per
from simulators import BaseScenario, register_scenario


@register_scenario
class CandidateBaselineCaptureScenario(BaseScenario):
    """Scenario PER-1: Initial enumeration captures inventory into CANDIDATE_REVIEW with 0 threats."""
    scenario_id = "PER-1"
    name = "Candidate Baseline Capture"
    description = "Simulates initial scan capturing baseline inventory into CANDIDATE_REVIEW awaiting review."
    target_signal = "persistence"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        mock_entries = {
            "registry:reg_app1": {
                "entry_type": "registry",
                "entry_key": "registry:reg_app1",
                "entry_value": "C:\\app1.exe",
                "fingerprint": "hash1",
                "structured_data": {"path": "C:\\app1.exe"},
            },
        }

        findings = per.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, mock_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        meta = db.get_category_baseline_meta("registry", db_path=self.db_path)
        threats = [f for f in findings if f.get("finding_type") == "threat"]
        diags = [f for f in findings if f.get("finding_type") == "diagnostic"]

        passed = (
            meta["baseline_state"] == "CANDIDATE_REVIEW"
            and meta["candidate_entry_count"] == 1
            and len(threats) == 0
            and len(diags) >= 1
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "state": meta["baseline_state"],
            "expected_outcome": "CANDIDATE_REVIEW state, 0 threats, operational diagnostic awaiting review",
            "passed": passed,
        }


@register_scenario
class AddedPersistenceThreatScenario(BaseScenario):
    """Scenario PER-2: Newly added autorun detected relative to ACCEPTED_TRUSTED reference baseline."""
    scenario_id = "PER-2"
    name = "Added Persistence Entry Deviation"
    description = "Simulates an unauthorized registry autorun added after baseline acceptance."
    target_signal = "persistence"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        # 1. Capture candidate baseline
        db.capture_candidate_baseline_atomic(
            "registry",
            [{
                "entry_type": "registry",
                "entry_key": "registry:LegitApp",
                "entry_value": "C:\\legit.exe",
                "fingerprint": "fp_legit",
                "structured_data": {"path": "C:\\legit.exe"},
            }],
            db_path=self.db_path,
        )
        # 2. Accept baseline to establish ACCEPTED_TRUSTED reference
        db.accept_baseline_atomic("registry", db_path=self.db_path)

    def run(self) -> Dict[str, Any]:
        # Current inventory contains legitimate app + newly added backdoor
        current_entries = {
            "registry:LegitApp": {
                "entry_type": "registry",
                "entry_key": "registry:LegitApp",
                "entry_value": "C:\\legit.exe",
                "fingerprint": "fp_legit",
                "structured_data": {"path": "C:\\legit.exe"},
            },
            "registry:BackdoorAutorun": {
                "entry_type": "registry",
                "entry_key": "registry:BackdoorAutorun",
                "entry_value": "C:\\temp\\backdoor.exe",
                "fingerprint": "fp_evil",
                "structured_data": {"path": "C:\\temp\\backdoor.exe"},
            },
        }

        findings = per.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, current_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        passed = (
            len(threats) == 1
            and "BackdoorAutorun" in threats[0]["evidence"]
            and threats[0]["score_eligible"] == 1
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "expected_outcome": "1 threat finding (BackdoorAutorun flagged as added)",
            "passed": passed,
        }


@register_scenario
class ModifiedPersistenceScenario(BaseScenario):
    """Scenario PER-3: Modified binary path/fingerprint of an accepted autorun detected."""
    scenario_id = "PER-3"
    name = "Modified Persistence Entry Deviation"
    description = "Simulates an existing trusted entry being modified to point to an altered binary."
    target_signal = "persistence"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        db.capture_candidate_baseline_atomic(
            "registry",
            [{
                "entry_type": "registry",
                "entry_key": "registry:Updater",
                "entry_value": "C:\\updater.exe",
                "fingerprint": "original_hash",
                "structured_data": {"path": "C:\\updater.exe"},
            }],
            db_path=self.db_path,
        )
        db.accept_baseline_atomic("registry", db_path=self.db_path)

    def run(self) -> Dict[str, Any]:
        # Modified fingerprint
        modified_entries = {
            "registry:Updater": {
                "entry_type": "registry",
                "entry_key": "registry:Updater",
                "entry_value": "C:\\updater.exe",
                "fingerprint": "tampered_hash",
                "structured_data": {"path": "C:\\updater.exe"},
            },
        }

        findings = per.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, modified_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        passed = (
            len(threats) == 1
            and "modified" in threats[0]["evidence"].lower()
            and threats[0]["score_eligible"] == 1
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "expected_outcome": "1 threat finding (Updater flagged as modified)",
            "passed": passed,
        }


@register_scenario
class CategoryFailureIsolationScenario(BaseScenario):
    """Scenario PER-4: Task scheduler query failure skips diffing without false removals."""
    scenario_id = "PER-4"
    name = "Persistence Enumeration Failure Isolation"
    description = "Simulates task query failure while tasks baseline is accepted. Zero false removals emitted."
    target_signal = "persistence"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        db.capture_candidate_baseline_atomic(
            "task",
            [{
                "entry_type": "task",
                "entry_key": "task:TaskA",
                "entry_value": "C:\\task.exe",
                "fingerprint": "hashA",
                "structured_data": {"path": "C:\\task.exe"},
            }],
            db_path=self.db_path,
        )
        db.accept_baseline_atomic("task", db_path=self.db_path)

    def run(self) -> Dict[str, Any]:
        # Tasks query fails
        findings = per.run_scan(
            db_path=self.db_path,
            registry_caller=lambda: (True, {}, None),
            tasks_caller=lambda: (False, {}, "RPC server unavailable"),
            services_caller=lambda: (True, {}, None),
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        diags = [f for f in findings if f.get("finding_type") == "diagnostic"]

        # Critical: ZERO false 'removed' threat findings!
        passed = (len(threats) == 0 and len(diags) >= 1)

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "diagnostic_count": len(diags),
            "expected_outcome": "0 threats (zero false removals), 1 operational diagnostic",
            "passed": passed,
        }
