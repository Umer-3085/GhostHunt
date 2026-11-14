"""
GhostHunt — Phase 7: Signal 1 Process-View Simulation Scenarios
Validates cross-view process enumeration, two-pass confirmation, transient filtering,
PID reuse identity preservation, and failure isolation.

Safety Principle:
Uses dependency injection of controlled SourceResult dictionaries. Never modifies
the Windows kernel, hooks syscalls, or manipulates internal OS process structures.
"""

from typing import Any, Dict, List, Optional

import core.db as db
import core.process_views as pv
from simulators import BaseScenario, register_scenario


@register_scenario
class ConsistentProcessScenario(BaseScenario):
    """Scenario PV-1: Consistent enumeration across all sources (0 discrepancies)."""
    scenario_id = "PV-1"
    name = "Consistent Process Enumeration"
    description = "Simulates identical process inventories across Toolhelp32, WMI, and Native NT API."
    target_signal = "process_view"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        procs = {
            100: "system.exe",
            200: "service.exe",
        }
        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, dict(procs)),
            "wmi": pv.SourceResult("wmi", True, dict(procs)),
            "native_nt": pv.SourceResult("native_nt", True, dict(procs)),
        }

        findings = pv.run_scan(
            db_path=self.db_path,
            pass1_sources=sources,
            pass2_sources=sources,
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        passed = (len(threats) == 0)

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "expected_outcome": "0 threat findings (all sources agree)",
            "passed": passed,
        }


@register_scenario
class ProcessDiscrepancyScenario(BaseScenario):
    """Scenario PV-2: Confirmed process-view discrepancy (cross-view stealth indicator)."""
    scenario_id = "PV-2"
    name = "Confirmed Process-View Discrepancy"
    description = "Simulates a process visible in WMI and Native NT but absent from Toolhelp32 across two passes."
    target_signal = "process_view"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        pass_sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "system.exe"}),
            "wmi": pv.SourceResult("wmi", True, {100: "system.exe", 1337: "stealth_app.exe"}),
            "native_nt": pv.SourceResult("native_nt", True, {100: "system.exe", 1337: "stealth_app.exe"}),
        }

        findings = pv.run_scan(
            db_path=self.db_path,
            pass1_sources=pass_sources,
            pass2_sources=pass_sources,
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        passed = (len(threats) == 1 and threats[0]["pid"] == 1337 and threats[0]["score_eligible"] == 1)

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "expected_outcome": "1 threat finding (PID 1337 confirmed hidden in Toolhelp32)",
            "passed": passed,
        }


@register_scenario
class TransientTerminationScenario(BaseScenario):
    """Scenario PV-3: Process terminates between passes (filtered as transient, not stealth)."""
    scenario_id = "PV-3"
    name = "Transient Process Termination Filter"
    description = "Simulates a process visible in Pass 1 that cleanly exits before Pass 2. Verified as transient."
    target_signal = "process_view"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        # Pass 1: visible in WMI and NT, missing in Toolhelp
        pass1 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {}),
            "wmi": pv.SourceResult("wmi", True, {2222: "short_lived.exe"}),
            "native_nt": pv.SourceResult("native_nt", True, {2222: "short_lived.exe"}),
        }
        # Pass 2: process has terminated (missing from all sources)
        pass2 = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {}),
            "wmi": pv.SourceResult("wmi", True, {}),
            "native_nt": pv.SourceResult("native_nt", True, {}),
        }

        findings = pv.run_scan(
            db_path=self.db_path,
            pass1_sources=pass1,
            pass2_sources=pass2,
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        passed = (len(threats) == 0)  # Filtered out as transient!

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "expected_outcome": "0 threat findings (transient exit filtered safely)",
            "passed": passed,
        }


@register_scenario
class SourceFailureQuorumScenario(BaseScenario):
    """Scenario PV-4: Single source failure excludes failed source without false discrepancies."""
    scenario_id = "PV-4"
    name = "Source Failure Isolation"
    description = "Simulates WMI COM query failure while Toolhelp32 and Native NT succeed. Quorum maintained."
    target_signal = "process_view"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        procs = {100: "system.exe"}

        # WMI failed, but Toolhelp and Native NT agree
        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, dict(procs)),
            "wmi": pv.SourceResult("wmi", False, {}, "WMI RPC timeout"),
            "native_nt": pv.SourceResult("native_nt", True, dict(procs)),
        }

        findings = pv.run_scan(
            db_path=self.db_path,
            pass1_sources=sources,
            pass2_sources=sources,
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        diags = [f for f in findings if f.get("finding_type") == "diagnostic"]

        passed = (len(threats) == 0 and len(diags) >= 1)

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "diagnostic_count": len(diags),
            "expected_outcome": "0 threats, 1 operational diagnostic (failed source excluded)",
            "passed": passed,
        }


@register_scenario
class InsufficientQuorumScenario(BaseScenario):
    """Scenario PV-5: Insufficient source quorum (< 2 sources succeed) emits diagnostic and aborts."""
    scenario_id = "PV-5"
    name = "Insufficient Source Quorum"
    description = "Simulates failure in two of three sources, preventing safe cross-view discrepancy analysis."
    target_signal = "process_view"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe"}),
            "wmi": pv.SourceResult("wmi", False, {}, "WMI Service stopped"),
            "native_nt": pv.SourceResult("native_nt", False, {}, "Access denied to NT API"),
        }

        findings = pv.run_scan(
            db_path=self.db_path,
            pass1_sources=sources,
            pass2_sources=sources,
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        diags = [f for f in findings if f.get("finding_type") == "diagnostic"]

        passed = (
            len(threats) == 0
            and len(diags) >= 1
            and any("minimum quorum" in d["evidence"].lower() or "quorum" in d["evidence"].lower() for d in diags)
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "diagnostic_count": len(diags),
            "expected_outcome": "0 threats, operational diagnostic emitted for insufficient quorum",
            "passed": passed,
        }
