"""
GhostHunt — Phase 7: Unified Scenario Runner & End-to-End Scenarios
Authoritative scenario runner specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Architectural & Safety Principles:
1. Implements authoritative Scenarios A through J validating single-signal,
   multi-signal correlation, linear risk scoring, diagnostic isolation, and deduplication.
2. Every scenario executes against an isolated temporary database.
3. Fully reversible: all temporary artifacts are cleaned up by SimulationCleanupManager.
4. Provides programmatic APIs (run_scenario, run_all_scenarios) and CLI execution.
"""

import argparse
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
import core.correlator as correlator
import core.db as db
import core.persistence as per
import core.process_views as pv
import core.signatures as sig
from simulators import (
    BaseScenario,
    SCENARIO_REGISTRY,
    get_scenario,
    list_scenarios,
    register_scenario,
)
from simulators.cleanup import SimulationCleanupManager

logger = logging.getLogger("ghosthunt.scenario_runner")


# ===========================================================================
# End-to-End Correlation Scenarios A through J
# ===========================================================================

@register_scenario
class CleanSystemScenario(BaseScenario):
    """Scenario A: Clean system baseline (0 threats, score 0.00, LOW risk)."""
    scenario_id = "SCENARIO-A"
    name = "Clean System Baseline"
    description = "All 3 process views agree, persistence matches accepted baseline, and all modules validly signed."
    target_signal = "multi_signal"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        # Capture and accept clean persistence baseline
        clean_entry = {
            "entry_type": "registry",
            "entry_key": "registry:HKCU:64bit:run:cleanapp",
            "entry_value": "C:\\Program Files\\App\\app.exe",
            "fingerprint": "hash_clean_0001",
            "structured_data": {"path": "C:\\Program Files\\App\\app.exe"},
        }
        db.capture_candidate_baseline_atomic("registry", [clean_entry], db_path=self.db_path)
        db.accept_baseline_atomic("registry", db_path=self.db_path)

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)

        # 1. Process View: All sources agree on PID 1000
        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {1000: "app.exe"}),
            "wmi": pv.SourceResult("wmi", True, {1000: "app.exe"}),
            "native_nt": pv.SourceResult("native_nt", True, {1000: "app.exe"}),
        }
        pv_findings = pv.run_scan(scan_id=scan_id, db_path=self.db_path, pass1_sources=sources, pass2_sources=sources)

        # 2. Persistence: Current matches accepted baseline
        current_per = {
            "registry:HKCU:64bit:run:cleanapp": {
                "entry_type": "registry",
                "entry_key": "registry:HKCU:64bit:run:cleanapp",
                "entry_value": "C:\\Program Files\\App\\app.exe",
                "fingerprint": "hash_clean_0001",
                "structured_data": {"path": "C:\\Program Files\\App\\app.exe"},
            }
        }
        per_findings = per.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            registry_caller=lambda: (True, current_per, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        # 3. Signature: Valid module in whitelisted System32 path
        sig_findings = sig.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            target_pids=[1000],
            module_caller=lambda pid: (True, ["C:\\Windows\\System32\\ntdll.dll"], None),
            embedded_caller=lambda p: ("VALID", "0x00000000"),
            catalog_caller=lambda p: ("VALID", "0x00000000", "ntdll.cat"),
        )

        all_findings = pv_findings + per_findings + sig_findings
        threats = [f for f in all_findings if f.get("finding_type") == "threat"]

        db.insert_findings(scan_id, all_findings, db_path=self.db_path)
        risk_scores, _ = correlator.correlate_all(scan_id, all_findings)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(all_findings), high_risk_count=0, duration_ms=5.0, db_path=self.db_path)

        passed = (len(threats) == 0 and all(r["score"] == 0.0 and r["risk_level"] == "LOW" for r in risk_scores))

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "risk_scores": risk_scores,
            "expected_outcome": "0 threats, score = 0.00, risk level = LOW",
            "passed": passed,
        }


@register_scenario
class ProcessViewOnlyScenario(BaseScenario):
    """Scenario B: Process-view discrepancy only (Signal 1 -> 0.40, MEDIUM risk)."""
    scenario_id = "SCENARIO-B"
    name = "Process-View Discrepancy Only"
    description = "Confirmed hidden process in Toolhelp32 triggers Signal 1 weight (0.40)."
    target_signal = "process_view"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)
        target_pid = 2001

        # Process present in WMI and NT, missing in Toolhelp
        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {}),
            "wmi": pv.SourceResult("wmi", True, {target_pid: "stealth_worker.exe"}),
            "native_nt": pv.SourceResult("native_nt", True, {target_pid: "stealth_worker.exe"}),
        }
        findings = pv.run_scan(scan_id=scan_id, db_path=self.db_path, pass1_sources=sources, pass2_sources=sources)

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        db.insert_findings(scan_id, findings, db_path=self.db_path)
        risk_scores, _ = correlator.correlate_all(scan_id, findings)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(findings), high_risk_count=0, duration_ms=5.0, db_path=self.db_path)

        entity = next((r for r in risk_scores if r["pid"] == target_pid), None)
        passed = (
            len(threats) == 1
            and entity is not None
            and abs(entity["score"] - 0.40) < 1e-5
            and entity["risk_level"] == "MEDIUM"
            and entity["signals_triggered"] == "process_view"
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "risk_scores": risk_scores,
            "expected_outcome": "1 threat, score = 0.40, risk level = MEDIUM",
            "passed": passed,
        }


@register_scenario
class PersistenceOnlyScenario(BaseScenario):
    """Scenario C: Persistence deviation only (Signal 2 -> 0.30, LOW risk)."""
    scenario_id = "SCENARIO-C"
    name = "Persistence Deviation Only"
    description = "Unauthorized registry autorun added relative to accepted baseline triggers Signal 2 weight (0.30)."
    target_signal = "persistence"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        db.capture_candidate_baseline_atomic("registry", [], db_path=self.db_path)
        db.accept_baseline_atomic("registry", db_path=self.db_path)

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)
        current_entries = {
            "registry:HKCU:64bit:run:evil_backdoor": {
                "entry_type": "registry",
                "entry_key": "registry:HKCU:64bit:run:evil_backdoor",
                "entry_value": "C:\\Temp\\evil.exe",
                "fingerprint": "hash_evil_0001",
                "structured_data": {"path": "C:\\Temp\\evil.exe"},
            }
        }

        findings = per.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            registry_caller=lambda: (True, current_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        db.insert_findings(scan_id, findings, db_path=self.db_path)
        risk_scores, _ = correlator.correlate_all(scan_id, findings)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(findings), high_risk_count=0, duration_ms=5.0, db_path=self.db_path)

        entity = next((r for r in risk_scores if "evil_backdoor" in r["item_key"]), None)
        passed = (
            len(threats) == 1
            and entity is not None
            and abs(entity["score"] - 0.30) < 1e-5
            and entity["risk_level"] == "LOW"
            and entity["signals_triggered"] == "persistence"
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "risk_scores": risk_scores,
            "expected_outcome": "1 threat, score = 0.30, risk level = LOW",
            "passed": passed,
        }


@register_scenario
class SignatureOnlyScenario(BaseScenario):
    """Scenario D: Signature anomaly only (Signal 3 -> 0.30, LOW risk)."""
    scenario_id = "SCENARIO-D"
    name = "Signature Anomaly Only"
    description = "Unsigned DLL in %TEMP% directory triggers Signal 3 weight (0.30)."
    target_signal = "signature"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        self.temp_dll = self.cleanup_manager.get_temp_file_path("hook.dll")
        with open(self.temp_dll, "wb") as f:
            f.write(b"MOCK_UNSIGNED_DLL_DATA")

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)
        target_pid = 3001

        findings = sig.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            target_pids=[target_pid],
            module_caller=lambda pid: (True, [self.temp_dll], None),
            embedded_caller=lambda p: ("UNSIGNED", "0x800B0100"),
            catalog_caller=lambda p: ("UNSIGNED", "0x00000000", None),
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        db.insert_findings(scan_id, findings, db_path=self.db_path)
        risk_scores, _ = correlator.correlate_all(scan_id, findings)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(findings), high_risk_count=0, duration_ms=5.0, db_path=self.db_path)

        entity = next((r for r in risk_scores if r["pid"] == target_pid), None)
        passed = (
            len(threats) == 1
            and entity is not None
            and abs(entity["score"] - 0.30) < 1e-5
            and entity["risk_level"] == "LOW"
            and entity["signals_triggered"] == "signature"
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "risk_scores": risk_scores,
            "expected_outcome": "1 threat, score = 0.30, risk level = LOW",
            "passed": passed,
        }


@register_scenario
class ProcessViewAndPersistenceScenario(BaseScenario):
    """Scenario E: Process-View + Persistence (Signals 1 + 2 -> 0.70, HIGH risk)."""
    scenario_id = "SCENARIO-E"
    name = "Process-View + Persistence Anomaly"
    description = "Correlated process discrepancy (0.40) and autorun deviation (0.30) escalate to HIGH risk (0.70)."
    target_signal = "multi_signal"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        db.capture_candidate_baseline_atomic("registry", [], db_path=self.db_path)
        db.accept_baseline_atomic("registry", db_path=self.db_path)

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)
        target_pid = 4001
        proc_name = "trojan.exe"
        exe_path = "C:\\Windows\\Temp\\trojan.exe"

        # Signal 1: Process hidden from Toolhelp32
        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {}),
            "wmi": pv.SourceResult("wmi", True, {target_pid: proc_name}),
            "native_nt": pv.SourceResult("native_nt", True, {target_pid: proc_name}),
        }
        pv_findings = pv.run_scan(scan_id=scan_id, db_path=self.db_path, pass1_sources=sources, pass2_sources=sources)

        # Signal 2: Added persistence pointing to trojan.exe
        current_entries = {
            "registry:HKCU:64bit:run:trojan": {
                "entry_type": "registry",
                "entry_key": "registry:HKCU:64bit:run:trojan",
                "entry_value": exe_path,
                "fingerprint": "hash_trojan_0001",
                "structured_data": {"path": exe_path},
            }
        }
        per_findings = per.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            registry_caller=lambda: (True, current_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )
        # Associate persistence threat with running process PID for multi-signal correlation
        for f in per_findings:
            if f.get("finding_type") == "threat":
                f["pid"] = target_pid

        all_findings = pv_findings + per_findings
        threats = [f for f in all_findings if f.get("finding_type") == "threat"]

        db.insert_findings(scan_id, all_findings, db_path=self.db_path)
        # Running processes dictionary maps PID to metadata allowing correlator to associate persistence with active PID
        running = {
            target_pid: {
                "pid": target_pid,
                "name": proc_name,
                "exe_path": exe_path,
            }
        }
        risk_scores, _ = correlator.correlate_all(scan_id, all_findings, running_processes=running)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(all_findings), high_risk_count=1, duration_ms=5.0, db_path=self.db_path)

        entity = next((r for r in risk_scores if r["pid"] == target_pid), None)
        passed = (
            len(threats) >= 2
            and entity is not None
            and abs(entity["score"] - 0.70) < 1e-5
            and entity["risk_level"] == "HIGH"
            and "process_view" in entity["signals_triggered"]
            and "persistence" in entity["signals_triggered"]
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "risk_scores": risk_scores,
            "expected_outcome": "score = 0.70, risk level = HIGH (process_view + persistence)",
            "passed": passed,
        }


@register_scenario
class PersistenceAndSignatureScenario(BaseScenario):
    """Scenario F: Persistence + Signature (Signals 2 + 3 -> 0.60, HIGH risk)."""
    scenario_id = "SCENARIO-F"
    name = "Persistence + Signature Anomaly"
    description = "Unauthorized autorun (0.30) + unsigned DLL in unusual path (0.30) escalate to HIGH risk (0.60)."
    target_signal = "multi_signal"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        db.capture_candidate_baseline_atomic("registry", [], db_path=self.db_path)
        db.accept_baseline_atomic("registry", db_path=self.db_path)
        self.hook_dll = self.cleanup_manager.get_temp_file_path("stealth_hook.dll")
        with open(self.hook_dll, "wb") as f:
            f.write(b"MOCK_UNSIGNED_DLL_BYTES")

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)
        target_pid = 5001
        proc_name = "beacon.exe"
        exe_path = "C:\\Users\\Public\\beacon.exe"

        # Signal 2: Persistence
        current_entries = {
            "registry:HKCU:64bit:run:beacon": {
                "entry_type": "registry",
                "entry_key": "registry:HKCU:64bit:run:beacon",
                "entry_value": exe_path,
                "fingerprint": "hash_beacon_0001",
                "structured_data": {"path": exe_path},
            }
        }
        per_findings = per.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            registry_caller=lambda: (True, current_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )
        # Associate persistence threat with running process PID for multi-signal correlation
        for f in per_findings:
            if f.get("finding_type") == "threat":
                f["pid"] = target_pid
                f["process_name"] = proc_name

        # Signal 3: Signature
        sig_findings = sig.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            target_pids=[target_pid],
            module_caller=lambda pid: (True, [self.hook_dll], None),
            embedded_caller=lambda p: ("UNSIGNED", "0x800B0100"),
            catalog_caller=lambda p: ("UNSIGNED", "0x00000000", None),
        )
        for f in sig_findings:
            f["process_name"] = proc_name
            try:
                import json
                m = json.loads(f["metadata"]) if isinstance(f["metadata"], str) else dict(f["metadata"])
                m["exe_path"] = exe_path
                f["metadata"] = json.dumps(m)
            except Exception:
                pass

        all_findings = per_findings + sig_findings
        threats = [f for f in all_findings if f.get("finding_type") == "threat"]

        db.insert_findings(scan_id, all_findings, db_path=self.db_path)
        running = {
            target_pid: {
                "pid": target_pid,
                "name": proc_name,
                "exe_path": exe_path,
            }
        }
        risk_scores, _ = correlator.correlate_all(scan_id, all_findings, running_processes=running)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(all_findings), high_risk_count=1, duration_ms=5.0, db_path=self.db_path)

        entity = next((r for r in risk_scores if r["pid"] == target_pid), None)
        passed = (
            len(threats) >= 2
            and entity is not None
            and abs(entity["score"] - 0.60) < 1e-5
            and entity["risk_level"] == "HIGH"
            and "persistence" in entity["signals_triggered"]
            and "signature" in entity["signals_triggered"]
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "risk_scores": risk_scores,
            "expected_outcome": "score = 0.60, risk level = HIGH (persistence + signature)",
            "passed": passed,
        }


@register_scenario
class AllThreeSignalsScenario(BaseScenario):
    """Scenario G: All 3 signals triggered (0.40 + 0.30 + 0.30 -> 1.00, HIGH risk)."""
    scenario_id = "SCENARIO-G"
    name = "All Three Signals Triggered"
    description = "Triangulated threat: hidden process (0.40) + persistence (0.30) + unsigned DLL (0.30) = 1.00."
    target_signal = "multi_signal"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        db.capture_candidate_baseline_atomic("registry", [], db_path=self.db_path)
        db.accept_baseline_atomic("registry", db_path=self.db_path)
        self.evil_dll = self.cleanup_manager.get_temp_file_path("rootkit_hook.dll")
        with open(self.evil_dll, "wb") as f:
            f.write(b"MOCK_ROOTKIT_HOOK_BYTES")

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)
        target_pid = 6001
        proc_name = "rootkit_core.exe"
        exe_path = "C:\\Windows\\Temp\\rootkit_core.exe"

        # Signal 1: Hidden from Toolhelp
        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {}),
            "wmi": pv.SourceResult("wmi", True, {target_pid: proc_name}),
            "native_nt": pv.SourceResult("native_nt", True, {target_pid: proc_name}),
        }
        pv_findings = pv.run_scan(scan_id=scan_id, db_path=self.db_path, pass1_sources=sources, pass2_sources=sources)

        # Signal 2: Persistence
        current_entries = {
            "registry:HKCU:64bit:run:rootkit_core": {
                "entry_type": "registry",
                "entry_key": "registry:HKCU:64bit:run:rootkit_core",
                "entry_value": exe_path,
                "fingerprint": "hash_rootkit_0001",
                "structured_data": {"path": exe_path},
            }
        }
        per_findings = per.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            registry_caller=lambda: (True, current_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )
        # Associate persistence threat with running process PID for multi-signal correlation
        for f in per_findings:
            if f.get("finding_type") == "threat":
                f["pid"] = target_pid
                f["process_name"] = proc_name

        # Signal 3: Signature
        sig_findings = sig.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            target_pids=[target_pid],
            module_caller=lambda pid: (True, [self.evil_dll], None),
            embedded_caller=lambda p: ("UNSIGNED", "0x800B0100"),
            catalog_caller=lambda p: ("UNSIGNED", "0x00000000", None),
        )
        for f in sig_findings:
            f["process_name"] = proc_name
            try:
                import json
                m = json.loads(f["metadata"]) if isinstance(f["metadata"], str) else dict(f["metadata"])
                m["exe_path"] = exe_path
                f["metadata"] = json.dumps(m)
            except Exception:
                pass

        all_findings = pv_findings + per_findings + sig_findings
        threats = [f for f in all_findings if f.get("finding_type") == "threat"]

        db.insert_findings(scan_id, all_findings, db_path=self.db_path)
        running = {
            target_pid: {
                "pid": target_pid,
                "name": proc_name,
                "exe_path": exe_path,
            }
        }
        risk_scores, _ = correlator.correlate_all(scan_id, all_findings, running_processes=running)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(all_findings), high_risk_count=1, duration_ms=5.0, db_path=self.db_path)

        entity = next((r for r in risk_scores if r["pid"] == target_pid), None)
        passed = (
            len(threats) >= 3
            and entity is not None
            and abs(entity["score"] - 1.00) < 1e-5
            and entity["risk_level"] == "HIGH"
            and len(entity["signals_triggered"].split(",")) == 3
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "risk_scores": risk_scores,
            "expected_outcome": "score = 1.00, risk level = HIGH (all 3 signals triggered)",
            "passed": passed,
        }


@register_scenario
class OperationalDiagnosticsOnlyScenario(BaseScenario):
    """Scenario H: Diagnostics only (Diagnostic Invariant Validation -> score 0.00, LOW risk)."""
    scenario_id = "SCENARIO-H"
    name = "Operational Diagnostics Only"
    description = "Access-denied, RPC failure, and locked file ERROR emit score_eligible=0 diagnostics. Score remains 0.00."
    target_signal = "multi_signal"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)
        target_pid = 4  # System protected process

        # Diagnostic 1: Process View source failure (WMI RPC error)
        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {target_pid: "system"}),
            "wmi": pv.SourceResult("wmi", False, {}, error="WMI RPC timeout"),
            "native_nt": pv.SourceResult("native_nt", True, {target_pid: "system"}),
        }
        pv_findings = pv.run_scan(scan_id=scan_id, db_path=self.db_path, pass1_sources=sources, pass2_sources=sources)

        # Diagnostic 2: Persistence task query failure
        per_findings = per.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            registry_caller=lambda: (True, {}, None),
            tasks_caller=lambda: (False, {}, "Task Scheduler service stopped"),
            services_caller=lambda: (True, {}, None),
        )

        # Diagnostic 3: Signature inspection operational ERROR (locked file / I/O error)
        sig_findings = sig.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            target_pids=[target_pid],
            module_caller=lambda pid: (True, ["C:\\Windows\\System32\\locked.sys"], None),
            embedded_caller=lambda p: ("ERROR", "0x80070020"),  # Sharing violation
            catalog_caller=lambda p: ("ERROR", "0x80070020", None),
        )

        all_findings = pv_findings + per_findings + sig_findings
        threats = [f for f in all_findings if f.get("finding_type") == "threat"]
        diags = [f for f in all_findings if f.get("finding_type") == "diagnostic"]

        # Enforce Diagnostic Invariant: finding_type == 'diagnostic' ==> score_eligible == 0
        invariant_ok = all(
            d["finding_type"] == "diagnostic" and d["score_eligible"] == 0
            for d in diags
        )

        db.insert_findings(scan_id, all_findings, db_path=self.db_path)
        risk_scores, _ = correlator.correlate_all(scan_id, all_findings)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(all_findings), high_risk_count=0, duration_ms=5.0, db_path=self.db_path)

        passed = (
            len(threats) == 0
            and len(diags) >= 3
            and invariant_ok
            and all(r["score"] == 0.0 and r["risk_level"] == "LOW" for r in risk_scores)
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "diagnostic_count": len(diags),
            "invariant_satisfied": invariant_ok,
            "risk_scores": risk_scores,
            "expected_outcome": "0 threats, >=3 diagnostics (score_eligible=0), score = 0.00, LOW risk",
            "passed": passed,
        }


@register_scenario
class EnumerationQuorumFailureScenario(BaseScenario):
    """Scenario I: Insufficient process quorum (< 2 sources succeed -> 0 threats, diagnostic)."""
    scenario_id = "SCENARIO-I"
    name = "Enumeration Quorum Failure"
    description = "Two of three process views fail. Engine aborts cross-view diffing to prevent false positives."
    target_signal = "process_view"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)

        sources = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {100: "app.exe"}),
            "wmi": pv.SourceResult("wmi", False, {}, "WMI Service unreachable"),
            "native_nt": pv.SourceResult("native_nt", False, {}, "NT API Access Denied"),
        }
        findings = pv.run_scan(scan_id=scan_id, db_path=self.db_path, pass1_sources=sources, pass2_sources=sources)

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        diags = [f for f in findings if f.get("finding_type") == "diagnostic"]

        db.insert_findings(scan_id, findings, db_path=self.db_path)
        risk_scores, _ = correlator.correlate_all(scan_id, findings)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(findings), high_risk_count=0, duration_ms=5.0, db_path=self.db_path)

        passed = (
            len(threats) == 0
            and len(diags) >= 1
            and any("minimum quorum" in d["evidence"].lower() or "quorum" in d["evidence"].lower() for d in diags)
            and all(r["score"] == 0.0 for r in risk_scores)
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "diagnostic_count": len(diags),
            "expected_outcome": "0 threats (diffing aborted), operational diagnostic emitted, score = 0.00",
            "passed": passed,
        }


@register_scenario
class SignalDeduplicationScenario(BaseScenario):
    """Scenario J: Signal Deduplication (2 threats under same signal -> 0.30, not 0.60)."""
    scenario_id = "SCENARIO-J"
    name = "Signal Deduplication Validation"
    description = "Two distinct unsigned DLL findings for the same PID contribute evidence but count signal weight once."
    target_signal = "signature"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        self.dll1 = self.cleanup_manager.get_temp_file_path("hook1.dll")
        self.dll2 = self.cleanup_manager.get_temp_file_path("hook2.dll")
        with open(self.dll1, "wb") as f:
            f.write(b"MOCK_HOOK_1")
        with open(self.dll2, "wb") as f:
            f.write(b"MOCK_HOOK_2")

    def run(self) -> Dict[str, Any]:
        scan_id = db.start_scan(db_path=self.db_path)
        target_pid = 7001

        findings = sig.run_scan(
            scan_id=scan_id,
            db_path=self.db_path,
            target_pids=[target_pid],
            module_caller=lambda pid: (True, [self.dll1, self.dll2], None),
            embedded_caller=lambda p: ("UNSIGNED", "0x800B0100"),
            catalog_caller=lambda p: ("UNSIGNED", "0x00000000", None),
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        db.insert_findings(scan_id, findings, db_path=self.db_path)
        risk_scores, _ = correlator.correlate_all(scan_id, findings)
        db.insert_risk_scores(scan_id, risk_scores, db_path=self.db_path)
        db.complete_scan(scan_id, total_findings=len(findings), high_risk_count=0, duration_ms=5.0, db_path=self.db_path)

        entity = next((r for r in risk_scores if r["pid"] == target_pid), None)
        # CRITICAL: len(threats) == 2, but score is strictly 0.30 (not 0.60!)
        passed = (
            len(threats) == 2
            and entity is not None
            and abs(entity["score"] - 0.30) < 1e-5
            and entity["risk_level"] == "LOW"
            and entity["signals_triggered"] == "signature"
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "threat_count": len(threats),
            "risk_scores": risk_scores,
            "expected_outcome": "2 threat findings deduplicated to single weight (score = 0.30, LOW)",
            "passed": passed,
        }


# ===========================================================================
# Public Runner Functions
# ===========================================================================

def run_scenario(scenario_id: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes a single simulation scenario by ID inside an isolated context.
    Guarantees cleanup of temporary files, processes, and databases.
    """
    scenario = get_scenario(scenario_id, db_path=db_path)
    if not scenario:
        return {
            "scenario_id": scenario_id,
            "passed": False,
            "error": f"Scenario '{scenario_id}' not found in registry",
        }

    start_time = time.perf_counter()
    try:
        with scenario:
            result = scenario.run()
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            result["duration_ms"] = round(duration_ms, 2)
            return result
    except Exception as e:
        logger.exception("Error executing scenario %s: %s", scenario_id, e)
        return {
            "scenario_id": scenario_id,
            "name": getattr(scenario, "name", scenario_id),
            "passed": False,
            "error": str(e),
            "duration_ms": round((time.perf_counter() - start_time) * 1000.0, 2),
        }


def run_all_scenarios(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Executes all registered simulation scenarios sequentially.
    Returns list of result dictionaries.
    """
    results: List[Dict[str, Any]] = []
    # Execute sorted by scenario_id
    for scenario_id in sorted(SCENARIO_REGISTRY.keys()):
        res = run_scenario(scenario_id, db_path=db_path)
        results.append(res)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="GhostHunt Phase 7 Scenario Runner")
    parser.add_argument("--scenario", "-s", type=str, help="Specific scenario ID to run (e.g., PV-1, PER-2, SCENARIO-G)")
    parser.add_argument("--all", "-a", action="store_true", help="Execute all registered scenarios")
    parser.add_argument("--list", "-l", action="store_true", help="List all registered scenarios")
    args = parser.parse_args()

    if args.list:
        print("Registered GhostHunt Simulation Scenarios:")
        for s in list_scenarios():
            print(f"  [{s['scenario_id']:<10}] {s['name']:<35} ({s['target_signal']})")
        return 0

    if args.scenario:
        res = run_scenario(args.scenario)
        status = "PASSED" if res.get("passed") else "FAILED"
        print(f"[{status}] {res.get('scenario_id')}: {res.get('name', '')} ({res.get('duration_ms', 0)}ms)")
        if not res.get("passed"):
            print(f"  Error: {res.get('error')}")
            return 1
        return 0

    # Default or --all: run all scenarios
    print("=" * 70)
    print("GhostHunt Phase 7: Executing Complete Simulation Scenario Suite")
    print("=" * 70)
    results = run_all_scenarios()

    passed_count = sum(1 for r in results if r.get("passed"))
    total_count = len(results)

    print("-" * 70)
    for r in results:
        status = "PASS" if r.get("passed") else "FAIL"
        print(f"  [{status}] {r.get('scenario_id'):<12} {r.get('name', ''):<40} {r.get('duration_ms', 0):>6.1f}ms")

    print("=" * 70)
    print(f"Summary: {passed_count}/{total_count} scenarios passed.")
    print("=" * 70)

    return 0 if passed_count == total_count else 1


if __name__ == "__main__":
    sys.exit(main())
