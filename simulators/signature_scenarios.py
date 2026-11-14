"""
GhostHunt — Phase 7: Signal 3 Signature & Path Anomaly Simulation Scenarios
Validates dual-path verification, 16-combination reconciliation, path heuristics,
PE header extraction, and verification cache invalidation.

Safety Principle:
Uses genuine harmless system binaries (sys.executable, cmd.exe) for positive signature checks.
Creates harmless non-executable test fixtures in a temporary directory for unsigned/malformed checks.
Never modifies system DLLs or certificate stores.
"""

import os
import sys
import tempfile
from typing import Any, Dict, List, Optional

import config
import core.db as db
import core.signatures as sig
from simulators import BaseScenario, register_scenario


@register_scenario
class ValidEmbeddedSignatureScenario(BaseScenario):
    """Scenario SIG-1: Valid embedded Authenticode signature verification (sys.executable)."""
    scenario_id = "SIG-1"
    name = "Valid Embedded Authenticode Verification"
    description = "Exercises WinVerifyTrust against the currently running Python executable."
    target_signal = "signature"
    is_synthetic = False

    def run(self) -> Dict[str, Any]:
        if not sig.IS_WINDOWS:
            return {"scenario_id": self.scenario_id, "passed": True, "skipped": True}

        status, code = sig.verify_embedded_authenticode(sys.executable)
        passed = (status == "VALID" and code == "0x00000000")

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "status": status,
            "code": code,
            "expected_outcome": "VALID (0x00000000)",
            "passed": passed,
        }


@register_scenario
class ValidCatalogSignatureScenario(BaseScenario):
    """Scenario SIG-2: Valid Windows catalog signature verification (cmd.exe)."""
    scenario_id = "SIG-2"
    name = "Valid Windows Catalog Verification"
    description = "Exercises CryptCATAdmin* catalog enumeration and WinVerifyTrust against cmd.exe."
    target_signal = "signature"
    is_synthetic = False

    def run(self) -> Dict[str, Any]:
        if not sig.IS_WINDOWS:
            return {"scenario_id": self.scenario_id, "passed": True, "skipped": True}

        cmd_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "cmd.exe")
        status, code, cat_file = sig.verify_catalog_signature(cmd_path)
        passed = (status == "VALID" and code == "0x00000000" and cat_file is not None)

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "status": status,
            "code": code,
            "catalog_file": cat_file,
            "expected_outcome": "VALID with matching Windows catalog file",
            "passed": passed,
        }


@register_scenario
class UnsignedModuleInTempPathScenario(BaseScenario):
    """Scenario SIG-3: Harmless unsigned test module in %TEMP% directory flagged as threat."""
    scenario_id = "SIG-3"
    name = "Unsigned DLL in %TEMP% Directory"
    description = "Simulates an unsigned loaded module residing in a suspicious temporary folder."
    target_signal = "signature"
    is_synthetic = True

    def setup(self):
        db.init_db(self.db_path)
        # Create a harmless dummy text file simulating a DLL in temp
        self.dummy_dll = self.cleanup_manager.get_temp_file_path("simulated_payload.dll")
        with open(self.dummy_dll, "wb") as f:
            f.write(b"MOCK_UNSIGNED_DLL_CONTENT")

    def run(self) -> Dict[str, Any]:
        target_pid = 7777

        def mock_modules(pid: int):
            return True, [self.dummy_dll], None

        def mock_embedded(path: str):
            return "UNSIGNED", "0x800B0100"

        def mock_catalog(path: str):
            return "UNSIGNED", "0x00000000", None

        findings = sig.run_scan(
            db_path=self.db_path,
            target_pids=[target_pid],
            module_caller=mock_modules,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        passed = (
            len(threats) == 1
            and threats[0]["signature_status"] == "UNSIGNED"
            and threats[0]["score_eligible"] == 1
            and threats[0]["severity"] == "high"
        )

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "findings": findings,
            "threat_count": len(threats),
            "expected_outcome": "1 threat finding (HIGH severity: unsigned in temp path)",
            "passed": passed,
        }


@register_scenario
class SignatureCacheInvalidationScenario(BaseScenario):
    """Scenario SIG-4: File size/mtime modification triggers cache invalidation and re-verification."""
    scenario_id = "SIG-4"
    name = "Signature Cache Invalidation"
    description = "Verifies that altering file content evicts stale cache entries."
    target_signal = "signature"
    is_synthetic = True

    def setup(self):
        self.test_file = self.cleanup_manager.get_temp_file_path("cached_mod.dll")
        with open(self.test_file, "wb") as f:
            f.write(b"INITIAL_BYTES_12345")
        self.cache = sig.SignatureCache(ttl_seconds=60)

    def run(self) -> Dict[str, Any]:
        calls = {"count": 0}

        def mock_emb(path: str):
            calls["count"] += 1
            return "VALID", "0x00000000"

        # Lookup 1: Miss and compute
        res1 = sig.verify_file_signature_cached(self.test_file, cache=self.cache, embedded_caller=mock_emb, catalog_caller=lambda p: ("UNSIGNED", "0x0", None))
        lookup1_ok = (calls["count"] == 1)

        # Lookup 2: Hit
        res2 = sig.verify_file_signature_cached(self.test_file, cache=self.cache, embedded_caller=mock_emb, catalog_caller=lambda p: ("UNSIGNED", "0x0", None))
        lookup2_cached = (calls["count"] == 1)  # Cached!

        # Modify file on disk
        with open(self.test_file, "wb") as f:
            f.write(b"ALTERED_CONTENT_NEW_SIZE_67890")

        # Lookup 3: Invalidation triggers recomputation
        res3 = sig.verify_file_signature_cached(self.test_file, cache=self.cache, embedded_caller=mock_emb, catalog_caller=lambda p: ("UNSIGNED", "0x0", None))
        passed = lookup1_ok and lookup2_cached and (calls["count"] == 2)

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "verification_calls": calls["count"],
            "expected_outcome": "2 verification calls (cache invalidated on file modification)",
            "passed": passed,
        }


@register_scenario
class PeHeaderStructuralInspectionScenario(BaseScenario):
    """Scenario SIG-5: Non-PE file returns PEFormatError safely without crashing."""
    scenario_id = "SIG-5"
    name = "PE Header Structural Safety"
    description = "Inspects a non-PE text file, confirming safe PEFormatError handling."
    target_signal = "signature"
    is_synthetic = True

    def setup(self):
        self.txt_file = self.cleanup_manager.get_temp_file_path("plain_text.txt")
        with open(self.txt_file, "w") as f:
            f.write("This is a plain ASCII text file, not a PE binary.")

    def run(self) -> Dict[str, Any]:
        pe_info = sig.inspect_pe_headers(self.txt_file)
        passed = (not pe_info["success"] and "Invalid PE format" in pe_info["error"])

        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "target_signal": self.target_signal,
            "pe_info": pe_info,
            "expected_outcome": "success=False with handled PEFormatError",
            "passed": passed,
        }
