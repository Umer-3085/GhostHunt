"""
GhostHunt — Demo C: Unsigned DLL in Temporary Directory Simulator
Authoritative demonstration script specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Demonstration Goal:
Demonstrates how GhostHunt's Signature Verification & Path Anomaly Engine detects
an unsigned DLL loaded from a suspicious/atypical directory (such as %TEMP%),
evaluates PE headers, applies the 4x4 reconciliation matrix, and scores the threat.

Safety Guarantees:
1. Purely academic and harmless: uses synthesized test DLL with a DllMain stub.
2. Contained within an isolated temporary sandbox directory.
3. Cleaned up immediately upon test completion using SimulationCleanupManager.
4. Never modifies system DLLs, Windows system folders, or certificate stores.
"""

import argparse
import logging
import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from typing import Any, Dict, List, Optional

import config
import core.correlator as correlator
import core.db as db
import core.signatures as sig
from simulators.cleanup import SimulationCleanupManager
from simulators.fake_unsigned_dll.build_dll import build_unsigned_pe_dll

logger = logging.getLogger("ghosthunt.demo_c")


def run_demo_c() -> bool:
    print("=" * 70)
    print("GhostHunt Demo C: Unsigned DLL in Suspicious Path Simulation")
    print("=" * 70)

    cleanup = SimulationCleanupManager(prefix="gh_demo_c_")
    test_db = cleanup.get_temp_file_path("demo_c.db")
    dll_path = cleanup.get_temp_file_path("simulated_stealth_hook.dll")

    try:
        # Step 1: Initialize isolated database
        print("[*] Initializing isolated database...")
        db.init_db(test_db)

        # Step 2: Synthesize harmless unsigned 64-bit PE DLL
        print(f"[*] Synthesizing harmless unsigned PE DLL at: '{dll_path}'...")
        build_unsigned_pe_dll(dll_path)
        print(f"[+] Harmless test DLL created ({os.path.getsize(dll_path)} bytes).")

        # Step 3: Verify Path Anomaly Engine flags %TEMP% path
        print("[*] Testing Path Anomaly Engine...")
        is_unusual, reason, path_meta = sig.is_unusual_path(dll_path)
        print(f"[+] Path anomaly check for '{dll_path}': unusual={is_unusual} (reason={reason})")
        if not is_unusual:
            print("[-] FAILED: %TEMP% directory was not flagged as unusual!")
            return False

        # Step 4: Inspect PE Header
        print("[*] Inspecting PE header via pefile...")
        pe_info = sig.inspect_pe_headers(dll_path)
        print(f"[+] PE Architecture: {pe_info.get('machine')} (Sections: {pe_info.get('sections')})")
        print(f"[+] Embedded Certificate Directory: present={pe_info.get('has_cert_table')}, size={pe_info.get('cert_table_size')}")

        if pe_info.get("has_cert_table"):
            print("[-] FAILED: Synthesized DLL should have no security directory!")
            return False

        # Step 5: Execute signature verification
        print("[*] Performing signature verification (Authenticode + Windows Catalog)...")
        if sig.IS_WINDOWS:
            emb_status, emb_code = sig.verify_embedded_authenticode(dll_path)
            cat_status, cat_code, cat_file = sig.verify_catalog_signature(dll_path)
            recon = sig.reconcile_signatures(emb_status, emb_code, cat_status, cat_code, cat_file)
            combined_status = recon["status"]
        else:
            emb_status, emb_code = "UNSIGNED", "0x800B0100"
            cat_status, cat_code, cat_file = "UNSIGNED", "0x00000000", None
            recon = sig.reconcile_signatures(emb_status, emb_code, cat_status, cat_code, cat_file)
            combined_status = recon["status"]

        print(f"[+] Embedded Authenticode Status: {emb_status} ({emb_code})")
        print(f"[+] Windows Catalog Status:       {cat_status} ({cat_code})")
        print(f"[+] Reconciled Status:           {combined_status}")

        if combined_status != "UNSIGNED":
            print(f"[-] FAILED: Expected UNSIGNED status, got {combined_status}!")
            return False

        # Step 6: Execute GhostHunt Signal 3 Scan
        print("[*] Executing GhostHunt Signal 3 detection scan...")
        target_pid = os.getpid()
        scan_id = db.start_scan(db_path=test_db)

        # Inject test DLL as a loaded module for current PID
        findings = sig.run_scan(
            scan_id=scan_id,
            db_path=test_db,
            target_pids=[target_pid],
            module_caller=lambda pid: (True, [dll_path], None),
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        diags = [f for f in findings if f.get("finding_type") == "diagnostic"]
        print(f"[+] Scan {scan_id} complete: {len(findings)} findings ({len(threats)} threats, {len(diags)} diagnostics)")

        if not threats:
            print("[-] FAILED: Expected threat finding for unsigned module in %TEMP%!")
            return False

        t = threats[0]
        print(f"[!] THREAT DETECTED:")
        print(f"    Signal:           {t.get('signal')}")
        print(f"    Process:          {t.get('process_name')} (PID {t.get('pid')})")
        print(f"    Severity:         {t.get('severity').upper()}")
        print(f"    Signature Status: {t.get('signature_status')}")
        print(f"    Finding Type:     {t.get('finding_type')} (Score Eligible: {t.get('score_eligible')})")
        print(f"    Evidence:         {t.get('evidence')}")

        # Step 7: Multi-Signal Risk Correlation
        print("[*] Running multi-signal risk correlator...")
        db.insert_findings(scan_id, findings, db_path=test_db)
        risk_scores, quarantined = correlator.correlate_all(scan_id, findings)
        db.insert_risk_scores(scan_id, risk_scores, db_path=test_db)
        db.complete_scan(scan_id, total_findings=len(findings), high_risk_count=0, duration_ms=10.0, db_path=test_db)

        print(f"[+] Risk scoring results ({len(risk_scores)} entities evaluated):")
        for r in risk_scores:
            print(f"    Item: {r['item_key']} -> Score: {r['score']:.2f} [{r['risk_level']}] (Signals: {r['signals_triggered']})")

        print("[+] Demo C successfully demonstrated unsigned DLL detection in suspicious path!")
        return True

    except Exception as e:
        print(f"[-] Demo C encountered an error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        print("[*] Purging temporary test artifacts...")
        cleanup.cleanup()
        print("[+] Demo C cleanup complete.")


if __name__ == "__main__":
    success = run_demo_c()
    sys.exit(0 if success else 1)
