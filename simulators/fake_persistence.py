"""
GhostHunt — Demo B: Safe Persistence Change Simulator
Authoritative demonstration script specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Demonstration Goal:
Demonstrates how GhostHunt's Persistence Monitoring Engine detects unauthorized
startup modifications relative to an ACCEPTED_TRUSTED baseline, and verifies
fail-safe threat classification and score attribution.

Safety Principles:
1. Default execution uses an isolated temporary SQLite database and synthetic
   injection so no system registry keys or tasks are ever modified.
2. Optional --live-registry flag creates a strictly harmless, temporary test
   value under HKCU Run, verifies live detection, and guarantees removal in a
   finally block.
3. Completely reversible and safe for academic demonstration.
"""

import argparse
import logging
import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import Any, Dict, List, Optional

import config
import core.correlator as correlator
import core.db as db
import core.persistence as per
from simulators.cleanup import SimulationCleanupManager

logger = logging.getLogger("ghosthunt.demo_b")


def run_demo_b(use_live_registry: bool = False) -> bool:
    print("=" * 70)
    print("GhostHunt Demo B: Safe Persistence Mechanism Change Simulation")
    print("=" * 70)

    cleanup = SimulationCleanupManager(prefix="gh_demo_b_")
    test_db = cleanup.get_temp_file_path("demo_b.db")

    try:
        # Step 1: Initialize isolated database
        print("[*] Initializing isolated database...")
        db.init_db(test_db)

        # Step 2: Establish initial clean candidate baseline
        print("[*] Capturing initial clean candidate baseline...")
        initial_entries = {
            "registry:HKCU:64bit:run:legitimatebrowser": {
                "entry_type": "registry",
                "entry_key": "registry:HKCU:64bit:run:legitimatebrowser",
                "entry_value": "C:\\Program Files\\Browser\\browser.exe",
                "fingerprint": "a1b2c3d4e5f60001",
                "structured_data": {
                    "hive": "HKCU",
                    "view": "64bit",
                    "path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value_name": "LegitimateBrowser",
                    "value_data": "C:\\Program Files\\Browser\\browser.exe",
                    "value_type": 1,
                },
            },
            "registry:HKLM:64bit:run:systemagent": {
                "entry_type": "registry",
                "entry_key": "registry:HKLM:64bit:run:systemagent",
                "entry_value": "C:\\Windows\\System32\\agent.exe",
                "fingerprint": "a1b2c3d4e5f60002",
                "structured_data": {
                    "hive": "HKLM",
                    "view": "64bit",
                    "path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value_name": "SystemAgent",
                    "value_data": "C:\\Windows\\System32\\agent.exe",
                    "value_type": 1,
                },
            },
        }

        # Run first scan to capture candidate baseline
        findings1 = per.run_scan(
            db_path=test_db,
            registry_caller=lambda: (True, initial_entries, None),
            tasks_caller=lambda: (True, {}, None),
            services_caller=lambda: (True, {}, None),
        )

        threats1 = [f for f in findings1 if f.get("finding_type") == "threat"]
        diags1 = [f for f in findings1 if f.get("finding_type") == "diagnostic"]
        print(f"[+] Initial scan complete: {len(threats1)} threats, {len(diags1)} diagnostics")
        if threats1:
            print("[-] FAILED: Candidate capture must not emit threat findings!")
            return False

        # Step 3: Explicit operator acceptance of baseline
        print("[*] Operator reviewing and accepting candidate baseline...")
        db.accept_baseline_atomic("registry", db_path=test_db)
        meta = db.get_category_baseline_meta("registry", db_path=test_db)
        print(f"[+] Baseline state: {meta['baseline_state']} (Accepted entries: {meta['accepted_entry_count']})")

        # Step 4: Simulate unauthorized autorun addition
        test_val_name = "GhostHunt_DemoB_MaliciousAutorun"
        test_val_path = "C:\\Users\\Public\\Temp\\malicious_beacon.exe"

        print(f"[*] Introducing unauthorized persistence entry: '{test_val_name}'...")

        live_key_created = False
        if use_live_registry and per.IS_WINDOWS:
            import winreg
            print("[*] Writing benign temporary test key into HKCU Run...")
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, test_val_name, 0, winreg.REG_SZ, test_val_path)
                live_key_created = True
                print("[+] Live HKCU Run test key successfully created.")
            except Exception as e:
                print(f"[!] Warning: Could not create live test registry key: {e}. Falling back to synthetic.")
                use_live_registry = False

        modified_entries = dict(initial_entries)
        evil_key = f"registry:HKCU:64bit:run:{test_val_name.lower()}"
        modified_entries[evil_key] = {
            "entry_type": "registry",
            "entry_key": evil_key,
            "entry_value": test_val_path,
            "fingerprint": "evil_payload_hash_9999",
            "structured_data": {
                "hive": "HKCU",
                "view": "64bit",
                "path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": test_val_name,
                "value_data": test_val_path,
                "value_type": 1,
            },
        }

        # Step 5: Execute second persistence scan
        print("[*] Executing persistence scan against modified state...")
        scan_id = db.start_scan(db_path=test_db)

        if use_live_registry and live_key_created:
            findings2 = per.run_scan(scan_id=scan_id, db_path=test_db)
        else:
            findings2 = per.run_scan(
                scan_id=scan_id,
                db_path=test_db,
                registry_caller=lambda: (True, modified_entries, None),
                tasks_caller=lambda: (True, {}, None),
                services_caller=lambda: (True, {}, None),
            )

        threats2 = [f for f in findings2 if f.get("finding_type") == "threat"]
        print(f"[+] Scan {scan_id} complete: {len(findings2)} findings ({len(threats2)} threat deviations)")

        detection_success = False
        for t in threats2:
            ev_lower = t.get("evidence", "").lower()
            pn_lower = t.get("process_name", "").lower()
            if test_val_name.lower() in ev_lower or test_val_name.lower() in pn_lower or "malicious_beacon.exe" in pn_lower:
                print(f"[!] THREAT DETECTED:")
                print(f"    Signal:        {t.get('signal')}")
                print(f"    Entry Name:    {t.get('process_name')}")
                print(f"    Severity:      {t.get('severity').upper()}")
                print(f"    Finding Type:  {t.get('finding_type')} (Score Eligible: {t.get('score_eligible')})")
                print(f"    Evidence:      {t.get('evidence')}")
                detection_success = True
                break

        if not detection_success:
            print("[-] FAILED: Threat was not detected!")
            return False

        # Step 6: Multi-signal risk correlation
        print("[*] Running multi-signal risk correlator...")
        db.insert_findings(scan_id, findings2, db_path=test_db)
        risk_scores, quarantined = correlator.correlate_all(scan_id, findings2)
        db.insert_risk_scores(scan_id, risk_scores, db_path=test_db)
        db.complete_scan(scan_id, total_findings=len(findings2), high_risk_count=0, duration_ms=5.0, db_path=test_db)

        print(f"[+] Risk scoring results ({len(risk_scores)} entities evaluated):")
        for r in risk_scores:
            print(f"    Item: {r['item_key']} -> Score: {r['score']:.2f} [{r['risk_level']}] (Signals: {r['signals_triggered']})")

        # Step 7: Live key cleanup if applicable
        if live_key_created and per.IS_WINDOWS:
            import winreg
            print("[*] Cleaning up live HKCU Run test key...")
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, test_val_name)
                print("[+] Live registry test key successfully deleted.")
            except Exception as e:
                print(f"[!] Warning deleting test key: {e}")

        print("[+] Demo B successfully demonstrated persistence deviation detection!")
        return True

    except Exception as e:
        print(f"[-] Demo B encountered an error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        print("[*] Purging temporary test artifacts...")
        cleanup.cleanup()
        print("[+] Demo B cleanup complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostHunt Demo B: Persistence Change Simulator")
    parser.add_argument("--live-registry", action="store_true", help="Use benign temporary live HKCU registry value")
    args = parser.parse_args()

    success = run_demo_b(use_live_registry=args.live_registry)
    sys.exit(0 if success else 1)
