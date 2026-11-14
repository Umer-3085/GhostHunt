"""
GhostHunt — Demo A: Safe Process-View Discrepancy Simulator
Authoritative demonstration script specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Demonstration Goal:
Demonstrates how cross-view enumeration detects a process-view mismatch
without modifying OS kernel structures, injecting DLLs, or hooking APIs.

Mechanism:
1. Launches a harmless Python child process ('python.exe -c "import time; time.sleep(30)"').
2. Uses dependency injection to simulate a Toolhelp32 view that omits this child PID,
   while WMI and Native NT API correctly enumerate it.
3. GhostHunt's two-pass engine confirms the discrepancy and emits a HIGH severity threat.
4. Cleans up by terminating the child process.
"""

import os
import subprocess
import sys
import time

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import core.process_views as pv
from simulators.cleanup import SimulationCleanupManager


def run_demo_a() -> bool:
    print("=" * 70)
    print("GhostHunt Demo A: Safe Cross-View Discrepancy Simulation")
    print("=" * 70)

    cleanup = SimulationCleanupManager(prefix="gh_demo_a_")

    try:
        # 1. Launch a harmless child process
        print("[*] Launching harmless Python worker process...")
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cleanup.track_pid(proc.pid)
        print(f"[+] Harmless process active: PID {proc.pid}")

        # 2. Formulate cross-view test scenario
        # Child process is present in WMI and Native NT, but omitted from Toolhelp32
        sources_mismatch = {
            "toolhelp32": pv.SourceResult("toolhelp32", True, {}),  # Hidden!
            "wmi": pv.SourceResult("wmi", True, {proc.pid: "python.exe"}),
            "native_nt": pv.SourceResult("native_nt", True, {proc.pid: "python.exe"}),
        }

        print("[*] Executing GhostHunt two-pass cross-view analysis...")
        findings = pv.run_scan(
            pass1_sources=sources_mismatch,
            pass2_sources=sources_mismatch,
        )

        threats = [f for f in findings if f.get("finding_type") == "threat"]
        print(f"[+] Total findings: {len(findings)} ({len(threats)} confirmed threats)")

        if threats:
            t = threats[0]
            print(f"[!] DETECTION CONFIRMED: Process {t['process_name']} (PID {t['pid']})")
            print(f"    Evidence: {t['evidence']}")
            print(f"    Severity: {t['severity'].upper()} (Score Eligible: {t['score_eligible']})")
            return True
        else:
            print("[-] No discrepancies detected.")
            return False

    finally:
        print("[*] Cleaning up child process...")
        cleanup.cleanup()
        print("[+] Demo A cleanup complete.")


if __name__ == "__main__":
    success = run_demo_a()
    sys.exit(0 if success else 1)
