# GhostHunt — Multi-Signal User-Mode Rootkit & Stealth Malware Detection System

**Target Platform:** Windows 10 / Windows 11 (x64)  
**Implementation:** Python 3.10+ / Flask / SQLite WAL / Win32 User-Mode APIs  
**Academic Context:** Senior Undergraduate Capstone Project  
**Roadmap Specification:** `Docs/DEVELOPMENT_ROADMAP.md` (Version 1.4.3)  

---

## 1. Project Overview

**GhostHunt** is a defensive, host-based stealth malware and user-mode rootkit detection system for Windows 10/11 x64. Unlike signature-only antivirus scanners or invasive kernel-mode drivers, GhostHunt operates entirely in user-mode using a multi-signal behavioral anomaly architecture.

GhostHunt correlates independent indicators of compromise (IoCs) across three distinct defensive signals:

```text
               +-------------------------------------------+
               |                 GhostHunt                 |
               |        Multi-Signal Detection Engine      |
               +-------------------------------------------+
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
+------------------+       +-------------------+       +--------------------+
|     Signal 1     |       |     Signal 2      |       |      Signal 3      |
|   Cross-View     |       |    Persistence    |       |   Dual-Path Sig    |
|   Process Views  |       |    Monitoring     |       |   & Path Anomaly   |
|   (Weight: 0.40) |       |   (Weight: 0.30)  |       |   (Weight: 0.30)   |
+------------------+       +-------------------+       +--------------------+
         |                           |                           |
         +---------------------------+---------------------------+
                                     |
                                     v
                   +-----------------------------------+
                   |     Linear Risk Correlator        |
                   |   Score = 0.4*PV + 0.3*PER + 0.3*SIG |
                   +-----------------------------------+
                                     |
                                     v
                   +-----------------------------------+
                   |   Flask Web UI & REST API Engine  |
                   |   (Risk-Ranked Dashboard & Lab)   |
                   +-----------------------------------+
```

### The Three Detection Signals
1. **Cross-View Process Enumeration (Signal 1 — Weight: 0.40):** Cross-compares active process tables across three distinct enumeration paths (Win32 Toolhelp32 snapshot, WMI COM / CIM query, and Native NT API `NtQuerySystemInformation`). Discrepancies are verified through a 50 ms micro-delay two-pass confirmation filter to dismiss transient exits, backed by a minimum quorum requirement ($\ge 2$ sources).
2. **Persistence Monitoring (Signal 2 — Weight: 0.30):** Monitors autostart execution points across 32-bit and 64-bit Registry Run/RunOnce keys, Scheduled Tasks, and Windows Services, evaluating deviations strictly against explicitly operator-accepted reference baselines.
3. **Loaded Module Signature & Path Anomaly Verification (Signal 3 — Weight: 0.30):** Enforces Authenticode embedded signatures and Windows Security Catalog bindings via `Wintrust.dll` using a 16-combination reconciliation matrix, alongside filesystem path anomaly detection (%TEMP%, %APPDATA%, Desktop, Downloads, root directory) and a high-speed hybrid verification cache.

---

## 2. Key Features & Architectural Guarantees

- **Multi-Signal Risk Correlation:** Combines independent weak signals into risk-ranked composite scores ($0.0 \le \text{Score} \le 1.0$). Correlated multi-vector attacks produce an immediate **+75% to +150% composite risk-score escalation**, crossing the HIGH risk threshold ($\ge 0.60$).
- **Strict Threat-Diagnostic Isolation:** Operational diagnostics (e.g. WMI query timeouts, RPC disconnects) are assigned `score_eligible = 0` and are strictly barred by schema CHECK constraints and DAL invariants from contaminating risk scores.
- **Candidate Baseline Security Ceremony:** Systems are never assumed clean on first launch. Persistence entries are captured into a candidate review state (`CANDIDATE_REVIEW`) requiring explicit operator acceptance (`POST /api/baseline/accept`) before diffing begins.
- **In-Process Concurrency Guard:** A thread-safe re-entrant synchronization lock (`threading.RLock()`) ensures that scheduled scans, manual scans, and baseline operations never overlap or corrupt SQLite transactions, returning HTTP 409 Conflict when busy.
- **Zero Kernel Dependencies:** Completely safe user-mode execution. No kernel drivers (`.sys`), no BSOD risks, no code injection, and no automated destructive remediation.
- **Rich Dark-Mode Dashboard & Simulation Lab:** Real-time web dashboard displaying risk-ranked processes, forensic evidence drill-downs, scan history, and an interactive 24-scenario simulation lab.

---

## 3. Quickstart & Installation

### 3.1 Prerequisites
- Windows 10 (64-bit) or Windows 11 (64-bit).
- Python 3.10+ (64-bit).
- Windows Administrator privileges (recommended).

### 3.2 Setup
```powershell
# 1. Clone or extract repository
cd GhostHunt

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch GhostHunt (single-process service)
python run.py
```

Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 4. Empirical Evaluation Summary

Real hardware measurements conducted on host Windows 10 x64 hardware (Intel/AMD x64, 4 cores, 16 GB RAM):

| Performance Dimension | Measured Empirical Value | Target / Specification |
| :--- | :---: | :---: |
| **Full Scan Cycle Duration** | **3.81s mean** / 3.57s median (Max: 5.73s) | 2.0 – 4.0 seconds (Met on average; qualified under load) |
| **Active Scan CPU Utilization** | **22.89%** average | Transient spike (< 35%) |
| **Process Memory Footprint** | **44.89 MB RSS** (+1.93 MB delta) | Lightweight (< 50 MB) |
| **Signature Cache Speedup** | **190.66×** (1.31 ms vs 249.77 ms) | 100.0% warm hit ratio |
| **REST API Latency** | **< 6.5 ms** across all endpoints | Highly responsive (< 10 ms) |
| **Functional Scenario Validation** | **24/24 Scenarios Verified** | Classified according to predefined expected outcomes |
| **Diagnostic Contamination** | **0.00%** | Invariant mathematically proven |

---

## 5. Verification & Testing

GhostHunt includes a comprehensive automated test pyramid and simulation scenario runner:

```powershell
# Run the complete regression test suite (261 test executions, 235 unique tests)
python -m unittest discover -v -s tests -p "test_*.py"

# Run the 24 academic demonstration scenarios
python simulators/scenario_runner.py --all

# Run empirical performance benchmarks (10 repetitions)
python simulators/benchmark.py 10
```

---

## 6. Comprehensive Documentation Index

Exhaustive engineering and academic documentation is available in the `Docs/` directory:

- [DEVELOPMENT_ROADMAP.md](Docs/DEVELOPMENT_ROADMAP.md) — Master Architectural Specification & Development Roadmap (v1.4.3).
- [architecture.md](Docs/architecture.md) — Complete System Architecture, Security Analysis & 5 Mermaid Diagrams.
- [evaluation_results.md](Docs/evaluation_results.md) — Empirical Evaluation, 10-Iteration Benchmarks & Composite Risk-Score Escalation Analysis.
- [limitations.md](Docs/limitations.md) — Exhaustive User-Mode Technical Boundaries, DKOM & Rootkit Scope Analysis.
- [USER_GUIDE.md](Docs/USER_GUIDE.md) — End-to-End User Manual, Dashboard Walkthrough, CLI Tools & REST API Reference.
- [TESTING.md](Docs/TESTING.md) — Test Suite Organization, Execution Guide & 261-Execution Accounting Proof.
