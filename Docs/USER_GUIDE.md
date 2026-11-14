# GhostHunt — Comprehensive User Guide & Operations Manual

**Document Version:** 1.4.3  
**Target Platform:** Windows 10 / Windows 11 (x64)  
**Target Audience:** Security Analysts, Systems Administrators, University Evaluators  
**Date:** November 2026  

---

## 1. Introduction

**GhostHunt** is a multi-signal user-mode stealth malware and rootkit detection system for Windows 10/11 x64. It detects evasive processes, unauthorized persistence entries, and anomalous loaded DLLs by correlating anomalies across three independent detection engines and presenting forensic evidence in a web dashboard and REST API.

---

## 2. System Requirements & Installation

### 2.1 Hardware & OS Prerequisites
- **Operating System:** Windows 10 (64-bit) or Windows 11 (64-bit).
- **Architecture:** AMD64 / x86_64.
- **Privilege Level:** Elevated Administrator privilege (recommended for full Service Control Manager and Task Scheduler access).
- **Memory & Storage:** 2 GB RAM minimum, 200 MB free disk space.
- **Python Runtime:** Python 3.10, 3.11, or 3.12 (64-bit).

### 2.2 Installation Steps

1. **Clone or Extract the GhostHunt Repository:**
   ```powershell
   cd GhostHunt
   ```

2. **Create and Activate a Python Virtual Environment (Optional but Recommended):**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install Required Python Dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```
   Dependencies installed:
   - `Flask==3.0.3` (Web application framework)
   - `psutil==6.0.0` (Cross-platform process and system monitoring)
   - `pefile==2023.2.7` (PE header analysis and Authenticode parsing)
   - `pywin32==306` (Win32 API bindings for Windows Registry, Wintrust, and COM)
   - `wmi==1.5.1` (Windows Management Instrumentation client)
   - `pytest==8.3.3` (Automated testing framework)

---

## 3. Configuration Management (`config.py`)

All system constants, operational intervals, and detection thresholds are centralized in `config.py`.

| Configuration Key | Default Value | Description |
| :--- | :---: | :--- |
| `SCAN_INTERVAL_SECONDS` | `10` | Frequency of automated background scan cycles (in seconds) |
| `DB_PATH` | `"ghosthunt.db"` | SQLite database file path (created automatically in WAL mode) |
| `RISK_WEIGHT_PROCESS_VIEW` | `0.40` | Signal 1 weight (Cross-view process enumeration) |
| `RISK_WEIGHT_PERSISTENCE` | `0.30` | Signal 2 weight (Persistence autostart monitoring) |
| `RISK_WEIGHT_SIGNATURE` | `0.30` | Signal 3 weight (Dual-path signature verification) |
| `RISK_THRESHOLD_HIGH` | `0.60` | Threshold for HIGH risk tier classification |
| `RISK_THRESHOLD_MEDIUM` | `0.40` | Threshold for MEDIUM risk tier classification |
| `MICRO_DELAY_SECONDS` | `0.05` | 50 ms delay between Pass 1 and Pass 2 for transient filtering |
| `CACHE_TTL_SECONDS` | `3600` | Signature cache time-to-live before revalidation (1 hour) |
| `DEFAULT_HOST` | `"127.0.0.1"` | Web dashboard bind host (strictly localhost for safety) |
| `DEFAULT_PORT` | `5000` | Web dashboard listening port |
| `FLASK_DEBUG` | `False` | Must remain `False` to preserve single-process concurrency |
| `USE_RELOADER` | `False` | Must remain `False` to prevent duplicate background schedulers |

---

## 4. Running GhostHunt

GhostHunt runs as a single-process service that simultaneously hosts the Flask dashboard web server and the background scanning scheduler daemon.

### 4.1 Launching in Production Mode
Open PowerShell as **Administrator** and run:
```powershell
python run.py
```
Expected output:
```text
======================================================================
GhostHunt — Stealth Malware & Rootkit Detection System
======================================================================
[+] Database initialized at: ghosthunt.db
[+] Background scheduler initialized (Interval: 10s)
[+] Background scheduler thread started successfully
[+] Starting Flask Dashboard on http://127.0.0.1:5000
======================================================================
```

### 4.2 Command-Line Flags
`run.py` supports several operational arguments:
```powershell
# Custom port and binding
python run.py --host 127.0.0.1 --port 8080

# Custom scan interval (e.g. every 30 seconds)
python run.py --interval 30

# Web-only mode without the automatic background scheduler daemon
python run.py --no-scheduler

# Custom SQLite database location
python run.py --db custom_ghosthunt.db
```

---

## 5. Web Dashboard Walkthrough

Open your web browser and navigate to: **`http://127.0.0.1:5000`**

### 5.1 Main Security Dashboard (`/`)
- **Quick Metrics Bar:** Displays Total Scans Executed, Latest Scan Duration, Active High-Risk Entities, and Scheduler Daemon Status.
- **Trigger Manual Scan Button:** Allows on-demand triggering of an immediate scan cycle (`POST /api/scan`). Returns an alert if a scan is already running.
- **Risk-Ranked Entities Table:** Lists all active entities ordered by composite risk score (High $\ge 0.60$ in red, Medium $[0.40, 0.60)$ in amber, Low $< 0.40$ in cyan). Displays PID, Process Name, Triggered Signals, Threat Count, and Composite Score.
- **Entity Drill-down:** Click on any process row or the "Inspect" button to open the forensic detail inspector for that PID.

### 5.2 Forensic Process Detail Page (`/process/<pid>`)
- **Metadata Card:** Displays executable path, process name, PID, and component risk scores ($S_{\text{PV}}, S_{\text{PER}}, S_{\text{SIG}}$).
- **Forensic Threat Evidence Tab:** Displays concrete threat findings (`score_eligible = 1`) including omission views, suspicious filesystem paths, or persistence modifications.
- **Operational Diagnostics Tab:** Displays system diagnostic events (`score_eligible = 0`) such as API query timings and handled timeouts, providing total transparency without inflating risk scores.

### 5.3 Baseline Management & Acceptance Workflow
On first run, persistence categories reside in the `CANDIDATE_REVIEW` state.
- **Candidate Inventory Table:** Review all autostart entries discovered on the system.
- **"Accept Baseline" Button:** Click to accept the candidate inventory. GhostHunt executes an atomic transaction promoting entries to `ACCEPTED_TRUSTED`. From that moment onward, deviations generate threat alerts.
- **"Reset Baselines" Button:** Atomically resets all persistence categories to `NOT_INITIALIZED`, requiring a new candidate capture cycle.

### 5.4 Scan History Explorer (`/history`)
- Chronological table of all past scans.
- Displays Scan ID, Start Time, Completion Time, Duration (ms), Status (`COMPLETED` or `FAILED`), and Findings Count.
- Click "View Scan" to inspect historical snapshots.

### 5.5 Academic Simulation Lab (`/simulations`)
- Dedicated visual interface for university evaluators and security analysts.
- **Interactive Scenarios:** Contains cards for all 24 simulation scenarios (PV-1..5, PER-1..4, SIG-1..5, and End-to-End Scenarios A through J).
- **One-Click Execution:** Click "Run Scenario" on any scenario to execute it safely in an isolated temporary environment with millisecond timing metadata.
- **Run All Button:** Executes all 24 scenarios in sequence and renders a real-time pass/fail summary.

---

## 6. Command-Line Simulation & Test Utilities

GhostHunt includes automated test suites and evaluation scripts:

### 6.1 Complete Simulation Scenario Runner
Execute the complete scenario suite from the command line:
```powershell
python simulators/scenario_runner.py --all
```
Run an individual scenario:
```powershell
python simulators/scenario_runner.py --scenario SCENARIO-G
```

### 6.2 Empirical Benchmarking Suite
Measure real hardware latencies, resource utilization, and cache efficacy:
```powershell
# Run 10 repetitions across all modules
python simulators/benchmark.py 10
```
Results are saved to `Docs/benchmark_data.json`.

### 6.3 Automated Regression Unit Test Suite
Execute all 261 test executions across 27 test classes:
```powershell
python -m unittest discover -v -s tests -p "test_*.py"
```

---

## 7. REST API Reference

All REST API endpoints exchange standard JSON payloads.

| Endpoint URI | Method | Description | Example Request / Response |
| :--- | :---: | :--- | :--- |
| `/api/health` | GET | Check service health and DB connectivity | `curl http://127.0.0.1:5000/api/health`<br>`{"status": "ok", "version": "1.4.3"}` |
| `/api/scan` | POST | Trigger manual scan cycle | Returns `200 OK` on success, or `409 Conflict` if busy |
| `/api/scan/latest` | GET | Retrieve latest completed scan summary | `{"id": 42, "status": "COMPLETED", "duration_ms": 3520.1}` |
| `/api/scan/<id>` | GET | Retrieve metadata for a specific scan ID | Returns scan execution timing and status |
| `/api/scores` | GET | Risk-ranked process scores for latest scan | Returns list of entities with composite scores |
| `/api/findings/<scan_id>` | GET | Findings for a specific scan ID | Supports `?type=threat` or `?type=diagnostic` |
| `/api/process/<pid>/findings` | GET | Findings for a specific PID | Returns categorized threat vs diagnostic findings |
| `/api/baseline` | GET | Query status of 3 persistence categories | `{"registry": "ACCEPTED_TRUSTED", ...}` |
| `/api/baseline/accept` | POST | Explicitly accept candidate baseline | `curl -X POST http://127.0.0.1:5000/api/baseline/accept` |
| `/api/baseline/reset` | POST | Hard reset of reference baseline | Payload: `{"confirm": true}` |
| `/api/scenarios` | GET | List all 24 simulation scenarios | Returns scenario IDs, names, and descriptions |
| `/api/scenarios/run` | POST | Execute a scenario via API | Payload: `{"scenario_id": "SCENARIO-E"}` |
| `/api/history` | GET | Query paginated historical scan logs | Supports `?page=1&per_page=20` |

---

## 8. Operational Troubleshooting & Diagnostics

- **Issue: `POST /api/scan` returns HTTP 409 Conflict**  
  *Cause:* Another scan, baseline acceptance, or baseline reset is currently executing under the shared in-process lock (`threading.RLock()`).  
  *Solution:* Wait a few seconds for the current scan cycle to complete, or inspect the dashboard header.
- **Issue: "Minimum quorum (< 2 successful sources) not met" in Diagnostics**  
  *Cause:* Two or more process enumeration sources failed simultaneously (e.g. standard user permissions preventing WMI and NT API access).  
  *Solution:* Run PowerShell as Administrator. GhostHunt safely aborted the comparison to avoid false alerts.
- **Issue: Tasks or Services show "ENUMERATION_FAILED"**  
  *Cause:* Service Control Manager or Task Scheduler RPC service was temporarily unavailable or access was denied.  
  *Solution:* GhostHunt's gated diffing automatically preserved your accepted baseline reference without false removals. Check Windows Event Viewer for RPC/SCM health.
