# GhostHunt — System Architecture & Security Analysis

**Document Version:** 1.4.3  
**Target Platform:** Windows 10 / Windows 11 (x64)  
**Architecture:** Python 3.10+ / Flask / SQLite WAL / Win32 User-Mode APIs  
**Academic Context:** Senior Undergraduate Capstone Project  
**Date:** November 2026  

---

## 1. System Overview

GhostHunt is a defensive, host-based stealth malware and user-mode rootkit detection system for Windows 10/11 x64. Unlike signature-only antivirus scanners or invasive kernel drivers, GhostHunt operates entirely in user-mode using a multi-signal behavioral anomaly architecture. It correlates independent indicators of compromise (IoCs) across three distinct defensive domains:

1. **Cross-View Process Enumeration (Signal 1 — Weight: 0.40):** Cross-compares active process tables across three distinct enumeration paths (Win32 Toolhelp32, WMI COM/PowerShell CIM, and Native NT API `NtQuerySystemInformation`) with quorum requirements and two-pass micro-delay confirmation to uncover hidden processes.
2. **Persistence Monitoring (Signal 2 — Weight: 0.30):** Monitors autostart execution points across 32-bit and 64-bit Registry Run/RunOnce keys, Scheduled Tasks, and Windows Services, evaluating deviations strictly against explicitly operator-reviewed and accepted reference baselines.
3. **Loaded Module Signature & Path Anomaly Verification (Signal 3 — Weight: 0.30):** Enforces Authenticode embedded signatures and Windows Security Catalog bindings via `Wintrust.dll` using a 16-combination reconciliation matrix, alongside filesystem path anomaly detection (%TEMP%, %APPDATA%, Desktop, Downloads, root directory).

Risk scores are computed through a linear multi-signal model:
$$\text{Score} = w_{\text{PV}} \cdot S_{\text{PV}} + w_{\text{PER}} \cdot S_{\text{PER}} + w_{\text{SIG}} \cdot S_{\text{SIG}} = 0.40 \cdot S_{\text{PV}} + 0.30 \cdot S_{\text{PER}} + 0.30 \cdot S_{\text{SIG}}$$

Entities scoring $\ge 0.60$ are classified as **HIGH** risk, $[0.40, 0.60)$ as **MEDIUM**, and $< 0.40$ as **LOW**.

---

## 2. High-Level Architecture & Data Flow

GhostHunt is architected as an integrated single-process application containing four modular subsystems:
- **`core/`**: Central Data Access Layer (`db.py`), Multi-Signal Risk Correlator (`correlator.py`), and In-Process Concurrency-Guarded Background Scheduler (`scheduler.py`).
- **`detectors/`**: Detector facades re-exporting underlying engines (`process_view.py`, `persistence.py`, `signature_check.py`).
- **`dashboard/`**: Flask web presentation layer and REST API (`routes.py`, Jinja2 templates, and responsive JavaScript).
- **`simulators/`**: Harmless academic simulation harness executing controlled validation scenarios with automated cleanup.

```mermaid
flowchart TD
    subgraph Host ["Windows 10/11 x64 Host Subsystems"]
        TH32["Win32 Toolhelp32 API"]
        WMI["WMI / CIM Subsystem"]
        NTAPI["ntdll.dll NtQuerySystemInformation"]
        REG["Windows Registry (HKLM/HKCU 32/64-bit)"]
        TASKS["Task Scheduler (schtasks / CIM)"]
        SVCS["Service Control Manager (advapi32 / CIM)"]
        WINTRUST["Wintrust.dll (WinVerifyTrust & Catalog)"]
        FS["Filesystem & PE Headers"]
    end

    subgraph Detectors ["GhostHunt Detection Engines"]
        PV["Signal 1: Process Views Engine<br/>(core.process_views)"]
        PER["Signal 2: Persistence Engine<br/>(core.persistence)"]
        SIG["Signal 3: Signatures Engine<br/>(core.signatures)"]
    end

    subgraph Storage ["SQLite Data Access Layer (WAL Mode)"]
        DB[("ghosthunt.db<br/>ON DELETE RESTRICT")]
    end

    subgraph Correlation ["Multi-Signal Correlation Engine"]
        CORR["Risk Correlator<br/>(core.correlator)<br/>Linear Weights: 0.40 / 0.30 / 0.30"]
    end

    subgraph Presentation ["Presentation & Control Layer"]
        SCHED["Background Scheduler Daemon<br/>(core.scheduler)"]
        API["Flask REST API & Web UI<br/>(dashboard)"]
        LOCK{{"threading.RLock()<br/>Concurrency Guard"}}
    end

    TH32 --> PV
    WMI --> PV
    NTAPI --> PV
    REG --> PER
    TASKS --> PER
    SVCS --> PER
    WINTRUST --> SIG
    FS --> SIG

    SCHED -- "Every 10s Cycle" --> LOCK
    API -- "Manual Scan / Accept / Reset" --> LOCK
    LOCK --> PV
    LOCK --> PER
    LOCK --> SIG

    PV --> CORR
    PER --> CORR
    SIG --> CORR

    CORR --> DB
    DB --> API
```

---

## 3. Detailed Component Architecture

### 3.1 Multi-Signal Correlation & Risk Scoring Flow

GhostHunt strictly isolates forensic threats from operational diagnostics. Operational diagnostics (e.g., query timeouts, permission limitations) are tagged `score_eligible = 0` and never contribute to entity risk scores. Threat findings (`score_eligible = 1`) contribute to the corresponding signal score component ($S_{\text{PV}}, S_{\text{PER}}, S_{\text{SIG}} \in \{0.0, 1.0\}$). Findings are deduplicated and mapped to active processes using a dual-key strategy (`pid:<PID>` if running, or `system:<category>:<name>` for dormant persistence entries).

```mermaid
flowchart TD
    F_IN["Raw Findings Stream (Signal 1, 2, 3)"] --> CHK{"Is finding_type == 'diagnostic'?"}
    
    CHK -- "Yes" --> DIAG["score_eligible = 0<br/>Diagnostic Logged for Audit Trail<br/>Zero Contribution to Risk Score"]
    CHK -- "No (Threat)" --> THREAT["score_eligible = 1<br/>Group by Entity Key (pid or system)"]
    
    THREAT --> MAP["Extract Triggered Signals per Entity:<br/>- Has Process View Threat? (S_PV = 1.0)<br/>- Has Persistence Threat? (S_PER = 1.0)<br/>- Has Signature Threat? (S_SIG = 1.0)"]
    
    MAP --> CALC["Compute Linear Risk Score:<br/>Score = 0.40*S_PV + 0.30*S_PER + 0.30*S_SIG"]
    
    CALC --> TIER{"Evaluate Risk Tier"}
    TIER -- "Score >= 0.60" --> HIGH["HIGH Risk Tier<br/>(Multi-signal correlation confirmed)"]
    TIER -- "0.40 <= Score < 0.60" --> MED["MEDIUM Risk Tier<br/>(Process discrepancy or moderate IoC)"]
    TIER -- "Score < 0.40" --> LOW["LOW Risk Tier<br/>(Single isolated persistence/signature IoC)"]

    HIGH --> PERSIST["Atomic SQLite Transaction:<br/>Insert findings & risk_scores<br/>Update scan status to 'COMPLETED'"]
    MED --> PERSIST
    LOW --> PERSIST
    DIAG --> PERSIST
```

### 3.2 Cross-View Process Enumeration Flow

The Process Views engine acquires process lists from three distinct system interfaces. To prevent false alarms caused by fast-exiting transient processes, any discrepancy detected in Pass 1 is re-evaluated after a 50 ms micro-delay (`MICRO_DELAY_SECONDS = 0.05`). A minimum quorum of $\ge 2$ operational sources is required; if fewer than 2 sources succeed, comparison is aborted and an operational diagnostic is emitted.

```mermaid
flowchart TD
    START["Initiate Process-View Scan"] --> P1["Pass 1: Query All 3 Independent Views"]
    P1 --> Q_TH["Win32 Toolhelp32 Snapshot"]
    P1 --> Q_WMI["WMI CIM / COM Query"]
    P1 --> Q_NT["Native NtQuerySystemInformation"]
    
    Q_TH --> QUORUM{"Successful Sources >= 2?"}
    Q_WMI --> QUORUM
    Q_NT --> QUORUM
    
    QUORUM -- "No (< 2 Successful)" --> ABORT["Abort Cross-Comparison<br/>Emit Operational Diagnostic<br/>score_eligible = 0, 0 False Threats"]
    
    QUORUM -- "Yes (>= 2 Successful)" --> DIFF1["Pass 1 View Comparison<br/>Exclude failed sources from missing checks"]
    
    DIFF1 --> DISC{"Any Discrepancies Found?"}
    DISC -- "No" --> CLEAN["Return Clean (0 Findings)"]
    
    DISC -- "Yes" --> DELAY["Micro-Delay Sleep (50 ms)"]
    DELAY --> P2["Pass 2: Re-query Views for Discrepant PIDs"]
    
    P2 --> CONFIRM{"Does Discrepancy Persist in Pass 2?"}
    CONFIRM -- "No (Process exited or resolved)" --> TRANSIENT["Discard as Transient Exit<br/>0 Threat Findings"]
    CONFIRM -- "Yes" --> EMIT_THREAT["Emit Confirmed Process Threat<br/>finding_type = 'threat', score_eligible = 1<br/>Severity: HIGH"]
```

### 3.3 Persistence Baseline Lifecycle State Machine

GhostHunt treats baseline management as an explicit, auditable security ceremony. Systems are never assumed clean on first launch. The baseline state machine enforces that autostart entries discovered during uninitialized states are captured as candidate inventories requiring operator inspection and explicit cryptographic acceptance.

```mermaid
stateDiagram-v2
    [*] --> NOT_INITIALIZED: Database Initialization / Hard Reset
    
    NOT_INITIALIZED --> CANDIDATE_REVIEW: First Successful Enumeration<br/>(Atomic candidate inventory captured, is_candidate = 1)
    
    CANDIDATE_REVIEW --> CANDIDATE_REVIEW: Subsequent Scans While Pending<br/>(Diffing suppressed, 0 threat findings, diagnostic emitted)
    
    CANDIDATE_REVIEW --> ACCEPTED_TRUSTED: Explicit Operator Acceptance<br/>(POST /api/baseline/accept, is_candidate = 0)
    
    ACCEPTED_TRUSTED --> ACCEPTED_TRUSTED: Regular Scanning Cycle<br/>(Full diffing active: Added, Modified, Removed emit threats)
    
    ACCEPTED_TRUSTED --> ENUMERATION_FAILED: Query Timeout / Access Denied<br/>(Gated diffing skips diff, accepted reference preserved)
    
    ENUMERATION_FAILED --> ACCEPTED_TRUSTED: Query Recovers Next Cycle<br/>(Diffing resumes against existing accepted reference)
    
    ACCEPTED_TRUSTED --> NOT_INITIALIZED: Operator Hard Reset<br/>(POST /api/baseline/reset, confirms required)
    CANDIDATE_REVIEW --> NOT_INITIALIZED: Operator Hard Reset
```

### 3.4 Dual-Path Signature Verification Matrix Flow

The Signature Verification engine subjects loaded executable modules to a dual-path verification process: WinVerifyTrust Authenticode checking and Windows Security Catalog checking. Results are reconciled through an exhaustive 4×4 decision matrix ensuring operational errors never convert into unsigned verdicts.

```mermaid
flowchart TD
    MOD["Inspect Module (.exe / .dll)"] --> PATH_CHK{"Is Path Suspicious?<br/>(%TEMP%, %APPDATA%, Desktop, Downloads, Drive Root)"}
    
    PATH_CHK -- "Yes" --> FLAG_PATH["Flag Path Anomaly IoC<br/>Severity: HIGH"]
    PATH_CHK -- "No" --> CHECK_CACHE{"In Verification Cache?<br/>(Canonical Path + Size + Timestamp)"}
    FLAG_PATH --> CHECK_CACHE
    
    CHECK_CACHE -- "Cache Hit (Valid TTL)" --> USE_CACHED["Return Cached Verification Record"]
    
    CHECK_CACHE -- "Cache Miss / Invalidated" --> DUAL_VERIFY["Execute Dual-Path Verification:<br/>1. Embedded Authenticode (WinVerifyTrust)<br/>2. Windows Catalog Lookup (CryptCATAdmin)"]
    
    DUAL_VERIFY --> MATRIX{"Apply 16-Combination Reconciliation Matrix"}
    
    MATRIX -- "Embedded VALID or Catalog VALID" --> RET_VALID["Status: VALID<br/>Cache as VALID<br/>0 Threat Findings"]
    MATRIX -- "Both UNSIGNED" --> RET_UNS["Status: UNSIGNED<br/>If Path Anomalous -> Threat (score_eligible = 1)<br/>If Normal System Path -> Low Threat"]
    MATRIX -- "Either INVALID (Tampered)" --> RET_INV["Status: INVALID<br/>Threat Finding (score_eligible = 1, Severity: HIGH)"]
    MATRIX -- "Operational ERROR (I/O, Access)" --> RET_ERR["Status: ERROR<br/>Emit Diagnostic Finding (score_eligible = 0)"]
    
    RET_VALID --> UPDATE_CACHE["Update Hybrid Verification Cache"]
    RET_UNS --> UPDATE_CACHE
    RET_INV --> UPDATE_CACHE
```

---

## 4. Security Model & Defensive Invariants

### 4.1 Strict Diagnostic-Threat Isolation Invariant
GhostHunt guarantees that administrative, environment, and communication failures never trigger false malware alerts.
$$\forall f \in \text{findings}: \left( f.\text{finding\_type} = \text{'diagnostic'} \implies f.\text{score\_eligible} = 0 \right)$$
This invariant is enforced at three independent layers:
1. **Engine Level:** Detectors assign `finding_type` and `score_eligible` explicitly.
2. **Data Access Layer Level:** `db.validate_finding()` rejects contradictory inputs before executing SQL.
3. **Database Schema Level:** SQLite table definition includes a table-level CHECK constraint:
   ```sql
   CONSTRAINT chk_diagnostic_invariants CHECK (
       (finding_type = 'diagnostic' AND score_eligible = 0) OR
       (finding_type = 'threat' AND score_eligible IN (0, 1))
   )
   ```

### 4.2 In-Process Concurrency & Re-Entrancy Control
The application operates within a single Python process protected by a global re-entrant synchronization primitive (`threading.RLock()`). 
- Scheduled scans, manual scans (`POST /api/scan`), baseline acceptances (`POST /api/baseline/accept`), and baseline resets (`POST /api/baseline/reset`) compete for the shared operation lock.
- If an operation is already executing, concurrent requests immediately return **HTTP 409 Conflict** with an informative JSON payload (`{"status": "busy", "message": "Operation already in progress"}`).
- The Flask presentation server is explicitly deployed with `debug=False` and `use_reloader=False` to prevent duplicate worker forks or lock bypasses.

### 4.3 SQLite WAL Mode & Historical Forensic Immutability
- SQLite is configured with **Write-Ahead Logging (WAL)** (`PRAGMA journal_mode = WAL;`) and synchronous normal mode (`PRAGMA synchronous = NORMAL;`), allowing concurrent read operations without blocking scan writes.
- Foreign keys are enforced strictly (`PRAGMA foreign_keys = ON;`). Child tables (`findings`, `risk_scores`) define `ON DELETE RESTRICT` constraints referencing `scans(id)`.
- Scans and findings are strictly append-only. Automated pruning or cascading deletions are architecturally prohibited to preserve forensic non-repudiation.
