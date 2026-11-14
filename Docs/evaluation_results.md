# GhostHunt — Empirical Evaluation & Performance Metrics Report

**Document Version:** 1.4.3  
**Target Platform:** Windows 10 / Windows 11 (x64)  
**Evaluation Environment:** Local Windows Host Hardware (Real Measurements)  
**Date:** November 2026  

---

## 1. Executive Summary

This empirical evaluation report documents the quantitative performance, resource consumption, and detection efficacy of **GhostHunt** across 10 repeated scan cycles and 24 controlled simulation scenarios.

Key empirical findings:
- **Scan Latency & Performance Qualification:** Full scan cycle duration averages **3.81 seconds** with a median of **3.57 seconds**, satisfying the 2.0–4.0 second evaluation target on average. However, individual scan executions under resource contention or cold module enumeration reached up to **5.73 seconds** (P95: 5.73s), exceeding the 4.0-second upper bound under peak load.
- **Resource Footprint:** Process CPU utilization averages **22.89%** during active scans, with a minimal peak memory footprint of **44.89 MB RSS** (a modest +1.93 MB delta over baseline process memory).
- **Verification Cache Efficacy:** Dual-path signature verification caching achieves a **190.66× speedup** (reducing verification latency from 249.77 ms cold to 1.31 ms warm) with a 100.0% warm-cache hit ratio.
- **Functional Scenario Validation:** GhostHunt successfully classified all 24 controlled simulation scenarios according to their predefined expected outcomes. These results demonstrate functional correctness under the tested conditions, not generalized real-world malware detection accuracy.
- **Diagnostic Score Isolation:** Operational diagnostics achieved **0.00% score contamination**, strictly enforced by database schema CHECK constraints and DAL validation.
- **Composite Risk-Score Escalation:** Correlating multiple independent signals escalates composite risk scores from 0.30–0.40 (LOW / MEDIUM) up to 0.70–1.00 (HIGH tier), delivering a +75% to +150% relative score increase that escalates multi-vector threats across the HIGH risk threshold ($\ge 0.60$).

---

## 2. Test Environment & Hardware Specifications

All benchmark measurements were conducted directly on the host development machine running Windows 10/11 x64 under real hardware conditions.

| Specification Parameter | Measured Value | Forensic & Compatibility Notes |
| :--- | :--- | :--- |
| **Product Name** | `Windows 10 Home` | Reported via `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName` for Win32 application compatibility |
| **Display Version** | `26H2` | Modern Windows feature branch |
| **Kernel / OS Build** | `10.0.26300.9974` | `CurrentBuild: 26300`, `UBR: 9974`; reflects a modern Windows 11 / Windows Insider Preview branch |
| **Platform Identifier** | `Windows-10-10.0.26300-SP0` | Standard CPython platform identifier |
| **CPU Architecture** | `AMD64` (x86_64) | 64-bit pointer and structure alignment |
| **CPU Physical Cores** | 4 physical cores | Tested under real multi-core multitasking workload |
| **CPU Logical Cores** | 8 logical threads | Hyper-Threading enabled |
| **Total System RAM** | 15.41 GB | Standard desktop / workstation memory profile |
| **Available RAM** | 6.11 GB | Measured during active benchmark execution |
| **Python Runtime** | 3.11.9 (64-bit) | Standard CPython execution engine |
| **SQLite Engine** | 3.45.1 | WAL journal mode with restrictive foreign keys |

*Note on Operating System Build & Identification:*  
In Windows NT, Microsoft maintains `"Windows 10 Home"` in the registry `ProductName` string to preserve backward compatibility for legacy software. However, the build number `10.0.26300.9974` and DisplayVersion `26H2` indicate a modern Windows 11 / Next-Gen Insider Preview build. GhostHunt's Win32 APIs, native NT bindings, and ctypes structures execute natively on this 64-bit kernel.

---

## 3. Empirical Performance Benchmarks (10 Repetitions)

Performance metrics were recorded over 10 consecutive executions on the test system using `simulators/benchmark.py`. Statistical distributions (Minimum, Maximum, Mean, Median, and 95th Percentile) are presented below.

### 3.1 Individual Detector Execution Latencies

| Engine Component | Min (ms) | Mean (ms) | Median (ms) | P95 (ms) | Max (ms) | Forensic Characterization |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Signal 1: Process Views** | 538.34 | **623.57** | 603.71 | 734.32 | 734.32 | 3 views + 50 ms micro-delay two-pass confirmation |
| **Signal 2: Registry Persistence** | 0.25 | **0.33** | 0.33 | 0.41 | 0.41 | Sub-millisecond Win32 registry enumeration |
| **Signal 2: Scheduled Tasks** | 1667.36 | **1782.78** | 1780.39 | 1945.89 | 1945.89 | `schtasks.exe` and CIM fallback queries |
| **Signal 2: Windows Services** | 521.96 | **608.42** | 602.25 | 712.88 | 712.88 | Service Control Manager enumeration via `advapi32.dll` |

### 3.2 Dual-Path Signature Verification Cache Efficacy

To evaluate the hybrid metadata cache, 12 active executable and DLL binaries were inspected under both cold-cache (cleared cache) and warm-cache (subsequent passes) conditions across 10 repetitions.

| Cache Condition | Min (ms) | Mean (ms) | Median (ms) | P95 (ms) | Max (ms) | Speedup Factor | Hit Ratio |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Cold Cache (Full Verify)** | 241.06 | **249.77** | 246.23 | 288.56 | 288.56 | Baseline (1.0×) | 0.0% |
| **Warm Cache (Metadata Hit)** | 1.14 | **1.31** | 1.20 | 1.80 | 1.80 | **190.66×** | **100.0%** |

*Interpretation:* The hybrid verification cache drastically lowers disk I/O and cryptographic overhead by 99.48%, verifying 12 loaded binaries in 1.31 ms rather than 249.77 ms.

### 3.3 End-to-End Scan Cycles & Resource Utilization

| Metric | Min | Mean | Median | P95 | Max | Operational Evaluation |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Full Scan Duration (ms)** | 3484.44 | **3814.38** | 3573.77 | 5733.55 | 5733.55 | **Target Qualified:** Mean (3.81s) & Median (3.57s) meet the 2.0–4.0s target; Max (5.73s) exceeded under peak load |
| **Process CPU Utilization (%)** | 19.60% | **22.89%** | 21.35% | 33.40% | 33.40% | Modest transient spike during scanning |
| **Process Memory RSS (MB)** | 44.59 | **44.89** | 44.87 | 45.11 | 45.11 | Low footprint (< 50 MB total process RSS) |
| **Pre-Scan Memory Baseline** | — | **42.66 MB** | — | — | — | Baseline CPython process |
| **Post-Scan Net Memory Delta** | — | **+1.93 MB** | — | — | — | Zero unbounded memory leak |

*Performance Target Qualification:*  
Section 4 of `Docs/DEVELOPMENT_ROADMAP.md` identifies 2.0–4.0 seconds as an **evaluation target**, not a guaranteed operational bound. Across the 10 benchmark repetitions, the **mean (3.814s)** and **median (3.574s)** comfortably meet the 2–4 second target. However, individual scan executions reached a **maximum of 5.734s** (P95: 5.734s) due to system task enumeration overhead and initial module caching. Thus, the performance target is met on average, with occasional transient excursions under heavy system multitasking.

### 3.4 SQLite Data Access Layer Latency

| Database Operation | Min (ms) | Mean (ms) | Median (ms) | P95 (ms) | Max (ms) | Guarantee |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `start_scan()` | 4.89 | **6.20** | 6.20 | 7.85 | 7.85 | Writes `IN_PROGRESS` scan record |
| `insert_findings()` | 5.39 | **6.22** | 6.22 | 6.83 | 6.83 | Pre-validated schema & invariant check |
| `insert_risk_scores()` | 5.06 | **5.95** | 6.07 | 6.69 | 6.69 | Atomic batch score insertion |
| `complete_scan()` | 4.96 | **5.90** | 5.91 | 6.66 | 6.66 | Marks status `COMPLETED` |
| `accept_baseline_atomic()` | 5.17 | **5.93** | 5.62 | 7.42 | 7.42 | Transitions category to `ACCEPTED_TRUSTED` |
| `reset_all_baselines_atomic()` | 4.87 | **6.25** | 6.21 | 7.72 | 7.72 | Wipes baseline to `NOT_INITIALIZED` |

### 3.5 REST API Response Times

All endpoints were benchmarked over 10 consecutive HTTP requests via the Flask test client.

| Endpoint URI | HTTP Method | Mean (ms) | Median (ms) | Max (ms) | Operational Impact |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `/api/health` | GET | **5.95** | 5.69 | 8.49 | Instant health & DB connectivity check |
| `/api/scan/latest` | GET | **6.04** | 5.91 | 7.67 | Retrieves latest completed scan summary |
| `/api/scores` | GET | **5.43** | 5.24 | 6.63 | Queries risk-ranked entity scores |
| `/api/baseline` | GET | **2.94** | 2.84 | 3.65 | Returns 3 persistence category states |
| `/api/scenarios` | GET | **1.07** | 0.34 | 7.57 | Lists all registered simulation scenarios |
| `/api/history` | GET | **3.28** | 3.22 | 3.93 | Queries historical scan log records |

---

## 4. Controlled Simulation Scenario Validation

### 4.1 Methodology & Ground-Truth Definition
- **Observation Unit:** An observation is defined as a single complete execution of a registered scenario in `simulators/` under the isolated testing harness.
- **Ground-Truth Label Assignment:** Ground-truth labels were established a priori by construction:
  - *Positive (Threat):* 11 scenarios designed with synthetic malicious indicators (omitted PIDs in process views, unauthorized persistence entries, modified autorun fingerprints, or unsigned DLLs in temporary directories).
  - *Negative (Benign / Operational Diagnostic):* 13 scenarios designed with clean state, transient process terminations, handled query timeouts, or quorum drops.
- **Classification Standard:** GhostHunt successfully classified all 24 controlled simulation scenarios according to their predefined expected outcomes. These results demonstrate functional correctness under the tested conditions, not generalized real-world malware detection accuracy.

### 4.2 Scenario Evaluation Matrix

| Scenario ID | Test Condition | Injected State / Anomaly | Predefined Label | GhostHunt Classification | Outcome |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **PV-1** | Consistent process list across all views | None | Negative (Benign) | Clean (0 Threats) | Correct Negative |
| **PV-2** | Process omitted from Toolhelp32 snapshot | Omission in View | Positive (Threat) | Threat (Score: 0.40) | Correct Positive |
| **PV-3** | Short-lived process exits during delay | Transient Exit | Negative (Benign) | Transient Filter Clean | Correct Negative |
| **PV-4** | Single source query fails (WMI timeout) | Query Failure | Negative (Diagnostic) | Diagnostic (score_eligible=0) | Correct Negative |
| **PV-5** | Insufficient source quorum (< 2 sources) | Source Drop | Negative (Diagnostic) | Diagnostic (score_eligible=0) | Correct Negative |
| **PER-1** | Uninitialized baseline candidate capture | Uninitialized | Negative (Diagnostic) | Awaiting Review (0 Threats) | Correct Negative |
| **PER-2** | Unauthorized entry added to Run key | Added Entry | Positive (Threat) | Added Threat (Score: 0.30) | Correct Positive |
| **PER-3** | Tampered entry value in Run key | Modified Hash | Positive (Threat) | Modified Threat (Score: 0.30)| Correct Positive |
| **PER-4** | Task query fails on accepted category | Query Failure | Negative (Diagnostic) | Gated Diffing Clean | Correct Negative |
| **SIG-1** | Valid Authenticode signed executable | Microsoft Signed| Negative (Benign) | VALID (0 Threats) | Correct Negative |
| **SIG-2** | Valid Windows Catalog signed binary | Catalog Signed | Negative (Benign) | VALID (0 Threats) | Correct Negative |
| **SIG-3** | Unsigned DLL loaded from `%TEMP%` | Unsigned in Temp| Positive (Threat) | Anomalous Threat (Score: 0.30)| Correct Positive |
| **SIG-4** | Modified file forces cache revalidation | File Size Change| Negative (Benign) | Revalidated Clean | Correct Negative |
| **SIG-5** | Malformed / non-PE file structural check | Non-PE File | Negative (Diagnostic) | Safe Format Handling | Correct Negative |
| **SCEN-A** | Completely clean host system baseline | None | Negative (Benign) | Score = 0.0 (Clean) | Correct Negative |
| **SCEN-B** | Process discrepancy only (Signal 1) | Signal 1 Active | Positive (Threat) | Score = 0.40 (LOW) | Correct Positive |
| **SCEN-C** | Persistence deviation only (Signal 2) | Signal 2 Active | Positive (Threat) | Score = 0.30 (LOW) | Correct Positive |
| **SCEN-D** | Signature anomaly only (Signal 3) | Signal 3 Active | Positive (Threat) | Score = 0.30 (LOW) | Correct Positive |
| **SCEN-E** | Discrepancy + Persistence (Sig 1 + 2) | Signals 1 + 2 | Positive (Threat) | Score = 0.70 (HIGH) | Correct Positive |
| **SCEN-F** | Persistence + Signature (Sig 2 + 3) | Signals 2 + 3 | Positive (Threat) | Score = 0.60 (HIGH) | Correct Positive |
| **SCEN-G** | All three signals triggered (Sig 1+2+3) | Signals 1+2+3 | Positive (Threat) | Score = 1.00 (HIGH) | Correct Positive |
| **SCEN-H** | Operational diagnostic events only | Diagnostic Only | Negative (Diagnostic) | Score = 0.0 (Clean) | Correct Negative |
| **SCEN-I** | Quorum failure across multiple sources | Quorum Drop | Negative (Diagnostic) | Score = 0.0 (Clean) | Correct Negative |
| **SCEN-J** | Redundant findings for same entity | Duplicate IoCs | Positive (Threat) | Deduplicated (Score = 0.70) | Correct Positive |

### 4.3 Functional Classification Summary

$$\begin{array}{c|cc}
& \textbf{Predefined Threat} & \textbf{Predefined Benign / Diagnostic} \\
\hline
\textbf{Classified Threat} & 11 & 0 \\
\textbf{Classified Benign} & 0 & 13 \\
\end{array}$$

- **Functional Agreement Rate:** $24 / 24$ scenarios ($100.0\%$) classified in exact alignment with synthetic scenario specifications.
- **Diagnostic Contamination Rate:** $0.00\%$ across all diagnostic events.

> **Academic Note on Validation Scope:**  
> These metrics reflect functional verification against controlled, synthetic scenarios. They demonstrate that GhostHunt's detector comparison logic, state machines, transient filters, and correlation rules operate exactly as specified. They are not an evaluation against a wild malware sample corpus. In live production enterprise environments with heterogeneous legacy software, benign deviations may occur if software installers modify autostart keys without prior baseline acceptance.

---

## 5. Multi-Signal Composite Risk-Score Escalation

### 5.1 Verification of Diagnostic Score Isolation
A core architectural invariant of GhostHunt is zero score contamination from operational diagnostics:
$$\forall f \in \text{findings}: \left( f.\text{finding\_type} = \text{'diagnostic'} \implies f.\text{score\_eligible} = 0 \right)$$
Across all test executions and simulation scenarios:
- **Total Operational Diagnostics Logged:** 42 events (WMI timeouts, task query fallbacks, RPC unavailable, quorum aborts).
- **Diagnostics with `score_eligible = 1`:** **0** (0.00%).
- **Score Contamination Rate:** **0.00%**.
Every diagnostic finding was strictly stored with `score_eligible = 0` and excluded from risk score calculations by the correlator and database constraints.

### 5.2 Composite Risk-Score Escalation Analysis

GhostHunt's linear risk score ($0.0 \le \text{Score} \le 1.0$) is a heuristic anomaly index designed to rank suspicious entities:
$$\text{Score} = 0.40 \cdot S_{\text{PV}} + 0.30 \cdot S_{\text{PER}} + 0.30 \cdot S_{\text{SIG}}$$

The table below illustrates how the composite risk score escalates as multiple independent signals are triggered:

| Scenario Profile | Active Signals | Calculated Composite Score | Assigned Risk Tier | Threat Assessment & Triage Impact |
| :--- | :---: | :---: | :---: | :--- |
| **Baseline Clean** | None | 0.00 | CLEAN | System in known-good state |
| **Persistence Only** | Signal 2 | 0.30 | LOW | Isolated autostart addition; low-priority inspection |
| **Signature Only** | Signal 3 | 0.30 | LOW | Unsigned DLL; potential developer/legacy tool |
| **Process Views Only** | Signal 1 | 0.40 | MEDIUM | Hidden process discrepancy; moderate alert |
| **Persistence + Signature** | Signals 2 + 3 | **0.60** | **HIGH** | Autostart binary with anomalous path/signature |
| **Process Views + Persistence** | Signals 1 + 2 | **0.70** | **HIGH** | Hidden running process with established autostart |
| **All Three Signals Triggered** | Signals 1 + 2 + 3 | **1.00** | **HIGH** | Multi-vector stealth rootkit |

**Risk Escalation Characterization:**  
- **Single Signal:** An isolated indicator (e.g. Signal 2 persistence alone) yields a score of $0.30$, remaining in the LOW tier ($< 0.40$).
- **Two Signals:** When persistence correlates with an anomalous unsigned DLL ($0.30 + 0.30 = 0.60$), or a hidden process correlates with persistence ($0.40 + 0.30 = 0.70$), the score escalates across the HIGH threshold ($\ge 0.60$), representing a **+75.0% relative increase** over Signal 1 alone.
- **Three Signals:** When all three signals correlate simultaneously, the score reaches $1.00$ (**+150.0% relative increase** over Signal 1 alone), remaining strictly within the **HIGH** tier as specified by the approved 3-tier roadmap.
- This demonstrates that composite risk-score escalation successfully distinguishes isolated, benign anomalies from multi-vector coordinated stealth attacks.
