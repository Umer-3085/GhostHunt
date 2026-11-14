# GhostHunt — Technical Limitations & Security Boundaries

**Document Version:** 1.4.3  
**Target Platform:** Windows 10 / Windows 11 (x64)  
**Security Model:** Defensive User-Mode Anomaly Detection  
**Academic Context:** Senior Undergraduate Capstone Project  
**Date:** November 2026  

---

## 1. Architectural Scope & User-Mode Boundaries

GhostHunt is intentionally designed as a lightweight, user-mode defensive monitoring system. It operates without deploying kernel-mode drivers (`.sys`), installing hypervisors, injecting hooking code into running processes, or modifying Windows operating system binaries.

While this architecture guarantees complete operating system stability, avoids Blue Screen of Death (BSOD) crashes, and requires no kernel-mode code-signing certificates, it introduces fundamental technical boundaries when defending against sophisticated kernel-level threats.

---

## 2. Kernel-Mode Rootkits & Direct Kernel Object Manipulation (DKOM)

### 2.1 The Shared Kernel Dependency Boundary
All three process enumeration paths queried by Signal 1 (`Toolhelp32`, `WMI Win32_Process`, and `ntdll.dll!NtQuerySystemInformation`) originate in user-mode and eventually transition across the user-kernel boundary via syscalls into `ntoskrnl.exe`. Within the Windows kernel, each of these interfaces queries common underlying kernel data structures:
- The active process linked list (`PsActiveProcessHead` traversing `ActiveProcessLinks` in the `EPROCESS` executive block).
- Handle tables and thread structures (`KPROCESS` / `ETHREAD`).

### 2.2 Direct Kernel Object Manipulation (DKOM)
If an adversary has acquired Ring 0 (kernel-mode) execution privilege (e.g., via a vulnerable signed driver exploit / BYOVD attack):
- **Unlinking `ActiveProcessLinks`:** The rootkit can unhook an `EPROCESS` block from the circular double-linked list (`Flink` / `Blink`).
- **Impact on GhostHunt:** Because all three user-mode enumeration mechanisms rely on kernel APIs that traverse `ActiveProcessLinks`, an unlinked process will be omitted from **all three views simultaneously**. 
- **Defensive Reality:** GhostHunt detects discrepancies *between* views. If an adversary hides from all views equally at the kernel scheduler level without leaving artifacts in any user-mode view, cross-view comparison will perceive a consistent view set and will not trigger a Process View discrepancy.

### 2.3 Hypervisor-Level (Ring -1) Rootkits
Rootkits operating beneath the operating system kernel within the hypervisor layer (e.g., Blue Pill style virtual machine rootkits) possess arbitrary read/write control over guest memory and virtual address translation. Such hypervisor-level manipulations cannot be observed or detected from Windows user-mode.

---

## 3. In-Memory Execution, Process Hollowing & Reflective Code Injection

### 3.1 Unbacked Memory Execution
Signal 3 (Loaded Module Verification) inspects loaded modules by traversing the Process Environment Block's loader data (`PEB.Ldr.InLoadOrderModuleList`) and querying Windows Memory APIs (`VirtualQueryEx`, `EnumProcessModulesEx`).
- **Reflective DLL Injection:** Adversaries who inject DLLs directly into target process memory without invoking standard Windows loader APIs (`LoadLibraryExW`) avoid creating entries in `InLoadOrderModuleList`.
- **Process Hollowing & Unbacked Executable Memory:** Shellcode and unbacked executable allocations (`PAGE_EXECUTE_READWRITE` without a backing PE file on disk) do not have a disk-backed file path for `WinVerifyTrust` or Catalog inspection.
- **Defensive Boundary:** Signal 3 evaluates PE files loaded into module tables. In-memory shellcode execution without registered PE headers must be addressed by dedicated memory scanners or EDR hooks, which are outside GhostHunt's user-mode scope.

---

## 4. Privilege Levels & Operating System Access Controls

GhostHunt requires administrative execution privilege to perform comprehensive host monitoring. When running under lower privileges, specific capabilities are naturally constrained:

| Subsystem | Running as Standard User | Running as Administrator | Running as Local SYSTEM |
| :--- | :--- | :--- | :--- |
| **Win32 Toolhelp32** | Enumerates user processes only | Enumerates all host processes | Enumerates all host processes |
| **Native NT API** | Enumerates system process IDs | Enumerates all host processes | Enumerates all host processes |
| **Service Control Manager** | Read access to public services; `OpenSCManagerW` error 5 on restricted | Full enumeration of all installed services and configs | Full enumeration and internal status inspection |
| **Task Scheduler** | Queries user-scheduled tasks | Queries system and admin scheduled tasks | Complete task database access |
| **Windows Catalog Admin** | `CryptCATAdminAcquireContext` succeeds | Full catalog lookup access | Full catalog lookup access |
| **64-bit Registry Run Keys** | Read access to `HKCU` and `HKLM` | Full read access across 32-bit and 64-bit views | Full read access across all registry hives |

*Operational Failure Handling:* When GhostHunt encounters permission restrictions, it emits an explicit operational diagnostic (`finding_type = 'diagnostic'`, `score_eligible = 0`) and isolates the failed source, preventing false threat alarms.

---

## 5. Time-of-Check to Time-of-Wait (TOCTOU) & Transient Fast-Exiting Processes

In a high-throughput multitasking operating system, processes constantly spawn, execute briefly (e.g., CLI compilers, batch scripts, telemetry workers), and terminate within milliseconds.
- **Race Condition Window:** A process might exist when Toolhelp32 snapshots the system, but terminate before WMI or `NtQuerySystemInformation` queries the kernel.
- **Mitigation & Boundary:** GhostHunt incorporates a **50 ms micro-delay two-pass confirmation filter** (`MICRO_DELAY_SECONDS = 0.05`). Discrepancies are re-evaluated in Pass 2. If positive evidence demonstrates that the process exited, the alert is dismissed as transient. However, highly adversarial processes that intentionally oscillate execution state within sub-millisecond windows present an inherent race condition for any polling-based architecture.

---

## 6. Pre-Existing Persistence & Reference Baseline Assumptions

GhostHunt's persistence engine relies on a reference baseline model:
- **Baseline State Machine:** On initial execution, the host's existing startup configurations are captured as a **Candidate Baseline** (`is_candidate = 1`, `CANDIDATE_REVIEW`).
- **Security Assumption:** GhostHunt assumes the operator inspects the candidate baseline before approving it via `POST /api/baseline/accept`.
- **Pre-Existing Compromise Boundary:** If a host machine is *already compromised* before GhostHunt is installed, and the security administrator blindly accepts the candidate baseline without reviewing the discovered entries, that pre-existing persistence mechanism becomes part of the trusted reference inventory. Subsequent scans diff against this accepted baseline and will not flag the pre-existing entry as an "addition."
- **Mitigation:** The GhostHunt dashboard provides an explicit baseline review table displaying every discovered entry, key, and fingerprint, requiring conscious human review before trust is granted.

---

## 7. No Automated Remediation or Active Defense by Design

GhostHunt is strictly a **detection, forensic visibility, and risk correlation platform**.
- **Architectural Policy:** GhostHunt does not terminate processes (`TerminateProcess`), unregister scheduled tasks, delete registry autorun keys, quarantine files, or inject code into running binaries.
- **Rationale:** Automated remediation in user-mode risks inducing Denial of Service (DoS) conditions against critical operating system services or user applications in the event of misclassification. GhostHunt presents structured, explainable forensic evidence to security analysts, leaving remediation decisions to human operators and established incident response workflows.
