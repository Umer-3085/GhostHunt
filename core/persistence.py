"""
GhostHunt — Phase 3: Persistence Monitoring Engine
Authoritative implementation of Signal 2 persistence mechanism inspection and baseline diffing.

Architectural Guarantees & Defensible Boundaries:
1. Three Persistence Categories Tracked Independently:
   - Registry: HKCU & HKLM Run and RunOnce in 32-bit and 64-bit views.
   - Scheduled Tasks: Windows scheduled tasks via schtasks.exe and PowerShell CIM fallback.
   - Services: Installed Windows services via SCM EnumServicesStatusExW and PowerShell fallback.
2. Controlled Fixed Reference Baseline Semantics:
   - First successful complete enumeration of an uninitialized category captures candidate
     records (is_candidate = 1) in state CANDIDATE_REVIEW. Zero threat findings emitted.
   - Pre-existing persistence mechanisms present at initial capture become part of the candidate
     baseline snapshot and are not retroactively flagged as added.
   - Deviation diffing is strictly suppressed while in CANDIDATE_REVIEW.
   - Explicit operator acceptance (POST /api/baseline/accept) promotes candidate records to ACCEPTED_TRUSTED.
   - Ordinary scans diff strictly against ACCEPTED_TRUSTED reference baselines and never silently
     update or advance the accepted baseline.
   - Discrepancies (added, modified, removed) persist across scans until remediated or reset.
3. Category Failure Isolation & Zero False Removals:
   - Every category captures independent success/failure status and error details.
   - A failed category does NOT erase or overwrite an accepted baseline.
   - Diffing is skipped for failed categories; ZERO false 'removed' findings are emitted.
   - A failure in one category never prevents the other categories from running.
4. Stable Identity Keys & Deterministic Fingerprints:
   - Every persistence item has a deterministic identity key (e.g. registry:{hive}:{view}:{path}:{name}).
   - Fingerprints use canonical sorted JSON SHA-256 serialization excluding volatile timestamps.
5. Defensive User-Mode Safety:
   - Strictly read-only enumeration.
   - No registry writes, no task modifications/deletions, no service reconfigurations/stops.
"""

import csv
import ctypes
from ctypes import wintypes
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import config
import core.db as db

logger = logging.getLogger("ghosthunt.persistence")

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import winreg
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32
else:
    winreg = None
    advapi32 = None
    kernel32 = None


# ---------------------------------------------------------------------------
# SCM / Windows Service Win32 Constants & Structures
# ---------------------------------------------------------------------------
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_WIN32 = 0x00000030
SERVICE_STATE_ALL = 0x00000003
SERVICE_QUERY_CONFIG = 0x0001
ERROR_MORE_DATA = 234
ERROR_INSUFFICIENT_BUFFER = 122


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


class QUERY_SERVICE_CONFIGW(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", wintypes.LPWSTR),
        ("lpLoadOrderGroup", wintypes.LPWSTR),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", wintypes.LPWSTR),
        ("lpServiceStartName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
    ]


SERVICE_STATE_NAMES = {
    1: "STOPPED",
    2: "START_PENDING",
    3: "STOP_PENDING",
    4: "RUNNING",
    5: "CONTINUE_PENDING",
    6: "PAUSE_PENDING",
    7: "PAUSED",
}

SERVICE_START_TYPE_NAMES = {
    0: "BOOT_START",
    1: "SYSTEM_START",
    2: "AUTO_START",
    3: "DEMAND_START",
    4: "DISABLED",
}


# ---------------------------------------------------------------------------
# Common Persistence Result & Fingerprint Helpers
# ---------------------------------------------------------------------------
def compute_fingerprint(data: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for a persistence record.
    Uses canonical JSON serialization (sorted keys, compact separators).
    Volatile attributes such as scan timestamps are excluded.
    """
    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class PersistenceEntry:
    """Structured representation of a single persistence entry."""

    def __init__(
        self,
        category: str,
        entry_key: str,
        entry_value: str,
        structured_data: Dict[str, Any],
        fingerprint: Optional[str] = None,
    ):
        self.category = str(category)
        self.entry_key = str(entry_key)
        self.entry_value = str(entry_value)
        self.structured_data = structured_data
        self.fingerprint = fingerprint or compute_fingerprint(structured_data)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_type": self.category,
            "entry_key": self.entry_key,
            "entry_value": self.entry_value,
            "fingerprint": self.fingerprint,
            "structured_data": self.structured_data,
        }

    def __repr__(self) -> str:
        return f"PersistenceEntry(cat='{self.category}', key='{self.entry_key}', fp='{self.fingerprint[:12]}...')"


class PersistenceResult:
    """Structured result returned by a persistence category enumerator."""

    def __init__(
        self,
        category: str,
        success: bool,
        entries: Optional[Dict[str, Dict[str, Any]]] = None,
        error: Optional[str] = None,
    ):
        self.category = category
        self.success = bool(success)
        self.entries = entries or {}
        self.error = error
        self.count = len(self.entries)

    def to_tuple(self) -> Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]:
        return self.success, self.entries, self.error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "success": self.success,
            "entries": self.entries,
            "error": self.error,
            "count": self.count,
        }

    def __repr__(self) -> str:
        return f"PersistenceResult(cat='{self.category}', success={self.success}, count={self.count}, error={self.error!r})"


# ---------------------------------------------------------------------------
# Category 1: Registry Autorun Enumeration
# ---------------------------------------------------------------------------
def read_registry_run_keys(
    caller: Optional[Callable[[], Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]]] = None
) -> Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Enumerates Windows autorun registry entries under HKLM and HKCU.
    Inspects configured Run and RunOnce locations in both 64-bit and 32-bit views.

    Requirements & Safeguards:
    - Uses winreg with explicit view masks (KEY_WOW64_64KEY and KEY_WOW64_32KEY).
    - Distinguishes missing keys (FileNotFoundError -> clean 0 entries) from access errors.
    - Preserves value name, data, type, hive, view, and path.
    - Generates deterministic stable identity keys and canonical fingerprints.
    - Strictly read-only: never modifies or creates keys.
    """
    if caller is not None:
        return caller()

    if not IS_WINDOWS or winreg is None:
        return False, {}, "Registry persistence enumeration is only supported on Windows hosts"

    hives = [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE),
        ("HKCU", winreg.HKEY_CURRENT_USER),
    ]
    views = [
        ("64bit", winreg.KEY_WOW64_64KEY),
        ("32bit", winreg.KEY_WOW64_32KEY),
    ]
    subkeys = list(config.STARTUP_REGISTRY_PATHS)

    entries: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    attempted_keys = 0
    successful_keys = 0

    for hive_name, hive_handle in hives:
        for view_name, view_mask in views:
            for subkey in subkeys:
                attempted_keys += 1
                try:
                    key = winreg.OpenKey(hive_handle, subkey, 0, winreg.KEY_READ | view_mask)
                except FileNotFoundError:
                    # Key does not exist on this machine; this is normal
                    successful_keys += 1
                    continue
                except PermissionError as ex:
                    errors.append(f"{hive_name}\\{subkey} ({view_name}): Access denied ({ex})")
                    continue
                except OSError as ex:
                    errors.append(f"{hive_name}\\{subkey} ({view_name}): OS error ({ex})")
                    continue

                successful_keys += 1
                try:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for idx in range(num_values):
                        try:
                            val_name, val_data, val_type = winreg.EnumValue(key, idx)
                            # Convert non-string data safely
                            if isinstance(val_data, bytes):
                                val_str = val_data.decode("utf-16le", errors="replace").rstrip("\x00")
                            else:
                                val_str = str(val_data)

                            entry_key = f"registry:{hive_name}:{view_name}:{subkey.lower()}:{val_name.lower()}"
                            struct_data = {
                                "hive": hive_name,
                                "view": view_name,
                                "path": subkey,
                                "value_name": val_name,
                                "value_data": val_str,
                                "value_type": val_type,
                            }
                            fp = compute_fingerprint(struct_data)

                            entries[entry_key] = {
                                "entry_type": "registry",
                                "entry_key": entry_key,
                                "entry_value": val_str,
                                "fingerprint": fp,
                                "structured_data": struct_data,
                            }
                        except Exception as val_ex:
                            errors.append(f"{hive_name}\\{subkey} value index {idx}: {val_ex}")
                finally:
                    winreg.CloseKey(key)

    # If all attempted keys encountered errors and none succeeded, treat as category failure
    if attempted_keys > 0 and successful_keys == 0:
        err_msg = "; ".join(errors) or "All registry autorun key attempts failed"
        return False, {}, err_msg

    err_summary = "; ".join(errors) if errors else None
    return True, entries, err_summary


# ---------------------------------------------------------------------------
# Category 2: Scheduled Task Persistence Enumeration
# ---------------------------------------------------------------------------
def _query_tasks_schtasks() -> Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Enumerates scheduled tasks using schtasks.exe /query /fo csv /v.
    Parses verbose CSV output preserving all task properties.
    """
    if not IS_WINDOWS:
        return False, {}, "schtasks is only supported on Windows"
    try:
        cmd = ["schtasks.exe", "/query", "/fo", "csv", "/v"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            err = res.stderr.strip() or f"schtasks.exe returned code {res.returncode}"
            return False, {}, f"schtasks failed: {err}"

        stdout = res.stdout.strip()
        if not stdout:
            return True, {}, None

        entries: Dict[str, Dict[str, Any]] = {}
        lines = stdout.splitlines()

        # schtasks /fo csv may output multiple header rows for task subfolders; parse safely
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith('"TaskName"'):
                continue

            try:
                reader = csv.reader([line_str])
                row = next(reader)
            except Exception:
                continue

            if not row or len(row) < 3:
                continue

            # Standard Windows /v columns:
            # 0: HostName, 1: TaskName, 2: Next Run Time, 3: Status, ...
            # In localized systems, TaskName is typically column 0 or 1
            task_name = row[1] if len(row) > 1 and row[1].startswith("\\") else row[0]
            if not task_name or task_name == "TaskName":
                continue

            task_status = row[3] if len(row) > 3 else "Unknown"
            # Task To Run (Action) is typically column 8 in English verbose schtasks
            task_action = row[8] if len(row) > 8 else "N/A"
            task_author = row[7] if len(row) > 7 else "Unknown"

            norm_name = task_name.strip().lower()
            entry_key = f"task:{norm_name}"

            struct_data = {
                "task_name": task_name.strip(),
                "status": task_status.strip(),
                "action": task_action.strip(),
                "author": task_author.strip(),
            }
            fp = compute_fingerprint(struct_data)

            entries[entry_key] = {
                "entry_type": "task",
                "entry_key": entry_key,
                "entry_value": task_action.strip(),
                "fingerprint": fp,
                "structured_data": struct_data,
            }

        return True, entries, None
    except subprocess.TimeoutExpired:
        return False, {}, "schtasks enumeration timed out after 15 seconds"
    except Exception as ex:
        return False, {}, f"schtasks enumeration exception: {ex}"


def _query_tasks_powershell() -> Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Fallback task query using PowerShell Get-ScheduledTask when schtasks encounters RPC errors.
    """
    if not IS_WINDOWS:
        return False, {}, "PowerShell task query is only supported on Windows"
    try:
        ps_cmd = (
            "Get-ScheduledTask | Select-Object TaskName, TaskPath, State, "
            "@{Name='Action';Expression={($_.Actions | ForEach-Object { \"$($_.Execute) $($_.Arguments)\".Trim() }) -join '; '}}, "
            "@{Name='Author';Expression={$_.Author}} | ConvertTo-Json -Compress"
        )
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            ps_cmd,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            err = res.stderr.strip() or f"PowerShell returned code {res.returncode}"
            return False, {}, f"PowerShell task query failed: {err}"

        stdout = res.stdout.strip()
        if not stdout:
            return True, {}, None

        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            return False, {}, f"Unexpected PowerShell JSON structure: {type(data).__name__}"

        entries: Dict[str, Dict[str, Any]] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(item.get("TaskName") or "")
            path = str(item.get("TaskPath") or "\\")
            full_path = f"{path.rstrip('/')}/{name.lstrip('/')}".replace("/", "\\")
            state = str(item.get("State") or "Unknown")
            action = str(item.get("Action") or "N/A")
            author = str(item.get("Author") or "Unknown")

            entry_key = f"task:{full_path.lower()}"
            struct_data = {
                "task_name": full_path,
                "status": state,
                "action": action,
                "author": author,
            }
            fp = compute_fingerprint(struct_data)

            entries[entry_key] = {
                "entry_type": "task",
                "entry_key": entry_key,
                "entry_value": action,
                "fingerprint": fp,
                "structured_data": struct_data,
            }

        return True, entries, None
    except subprocess.TimeoutExpired:
        return False, {}, "PowerShell task query timed out after 15 seconds"
    except Exception as ex:
        return False, {}, f"PowerShell task query exception: {ex}"


def read_scheduled_tasks(
    caller: Optional[Callable[[], Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]]] = None
) -> Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Enumerates Windows scheduled tasks via schtasks.exe with PowerShell CIM fallback.

    Requirements & Safeguards:
    - Captures task path, status, executable/action, and author.
    - Includes disabled and stopped tasks; never silently omits them.
    - Handles tasks with multiple actions or no executable action.
    - Distinguishes permission/service errors from successful empty results.
    - Strictly read-only: never modifies, enables, disables, or creates tasks.
    """
    if caller is not None:
        return caller()

    # 1. Attempt schtasks.exe
    success, entries, err = _query_tasks_schtasks()
    if success:
        return True, entries, None

    # 2. Attempt PowerShell fallback
    ps_success, ps_entries, ps_err = _query_tasks_powershell()
    if ps_success:
        return True, ps_entries, None

    combined_err = f"schtasks failed ({err}); PowerShell task query failed ({ps_err})"
    logger.warning("Scheduled task enumeration failed: %s", combined_err)
    return False, {}, combined_err


# ---------------------------------------------------------------------------
# Category 3: Windows Service Persistence Enumeration
# ---------------------------------------------------------------------------
def _query_services_advapi32() -> Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Enumerates installed services using advapi32.dll!OpenSCManagerW and EnumServicesStatusExW.
    Queries configuration (binary path, start type, service account) for each service.
    """
    if not IS_WINDOWS or advapi32 is None or kernel32 is None:
        return False, {}, "SCM API is only supported on Windows hosts"

    hSCM = advapi32.OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
    if not hSCM:
        err = kernel32.GetLastError()
        return False, {}, f"OpenSCManagerW failed with Win32 error {err}"

    entries: Dict[str, Dict[str, Any]] = {}
    try:
        bytes_needed = wintypes.DWORD(0)
        services_returned = wintypes.DWORD(0)
        resume_handle = wintypes.DWORD(0)

        # Call with null buffer to query required buffer size
        advapi32.EnumServicesStatusExW(
            hSCM,
            0,  # SC_ENUM_PROCESS_INFO
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            0,
            ctypes.byref(bytes_needed),
            ctypes.byref(services_returned),
            ctypes.byref(resume_handle),
            None,
        )

        buf_size = bytes_needed.value
        if buf_size == 0:
            return True, {}, None

        buf = ctypes.create_string_buffer(buf_size)
        ret = advapi32.EnumServicesStatusExW(
            hSCM,
            0,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buf,
            buf_size,
            ctypes.byref(bytes_needed),
            ctypes.byref(services_returned),
            ctypes.byref(resume_handle),
            None,
        )

        if not ret:
            err = kernel32.GetLastError()
            return False, {}, f"EnumServicesStatusExW failed with Win32 error {err}"

        num_services = services_returned.value
        entry_size = ctypes.sizeof(ENUM_SERVICE_STATUS_PROCESSW)
        buf_ptr = ctypes.addressof(buf)

        for i in range(num_services):
            addr = buf_ptr + (i * entry_size)
            item = ENUM_SERVICE_STATUS_PROCESSW.from_address(addr)

            svc_name = str(item.lpServiceName or "")
            disp_name = str(item.lpDisplayName or "")
            state_code = int(item.dwCurrentState)
            state_str = SERVICE_STATE_NAMES.get(state_code, f"STATE_{state_code}")

            # Query service configuration details
            bin_path = ""
            start_mode_str = "UNKNOWN"
            start_account = "LocalSystem"

            hSvc = advapi32.OpenServiceW(hSCM, item.lpServiceName, SERVICE_QUERY_CONFIG)
            if hSvc:
                try:
                    cfg_needed = wintypes.DWORD(0)
                    advapi32.QueryServiceConfigW(hSvc, None, 0, ctypes.byref(cfg_needed))
                    if cfg_needed.value > 0:
                        cfg_buf = ctypes.create_string_buffer(cfg_needed.value)
                        if advapi32.QueryServiceConfigW(hSvc, cfg_buf, cfg_needed.value, ctypes.byref(cfg_needed)):
                            cfg = QUERY_SERVICE_CONFIGW.from_address(ctypes.addressof(cfg_buf))
                            bin_path = str(cfg.lpBinaryPathName or "")
                            start_mode_str = SERVICE_START_TYPE_NAMES.get(cfg.dwStartType, f"START_{cfg.dwStartType}")
                            start_account = str(cfg.lpServiceStartName or "LocalSystem")
                finally:
                    advapi32.CloseServiceHandle(hSvc)

            norm_name = svc_name.lower()
            entry_key = f"service:{norm_name}"

            struct_data = {
                "service_name": svc_name,
                "display_name": disp_name,
                "binary_path": bin_path,
                "state": state_str,
                "start_mode": start_mode_str,
                "account": start_account,
            }
            fp = compute_fingerprint(struct_data)

            entries[entry_key] = {
                "entry_type": "service",
                "entry_key": entry_key,
                "entry_value": bin_path or disp_name,
                "fingerprint": fp,
                "structured_data": struct_data,
            }

        return True, entries, None
    finally:
        advapi32.CloseServiceHandle(hSCM)


def _query_services_powershell() -> Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Fallback service query using PowerShell Get-CimInstance Win32_Service.
    """
    if not IS_WINDOWS:
        return False, {}, "PowerShell service query is only supported on Windows"
    try:
        ps_cmd = (
            "Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName "
            "| ConvertTo-Json -Compress"
        )
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            ps_cmd,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            err = res.stderr.strip() or f"PowerShell returned code {res.returncode}"
            return False, {}, f"PowerShell service query failed: {err}"

        stdout = res.stdout.strip()
        if not stdout:
            return True, {}, None

        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            return False, {}, f"Unexpected PowerShell JSON structure: {type(data).__name__}"

        entries: Dict[str, Dict[str, Any]] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            name = str(item.get("Name") or "")
            disp = str(item.get("DisplayName") or name)
            path = str(item.get("PathName") or "")
            mode = str(item.get("StartMode") or "Unknown")
            state = str(item.get("State") or "Unknown")
            acct = str(item.get("StartName") or "LocalSystem")

            entry_key = f"service:{name.lower()}"
            struct_data = {
                "service_name": name,
                "display_name": disp,
                "binary_path": path,
                "state": state,
                "start_mode": mode,
                "account": acct,
            }
            fp = compute_fingerprint(struct_data)

            entries[entry_key] = {
                "entry_type": "service",
                "entry_key": entry_key,
                "entry_value": path or disp,
                "fingerprint": fp,
                "structured_data": struct_data,
            }

        return True, entries, None
    except subprocess.TimeoutExpired:
        return False, {}, "PowerShell service query timed out after 15 seconds"
    except Exception as ex:
        return False, {}, f"PowerShell service query exception: {ex}"


def read_windows_services(
    caller: Optional[Callable[[], Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]]] = None
) -> Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Enumerates installed Windows services via Win32 SCM API with PowerShell fallback.

    Requirements & Safeguards:
    - Captures service name, display name, binary path, start mode, state, and account.
    - Includes stopped and disabled services; never silently omits them.
    - Handles access denied and SCM errors cleanly.
    - Preserves incomplete metadata without crashing.
    - Strictly read-only: never starts, stops, creates, or reconfigures services.
    """
    if caller is not None:
        return caller()

    # 1. Attempt Win32 SCM API
    success, entries, err = _query_services_advapi32()
    if success:
        return True, entries, None

    # 2. Attempt PowerShell CIM fallback
    ps_success, ps_entries, ps_err = _query_services_powershell()
    if ps_success:
        return True, ps_entries, None

    combined_err = f"SCM EnumServicesStatusExW failed ({err}); PowerShell service query failed ({ps_err})"
    logger.warning("Windows service enumeration failed: %s", combined_err)
    return False, {}, combined_err


# ---------------------------------------------------------------------------
# Persistence Baseline Lifecycle & Comparison Engine
# ---------------------------------------------------------------------------
def diff_persistence_category(
    category: str,
    current_entries: Dict[str, Dict[str, Any]],
    baseline_entries: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Diffs a successfully enumerated current category against an accepted baseline.
    Identifies added, modified, and removed persistence mechanisms.
    """
    current_keys = set(current_entries.keys())
    baseline_keys = set(baseline_entries.keys())

    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    modified: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []

    # 1. Added entries (present currently, absent from baseline)
    for k in sorted(current_keys - baseline_keys):
        item = current_entries[k]
        added.append({
            "entry_key": k,
            "category": category,
            "entry_value": item["entry_value"],
            "fingerprint": item["fingerprint"],
            "structured_data": item["structured_data"],
            "deviation_type": "added",
            "evidence": (
                f"Persistence deviation in '{category}': New entry '{k}' added. "
                f"Value: '{item['entry_value']}'."
            ),
        })

    # 2. Removed entries (present in baseline, absent currently)
    for k in sorted(baseline_keys - current_keys):
        item = baseline_entries[k]
        removed.append({
            "entry_key": k,
            "category": category,
            "entry_value": item.get("entry_value", ""),
            "fingerprint": item.get("fingerprint", ""),
            "structured_data": item.get("structured_data", {}),
            "deviation_type": "removed",
            "evidence": (
                f"Persistence deviation in '{category}': Baseline entry '{k}' removed from system. "
                f"Baseline value was: '{item.get('entry_value', '')}'."
            ),
        })

    # 3. Common entries (check fingerprint modifications)
    for k in sorted(current_keys & baseline_keys):
        curr_item = current_entries[k]
        base_item = baseline_entries[k]

        curr_fp = curr_item["fingerprint"]
        base_fp = base_item.get("fingerprint", "")

        if curr_fp != base_fp:
            modified.append({
                "entry_key": k,
                "category": category,
                "entry_value": curr_item["entry_value"],
                "baseline_value": base_item.get("entry_value", ""),
                "fingerprint": curr_fp,
                "baseline_fingerprint": base_fp,
                "structured_data": curr_item["structured_data"],
                "baseline_structured_data": base_item.get("structured_data", {}),
                "deviation_type": "modified",
                "evidence": (
                    f"Persistence deviation in '{category}': Entry '{k}' modified. "
                    f"Current fingerprint: {curr_fp[:16]}..., Baseline fingerprint: {base_fp[:16]}... "
                    f"Current value: '{curr_item['entry_value']}', Baseline value: '{base_item.get('entry_value', '')}'."
                ),
            })
        else:
            unchanged.append(curr_item)

    return {
        "category": category,
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged": unchanged,
        "total_deviations": len(added) + len(removed) + len(modified),
    }


def evaluate_category_persistence(
    category: str,
    success: bool,
    current_entries: Dict[str, Dict[str, Any]],
    error_message: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluates persistence observations for a specific category against its baseline metadata
    strictly obeying the Version 1.4.3 fixed reference baseline lifecycle state machine.

    Returns:
    {
        "category": category,
        "state": state,
        "threats": List[Dict[str, Any]],
        "diagnostics": List[Dict[str, Any]],
        "diff": Optional[Dict[str, Any]]
    }
    """
    meta = db.get_category_baseline_meta(category, db_path=db_path)
    current_state = meta["baseline_state"] if meta else "NOT_INITIALIZED"

    threats: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []
    diff_result: Optional[Dict[str, Any]] = None

    # Handle Category Enumeration Failure
    if not success:
        err_text = error_message or "Category enumeration encountered an operational failure"
        db.record_enumeration_failure(category, err_text, db_path=db_path)

        diag_evidence = (
            f"Operational diagnostic: Persistence enumeration failed for category '{category}': {err_text}. "
            f"Baseline state '{current_state}' preserved; diffing skipped to prevent false 'removed' findings."
        )
        diagnostics.append({
            "category": category,
            "type": "category_enumeration_failure",
            "state": current_state,
            "evidence": diag_evidence,
            "error": err_text,
        })
        return {
            "category": category,
            "state": current_state,
            "threats": [],
            "diagnostics": diagnostics,
            "diff": None,
        }

    # Enumeration Succeeded — Evaluate by Lifecycle State
    if current_state in ("NOT_INITIALIZED", "ENUMERATION_FAILED"):
        # First successful enumeration captures candidate baseline snapshot
        entry_list = list(current_entries.values())
        promoted = db.capture_candidate_baseline_atomic(category, entry_list, db_path=db_path)

        diag_evidence = (
            f"Operational diagnostic: Initial candidate baseline captured for category '{category}' "
            f"({promoted} entries). State transitioned to CANDIDATE_REVIEW. "
            f"Pre-existing persistence entries incorporated into candidate snapshot. "
            f"Baseline review and explicit operator acceptance required before deviation diffing begins."
        )
        logger.info(diag_evidence)
        diagnostics.append({
            "category": category,
            "type": "candidate_baseline_captured",
            "state": "CANDIDATE_REVIEW",
            "candidate_count": promoted,
            "evidence": diag_evidence,
        })
        return {
            "category": category,
            "state": "CANDIDATE_REVIEW",
            "threats": [],
            "diagnostics": diagnostics,
            "diff": None,
        }

    elif current_state == "CANDIDATE_REVIEW":
        # Candidate baseline captured but unaccepted; diffing is suppressed
        diag_evidence = (
            f"Operational diagnostic: Category '{category}' is in CANDIDATE_REVIEW awaiting explicit "
            f"operator acceptance. Persistence deviation diffing is suppressed pending acceptance."
        )
        diagnostics.append({
            "category": category,
            "type": "candidate_review_suppressed",
            "state": "CANDIDATE_REVIEW",
            "candidate_count": meta["candidate_entry_count"] if meta else len(current_entries),
            "evidence": diag_evidence,
        })
        return {
            "category": category,
            "state": "CANDIDATE_REVIEW",
            "threats": [],
            "diagnostics": diagnostics,
            "diff": None,
        }

    elif current_state == "ACCEPTED_TRUSTED":
        # Fixed reference baseline diffing
        baseline = db.get_persistence_baseline(category=category, only_accepted=True, db_path=db_path)
        # Extract category map safely from BaselineDict
        baseline_map = baseline.by_category().get(category, {})

        diff_result = diff_persistence_category(category, current_entries, baseline_map)

        # Convert additions, modifications, and removals into threat findings
        for dev in diff_result["added"]:
            threats.append({
                "category": category,
                "deviation_type": "added",
                "entry_key": dev["entry_key"],
                "process_name": _extract_display_name(dev["entry_value"], dev["entry_key"]),
                "evidence": dev["evidence"],
                "metadata": {
                    "signal": "persistence",
                    "category": category,
                    "deviation_type": "added",
                    "entry_key": dev["entry_key"],
                    "entry_value": dev["entry_value"],
                    "fingerprint": dev["fingerprint"],
                    "structured_data": dev["structured_data"],
                },
            })

        for dev in diff_result["modified"]:
            threats.append({
                "category": category,
                "deviation_type": "modified",
                "entry_key": dev["entry_key"],
                "process_name": _extract_display_name(dev["entry_value"], dev["entry_key"]),
                "evidence": dev["evidence"],
                "metadata": {
                    "signal": "persistence",
                    "category": category,
                    "deviation_type": "modified",
                    "entry_key": dev["entry_key"],
                    "current_value": dev["entry_value"],
                    "baseline_value": dev["baseline_value"],
                    "current_fingerprint": dev["fingerprint"],
                    "baseline_fingerprint": dev["baseline_fingerprint"],
                    "structured_data": dev["structured_data"],
                },
            })

        for dev in diff_result["removed"]:
            threats.append({
                "category": category,
                "deviation_type": "removed",
                "entry_key": dev["entry_key"],
                "process_name": _extract_display_name(dev["entry_value"], dev["entry_key"]),
                "evidence": dev["evidence"],
                "metadata": {
                    "signal": "persistence",
                    "category": category,
                    "deviation_type": "removed",
                    "entry_key": dev["entry_key"],
                    "baseline_value": dev["entry_value"],
                    "baseline_fingerprint": dev["fingerprint"],
                },
            })

        return {
            "category": category,
            "state": "ACCEPTED_TRUSTED",
            "threats": threats,
            "diagnostics": diagnostics,
            "diff": diff_result,
        }

    else:
        # Unknown state
        err_msg = f"Unknown baseline state '{current_state}' for category '{category}'"
        diagnostics.append({"category": category, "type": "unknown_state", "evidence": err_msg})
        return {
            "category": category,
            "state": current_state,
            "threats": [],
            "diagnostics": diagnostics,
            "diff": None,
        }


def _extract_display_name(value: str, fallback_key: str) -> str:
    """Extracts a concise, readable process or binary name for a persistence entry."""
    fallback_part = (fallback_key or "").split(":")[-1].strip() or "Persistence_Item"
    if not value or value.strip() == "N/A":
        return fallback_part
    # Clean quotes or command line arguments
    clean = value.strip().strip('"').strip("'")
    if " -Jack" in clean:
        clean = clean.split(" -Jack")[0]
    first_token = clean.split()[0] if clean else fallback_part
    base = os.path.basename(first_token).strip() if first_token else ""
    return base or fallback_part


# ---------------------------------------------------------------------------
# Finding Generation & Scan Execution
# ---------------------------------------------------------------------------
def run_scan(
    scan_id: Optional[int] = None,
    db_path: Optional[str] = None,
    # Injectable custom enumerators for deterministic unit testing
    registry_caller: Optional[Callable[[], Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]]] = None,
    tasks_caller: Optional[Callable[[], Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]]] = None,
    services_caller: Optional[Callable[[], Tuple[bool, Dict[str, Dict[str, Any]], Optional[str]]]] = None,
) -> List[Dict[str, Any]]:
    """
    Executes the Signal 2 Persistence Monitoring Engine.
    Enumerate registry autoruns, scheduled tasks, and Windows services independently.
    Evaluates findings adhering to the Phase 1 SQLite schema and invariants:
      finding_type == 'diagnostic' => score_eligible == 0
      finding_type == 'threat'     => score_eligible in (0, 1)

    If scan_id is provided, findings are validated and persisted to SQLite
    inside an atomic database transaction.

    Returns the list of generated finding dictionaries.
    """
    effective_scan_id = scan_id or 1

    # 1. Enumerate all three categories independently
    reg_ok, reg_entries, reg_err = read_registry_run_keys(caller=registry_caller)
    task_ok, task_entries, task_err = read_scheduled_tasks(caller=tasks_caller)
    svc_ok, svc_entries, svc_err = read_windows_services(caller=services_caller)

    cat_runs = [
        ("registry", reg_ok, reg_entries, reg_err),
        ("task", task_ok, task_entries, task_err),
        ("service", svc_ok, svc_entries, svc_err),
    ]

    findings: List[Dict[str, Any]] = []

    # 2. Evaluate each category against the fixed reference baseline state machine
    for cat_name, ok, entries, err in cat_runs:
        eval_res = evaluate_category_persistence(
            category=cat_name,
            success=ok,
            current_entries=entries,
            error_message=err,
            db_path=db_path,
        )

        # Threat findings (actual deviations against ACCEPTED_TRUSTED baseline)
        for t in eval_res["threats"]:
            dev_type = t.get("deviation_type", "added")
            severity = "high" if dev_type in ("added", "modified") else "medium"
            finding = {
                "scan_id": effective_scan_id,
                "pid": None,  # Persistence mechanisms are system/host level
                "process_name": t["process_name"],
                "signal": "persistence",
                "evidence": t["evidence"],
                "severity": severity,
                "finding_type": "threat",
                "score_eligible": 1,
                "signature_status": "N/A",
                "metadata": json.dumps(t["metadata"]),
            }
            findings.append(finding)

        # Operational diagnostics (source failures, candidate review, diffing suppression)
        for d in eval_res["diagnostics"]:
            meta_payload = dict(d)
            meta_payload["signal"] = "persistence"
            meta_payload["is_diagnostic"] = True

            finding = {
                "scan_id": effective_scan_id,
                "pid": None,
                "process_name": f"{cat_name.capitalize()}_Subsystem",
                "signal": "persistence",
                "evidence": d["evidence"],
                "severity": "low",
                "finding_type": "diagnostic",
                "score_eligible": 0,
                "signature_status": "N/A",
                "metadata": json.dumps(meta_payload),
            }
            findings.append(finding)

    # Validate findings against Phase 1 DAL validator
    validated_findings = [db.validate_finding(f) for f in findings]

    # If scan_id was provided, persist findings to SQLite
    if scan_id is not None:
        db.insert_findings(scan_id, validated_findings, db_path=db_path)

    return validated_findings


# ---------------------------------------------------------------------------
# Public Lifecycle Management Helpers
# ---------------------------------------------------------------------------
def accept_baseline(
    category: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Atomically promotes candidate baseline entries (CANDIDATE_REVIEW) to ACCEPTED_TRUSTED.
    Delegates to core.db.accept_baseline_atomic inside an isolated transaction.
    """
    return db.accept_baseline_atomic(category=category, db_path=db_path)


def reset_all_baselines(db_path: Optional[str] = None) -> None:
    """
    Atomically clears all baseline records and resets metadata to NOT_INITIALIZED.
    Delegates to core.db.reset_all_baselines_atomic.
    """
    db.reset_all_baselines_atomic(db_path=db_path)
