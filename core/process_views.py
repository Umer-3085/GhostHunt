"""
GhostHunt — Phase 2: Cross-View Process Enumeration Engine
Authoritative implementation of Signal 1 cross-view process discrepancy detection.

Architectural Guarantees & Defensible Boundaries:
1. Three Independent Process Views:
   - Path 1: Win32 Toolhelp32 snapshot (CreateToolhelp32Snapshot, Process32FirstW, Process32NextW).
   - Path 2: WMI CIM / COM interface (Win32_Process via COM with PowerShell CIM fallback).
   - Path 3: Native NT API (ntdll.dll!NtQuerySystemInformation with SystemProcessInformation = 5).
2. Accurate Technical Boundary:
   Calling NtQuerySystemInformation provides a separate, lower-level enumeration path
   from high-level Win32 APIs, but it DOES NOT guarantee bypassing user-mode hooks.
   ntdll.dll resides inside user-mode virtual address space and can itself be hooked
   (e.g., inline function hooking or IAT patching). Furthermore, all paths query common
   underlying kernel data structures (EPROCESS blocks). Discrepancies represent
   anomalous behavioral evidence requiring forensic investigation, not conclusive proof of a rootkit.
3. Source Failure Isolation & No Empty-List Spoofing:
   Every source explicitly returns (success: bool, processes: Dict[int, str], error: Optional[str]).
   A failed or timed-out source is never treated as an empty process list ({}).
   Failed sources are excluded from comparison so that processes are never marked
   "missing" from a source that failed.
4. Minimum Quorum Requirement:
   If fewer than 2 sources succeed, cross-view comparison is aborted for that cycle;
   an operational diagnostic finding is emitted (finding_type='diagnostic', score_eligible=0),
   and zero false process discrepancies are emitted.
5. Two-Pass Micro-Delay Confirmation:
   Discrepancies identified in Pass 1 are re-checked after config.MICRO_DELAY_SECONDS (50 ms).
   A discrepancy is discarded as transient only if positive evidence shows the process exited
   or the discrepancy resolved.
6. PID Reuse & Process Identity Limitations:
   PID equality alone does not prove identical instance. Process name changes between passes
   for the same PID are flagged as identity uncertainty, not false hidden processes.
7. Defensive User-Mode Safety:
   Read-only inspection. No kernel drivers, no code injection, no API hooks, no process modification.
"""

import ctypes
from ctypes import wintypes
import json
import logging
import os
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import config
import core.db as db

logger = logging.getLogger("ghosthunt.process_views")

# Platform check for safe test discovery on non-Windows hosts
IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    ole32 = ctypes.windll.ole32
    oleaut32 = ctypes.windll.oleaut32
else:
    kernel32 = None
    ntdll = None
    ole32 = None
    oleaut32 = None


# ---------------------------------------------------------------------------
# Windows API Constants & Structures
# ---------------------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = -1
ERROR_NO_MORE_FILES = 18

SystemProcessInformation = 5
STATUS_SUCCESS = 0x00000000
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_BUFFER_TOO_SMALL = 0xC0000023
STATUS_ACCESS_DENIED = 0xC0000022

COINIT_MULTITHREADED = 0x0
RPC_E_CHANGED_MODE = 0x80010106
CLSCTX_INPROC_SERVER = 0x1
WBEM_FLAG_FORWARD_ONLY = 0x20
WBEM_FLAG_RETURN_IMMEDIATELY = 0x10

CLSID_WbemLocator_STR = "{4590F811-1D3A-11D0-891F-00AA004B2E24}"
IID_IWbemLocator_STR = "{DC12A687-737F-11CF-884D-00AA004B2E24}"


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def string_to_guid(guid_str: str) -> GUID:
    """Parses a standard GUID string into a GUID ctypes Structure."""
    guid = GUID()
    if ole32 is not None:
        hr = ole32.CLSIDFromString(ctypes.c_wchar_p(guid_str), ctypes.byref(guid))
        if hr != 0:
            raise ValueError(f"Failed to parse GUID '{guid_str}', HRESULT: 0x{hr & 0xFFFFFFFF:08X}")
    return guid


class VARIANT(ctypes.Structure):
    """COM VARIANT structure for extracting WMI property values."""
    class U(ctypes.Union):
        _fields_ = [
            ("lVal", ctypes.c_long),
            ("ulVal", ctypes.c_ulong),
            ("llVal", ctypes.c_int64),
            ("ullVal", ctypes.c_uint64),
            ("bstrVal", ctypes.c_wchar_p),
            ("byref", ctypes.c_void_p),
        ]
    _fields_ = [
        ("vt", wintypes.USHORT),
        ("wReserved1", wintypes.WORD),
        ("wReserved2", wintypes.WORD),
        ("wReserved3", wintypes.WORD),
        ("_u", U),
    ]

    def get_int_value(self) -> Optional[int]:
        if self.vt in (3, 19):  # VT_I4, VT_UI4
            return int(self._u.ulVal)
        if self.vt in (2, 18):  # VT_I2, VT_UI2
            return int(self._u.lVal & 0xFFFF)
        if self.vt in (20, 21):  # VT_I8, VT_UI8
            return int(self._u.ullVal)
        return None

    def get_str_value(self) -> Optional[str]:
        if self.vt == 8 and self._u.bstrVal:  # VT_BSTR
            return str(self._u.bstrVal)
        return None


class PROCESSENTRY32W(ctypes.Structure):
    """Win32 Toolhelp32 process snapshot entry structure."""
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class UNICODE_STRING(ctypes.Structure):
    """Native NT Unicode String buffer structure."""
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    """
    Native NT SystemProcessInformation structure layout (64-bit AMD64).
    Matches Windows 10/11 x64 kernel executive structure offsets.
    """
    _fields_ = [
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_int64),
        ("HardFaultCount", wintypes.ULONG),
        ("NumberOfThreadsHighWatermark", wintypes.ULONG),
        ("CycleTime", ctypes.c_uint64),
        ("CreateTime", ctypes.c_int64),
        ("UserTime", ctypes.c_int64),
        ("KernelTime", ctypes.c_int64),
        ("ImageName", UNICODE_STRING),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
        ("HandleCount", wintypes.ULONG),
        ("SessionId", wintypes.ULONG),
    ]


# ---------------------------------------------------------------------------
# Common Result Model
# ---------------------------------------------------------------------------
class ProcessRecord:
    """Structured record representing a single observed process instance."""

    def __init__(self, pid: int, name: str, source: str):
        self.pid = int(pid)
        self.original_name = str(name)
        self.normalized_name = normalize_process_name(name)
        self.source = str(source)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "original_name": self.original_name,
            "normalized_name": self.normalized_name,
            "source": self.source,
        }

    def __repr__(self) -> str:
        return f"ProcessRecord(pid={self.pid}, name='{self.original_name}', source='{self.source}')"


class SourceResult:
    """Structured result returned by an enumeration source."""

    def __init__(
        self,
        source: str,
        success: bool,
        processes: Optional[Dict[int, str]] = None,
        error: Optional[str] = None,
    ):
        self.source = source
        self.success = bool(success)
        self.processes = processes or {}
        self.error = error
        self.records: List[ProcessRecord] = [
            ProcessRecord(pid=pid, name=name, source=source)
            for pid, name in self.processes.items()
        ]

    def to_tuple(self) -> Tuple[bool, Dict[int, str], Optional[str]]:
        return self.success, self.processes, self.error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "success": self.success,
            "processes": self.processes,
            "error": self.error,
            "count": len(self.processes),
        }

    def __repr__(self) -> str:
        return f"SourceResult(source='{self.source}', success={self.success}, count={len(self.processes)}, error={self.error!r})"


def normalize_process_name(name: str) -> str:
    """
    Normalizes process executable names for cross-view matching.
    Strips directory paths, trims whitespace, converts to lowercase,
    and canonicalizes system idle process naming variations.
    """
    if not name:
        return ""
    clean = os.path.basename(name.strip()).lower()
    if clean in ("[system process]", "system idle process"):
        return "system idle process"
    return clean


# ---------------------------------------------------------------------------
# Source 1: Win32 Toolhelp32 Process Snapshot
# ---------------------------------------------------------------------------
def get_processes_toolhelp32(
    caller: Optional[Callable[[], Tuple[bool, Dict[int, str], Optional[str]]]] = None
) -> Tuple[bool, Dict[int, str], Optional[str]]:
    """
    Enumerates running processes via Win32 Toolhelp32 snapshot.
    Uses kernel32.dll!CreateToolhelp32Snapshot, Process32FirstW, and Process32NextW.

    Requirements & Defensible Safeguards:
    - Defines PROCESSENTRY32W structure with exact field types and 4/8-byte alignments.
    - Closes snapshot handle reliably in all code paths, including exceptions.
    - Explicitly detects and reports Win32 API errors via GetLastError().
    - Treats ERROR_NO_MORE_FILES (18) as normal end-of-enumeration.
    - Does NOT silently convert API failures into an empty process list.
    """
    if caller is not None:
        return caller()

    if not IS_WINDOWS or kernel32 is None:
        return False, {}, "Toolhelp32 is only supported on Windows hosts"

    hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    # Check invalid handle values (-1 or 64-bit / 32-bit max unsigned integer)
    if hSnapshot in (INVALID_HANDLE_VALUE, 0, (1 << 64) - 1, (1 << 32) - 1):
        err = kernel32.GetLastError()
        return False, {}, f"CreateToolhelp32Snapshot failed with Win32 error {err}"

    processes: Dict[int, str] = {}
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if not kernel32.Process32FirstW(hSnapshot, ctypes.byref(pe)):
            err = kernel32.GetLastError()
            if err == ERROR_NO_MORE_FILES:
                return True, {}, None
            return False, {}, f"Process32FirstW failed with Win32 error {err}"

        while True:
            pid = int(pe.th32ProcessID)
            exe_name = str(pe.szExeFile)
            processes[pid] = exe_name

            if not kernel32.Process32NextW(hSnapshot, ctypes.byref(pe)):
                err = kernel32.GetLastError()
                if err == ERROR_NO_MORE_FILES:
                    break
                return False, {}, f"Process32NextW failed with Win32 error {err}"

        return True, processes, None
    except Exception as ex:
        logger.exception("Unexpected exception during Toolhelp32 enumeration: %s", ex)
        return False, {}, f"Toolhelp32 enumeration exception: {ex}"
    finally:
        kernel32.CloseHandle(hSnapshot)


# ---------------------------------------------------------------------------
# Source 2: WMI / CIM Interface
# ---------------------------------------------------------------------------
def _query_wmi_com() -> Tuple[bool, Dict[int, str], Optional[str]]:
    """
    Direct COM query for Win32_Process via IWbemLocator and IWbemServices.
    Handles thread-level COM initialization (CoInitializeEx / CoUninitialize)
    and releases all COM interfaces in finally blocks to prevent memory leaks.
    """
    if not IS_WINDOWS or ole32 is None or oleaut32 is None:
        return False, {}, "WMI COM query is only supported on Windows hosts"

    # Initialize COM on calling thread
    hr_init = ole32.CoInitializeEx(None, COINIT_MULTITHREADED)
    need_uninit = hr_init in (0, 1)  # S_OK (0) or S_FALSE (1)

    pLocator = ctypes.c_void_p()
    pServices = ctypes.c_void_p()
    pEnum = ctypes.c_void_p()

    ReleaseProto = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)

    try:
        clsid_locator = string_to_guid(CLSID_WbemLocator_STR)
        iid_locator = string_to_guid(IID_IWbemLocator_STR)

        hr = ole32.CoCreateInstance(
            ctypes.byref(clsid_locator),
            None,
            CLSCTX_INPROC_SERVER,
            ctypes.byref(iid_locator),
            ctypes.byref(pLocator),
        )
        if hr != 0 or not pLocator.value:
            return False, {}, f"CoCreateInstance(WbemLocator) failed with HRESULT 0x{hr & 0xFFFFFFFF:08X}"

        # ConnectServer is at vtable[3] on IWbemLocator
        vtable_locator = ctypes.cast(pLocator.value, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        ConnectServerProto = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_wchar_p,  # strNetworkResource
            ctypes.c_wchar_p,  # strUser
            ctypes.c_wchar_p,  # strPassword
            ctypes.c_wchar_p,  # strLocale
            ctypes.c_long,     # lSecurityFlags
            ctypes.c_wchar_p,  # strAuthority
            ctypes.c_void_p,   # pCtx
            ctypes.POINTER(ctypes.c_void_p),  # ppNamespace
        )
        ConnectServer = ConnectServerProto(vtable_locator[3])
        hr = ConnectServer(
            pLocator,
            "ROOT\\CIMV2",
            None, None, None, 0, None, None,
            ctypes.byref(pServices),
        )
        if hr != 0 or not pServices.value:
            return False, {}, f"WMI ConnectServer failed with HRESULT 0x{hr & 0xFFFFFFFF:08X}"

        # ExecQuery is at vtable[20] on IWbemServices
        vtable_services = ctypes.cast(pServices.value, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        ExecQueryProto = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_wchar_p,  # strQueryLanguage
            ctypes.c_wchar_p,  # strQuery
            ctypes.c_long,     # lFlags
            ctypes.c_void_p,   # pCtx
            ctypes.POINTER(ctypes.c_void_p),  # ppEnum
        )
        ExecQuery = ExecQueryProto(vtable_services[20])
        hr = ExecQuery(
            pServices,
            "WQL",
            "SELECT ProcessId, Name FROM Win32_Process",
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
            ctypes.byref(pEnum),
        )
        if hr != 0 or not pEnum.value:
            return False, {}, f"WMI ExecQuery failed with HRESULT 0x{hr & 0xFFFFFFFF:08X}"

        # Next is at vtable[4] on IEnumWbemClassObject
        vtable_enum = ctypes.cast(pEnum.value, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        NextProto = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_long,   # lTimeout (ms)
            ctypes.c_ulong,  # uCount
            ctypes.POINTER(ctypes.c_void_p),  # apObjects
            ctypes.POINTER(ctypes.c_ulong),   # puReturned
        )
        Next = NextProto(vtable_enum[4])

        processes: Dict[int, str] = {}
        pObj = ctypes.c_void_p()
        uReturned = ctypes.c_ulong(0)

        while True:
            hr = Next(pEnum, 5000, 1, ctypes.byref(pObj), ctypes.byref(uReturned))
            if hr != 0 or uReturned.value == 0 or not pObj.value:
                break

            try:
                # Get is at vtable[4] on IWbemClassObject
                vtable_obj = ctypes.cast(pObj.value, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
                GetProto = ctypes.WINFUNCTYPE(
                    ctypes.c_long,
                    ctypes.c_void_p,
                    ctypes.c_wchar_p,  # wszName
                    ctypes.c_long,     # lFlags
                    ctypes.POINTER(VARIANT),  # pVal
                    ctypes.c_void_p,   # pType
                    ctypes.c_void_p,   # plFlavor
                )
                Get = GetProto(vtable_obj[4])

                # Read ProcessId
                var_pid = VARIANT()
                oleaut32.VariantInit(ctypes.byref(var_pid))
                pid_val = None
                if Get(pObj, "ProcessId", 0, ctypes.byref(var_pid), None, None) == 0:
                    pid_val = var_pid.get_int_value()
                oleaut32.VariantClear(ctypes.byref(var_pid))

                # Read Name
                var_name = VARIANT()
                oleaut32.VariantInit(ctypes.byref(var_name))
                name_val = None
                if Get(pObj, "Name", 0, ctypes.byref(var_name), None, None) == 0:
                    name_val = var_name.get_str_value()
                oleaut32.VariantClear(ctypes.byref(var_name))

                if pid_val is not None:
                    processes[int(pid_val)] = str(name_val or f"PID_{pid_val}")
            finally:
                Release_obj = ReleaseProto(vtable_obj[2])
                Release_obj(pObj)
                pObj = ctypes.c_void_p()

        return True, processes, None
    except Exception as ex:
        return False, {}, f"WMI COM query exception: {ex}"
    finally:
        # Guarantee release of all COM interfaces in reverse order of creation
        if pEnum.value:
            vtable = ctypes.cast(pEnum.value, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            ReleaseProto(vtable[2])(pEnum)
        if pServices.value:
            vtable = ctypes.cast(pServices.value, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            ReleaseProto(vtable[2])(pServices)
        if pLocator.value:
            vtable = ctypes.cast(pLocator.value, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            ReleaseProto(vtable[2])(pLocator)
        if need_uninit and ole32 is not None:
            ole32.CoUninitialize()


def _query_wmi_powershell() -> Tuple[bool, Dict[int, str], Optional[str]]:
    """
    Fallback query using PowerShell Get-CimInstance Win32_Process.
    Used when direct COM connection fails due to security context restrictions.
    """
    if not IS_WINDOWS:
        return False, {}, "WMI PowerShell is only supported on Windows hosts"
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "Get-CimInstance Win32_Process | Select-Object ProcessId, Name | ConvertTo-Json -Compress",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            err = res.stderr.strip() or f"PowerShell process returned exit code {res.returncode}"
            return False, {}, f"WMI PowerShell CIM query failed: {err}"

        stdout = res.stdout.strip()
        if not stdout:
            return True, {}, None

        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            return False, {}, f"Unexpected WMI JSON output format: {type(data).__name__}"

        processes: Dict[int, str] = {}
        for item in data:
            if isinstance(item, dict) and "ProcessId" in item and item["ProcessId"] is not None:
                pid = int(item["ProcessId"])
                name = str(item.get("Name") or f"PID_{pid}")
                processes[pid] = name

        return True, processes, None
    except subprocess.TimeoutExpired:
        return False, {}, "WMI PowerShell CIM query timed out after 10 seconds"
    except Exception as ex:
        return False, {}, f"WMI PowerShell CIM query encountered unexpected error: {ex}"


def get_processes_wmi(
    caller: Optional[Callable[[], Tuple[bool, Dict[int, str], Optional[str]]]] = None
) -> Tuple[bool, Dict[int, str], Optional[str]]:
    """
    Enumerates running processes via Windows Management Instrumentation (Win32_Process).

    Requirements & Defensible Safeguards:
    - Queries ProcessId and Name via direct COM interface.
    - Manages per-thread COM initialization and cleanup without COM resource leaks.
    - Handles unavailable WMI services, access denied, query failures, and malformed results.
    - Uses PowerShell CIM as secondary fallback when direct COM connection encounters permission constraints.
    - Does NOT treat WMI failure as a successful empty enumeration.
    """
    if caller is not None:
        return caller()

    # 1. Attempt direct COM execution
    success, procs, err = _query_wmi_com()
    if success:
        return True, procs, None

    # 2. Attempt PowerShell CIM fallback
    ps_success, ps_procs, ps_err = _query_wmi_powershell()
    if ps_success:
        return True, ps_procs, None

    # Report combined failure details explicitly
    combined_err = f"WMI COM failed ({err}); PowerShell CIM fallback failed ({ps_err})"
    logger.warning("WMI process enumeration failed: %s", combined_err)
    return False, {}, combined_err


# ---------------------------------------------------------------------------
# Source 3: Native NT System Call (NtQuerySystemInformation)
# ---------------------------------------------------------------------------
def get_processes_nt(
    caller: Optional[Callable[[], Tuple[bool, Dict[int, str], Optional[str]]]] = None
) -> Tuple[bool, Dict[int, str], Optional[str]]:
    """
    Enumerates running processes via ntdll.dll!NtQuerySystemInformation(SystemProcessInformation = 5).

    Accurate Technical Boundary & Scope:
    This is a native user-mode API in ntdll.dll. It bypasses high-level Win32 wrappers
    (kernel32.dll), providing a lower-level observation path. However, it DOES NOT
    guarantee bypassing user-mode hooks (ntdll.dll resides in user-mode virtual memory
    and can be hooked via inline code modification or IAT patching). Furthermore, all views
    query underlying kernel EPROCESS structures. Discrepancies are behavioral anomalies
    requiring forensic review, not conclusive proof of a rootkit.

    Requirements & Defensible Safeguards:
    - Handles STATUS_INFO_LENGTH_MISMATCH (0xC0000004) by dynamically resizing buffer.
    - Enforces sensible buffer growth limits and retry limits (10 retries, 32 MB cap).
    - Validates buffer boundaries and linked offsets (NextEntryOffset) before parsing.
    - Detects cyclic or out-of-bounds offsets to prevent memory corruption or infinite loops.
    - Safely copies Unicode image names up to Length bytes without assuming null-termination.
    - Reports NTSTATUS failures explicitly.
    """
    if caller is not None:
        return caller()

    if not IS_WINDOWS or ntdll is None:
        return False, {}, "Native NT API is only supported on Windows hosts"

    # Start with 512 KB buffer
    buffer_size = 512 * 1024
    max_buffer_size = 32 * 1024 * 1024  # 32 MB safety cap
    max_retries = 10
    ret_len = wintypes.ULONG(0)

    for attempt in range(max_retries):
        buf = ctypes.create_string_buffer(buffer_size)
        status = ntdll.NtQuerySystemInformation(
            SystemProcessInformation,
            buf,
            buffer_size,
            ctypes.byref(ret_len),
        )
        status_u32 = status & 0xFFFFFFFF

        if status_u32 == STATUS_SUCCESS:
            break
        elif status_u32 in (STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_TOO_SMALL):
            # Grow buffer
            required = ret_len.value
            if required > buffer_size:
                buffer_size = required + 64 * 1024
            else:
                buffer_size = buffer_size * 2

            if buffer_size > max_buffer_size:
                return False, {}, (
                    f"NtQuerySystemInformation buffer size ({buffer_size}) exceeded maximum safety cap ({max_buffer_size})"
                )
        else:
            return False, {}, f"NtQuerySystemInformation failed with NTSTATUS 0x{status_u32:08X}"
    else:
        return False, {}, f"NtQuerySystemInformation failed after {max_retries} buffer resize attempts"

    # Parse SYSTEM_PROCESS_INFORMATION linked list safely
    processes: Dict[int, str] = {}
    buf_ptr = ctypes.addressof(buf)
    offset = 0
    seen_offsets: Set[int] = set()

    # Minimum size required for header up to ImageName + PIDs
    min_entry_size = 104

    while True:
        if offset in seen_offsets:
            return False, {}, f"Malformed NT buffer: cyclic offset {offset} detected"
        seen_offsets.add(offset)

        if offset + min_entry_size > buffer_size:
            return False, {}, (
                f"Malformed NT buffer: offset {offset} + min_size {min_entry_size} exceeds buffer size {buffer_size}"
            )

        entry_addr = buf_ptr + offset

        # Parse linked offset
        next_offset = wintypes.ULONG.from_address(entry_addr).value

        # Parse ImageName (UNICODE_STRING at offset 56)
        name_len = wintypes.USHORT.from_address(entry_addr + 56).value
        name_buf_ptr = ctypes.c_void_p.from_address(entry_addr + 64).value

        # Parse UniqueProcessId (HANDLE at offset 80)
        pid_raw = ctypes.c_size_t.from_address(entry_addr + 80).value
        pid = int(pid_raw)

        if name_len > 0 and name_buf_ptr:
            num_wchars = name_len // 2
            try:
                name = ctypes.wstring_at(name_buf_ptr, num_wchars)
            except Exception as err:
                name = f"CorruptName_PID_{pid}"
        else:
            name = "System Idle Process" if pid == 0 else f"PID_{pid}"

        processes[pid] = name

        if next_offset == 0:
            break

        if next_offset < 0 or offset + next_offset > buffer_size:
            return False, {}, (
                f"Malformed NT buffer: next_offset {next_offset} from {offset} points outside buffer capacity {buffer_size}"
            )

        offset += next_offset

    return True, processes, None


# ---------------------------------------------------------------------------
# Cross-View Comparison Engine
# ---------------------------------------------------------------------------
def compare_views(
    views: Dict[str, Dict[int, str]],
    source_statuses: Dict[str, bool],
    source_errors: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, Any]:
    """
    Compares process views from successfully enumerated sources only.
    Excludes failed sources to prevent false discrepancy findings.

    Defensible Safeguards:
    - Never treats a failed source as an empty list ({}).
    - Compares only sources where source_statuses[s] is True.
    - Enforces Minimum Source Quorum: requires at least 2 successful sources.
      If quorum < 2, comparison is aborted, emitting an operational diagnostic
      and zero false process discrepancies.
    - Distinguishes one-source-only observations from multi-source disagreements.
    - Discrepancies are treated as suspicious anomalies, NOT proof of malware.

    Returns structured comparison result dictionary.
    """
    errors = source_errors or {}
    successful_sources = [s for s, ok in source_statuses.items() if ok]
    failed_sources = [s for s, ok in source_statuses.items() if not ok]

    diagnostics: List[Dict[str, Any]] = []

    # Record operational diagnostics for any failed source
    for src in failed_sources:
        err_msg = errors.get(src) or "Source enumeration failed without specific error message"
        diagnostics.append({
            "type": "source_failure",
            "source": src,
            "error": err_msg,
            "evidence": f"Operational diagnostic: Source '{src}' enumeration failed: {err_msg}",
        })

    # Quorum check
    if len(successful_sources) < 2:
        quorum_msg = (
            f"Process-view cross-comparison aborted: minimum quorum (< 2 successful sources) not met. "
            f"Successful sources: {successful_sources}; failed sources: {failed_sources}."
        )
        logger.warning(quorum_msg)
        diagnostics.append({
            "type": "quorum_failure",
            "successful_sources": successful_sources,
            "failed_sources": failed_sources,
            "evidence": quorum_msg,
        })
        return {
            "quorum_met": False,
            "successful_sources": successful_sources,
            "failed_sources": failed_sources,
            "discrepancies": [],
            "diagnostics": diagnostics,
        }

    # Gather union of all PIDs across successful sources
    all_pids: Set[int] = set()
    for src in successful_sources:
        all_pids.update(views.get(src, {}).keys())

    discrepancies: List[Dict[str, Any]] = []

    for pid in sorted(all_pids):
        observed_in = [s for s in successful_sources if pid in views.get(s, {})]
        missing_from = [s for s in successful_sources if pid not in views.get(s, {})]

        if missing_from:
            # Capture original observed names
            names_by_source = {s: views[s][pid] for s in observed_in}
            raw_primary = list(names_by_source.values())[0] if names_by_source else ""
            primary_name = str(raw_primary).strip() if (raw_primary and str(raw_primary).strip()) else f"PID_{pid}"

            discrepancy_type = (
                "one_source_only" if len(observed_in) == 1 else "multi_source_disagreement"
            )
            evidence = (
                f"Process discrepancy: '{primary_name}' (PID {pid}) observed in {observed_in} "
                f"but missing from successful sources {missing_from}. "
                f"Comparison evaluated successful sources {successful_sources}."
            )

            discrepancies.append({
                "pid": pid,
                "process_name": primary_name,
                "observed_sources": observed_in,
                "missing_sources": missing_from,
                "names_by_source": names_by_source,
                "successful_sources": successful_sources,
                "discrepancy_type": discrepancy_type,
                "evidence": evidence,
            })

    return {
        "quorum_met": True,
        "successful_sources": successful_sources,
        "failed_sources": failed_sources,
        "discrepancies": discrepancies,
        "diagnostics": diagnostics,
    }


# ---------------------------------------------------------------------------
# Two-Pass Confirmation & Transient Race Handling
# ---------------------------------------------------------------------------
def run_two_pass_enumeration(
    micro_delay: Optional[float] = None,
    # Optional injectables for deterministic testing
    pass1_sources: Optional[Dict[str, SourceResult]] = None,
    pass2_sources: Optional[Dict[str, SourceResult]] = None,
) -> Dict[str, Any]:
    """
    Executes a complete two-pass cross-view process enumeration scan.

    Two-Pass Confirmation Safeguards:
    1. Pass 1: Queries all three sources, performs cross-view comparison.
    2. If Pass 1 finds candidate discrepancies, waits for config.MICRO_DELAY_SECONDS (50 ms).
    3. Pass 2: Queries all sources again and re-evaluates discrepancies.
    4. Transient Filtering:
       - If a process exited between passes (PID absent everywhere in Pass 2), it is discarded
         as a transient termination.
       - If a process appeared in all sources in Pass 2, it is discarded as a transient start.
       - If the PID exists in Pass 2 with a DIFFERENT process name (PID reuse), it is flagged
         as an identity uncertainty diagnostic rather than confirmed hiding.
       - A mismatch is confirmed ONLY when the required evidence persists across both passes.
    """
    delay = config.MICRO_DELAY_SECONDS if micro_delay is None else micro_delay

    # --- PASS 1 ---
    if pass1_sources is not None:
        p1_results = pass1_sources
    else:
        th_ok, th_procs, th_err = get_processes_toolhelp32()
        wmi_ok, wmi_procs, wmi_err = get_processes_wmi()
        nt_ok, nt_procs, nt_err = get_processes_nt()
        p1_results = {
            "toolhelp32": SourceResult("toolhelp32", th_ok, th_procs, th_err),
            "wmi": SourceResult("wmi", wmi_ok, wmi_procs, wmi_err),
            "nt": SourceResult("nt", nt_ok, nt_procs, nt_err),
        }

    p1_views = {s: res.processes for s, res in p1_results.items()}
    p1_statuses = {s: res.success for s, res in p1_results.items()}
    p1_errors = {s: res.error for s, res in p1_results.items()}

    p1_comparison = compare_views(p1_views, p1_statuses, p1_errors)
    diagnostics: List[Dict[str, Any]] = list(p1_comparison["diagnostics"])

    # If quorum was not met in Pass 1 or zero discrepancies found, return immediately
    if not p1_comparison["quorum_met"] or not p1_comparison["discrepancies"]:
        return {
            "confirmed_discrepancies": [],
            "transient_discrepancies": [],
            "diagnostics": diagnostics,
            "pass1": p1_comparison,
            "pass2": None,
        }

    # Micro-delay before Pass 2
    if delay > 0:
        time.sleep(delay)

    # --- PASS 2 ---
    if pass2_sources is not None:
        p2_results = pass2_sources
    else:
        th_ok2, th_procs2, th_err2 = get_processes_toolhelp32()
        wmi_ok2, wmi_procs2, wmi_err2 = get_processes_wmi()
        nt_ok2, nt_procs2, nt_err2 = get_processes_nt()
        p2_results = {
            "toolhelp32": SourceResult("toolhelp32", th_ok2, th_procs2, th_err2),
            "wmi": SourceResult("wmi", wmi_ok2, wmi_procs2, wmi_err2),
            "nt": SourceResult("nt", nt_ok2, nt_procs2, nt_err2),
        }

    p2_views = {s: res.processes for s, res in p2_results.items()}
    p2_statuses = {s: res.success for s, res in p2_results.items()}
    p2_errors = {s: res.error for s, res in p2_results.items()}

    p2_comparison = compare_views(p2_views, p2_statuses, p2_errors)
    diagnostics.extend(p2_comparison["diagnostics"])

    if not p2_comparison["quorum_met"]:
        # Quorum lost in Pass 2; cannot confirm discrepancy safely
        loss_msg = (
            "Two-pass confirmation aborted: Pass 2 lost minimum source quorum. "
            "Pass 1 discrepancies preserved as unconfirmed operational diagnostics."
        )
        diagnostics.append({"type": "pass2_quorum_loss", "evidence": loss_msg})
        return {
            "confirmed_discrepancies": [],
            "transient_discrepancies": [],
            "diagnostics": diagnostics,
            "pass1": p1_comparison,
            "pass2": p2_comparison,
        }

    confirmed_discrepancies: List[Dict[str, Any]] = []
    transient_discrepancies: List[Dict[str, Any]] = []

    p2_discrepancies_by_pid = {d["pid"]: d for d in p2_comparison["discrepancies"]}

    for cand in p1_comparison["discrepancies"]:
        pid = cand["pid"]
        name_p1 = cand["process_name"]

        # Check PID presence across Pass 2 successful sources
        p2_present_sources = [s for s in p2_comparison["successful_sources"] if pid in p2_views.get(s, {})]

        if not p2_present_sources:
            # Process exited between Pass 1 and Pass 2
            reason = f"Process '{name_p1}' (PID {pid}) terminated between Pass 1 and Pass 2 (transient exit)."
            logger.info("Transient filter: %s", reason)
            transient_discrepancies.append({
                "pid": pid,
                "process_name": name_p1,
                "resolution": "process_exited",
                "evidence": reason,
            })
            diagnostics.append({
                "type": "transient_process_exit",
                "pid": pid,
                "process_name": name_p1,
                "evidence": reason,
            })
            continue

        if len(p2_present_sources) == len(p2_comparison["successful_sources"]):
            # Discrepancy resolved: process appeared across all sources in Pass 2
            reason = (
                f"Discrepancy for '{name_p1}' (PID {pid}) resolved in Pass 2 "
                f"(observed in all successful sources {p2_present_sources})."
            )
            logger.info("Transient filter: %s", reason)
            transient_discrepancies.append({
                "pid": pid,
                "process_name": name_p1,
                "resolution": "timing_resolved",
                "evidence": reason,
            })
            diagnostics.append({
                "type": "transient_timing_resolved",
                "pid": pid,
                "process_name": name_p1,
                "evidence": reason,
            })
            continue

        # Check for PID reuse / process identity mismatch
        p2_names = [p2_views[s][pid] for s in p2_present_sources]
        name_p2 = p2_names[0] if p2_names else name_p1
        if normalize_process_name(name_p1) != normalize_process_name(name_p2):
            reuse_msg = (
                f"PID reuse / identity uncertainty detected for PID {pid}: "
                f"Pass 1 observed '{name_p1}', but Pass 2 observed '{name_p2}'. "
                f"PID equality alone does not prove process identity; withheld from confirmed hidden list."
            )
            logger.warning(reuse_msg)
            diagnostics.append({
                "type": "pid_reuse_uncertainty",
                "pid": pid,
                "process_name": name_p1,
                "pass2_process_name": name_p2,
                "evidence": reuse_msg,
            })
            continue

        # Discrepancy persisted across both passes!
        if pid in p2_discrepancies_by_pid:
            p2_cand = p2_discrepancies_by_pid[pid]
            confirmed_evidence = (
                f"CONFIRMED Process Discrepancy: '{name_p1}' (PID {pid}) persisted across two enumeration passes "
                f"({int(delay * 1000)} ms micro-delay). "
                f"Pass 1: observed in {cand['observed_sources']}, missing from {cand['missing_sources']}. "
                f"Pass 2: observed in {p2_cand['observed_sources']}, missing from {p2_cand['missing_sources']}."
            )
            confirmed_discrepancies.append({
                "pid": pid,
                "process_name": name_p1,
                "observed_sources": p2_cand["observed_sources"],
                "missing_sources": p2_cand["missing_sources"],
                "discrepancy_type": p2_cand["discrepancy_type"],
                "pass1_observed": cand["observed_sources"],
                "pass1_missing": cand["missing_sources"],
                "pass2_observed": p2_cand["observed_sources"],
                "pass2_missing": p2_cand["missing_sources"],
                "evidence": confirmed_evidence,
            })

    return {
        "confirmed_discrepancies": confirmed_discrepancies,
        "transient_discrepancies": transient_discrepancies,
        "diagnostics": diagnostics,
        "pass1": p1_comparison,
        "pass2": p2_comparison,
    }


# ---------------------------------------------------------------------------
# Finding Generation & Scan Execution
# ---------------------------------------------------------------------------
def run_scan(
    scan_id: Optional[int] = None,
    db_path: Optional[str] = None,
    micro_delay: Optional[float] = None,
    # Test overrides
    pass1_sources: Optional[Dict[str, SourceResult]] = None,
    pass2_sources: Optional[Dict[str, SourceResult]] = None,
) -> List[Dict[str, Any]]:
    """
    Executes the Signal 1 Cross-View Process Enumeration Engine and generates
    structured findings adhering strictly to the Phase 1 SQLite schema and invariants:
      finding_type == 'diagnostic' => score_eligible == 0
      finding_type == 'threat'     => score_eligible in (0, 1)

    If scan_id and db_path are provided, automatically validates and persists findings
    via core.db.insert_findings inside an atomic database transaction.

    Returns the list of generated finding dictionaries.
    """
    result = run_two_pass_enumeration(
        micro_delay=micro_delay,
        pass1_sources=pass1_sources,
        pass2_sources=pass2_sources,
    )

    findings: List[Dict[str, Any]] = []
    effective_scan_id = scan_id or 1

    # 1. Confirmed Threat Findings (persisted discrepancies across both passes)
    for conf in result["confirmed_discrepancies"]:
        metadata = {
            "signal": "process_view",
            "pid": conf["pid"],
            "process_name": conf["process_name"],
            "discrepancy_type": conf["discrepancy_type"],
            "pass1_observed": conf["pass1_observed"],
            "pass1_missing": conf["pass1_missing"],
            "pass2_observed": conf["pass2_observed"],
            "pass2_missing": conf["pass2_missing"],
            "micro_delay_seconds": config.MICRO_DELAY_SECONDS if micro_delay is None else micro_delay,
            "two_pass_confirmed": True,
        }
        finding = {
            "scan_id": effective_scan_id,
            "pid": conf["pid"],
            "process_name": conf["process_name"],
            "signal": "process_view",
            "evidence": conf["evidence"],
            "severity": "high",
            "finding_type": "threat",
            "score_eligible": 1,
            "signature_status": "N/A",
            "metadata": json.dumps(metadata),
        }
        findings.append(finding)

    # 2. Operational Diagnostics (source failures, quorum loss, transient events, identity uncertainties)
    for diag in result["diagnostics"]:
        diag_meta = dict(diag)
        pid_val = diag.get("pid")
        raw_pname = diag.get("process_name")
        proc_name = str(raw_pname).strip() if (raw_pname and str(raw_pname).strip()) else "System"
        diag_meta["signal"] = "process_view"
        diag_meta["is_diagnostic"] = True

        diag_finding = {
            "scan_id": effective_scan_id,
            "pid": pid_val,
            "process_name": proc_name,
            "signal": "process_view",
            "evidence": diag.get("evidence", "Operational diagnostic"),
            "severity": "low",
            "finding_type": "diagnostic",
            "score_eligible": 0,
            "signature_status": "N/A",
            "metadata": json.dumps(diag_meta),
        }
        findings.append(diag_finding)

    # Validate findings against Phase 1 DAL validator
    validated_findings = [db.validate_finding(f) for f in findings]

    # If scan_id was explicitly provided, persist findings to the database
    if scan_id is not None:
        db.insert_findings(scan_id, validated_findings, db_path=db_path)

    return validated_findings
