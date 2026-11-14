"""
GhostHunt — Signal 1 Detector: Cross-View Process Enumeration Engine
Authoritative detector module specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).
Re-exports functionality from core.process_views.
"""

from core.process_views import (
    PROCESSENTRY32W,
    SYSTEM_PROCESS_INFORMATION,
    UNICODE_STRING,
    ProcessRecord,
    SourceResult,
    compare_views,
    get_processes_nt,
    get_processes_toolhelp32,
    get_processes_wmi,
    normalize_process_name,
    run_scan,
    run_two_pass_enumeration,
)

__all__ = [
    "PROCESSENTRY32W",
    "SYSTEM_PROCESS_INFORMATION",
    "UNICODE_STRING",
    "ProcessRecord",
    "SourceResult",
    "compare_views",
    "get_processes_nt",
    "get_processes_toolhelp32",
    "get_processes_wmi",
    "normalize_process_name",
    "run_scan",
    "run_two_pass_enumeration",
]
