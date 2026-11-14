"""
GhostHunt — Phase 4: Signature Verification & DLL Path Anomaly Engine
Authoritative implementation of Signal 3 DLL signature verification, PE header inspection,
and load-path anomaly analysis.

Architectural Guarantees & Defensible Boundaries:
1. Complete 4x4 Independent Dual-Path Reconciliation Matrix:
   - Path 1: Embedded Authenticode verification (Wintrust.dll!WinVerifyTrust with WINTRUST_FILE_INFO).
   - Path 2: Windows Catalog lookup (Wintrust.dll!CryptCATAdmin* and WinVerifyTrust with WINTRUST_CATALOG_INFO).
   - All 16 combinations of Embedded and Catalog outcomes (VALID, UNSIGNED, INVALID, ERROR) are
     evaluated deterministically.
   - Dual verification outcomes, catalog filenames, and HRESULT error codes are permanently preserved.
   - Operational failures (ERROR) are never silently converted to UNSIGNED.
2. Accurate API Placement:
   - Catalog administration functions (CryptCATAdminAcquireContext, CryptCATAdminCalcHashFromFileHandle,
     CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext)
     are exported by Wintrust.dll, NOT Crypt32.dll.
   - All 64-bit ctypes prototypes specify explicit restype and argtypes to prevent pointer truncation.
3. PE Metadata Analysis:
   - pefile is used as an informational PE structural parser, NOT an Authenticode trust verifier.
   - Certificate table presence (IMAGE_DIRECTORY_ENTRY_SECURITY) is extracted but never treated
     as proof of valid cryptographic trust.
4. Path Anomaly Analysis:
   - Normalized path comparison against config.SYSTEM_WHITELIST_PATHS and config.SUSPICIOUS_PATH_PATTERNS.
   - Accounts for environment-variable expansion and case-insensitivity.
   - Distinguishes path anomalies from signature findings.
5. Verification Cache (Hybrid Integrity & Performance Policy):
   - Fast path: canonical path, file size (st_size), and high-precision mtime (st_mtime_ns).
   - Slow path on miss/invalidation: SHA-256 binary recalculation, full dual-path verification.
   - Periodic forced revalidation on TTL expiration (config.CACHE_TTL_SECONDS).
6. Fail-Safe Finding Classification:
   - Threat findings: verified UNSIGNED or INVALID DLLs loaded from unusual or suspicious paths
     (finding_type = 'threat', score_eligible = 1).
   - Operational diagnostics: access denied, WinTrust errors, catalog errors, unreadable files
     (finding_type = 'diagnostic', score_eligible = 0).
7. Defensive User-Mode Safety:
   - Strictly read-only analysis. Never loads/executes inspected DLLs, never injects code,
     never alters certificate stores or system trust settings.
"""

import ctypes
from ctypes import wintypes
import hashlib
import json
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import config
import core.db as db
import pefile
import psutil

logger = logging.getLogger("ghosthunt.signatures")

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    wintrust = ctypes.windll.wintrust
    kernel32 = ctypes.windll.kernel32
else:
    wintrust = None
    kernel32 = None


# ---------------------------------------------------------------------------
# Windows WinTrust & Catalog API Constants & Structures
# ---------------------------------------------------------------------------
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001 | 0x00000002
OPEN_EXISTING = 3

WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2

WTD_STATEACTION_IGNORE = 0
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_UICONTEXT_EXECUTE = 0

WTD_REVOCATION_CHECK_NONE = 0x00000080
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

# Error Codes
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_BAD_DIGEST = 0x80096010
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
CERT_E_EXPIRED = 0x800B0101
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_CHAINING = 0x800B010A
CERT_E_REVOKED = 0x800B010E
CRYPT_E_FILE_ERROR = 0x80092003
CRYPT_E_NOT_FOUND = 0x80092004


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

# Driver Action GUID for CryptCATAdminAcquireContext
# {F750E6C3-38EE-11D1-85E5-00C04FC295EE}
DRIVER_ACTION_VERIFY = GUID(
    0xF750E6C3,
    0x38EE,
    0x11D1,
    (ctypes.c_ubyte * 8)(0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("wszCatalogFile", wintypes.WCHAR * 260),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.c_void_p),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", ctypes.c_void_p),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.c_void_p),  # POINTER(WINTRUST_FILE_INFO) or POINTER(WINTRUST_CATALOG_INFO)
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


# Configure explicit 64-bit function prototypes on Windows
if IS_WINDOWS and wintrust is not None and kernel32 is not None:
    wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL
    wintrust.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(GUID),
        wintypes.DWORD,
    ]

    wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
    wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_char_p,
        wintypes.DWORD,
    ]

    wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]

    wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
    wintrust.CryptCATCatalogInfoFromContext.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(CATALOG_INFO),
        wintypes.DWORD,
    ]

    wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
    wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]

    wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL
    wintrust.CryptCATAdminReleaseContext.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
    ]

    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]

    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WinVerifyTrust.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(GUID),
        ctypes.c_void_p,
    ]


# ---------------------------------------------------------------------------
# Path Anomaly Analysis
# ---------------------------------------------------------------------------
def normalize_path(path: str) -> str:
    """Safely normalizes Windows file paths with environment expansion and case canonicalization."""
    if not path:
        return ""
    expanded = os.path.expandvars(os.path.expanduser(path.strip().strip('"').strip("'")))
    return os.path.normcase(os.path.normpath(os.path.abspath(expanded)))


def is_unusual_path(file_path: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Evaluates whether a module was loaded from an unusual or suspicious file system location.

    Rules & Safeguards:
    - Normalizes path and compares against system whitelists and suspicious path patterns.
    - Matches against %TEMP%, %APPDATA%, Downloads, Desktop, or drive root locations.
    - Avoids simplistic substring checks that trigger false positives on legitimate software.
    - Returns (is_anomalous: bool, rule_triggered: str, details: dict).
    """
    norm = normalize_path(file_path)
    if not norm:
        return True, "empty_path", {"path": file_path, "normalized": ""}

    # Check suspicious path patterns from configuration
    for pattern in config.SUSPICIOUS_PATH_PATTERNS:
        norm_pattern = os.path.normcase(pattern.strip("\\"))
        # Match as path segment to avoid substring false positives
        parts = norm.split(os.sep)
        pattern_parts = norm_pattern.split(os.sep)
        # Check if pattern_parts is a contiguous sub-sequence
        is_subseq = any(
            parts[i:i + len(pattern_parts)] == pattern_parts
            for i in range(len(parts) - len(pattern_parts) + 1)
        )
        if is_subseq:
            return True, f"suspicious_directory_{norm_pattern}", {
                "path": file_path,
                "normalized": norm,
                "pattern": pattern,
            }

    # Check drive root execution (e.g. C:\malware.dll without directory)
    drive, tail = os.path.splitdrive(norm)
    if drive and tail:
        segments = [s for s in tail.split(os.sep) if s]
        if len(segments) <= 1:
            return True, "drive_root_directory", {"path": file_path, "normalized": norm}

    # Check system whitelist paths from configuration
    is_whitelisted = False
    for white in config.SYSTEM_WHITELIST_PATHS:
        norm_white = normalize_path(white)
        if norm.startswith(norm_white + os.sep) or norm == norm_white:
            is_whitelisted = True
            break

    if not is_whitelisted:
        return True, "outside_system_whitelist", {
            "path": file_path,
            "normalized": norm,
        }

    return False, "trusted_system_path", {"path": file_path, "normalized": norm}


# ---------------------------------------------------------------------------
# PE Header Metadata Analysis
# ---------------------------------------------------------------------------
def inspect_pe_headers(file_path: str) -> Dict[str, Any]:
    """
    Extracts structural PE header metadata using pefile.

    Accurate Technical Boundary:
    pefile is a structural file-format parser, NOT an Authenticode trust verifier.
    Extracting IMAGE_DIRECTORY_ENTRY_SECURITY verifies certificate table presence,
    but does NOT verify cryptographic validity or chain of trust.

    Handles non-PE, truncated, or malformed files safely.
    """
    norm = normalize_path(file_path)
    if not os.path.exists(norm):
        return {"success": False, "error": f"File does not exist: {file_path}"}

    try:
        pe = pefile.PE(norm, fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ])

            machine = hex(pe.FILE_HEADER.Machine) if hasattr(pe, "FILE_HEADER") else "unknown"
            timestamp = int(pe.FILE_HEADER.TimeDateStamp) if hasattr(pe, "FILE_HEADER") else 0
            num_sections = len(pe.sections) if hasattr(pe, "sections") else 0

            has_cert_table = False
            cert_table_offset = 0
            cert_table_size = 0

            if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
                sec_dir_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
                    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
                    if sec_dir.VirtualAddress > 0 and sec_dir.Size > 0:
                        has_cert_table = True
                        cert_table_offset = int(sec_dir.VirtualAddress)
                        cert_table_size = int(sec_dir.Size)

            sections = [
                s.Name.decode("utf-8", errors="replace").strip("\x00")
                for s in pe.sections
            ] if hasattr(pe, "sections") else []

            return {
                "success": True,
                "machine": machine,
                "timestamp": timestamp,
                "sections": sections,
                "num_sections": num_sections,
                "has_cert_table": has_cert_table,
                "cert_table_offset": cert_table_offset,
                "cert_table_size": cert_table_size,
            }
        finally:
            pe.close()
    except pefile.PEFormatError as ex:
        return {"success": False, "error": f"Invalid PE format: {ex}"}
    except Exception as ex:
        return {"success": False, "error": f"PE inspection exception: {ex}"}


# ---------------------------------------------------------------------------
# Path 1: Embedded Authenticode Verification
# ---------------------------------------------------------------------------
def verify_embedded_authenticode(
    file_path: str,
    caller: Optional[Callable[[str], Tuple[str, str]]] = None,
) -> Tuple[str, str]:
    """
    Verifies embedded Authenticode signature using Wintrust.dll!WinVerifyTrust.
    Configures WINTRUST_FILE_INFO and WINTRUST_DATA with WTD_CHOICE_FILE.
    Closes provider state reliably to prevent native memory leaks.

    Returns:
    (status: 'VALID' | 'UNSIGNED' | 'INVALID' | 'ERROR', error_code: str)
    """
    if caller is not None:
        return caller(file_path)

    if not IS_WINDOWS or wintrust is None:
        return "ERROR", "WinVerifyTrust is only supported on Windows hosts"

    norm = normalize_path(file_path)
    if not os.path.exists(norm):
        return "ERROR", f"File does not exist: {file_path}"

    fi = WINTRUST_FILE_INFO()
    fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    fi.pcwszFilePath = norm
    fi.hFile = None
    fi.pgKnownSubject = None

    wtd = WINTRUST_DATA()
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.dwUIChoice = WTD_UI_NONE
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE
    wtd.dwUnionChoice = WTD_CHOICE_FILE
    wtd.pFile = ctypes.cast(ctypes.pointer(fi), ctypes.c_void_p)
    wtd.dwStateAction = WTD_STATEACTION_VERIFY
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL

    action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2

    try:
        hr = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
        hr_u32 = hr & 0xFFFFFFFF
    except Exception as ex:
        return "ERROR", f"WinVerifyTrust exception: {ex}"
    finally:
        # Guarantee provider state closure
        wtd.dwStateAction = WTD_STATEACTION_CLOSE
        try:
            wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
        except Exception:
            pass

    hex_code = f"0x{hr_u32:08X}"

    if hr_u32 == 0:
        return "VALID", hex_code
    elif hr_u32 in (TRUST_E_NOSIGNATURE, CRYPT_E_NOT_FOUND):
        return "UNSIGNED", hex_code
    elif hr_u32 in (
        TRUST_E_BAD_DIGEST,
        TRUST_E_EXPLICIT_DISTRUST,
        TRUST_E_SUBJECT_NOT_TRUSTED,
        CERT_E_EXPIRED,
        CERT_E_UNTRUSTEDROOT,
        CERT_E_CHAINING,
        CERT_E_REVOKED,
    ):
        return "INVALID", hex_code
    else:
        # File I/O, sharing violation, access denied, or operational provider error
        return "ERROR", hex_code


# ---------------------------------------------------------------------------
# Path 2: Windows Catalog Signature Verification
# ---------------------------------------------------------------------------
def verify_catalog_signature(
    file_path: str,
    caller: Optional[Callable[[str], Tuple[str, str, Optional[str]]]] = None,
) -> Tuple[str, str, Optional[str]]:
    """
    Verifies Windows Security Catalog signature using Wintrust.dll!CryptCATAdmin* APIs.
    Calculates member file hash, queries catalog databases, and validates catalog trust.

    Returns:
    (status: 'VALID' | 'UNSIGNED' | 'INVALID' | 'ERROR', error_code: str, catalog_file: Optional[str])
    """
    if caller is not None:
        return caller(file_path)

    if not IS_WINDOWS or wintrust is None or kernel32 is None:
        return "ERROR", "Catalog verification is only supported on Windows hosts", None

    norm = normalize_path(file_path)
    if not os.path.exists(norm):
        return "ERROR", f"File does not exist: {file_path}", None

    hCatAdmin = ctypes.c_void_p()
    # Driver action GUID queries catalog databases
    driver_guid = DRIVER_ACTION_VERIFY
    if not wintrust.CryptCATAdminAcquireContext(ctypes.byref(hCatAdmin), ctypes.byref(driver_guid), 0):
        # Fallback with NULL subsystem GUID
        if not wintrust.CryptCATAdminAcquireContext(ctypes.byref(hCatAdmin), None, 0):
            err = kernel32.GetLastError()
            return "ERROR", f"CryptCATAdminAcquireContext failed: Win32 error {err}", None

    hFile = kernel32.CreateFileW(norm, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
    if hFile in (-1, 0, (1 << 64) - 1, (1 << 32) - 1):
        err = kernel32.GetLastError()
        wintrust.CryptCATAdminReleaseContext(hCatAdmin, 0)
        return "ERROR", f"CreateFileW failed: Win32 error {err}", None

    try:
        cbHash = wintypes.DWORD(0)
        # Determine required hash size
        wintrust.CryptCATAdminCalcHashFromFileHandle(hFile, ctypes.byref(cbHash), None, 0)
        if cbHash.value == 0:
            err = kernel32.GetLastError()
            return "ERROR", f"CryptCATAdminCalcHashFromFileHandle (size) failed: Win32 error {err}", None

        pbHash = ctypes.create_string_buffer(cbHash.value)
        if not wintrust.CryptCATAdminCalcHashFromFileHandle(hFile, ctypes.byref(cbHash), pbHash, 0):
            err = kernel32.GetLastError()
            return "ERROR", f"CryptCATAdminCalcHashFromFileHandle failed: Win32 error {err}", None

        # Look up catalog containing this hash
        hCatInfo = wintrust.CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash.value, 0, None)
        if not hCatInfo:
            # Clean absence of catalog entry confirms file is not catalog-signed
            return "UNSIGNED", "0x00000000", None

        try:
            catInfo = CATALOG_INFO()
            catInfo.cbStruct = ctypes.sizeof(CATALOG_INFO)
            if not wintrust.CryptCATCatalogInfoFromContext(hCatInfo, ctypes.byref(catInfo), 0):
                err = kernel32.GetLastError()
                return "ERROR", f"CryptCATCatalogInfoFromContext failed: Win32 error {err}", None

            catFile = str(catInfo.wszCatalogFile)
            memberTag = "".join(f"{b:02X}" for b in pbHash.raw[:cbHash.value])

            ci = WINTRUST_CATALOG_INFO()
            ci.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
            ci.pcwszCatalogFilePath = catFile
            ci.pcwszMemberFilePath = norm
            ci.pcwszMemberTag = memberTag
            ci.pbCalculatedFileHash = ctypes.cast(pbHash, ctypes.c_void_p)
            ci.cbCalculatedFileHash = cbHash.value
            ci.hCatAdmin = hCatAdmin

            wtd = WINTRUST_DATA()
            wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            wtd.dwUIChoice = WTD_UI_NONE
            wtd.fdwRevocationChecks = WTD_REVOKE_NONE
            wtd.dwUnionChoice = WTD_CHOICE_CATALOG
            wtd.pFile = ctypes.cast(ctypes.pointer(ci), ctypes.c_void_p)
            wtd.dwStateAction = WTD_STATEACTION_VERIFY
            wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL

            action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2
            hr = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
            hr_u32 = hr & 0xFFFFFFFF

            # Close provider state
            wtd.dwStateAction = WTD_STATEACTION_CLOSE
            try:
                wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
            except Exception:
                pass

            hex_code = f"0x{hr_u32:08X}"
            if hr_u32 == 0:
                return "VALID", hex_code, catFile
            elif hr_u32 in (TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, CERT_E_EXPIRED, CERT_E_REVOKED):
                return "INVALID", hex_code, catFile
            else:
                return "ERROR", hex_code, catFile
        finally:
            wintrust.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0)
    finally:
        kernel32.CloseHandle(hFile)
        wintrust.CryptCATAdminReleaseContext(hCatAdmin, 0)


# ---------------------------------------------------------------------------
# Complete 4x4 Signature Reconciliation Engine
# ---------------------------------------------------------------------------
RECONCILIATION_MATRIX: Dict[Tuple[str, str], Tuple[str, str]] = {
    # (Embedded, Catalog) -> (Combined, PrimaryMethod)
    ("VALID", "VALID"): ("VALID", "embedded_authenticode"),
    ("VALID", "UNSIGNED"): ("VALID", "embedded_authenticode"),
    ("VALID", "INVALID"): ("VALID", "embedded_authenticode"),
    ("VALID", "ERROR"): ("VALID", "embedded_authenticode"),

    ("UNSIGNED", "VALID"): ("VALID", "windows_catalog"),
    ("UNSIGNED", "UNSIGNED"): ("UNSIGNED", "none_found"),
    ("UNSIGNED", "INVALID"): ("INVALID", "windows_catalog"),
    ("UNSIGNED", "ERROR"): ("ERROR", "catalog_lookup_error"),

    ("INVALID", "VALID"): ("VALID", "windows_catalog"),
    ("INVALID", "UNSIGNED"): ("INVALID", "embedded_authenticode"),
    ("INVALID", "INVALID"): ("INVALID", "dual_invalid"),
    ("INVALID", "ERROR"): ("INVALID", "embedded_authenticode"),

    ("ERROR", "VALID"): ("VALID", "windows_catalog"),
    ("ERROR", "UNSIGNED"): ("ERROR", "embedded_error"),
    ("ERROR", "INVALID"): ("INVALID", "windows_catalog"),
    ("ERROR", "ERROR"): ("ERROR", "dual_error"),
}


def reconcile_signatures(
    embedded_status: str,
    embedded_code: str,
    catalog_status: str,
    catalog_code: str,
    catalog_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Applies the authoritative 4x4 Signature Reconciliation Matrix from Section 3.3.
    Evaluates all 16 combinations deterministically and permanently preserves both
    individual verification outcomes in the result dictionary.
    """
    pair = (embedded_status, catalog_status)
    if pair in RECONCILIATION_MATRIX:
        combined_status, primary_method = RECONCILIATION_MATRIX[pair]
    else:
        # Fallback safety guard for unknown input statuses
        combined_status = "ERROR"
        primary_method = "unknown_status_combination"

    return {
        "status": combined_status,
        "primary_method": primary_method,
        "embedded_status": embedded_status,
        "embedded_code": embedded_code,
        "catalog_status": catalog_status,
        "catalog_code": catalog_code,
        "catalog_file": catalog_file,
    }


# ---------------------------------------------------------------------------
# Hybrid Verification Cache
# ---------------------------------------------------------------------------
class CacheEntry:
    def __init__(
        self,
        canonical_path: str,
        file_size: int,
        mtime_ns: int,
        file_digest: str,
        verification_result: Dict[str, Any],
        cached_at: float,
    ):
        self.canonical_path = canonical_path
        self.file_size = file_size
        self.mtime_ns = mtime_ns
        self.file_digest = file_digest
        self.verification_result = verification_result
        self.cached_at = cached_at
        self.last_verified_at = cached_at
        self.hit_count = 0


class SignatureCache:
    """
    Hybrid metadata-keyed verification cache with safe invalidation and TTL revalidation.
    Keyed by canonical path, file size, and high-precision mtime.
    """

    def __init__(self, ttl_seconds: int = config.CACHE_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, CacheEntry] = {}
        self.hits = 0
        self.misses = 0

    def get(self, canonical_path: str) -> Optional[Dict[str, Any]]:
        norm = normalize_path(canonical_path)
        if norm not in self.cache:
            self.misses += 1
            return None

        entry = self.cache[norm]
        now = time.time()

        # Check TTL expiration
        if (now - entry.last_verified_at) > self.ttl_seconds:
            self.misses += 1
            return None

        # Check file size and mtime on disk (fast path)
        try:
            stat = os.stat(norm)
            if stat.st_size != entry.file_size or stat.st_mtime_ns != entry.mtime_ns:
                self.misses += 1
                return None
        except Exception:
            self.misses += 1
            return None

        # Cache hit accepted
        self.hits += 1
        entry.hit_count += 1
        return entry.verification_result

    def put(
        self,
        canonical_path: str,
        file_digest: str,
        verification_result: Dict[str, Any],
    ) -> None:
        norm = normalize_path(canonical_path)
        try:
            stat = os.stat(norm)
            size = stat.st_size
            mtime = stat.st_mtime_ns
        except Exception:
            size = 0
            mtime = 0

        now = time.time()
        self.cache[norm] = CacheEntry(
            canonical_path=norm,
            file_size=size,
            mtime_ns=mtime,
            file_digest=file_digest,
            verification_result=verification_result,
            cached_at=now,
        )

    def clear(self) -> None:
        self.cache.clear()
        self.hits = 0
        self.misses = 0


# Global engine verification cache
GLOBAL_VERIFICATION_CACHE = SignatureCache()


def compute_file_sha256(file_path: str) -> str:
    """Computes SHA-256 binary digest of a file in 64 KB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_file_signature_cached(
    file_path: str,
    cache: Optional[SignatureCache] = None,
    embedded_caller: Optional[Callable[[str], Tuple[str, str]]] = None,
    catalog_caller: Optional[Callable[[str], Tuple[str, str, Optional[str]]]] = None,
) -> Dict[str, Any]:
    """
    Verifies a file's signature using the hybrid verification cache.
    On cache hit: returns cached result.
    On cache miss / invalidation: computes SHA-256 digest, executes full dual-path
    verification, applies the 4x4 reconciliation matrix, and updates cache.
    """
    active_cache = cache if cache is not None else GLOBAL_VERIFICATION_CACHE
    norm = normalize_path(file_path)

    # 1. Check cache fast path
    cached = active_cache.get(norm)
    if cached is not None:
        return cached

    # 2. Cache miss / slow path
    if not os.path.exists(norm):
        if embedded_caller is not None or catalog_caller is not None:
            sha256 = "mock_sha256"
        else:
            return {
                "status": "ERROR",
                "primary_method": "file_missing",
                "embedded_status": "ERROR",
                "embedded_code": "0x80070002",
                "catalog_status": "ERROR",
                "catalog_code": "0x80070002",
                "catalog_file": None,
                "sha256": "",
            }
    else:
        try:
            sha256 = compute_file_sha256(norm)
        except Exception as ex:
            return {
                "status": "ERROR",
                "primary_method": "io_error",
                "embedded_status": "ERROR",
                "embedded_code": str(ex),
                "catalog_status": "ERROR",
                "catalog_code": str(ex),
                "catalog_file": None,
                "sha256": "",
            }

    emb_status, emb_code = verify_embedded_authenticode(norm, caller=embedded_caller)
    cat_status, cat_code, cat_file = verify_catalog_signature(norm, caller=catalog_caller)

    recon = reconcile_signatures(emb_status, emb_code, cat_status, cat_code, cat_file)
    recon["sha256"] = sha256

    # Update cache record
    active_cache.put(norm, sha256, recon)
    return recon


# ---------------------------------------------------------------------------
# Loaded Module Enumeration via psutil
# ---------------------------------------------------------------------------
def get_loaded_dlls(
    pid: int,
    caller: Optional[Callable[[int], Tuple[bool, List[str], Optional[str]]]] = None,
) -> Tuple[bool, List[str], Optional[str]]:
    """
    Enumerates loaded DLL modules for a running process using psutil memory_maps().

    Requirements & Safeguards:
    - Handles psutil.NoSuchProcess, AccessDenied, and ZombieProcess explicitly.
    - Preserves module paths, converting to canonical normalized paths.
    - Distinguishes access denial or process exit from legitimate empty results.
    - Strictly read-only: does not modify or inject into process memory.
    """
    if caller is not None:
        return caller(pid)

    if pid <= 0:
        return True, [], None

    try:
        p = psutil.Process(pid)
        # Verify process is still alive and accessible
        if not p.is_running():
            return False, [], f"Process with PID {pid} is no longer running"

        mmaps = p.memory_maps()
        dll_paths: Set[str] = set()

        for m in mmaps:
            path = m.path
            if path and os.path.exists(path) and path.lower().endswith(".dll"):
                dll_paths.add(normalize_path(path))

        return True, sorted(list(dll_paths)), None
    except psutil.ZombieProcess:
        return False, [], f"PID {pid} is a zombie process"
    except psutil.NoSuchProcess:
        return False, [], f"Process with PID {pid} terminated during module enumeration"
    except psutil.AccessDenied:
        return False, [], f"Access denied enumerating modules for PID {pid}"
    except Exception as ex:
        return False, [], f"Module enumeration exception for PID {pid}: {ex}"


# ---------------------------------------------------------------------------
# Finding Generation & Scan Execution
# ---------------------------------------------------------------------------
def run_scan(
    scan_id: Optional[int] = None,
    db_path: Optional[str] = None,
    target_pids: Optional[List[int]] = None,
    cache: Optional[SignatureCache] = None,
    # Custom injectors for unit testing
    module_caller: Optional[Callable[[int], Tuple[bool, List[str], Optional[str]]]] = None,
    embedded_caller: Optional[Callable[[str], Tuple[str, str]]] = None,
    catalog_caller: Optional[Callable[[str], Tuple[str, str, Optional[str]]]] = None,
) -> List[Dict[str, Any]]:
    """
    Executes the Signal 3 Signature Verification and DLL Path Anomaly Engine.
    Inspects loaded modules across targeted PIDs (or all accessible processes).
    Generates findings adhering strictly to the Phase 1 SQLite schema and invariants:
      finding_type == 'diagnostic' => score_eligible == 0
      finding_type == 'threat'     => score_eligible in (0, 1)

    If scan_id is provided, findings are validated and persisted to SQLite.
    Returns the list of generated finding dictionaries.
    """
    effective_scan_id = scan_id or 1
    active_cache = cache if cache is not None else GLOBAL_VERIFICATION_CACHE

    pids_to_inspect: List[int] = []
    if target_pids is not None:
        pids_to_inspect = target_pids
    else:
        # Enumerate running PIDs safely
        try:
            pids_to_inspect = [p.pid for p in psutil.process_iter(["pid"]) if p.pid > 0]
        except Exception:
            pids_to_inspect = [os.getpid()]

    findings: List[Dict[str, Any]] = []

    for pid in pids_to_inspect:
        proc_name = f"PID_{pid}"
        try:
            if psutil.pid_exists(pid):
                raw_proc_name = psutil.Process(pid).name()
                if raw_proc_name and isinstance(raw_proc_name, str) and raw_proc_name.strip():
                    proc_name = raw_proc_name.strip()
        except Exception:
            pass

        if not proc_name or not proc_name.strip():
            proc_name = f"PID_{pid}"

        # 1. Enumerate loaded modules
        mod_ok, modules, mod_err = get_loaded_dlls(pid, caller=module_caller)

        if not mod_ok:
            # Operational diagnostic for module enumeration failure (e.g. Access Denied)
            diag = {
                "scan_id": effective_scan_id,
                "pid": pid,
                "process_name": proc_name,
                "signal": "signature",
                "evidence": f"Operational diagnostic: Module enumeration failed for '{proc_name}' (PID {pid}): {mod_err}",
                "severity": "low",
                "finding_type": "diagnostic",
                "score_eligible": 0,
                "signature_status": "N/A",
                "metadata": json.dumps({
                    "signal": "signature",
                    "pid": pid,
                    "process_name": proc_name,
                    "error": mod_err,
                    "is_diagnostic": True,
                }),
            }
            findings.append(diag)
            continue

        # 2. Inspect each loaded module
        for dll_path in modules:
            module_name = os.path.basename(dll_path)

            # A. Path anomaly analysis
            is_anom, rule_name, path_details = is_unusual_path(dll_path)

            # B. Dual-path signature verification with hybrid cache
            sig_result = verify_file_signature_cached(
                dll_path,
                cache=active_cache,
                embedded_caller=embedded_caller,
                catalog_caller=catalog_caller,
            )

            status = sig_result["status"]  # VALID | UNSIGNED | INVALID | ERROR
            pe_info = inspect_pe_headers(dll_path)

            metadata_payload = {
                "signal": "signature",
                "pid": pid,
                "process_name": proc_name,
                "module_name": module_name,
                "module_path": dll_path,
                "signature_result": sig_result,
                "path_anomaly": {
                    "is_anomalous": is_anom,
                    "rule": rule_name,
                    "details": path_details,
                },
                "pe_info": pe_info,
            }

            # Classify into threats vs diagnostics
            if status == "ERROR":
                # Operational verification error
                diag_finding = {
                    "scan_id": effective_scan_id,
                    "pid": pid,
                    "process_name": proc_name,
                    "signal": "signature",
                    "evidence": (
                        f"Operational diagnostic: Signature verification error on module '{module_name}' "
                        f"(PID {pid}, path '{dll_path}'): embedded={sig_result.get('embedded_code')}, "
                        f"catalog={sig_result.get('catalog_code')}."
                    ),
                    "severity": "low",
                    "finding_type": "diagnostic",
                    "score_eligible": 0,
                    "signature_status": "ERROR",
                    "metadata": json.dumps(metadata_payload),
                }
                findings.append(diag_finding)

            elif status in ("UNSIGNED", "INVALID"):
                if is_anom:
                    # Verified unsigned or invalid DLL loaded from suspicious/unusual path -> Threat!
                    sev = "high" if "suspicious" in rule_name or "root" in rule_name else "medium"
                    threat_finding = {
                        "scan_id": effective_scan_id,
                        "pid": pid,
                        "process_name": proc_name,
                        "signal": "signature",
                        "evidence": (
                            f"Suspicious module detected: '{module_name}' loaded by '{proc_name}' (PID {pid}) "
                            f"has signature status '{status}' and was loaded from unusual path "
                            f"(rule: '{rule_name}', path: '{dll_path}')."
                        ),
                        "severity": sev,
                        "finding_type": "threat",
                        "score_eligible": 1,
                        "signature_status": status,
                        "metadata": json.dumps(metadata_payload),
                    }
                    findings.append(threat_finding)
                else:
                    # Unsigned or invalid in standard directory: behavioral finding
                    threat_finding = {
                        "scan_id": effective_scan_id,
                        "pid": pid,
                        "process_name": proc_name,
                        "signal": "signature",
                        "evidence": (
                            f"Module signature anomaly: '{module_name}' loaded by '{proc_name}' (PID {pid}) "
                            f"has status '{status}' (path: '{dll_path}')."
                        ),
                        "severity": "low",
                        "finding_type": "threat",
                        "score_eligible": 1,
                        "signature_status": status,
                        "metadata": json.dumps(metadata_payload),
                    }
                    findings.append(threat_finding)

            elif status == "VALID":
                # Validly signed module
                if is_anom and ("suspicious" in rule_name):
                    # Even if signed, loading from %TEMP% or %APPDATA% is an unusual operational indicator
                    diag_finding = {
                        "scan_id": effective_scan_id,
                        "pid": pid,
                        "process_name": proc_name,
                        "signal": "signature",
                        "evidence": (
                            f"Operational diagnostic: Validly signed module '{module_name}' loaded from "
                            f"suspicious path (rule: '{rule_name}', path: '{dll_path}')."
                        ),
                        "severity": "low",
                        "finding_type": "diagnostic",
                        "score_eligible": 0,
                        "signature_status": "VALID",
                        "metadata": json.dumps(metadata_payload),
                    }
                    findings.append(diag_finding)

    # Validate findings against Phase 1 DAL schema
    validated_findings = [db.validate_finding(f) for f in findings]

    if scan_id is not None:
        db.insert_findings(scan_id, validated_findings, db_path=db_path)

    return validated_findings
