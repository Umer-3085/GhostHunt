"""
GhostHunt — Signal 3 Detector: Loaded DLL Signature and Path Anomaly Engine
Authoritative detector module specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).
Re-exports functionality from core.signatures.
"""

from core.signatures import (
    CATALOG_INFO,
    GUID,
    RECONCILIATION_MATRIX,
    WINTRUST_CATALOG_INFO,
    WINTRUST_DATA,
    WINTRUST_FILE_INFO,
    CacheEntry,
    GLOBAL_VERIFICATION_CACHE,
    SignatureCache,
    compute_file_sha256,
    get_loaded_dlls,
    inspect_pe_headers,
    is_unusual_path,
    normalize_path,
    reconcile_signatures,
    run_scan,
    verify_catalog_signature,
    verify_embedded_authenticode,
    verify_file_signature_cached,
)

__all__ = [
    "CATALOG_INFO",
    "GUID",
    "RECONCILIATION_MATRIX",
    "WINTRUST_CATALOG_INFO",
    "WINTRUST_DATA",
    "WINTRUST_FILE_INFO",
    "CacheEntry",
    "GLOBAL_VERIFICATION_CACHE",
    "SignatureCache",
    "compute_file_sha256",
    "get_loaded_dlls",
    "inspect_pe_headers",
    "is_unusual_path",
    "normalize_path",
    "reconcile_signatures",
    "run_scan",
    "verify_catalog_signature",
    "verify_embedded_authenticode",
    "verify_file_signature_cached",
]
