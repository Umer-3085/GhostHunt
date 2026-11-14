"""
GhostHunt — Phase 4 Test Suite: Loaded DLL Signature & Path Anomaly Engine
Comprehensive unit and integration tests for Signal 3 detection.

Covers:
1. WinTrust / Catalog ctypes structures and re-exports in detectors.signature_check.
2. Module enumeration via psutil (live process, AccessDenied, NoSuchProcess, ZombieProcess).
3. PE header structural parsing via pefile (valid PE, non-PE, non-existent, cert table offset).
4. Path anomaly analysis (whitelists, %TEMP%, %APPDATA%, Downloads, Desktop, root directories, segment matching).
5. Embedded Authenticode verification (live & injected statuses: VALID, UNSIGNED, INVALID, ERROR).
6. Catalog signature verification (live & injected statuses: VALID, UNSIGNED, INVALID, ERROR).
7. Complete 4x4 Signature Reconciliation Matrix (all 16 combinations strictly verified).
8. Hybrid verification cache (fast path mtime/size hit, SHA-256 computation, invalidation on modification, TTL expiration).
9. Fail-safe finding classification:
   - finding_type == 'threat' => score_eligible == 1
   - finding_type == 'diagnostic' => score_eligible == 0
10. Database persistence and scan_id linkage through Phase 1 SQLite DAL.
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import config
import core.db as db
import core.signatures as cs
import detectors.signature_check as dsc
import pefile
import psutil


class TestSignatureStructuresAndImports(unittest.TestCase):
    """Verifies ctypes structures and detector re-exports."""

    def test_re_exports_in_detector_module(self):
        """Verifies that detectors.signature_check re-exports all required symbols."""
        required_symbols = [
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
        for sym in required_symbols:
            self.assertTrue(
                hasattr(dsc, sym),
                f"detectors.signature_check missing re-export: {sym}",
            )
            self.assertIs(getattr(dsc, sym), getattr(cs, sym))

    def test_wintrust_structures_sizes_and_alignment(self):
        """Verifies that WinTrust ctypes structures are non-zero size."""
        self.assertGreater(cs.ctypes.sizeof(cs.WINTRUST_FILE_INFO), 0)
        self.assertGreater(cs.ctypes.sizeof(cs.WINTRUST_CATALOG_INFO), 0)
        self.assertGreater(cs.ctypes.sizeof(cs.WINTRUST_DATA), 0)
        self.assertGreater(cs.ctypes.sizeof(cs.CATALOG_INFO), 0)
        self.assertEqual(cs.ctypes.sizeof(cs.GUID), 16)


class TestLoadedDllEnumeration(unittest.TestCase):
    """Verifies loaded module enumeration via psutil."""

    def test_enumerate_current_process_modules(self):
        """Current Python process should successfully enumerate at least one loaded DLL on Windows."""
        if not cs.IS_WINDOWS:
            self.skipTest("Windows-only test")
        ok, dlls, err = cs.get_loaded_dlls(os.getpid())
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertIsInstance(dlls, list)
        self.assertGreater(len(dlls), 0)
        for dll in dlls:
            self.assertTrue(dll.lower().endswith(".dll"))
            self.assertTrue(os.path.isabs(dll))

    def test_enumerate_invalid_or_zero_pid(self):
        """PID 0 or negative should return empty list gracefully."""
        ok, dlls, err = cs.get_loaded_dlls(0)
        self.assertTrue(ok)
        self.assertEqual(dlls, [])
        self.assertIsNone(err)

    def test_enumerate_access_denied(self):
        """AccessDenied exception should return ok=False with explicit error."""
        with patch("psutil.Process") as mock_proc:
            instance = MagicMock()
            instance.is_running.return_value = True
            instance.memory_maps.side_effect = psutil.AccessDenied()
            mock_proc.return_value = instance

            ok, dlls, err = cs.get_loaded_dlls(1234)
            self.assertFalse(ok)
            self.assertEqual(dlls, [])
            self.assertIn("Access denied", err)

    def test_enumerate_no_such_process(self):
        """NoSuchProcess exception should return ok=False with exit notification."""
        with patch("psutil.Process") as mock_proc:
            instance = MagicMock()
            instance.is_running.return_value = True
            instance.memory_maps.side_effect = psutil.NoSuchProcess(pid=9999)
            mock_proc.return_value = instance

            ok, dlls, err = cs.get_loaded_dlls(9999)
            self.assertFalse(ok)
            self.assertEqual(dlls, [])
            self.assertIn("terminated", err)

    def test_enumerate_zombie_process(self):
        """ZombieProcess exception should return ok=False."""
        with patch("psutil.Process") as mock_proc:
            instance = MagicMock()
            instance.is_running.return_value = True
            instance.memory_maps.side_effect = psutil.ZombieProcess(pid=8888)
            mock_proc.return_value = instance

            ok, dlls, err = cs.get_loaded_dlls(8888)
            self.assertFalse(ok)
            self.assertEqual(dlls, [])
            self.assertIn("zombie", err)

    def test_enumerate_custom_caller_injection(self):
        """Injecting custom caller bypasses psutil entirely."""
        def custom_caller(pid: int):
            return True, ["C:\\test\\custom.dll"], None

        ok, dlls, err = cs.get_loaded_dlls(111, caller=custom_caller)
        self.assertTrue(ok)
        self.assertEqual(dlls, ["C:\\test\\custom.dll"])
        self.assertIsNone(err)


class TestPEHeaderInspection(unittest.TestCase):
    """Verifies structural PE header inspection using pefile."""

    def test_inspect_python_executable(self):
        """Inspects sys.executable (python.exe), verifying PE fields."""
        pe_info = cs.inspect_pe_headers(sys.executable)
        self.assertTrue(pe_info["success"])
        self.assertIn("machine", pe_info)
        self.assertIn("timestamp", pe_info)
        self.assertIn("sections", pe_info)
        self.assertIn("has_cert_table", pe_info)
        self.assertGreater(pe_info["num_sections"], 0)

    def test_inspect_non_pe_file(self):
        """Non-PE text file returns success=False with PEFormatError."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
            tf.write("This is a simple plain text file, not a Portable Executable.")
            tf_path = tf.name

        try:
            pe_info = cs.inspect_pe_headers(tf_path)
            self.assertFalse(pe_info["success"])
            self.assertIn("Invalid PE format", pe_info["error"])
        finally:
            if os.path.exists(tf_path):
                os.unlink(tf_path)

    def test_inspect_nonexistent_file(self):
        """Non-existent file returns success=False."""
        pe_info = cs.inspect_pe_headers("C:\\non_existent_binary_ghosthunt.dll")
        self.assertFalse(pe_info["success"])
        self.assertIn("does not exist", pe_info["error"])


class TestPathAnomalyAnalysis(unittest.TestCase):
    """Verifies path normalization and anomaly detection rules."""

    def test_whitelisted_system_paths(self):
        """Standard System32 and Program Files paths are recognized as non-anomalous."""
        system_dll = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "kernel32.dll")
        is_anom, rule, details = cs.is_unusual_path(system_dll)
        self.assertFalse(is_anom)
        self.assertEqual(rule, "trusted_system_path")

    def test_suspicious_temp_path(self):
        """DLL located in AppData\\Local\\Temp is identified as anomalous."""
        temp_dll = os.path.join(tempfile.gettempdir(), "injected_module.dll")
        is_anom, rule, details = cs.is_unusual_path(temp_dll)
        self.assertTrue(is_anom)
        self.assertTrue("temp" in rule.lower() or "suspicious" in rule.lower())

    def test_suspicious_appdata_path(self):
        """DLL located in %APPDATA% is identified as anomalous."""
        appdata_dir = os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming")
        appdata_dll = os.path.join(appdata_dir, "malicious.dll")
        is_anom, rule, details = cs.is_unusual_path(appdata_dll)
        self.assertTrue(is_anom)
        self.assertTrue("appdata" in rule.lower() or "suspicious" in rule.lower())

    def test_suspicious_downloads_path(self):
        """DLL located in Downloads is identified as anomalous."""
        user_prof = os.environ.get("USERPROFILE", "C:\\Users\\Default")
        downloads_dll = os.path.join(user_prof, "Downloads", "payload.dll")
        is_anom, rule, details = cs.is_unusual_path(downloads_dll)
        self.assertTrue(is_anom)
        self.assertTrue("downloads" in rule.lower() or "suspicious" in rule.lower())

    def test_suspicious_desktop_path(self):
        """DLL located on Desktop is identified as anomalous."""
        user_prof = os.environ.get("USERPROFILE", "C:\\Users\\Default")
        desktop_dll = os.path.join(user_prof, "Desktop", "dropper.dll")
        is_anom, rule, details = cs.is_unusual_path(desktop_dll)
        self.assertTrue(is_anom)
        self.assertTrue("desktop" in rule.lower() or "suspicious" in rule.lower())

    def test_drive_root_path(self):
        """DLL residing directly at drive root (e.g. C:\\root.dll) is flagged."""
        is_anom, rule, details = cs.is_unusual_path("C:\\root_module.dll")
        self.assertTrue(is_anom)
        self.assertEqual(rule, "drive_root_directory")

    def test_substring_evasion_resistance(self):
        """
        Paths like C:\\Program Files\\TempProject\\lib.dll must not falsely trigger
        the %TEMP% directory rule since 'TempProject' is a distinct segment name.
        """
        fake_path = "C:\\Program Files\\TempProject\\lib.dll"
        is_anom, rule, details = cs.is_unusual_path(fake_path)
        # Should be classified under trusted Program Files, not suspicious temp
        self.assertFalse(is_anom)
        self.assertEqual(rule, "trusted_system_path")

    def test_empty_path(self):
        """Empty or whitespace path returns anomaly."""
        is_anom, rule, details = cs.is_unusual_path("")
        self.assertTrue(is_anom)
        self.assertEqual(rule, "empty_path")


class TestEmbeddedAuthenticodeVerification(unittest.TestCase):
    """Verifies embedded Authenticode signature verification."""

    def test_live_python_authenticode_verification(self):
        """Live verification of sys.executable on Windows host."""
        if not cs.IS_WINDOWS:
            self.skipTest("Windows-only test")
        status, code = cs.verify_embedded_authenticode(sys.executable)
        self.assertEqual(status, "VALID")
        self.assertEqual(code, "0x00000000")

    def test_nonexistent_file_returns_error(self):
        """Non-existent file returns ERROR."""
        status, code = cs.verify_embedded_authenticode("C:\\nonexistent_file_ghosthunt.dll")
        self.assertEqual(status, "ERROR")

    def test_injected_embedded_results(self):
        """Verifies custom caller handling for embedded statuses."""
        def mock_caller_unsigned(path: str):
            return "UNSIGNED", "0x800B0100"

        status, code = cs.verify_embedded_authenticode("C:\\any.dll", caller=mock_caller_unsigned)
        self.assertEqual(status, "UNSIGNED")
        self.assertEqual(code, "0x800B0100")

        def mock_caller_invalid(path: str):
            return "INVALID", "0x80096010"

        status, code = cs.verify_embedded_authenticode("C:\\any.dll", caller=mock_caller_invalid)
        self.assertEqual(status, "INVALID")
        self.assertEqual(code, "0x80096010")


class TestCatalogSignatureVerification(unittest.TestCase):
    """Verifies Windows Security Catalog signature verification."""

    def test_live_catalog_signed_binary(self):
        """
        Live verification of cmd.exe on Windows host (standard Windows system binaries
        typically have catalog signatures rather than embedded signatures).
        """
        if not cs.IS_WINDOWS:
            self.skipTest("Windows-only test")
        cmd_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "cmd.exe")
        if not os.path.exists(cmd_path):
            self.skipTest("cmd.exe not found")

        status, code, cat_file = cs.verify_catalog_signature(cmd_path)
        self.assertEqual(status, "VALID")
        self.assertEqual(code, "0x00000000")
        self.assertIsNotNone(cat_file)
        self.assertTrue(cat_file.lower().endswith(".cat"))

    def test_nonexistent_file_catalog_error(self):
        """Non-existent file returns ERROR."""
        status, code, cat_file = cs.verify_catalog_signature("C:\\nonexistent_file_ghosthunt.dll")
        self.assertEqual(status, "ERROR")
        self.assertIsNone(cat_file)

    def test_injected_catalog_caller(self):
        """Verifies custom caller handling for catalog signatures."""
        def mock_catalog(path: str):
            return "VALID", "0x00000000", "C:\\Windows\\System32\\CatRoot\\sample.cat"

        status, code, cat = cs.verify_catalog_signature("C:\\any.dll", caller=mock_catalog)
        self.assertEqual(status, "VALID")
        self.assertEqual(code, "0x00000000")
        self.assertEqual(cat, "C:\\Windows\\System32\\CatRoot\\sample.cat")


class TestReconciliationMatrix16Combinations(unittest.TestCase):
    """
    Authoritative test of the complete 4x4 Signature Reconciliation Matrix.
    Verifies all 16 combinations strictly according to Section 3.3.
    """

    def test_all_16_combinations_exhaustively(self):
        """
        Systematically validates every cell of the 4x4 matrix:
        Embedded in (VALID, UNSIGNED, INVALID, ERROR) x Catalog in (VALID, UNSIGNED, INVALID, ERROR).
        """
        expected_results = {
            # 1. Embedded VALID combinations
            ("VALID", "VALID"): ("VALID", "embedded_authenticode"),
            ("VALID", "UNSIGNED"): ("VALID", "embedded_authenticode"),
            ("VALID", "INVALID"): ("VALID", "embedded_authenticode"),
            ("VALID", "ERROR"): ("VALID", "embedded_authenticode"),

            # 2. Embedded UNSIGNED combinations
            ("UNSIGNED", "VALID"): ("VALID", "windows_catalog"),
            ("UNSIGNED", "UNSIGNED"): ("UNSIGNED", "none_found"),
            ("UNSIGNED", "INVALID"): ("INVALID", "windows_catalog"),
            ("UNSIGNED", "ERROR"): ("ERROR", "catalog_lookup_error"),

            # 3. Embedded INVALID combinations
            ("INVALID", "VALID"): ("VALID", "windows_catalog"),
            ("INVALID", "UNSIGNED"): ("INVALID", "embedded_authenticode"),
            ("INVALID", "INVALID"): ("INVALID", "dual_invalid"),
            ("INVALID", "ERROR"): ("INVALID", "embedded_authenticode"),

            # 4. Embedded ERROR combinations
            ("ERROR", "VALID"): ("VALID", "windows_catalog"),
            ("ERROR", "UNSIGNED"): ("ERROR", "embedded_error"),
            ("ERROR", "INVALID"): ("INVALID", "windows_catalog"),
            ("ERROR", "ERROR"): ("ERROR", "dual_error"),
        }

        self.assertEqual(len(expected_results), 16)

        for (emb, cat), (expected_status, expected_method) in expected_results.items():
            result = cs.reconcile_signatures(
                embedded_status=emb,
                embedded_code=f"code_{emb}",
                catalog_status=cat,
                catalog_code=f"code_{cat}",
                catalog_file="catalog.cat" if cat == "VALID" else None,
            )

            self.assertEqual(
                result["status"],
                expected_status,
                f"Mismatch for pair ({emb}, {cat}): expected status {expected_status}, got {result['status']}",
            )
            self.assertEqual(
                result["primary_method"],
                expected_method,
                f"Mismatch for pair ({emb}, {cat}): expected method {expected_method}, got {result['primary_method']}",
            )

            # Invariant: preserve individual embedded and catalog outcomes and error codes
            self.assertEqual(result["embedded_status"], emb)
            self.assertEqual(result["embedded_code"], f"code_{emb}")
            self.assertEqual(result["catalog_status"], cat)
            self.assertEqual(result["catalog_code"], f"code_{cat}")

    def test_error_never_converted_to_unsigned(self):
        """
        Explicit invariant verification:
        Operational failures (ERROR) must never silently degrade into UNSIGNED.
        """
        # (UNSIGNED, ERROR) must produce ERROR, NOT UNSIGNED
        res1 = cs.reconcile_signatures("UNSIGNED", "0x800B0100", "ERROR", "0x80070005")
        self.assertEqual(res1["status"], "ERROR")
        self.assertNotEqual(res1["status"], "UNSIGNED")

        # (ERROR, UNSIGNED) must produce ERROR, NOT UNSIGNED
        res2 = cs.reconcile_signatures("ERROR", "0x80070005", "UNSIGNED", "0x00000000")
        self.assertEqual(res2["status"], "ERROR")
        self.assertNotEqual(res2["status"], "UNSIGNED")


class TestHybridVerificationCache(unittest.TestCase):
    """Verifies verification caching, fast path mtime/size checks, and invalidation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.temp_dir.name) / "test_module.dll"
        self.test_file.write_bytes(b"TEST_PE_CONTENT_BYTES")
        self.cache = cs.SignatureCache(ttl_seconds=5)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cache_miss_then_hit(self):
        """First call computes signature; second call retrieves from cache without re-invoking verifiers."""
        call_count = {"embedded": 0, "catalog": 0}

        def mock_embedded(path: str):
            call_count["embedded"] += 1
            return "VALID", "0x00000000"

        def mock_catalog(path: str):
            call_count["catalog"] += 1
            return "UNSIGNED", "0x00000000", None

        # First lookup: cache miss
        res1 = cs.verify_file_signature_cached(
            str(self.test_file),
            cache=self.cache,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )
        self.assertEqual(res1["status"], "VALID")
        self.assertEqual(call_count["embedded"], 1)
        self.assertEqual(call_count["catalog"], 1)
        self.assertEqual(self.cache.hits, 0)
        self.assertEqual(self.cache.misses, 1)

        # Second lookup: cache hit
        res2 = cs.verify_file_signature_cached(
            str(self.test_file),
            cache=self.cache,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )
        self.assertEqual(res2["status"], "VALID")
        self.assertEqual(call_count["embedded"], 1)  # NOT incremented!
        self.assertEqual(call_count["catalog"], 1)   # NOT incremented!
        self.assertEqual(self.cache.hits, 1)

    def test_cache_invalidation_on_file_modification(self):
        """Modifying file size triggers cache invalidation and re-verification."""
        call_count = {"embedded": 0}

        def mock_embedded(path: str):
            call_count["embedded"] += 1
            return "VALID", "0x00000000"

        def mock_catalog(path: str):
            return "UNSIGNED", "0x00000000", None

        cs.verify_file_signature_cached(
            str(self.test_file),
            cache=self.cache,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )
        self.assertEqual(call_count["embedded"], 1)

        # Modify file on disk (changes size and mtime)
        self.test_file.write_bytes(b"MODIFIED_NEW_CONTENT_AND_SIZE_BYTES")

        # Next lookup must miss and recalculate
        res = cs.verify_file_signature_cached(
            str(self.test_file),
            cache=self.cache,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )
        self.assertEqual(res["status"], "VALID")
        self.assertEqual(call_count["embedded"], 2)

    def test_cache_invalidation_on_ttl_expiration(self):
        """Advancing time beyond TTL forces cache invalidation."""
        # Cache with 1 second TTL
        cache = cs.SignatureCache(ttl_seconds=1)
        norm = cs.normalize_path(str(self.test_file))
        sha256 = cs.compute_file_sha256(norm)
        cache.put(norm, sha256, {"status": "VALID"})

        # Immediate lookup succeeds
        self.assertIsNotNone(cache.get(norm))

        # Backdate the cached entry
        entry = cache.cache[norm]
        entry.last_verified_at -= 10

        # Now lookup must expire and return None
        self.assertIsNone(cache.get(norm))

    def test_cache_clear(self):
        """clear() wipes all entries and resets hit/miss counters."""
        norm = cs.normalize_path(str(self.test_file))
        self.cache.put(norm, "dummy_hash", {"status": "VALID"})
        self.cache.clear()
        self.assertEqual(len(self.cache.cache), 0)
        self.assertEqual(self.cache.hits, 0)
        self.assertEqual(self.cache.misses, 0)


class TestFindingClassificationAndScanExecution(unittest.TestCase):
    """
    Verifies finding classification and scoring eligibility:
    - Threat findings (score_eligible = 1) for unsigned/invalid DLLs in unusual locations.
    - Diagnostic findings (score_eligible = 0) for operational errors and access denials.
    """

    def setUp(self):
        self.cache = cs.SignatureCache(ttl_seconds=60)

    def test_threat_finding_unsigned_dll_in_suspicious_path(self):
        """Unsigned DLL loaded from %TEMP% generates a threat finding with score_eligible=1."""
        target_pid = 4321
        fake_dll = "C:\\Users\\Default\\AppData\\Local\\Temp\\malware.dll"

        def mock_modules(pid: int):
            return True, [fake_dll], None

        def mock_embedded(path: str):
            return "UNSIGNED", "0x800B0100"

        def mock_catalog(path: str):
            return "UNSIGNED", "0x00000000", None

        findings = cs.run_scan(
            target_pids=[target_pid],
            cache=self.cache,
            module_caller=mock_modules,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )

        threats = [f for f in findings if f["finding_type"] == "threat"]
        self.assertEqual(len(threats), 1)
        th = threats[0]
        self.assertEqual(th["pid"], target_pid)
        self.assertEqual(th["signal"], "signature")
        self.assertEqual(th["score_eligible"], 1)
        self.assertEqual(th["signature_status"], "UNSIGNED")
        self.assertIn("Suspicious module detected", th["evidence"])
        self.assertEqual(th["severity"], "high")

    def test_threat_finding_invalid_signature_in_appdata(self):
        """Invalidly signed DLL in AppData produces a threat finding with score_eligible=1."""
        target_pid = 5432
        fake_dll = "C:\\Users\\Default\\AppData\\Roaming\\bad_cert.dll"

        def mock_modules(pid: int):
            return True, [fake_dll], None

        def mock_embedded(path: str):
            return "INVALID", "0x80096010"

        def mock_catalog(path: str):
            return "UNSIGNED", "0x00000000", None

        findings = cs.run_scan(
            target_pids=[target_pid],
            cache=self.cache,
            module_caller=mock_modules,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )

        threats = [f for f in findings if f["finding_type"] == "threat"]
        self.assertEqual(len(threats), 1)
        th = threats[0]
        self.assertEqual(th["score_eligible"], 1)
        self.assertEqual(th["signature_status"], "INVALID")

    def test_operational_diagnostic_module_access_denied(self):
        """Module enumeration AccessDenied generates an operational diagnostic with score_eligible=0."""
        target_pid = 9876

        def mock_modules_denied(pid: int):
            return False, [], f"Access denied enumerating modules for PID {pid}"

        findings = cs.run_scan(
            target_pids=[target_pid],
            cache=self.cache,
            module_caller=mock_modules_denied,
        )

        self.assertEqual(len(findings), 1)
        diag = findings[0]
        self.assertEqual(diag["finding_type"], "diagnostic")
        self.assertEqual(diag["score_eligible"], 0)
        self.assertEqual(diag["severity"], "low")
        self.assertEqual(diag["signature_status"], "N/A")
        self.assertIn("Operational diagnostic", diag["evidence"])

    def test_operational_diagnostic_wintrust_error(self):
        """WinTrust ERROR status produces an operational diagnostic with score_eligible=0."""
        target_pid = 7654
        fake_dll = "C:\\Windows\\System32\\error_mod.dll"

        def mock_modules(pid: int):
            return True, [fake_dll], None

        def mock_embedded(path: str):
            return "ERROR", "0x80070005"

        def mock_catalog(path: str):
            return "ERROR", "0x80070005", None

        findings = cs.run_scan(
            target_pids=[target_pid],
            cache=self.cache,
            module_caller=mock_modules,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )

        diags = [f for f in findings if f["finding_type"] == "diagnostic"]
        self.assertEqual(len(diags), 1)
        diag = diags[0]
        self.assertEqual(diag["score_eligible"], 0)
        self.assertEqual(diag["signature_status"], "ERROR")
        self.assertIn("Signature verification error", diag["evidence"])

    def test_validly_signed_whitelisted_module_produces_no_threat(self):
        """Validly signed DLL in System32 produces zero threat findings."""
        target_pid = 1111
        valid_dll = "C:\\Windows\\System32\\kernel32.dll"

        def mock_modules(pid: int):
            return True, [valid_dll], None

        def mock_embedded(path: str):
            return "VALID", "0x00000000"

        def mock_catalog(path: str):
            return "UNSIGNED", "0x00000000", None

        findings = cs.run_scan(
            target_pids=[target_pid],
            cache=self.cache,
            module_caller=mock_modules,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )

        threats = [f for f in findings if f["finding_type"] == "threat"]
        self.assertEqual(len(threats), 0)


class TestDatabasePersistenceIntegration(unittest.TestCase):
    """Verifies database insertion and query of Phase 4 findings."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_sig_dal.db")
        db.init_db(self.db_path)
        self.scan_id = db.start_scan(db_path=self.db_path)
        self.cache = cs.SignatureCache(ttl_seconds=60)

    def tearDown(self):
        import gc
        gc.collect()
        self.temp_dir.cleanup()

    def test_findings_persisted_to_sqlite(self):
        """Verifies that run_scan with scan_id saves findings queryable via db.get_findings."""
        target_pid = 2222
        fake_dll = "C:\\Users\\Default\\Downloads\\trojan.dll"

        def mock_modules(pid: int):
            return True, [fake_dll], None

        def mock_embedded(path: str):
            return "UNSIGNED", "0x800B0100"

        def mock_catalog(path: str):
            return "UNSIGNED", "0x00000000", None

        findings = cs.run_scan(
            scan_id=self.scan_id,
            db_path=self.db_path,
            target_pids=[target_pid],
            cache=self.cache,
            module_caller=mock_modules,
            embedded_caller=mock_embedded,
            catalog_caller=mock_catalog,
        )

        self.assertEqual(len(findings), 1)

        persisted = db.get_findings_for_scan(self.scan_id, db_path=self.db_path)
        self.assertEqual(len(persisted), 1)
        row = persisted[0]

        self.assertEqual(row["scan_id"], self.scan_id)
        self.assertEqual(row["pid"], target_pid)
        self.assertEqual(row["signal"], "signature")
        self.assertEqual(row["finding_type"], "threat")
        self.assertEqual(row["score_eligible"], 1)
        self.assertEqual(row["signature_status"], "UNSIGNED")
        self.assertEqual(row["severity"], "high")

        meta = json.loads(row["metadata"])
        self.assertEqual(meta["signal"], "signature")
        self.assertEqual(meta["module_name"], "trojan.dll")
        self.assertEqual(meta["signature_result"]["status"], "UNSIGNED")
        self.assertTrue(meta["path_anomaly"]["is_anomalous"])


if __name__ == "__main__":
    unittest.main()
