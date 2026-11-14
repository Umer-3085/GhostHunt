"""
GhostHunt — Phase 7 Tests: Signature & Path Anomaly Simulation Scenarios
Validates SIG-1 through SIG-5 using the standard scenario framework.
"""

import sys
import unittest

from simulators.signature_scenarios import (
    PeHeaderStructuralInspectionScenario,
    SignatureCacheInvalidationScenario,
    UnsignedModuleInTempPathScenario,
    ValidCatalogSignatureScenario,
    ValidEmbeddedSignatureScenario,
)


class TestSignatureSimulationScenarios(unittest.TestCase):
    """Verifies Signal 3 signature scenarios produce authoritative results."""

    def test_sig1_valid_embedded_authenticode(self):
        """SIG-1: Valid embedded Authenticode verification against running Python executable."""
        if sys.platform != "win32":
            self.skipTest("Windows-only test")
        with ValidEmbeddedSignatureScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"SIG-1 failed: {res}")
            self.assertEqual(res["status"], "VALID")

    def test_sig2_valid_windows_catalog(self):
        """SIG-2: Valid Windows catalog verification against cmd.exe."""
        if sys.platform != "win32":
            self.skipTest("Windows-only test")
        with ValidCatalogSignatureScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"SIG-2 failed: {res}")
            self.assertEqual(res["status"], "VALID")
            self.assertIsNotNone(res["catalog_file"])

    def test_sig3_unsigned_dll_in_temp_path(self):
        """SIG-3: Unsigned DLL in %TEMP% produces HIGH threat finding with score_eligible=1."""
        with UnsignedModuleInTempPathScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"SIG-3 failed: {res}")
            self.assertEqual(res["threat_count"], 1)

    def test_sig4_cache_invalidation_on_file_modification(self):
        """SIG-4: Altering file size forces cache eviction and re-verification."""
        with SignatureCacheInvalidationScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"SIG-4 failed: {res}")
            self.assertEqual(res["verification_calls"], 2)

    def test_sig5_pe_structural_safety(self):
        """SIG-5: Non-PE text file safely handles PEFormatError without crashing."""
        with PeHeaderStructuralInspectionScenario() as s:
            res = s.run()
            self.assertTrue(res["passed"], f"SIG-5 failed: {res}")
            self.assertFalse(res["pe_info"]["success"])


if __name__ == "__main__":
    unittest.main()
