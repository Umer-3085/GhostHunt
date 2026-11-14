"""
GhostHunt — Signal 1 Tests: Process View Engine
Authoritative test module matching DEVELOPMENT_ROADMAP.md naming convention.
Re-exports test cases from tests.test_process_views.
"""

from tests.test_process_views import TestProcessViewsEngine

__all__ = ["TestProcessViewsEngine"]

if __name__ == "__main__":
    import unittest
    unittest.main()
