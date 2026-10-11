"""Run all UI contracts, including the legacy function tests, without pytest."""
from __future__ import annotations

import os
import unittest

os.environ["WIFI_TOOL_NO_BOARD"] = "1"

MODULES = ("_test_board_captures", "_test_secondary_ui", "_test_ui_focus", "_test_tui_setup",
           "_test_ui_context", "_test_ui_runtime", "_test_ui_redesign", "_test_ui_motion",
           "_test_cracking", "_test_regressions")


def suite() -> unittest.TestSuite:
    import _test_ui
    tests = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromNames(MODULES))
    tests.addTests(unittest.FunctionTestCase(value, description=name)
                   for name, value in vars(_test_ui).items()
                   if name.startswith("test_") and callable(value)
                   and getattr(value, "__module__", "") == _test_ui.__name__)
    return tests


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(suite())
    raise SystemExit(0 if result.wasSuccessful() else 1)
