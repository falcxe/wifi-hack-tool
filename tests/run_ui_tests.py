"""Run all UI contracts, including the legacy function tests, without pytest.

    uv run python -m tests.run_ui_tests
"""
from __future__ import annotations

import os
import unittest

os.environ["WIFI_TOOL_NO_BOARD"] = "1"

MODULES = ("tests.test_board_captures", "tests.test_secondary_ui",
           "tests.test_ui_focus", "tests.test_tui_setup", "tests.test_ui_context",
           "tests.test_ui_runtime", "tests.test_ui_redesign", "tests.test_ui_motion",
           "tests.test_cracking", "tests.test_regressions")


def suite() -> unittest.TestSuite:
    from . import test_ui

    tests = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromNames(MODULES))
    tests.addTests(unittest.FunctionTestCase(value, description=name)
                   for name, value in vars(test_ui).items()
                   if name.startswith("test_") and callable(value)
                   and getattr(value, "__module__", "") == test_ui.__name__)
    return tests


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(suite())
    raise SystemExit(0 if result.wasSuccessful() else 1)