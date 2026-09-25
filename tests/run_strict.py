"""Runs test modules and fails if any test was skipped (or only the ones whose
skip reason matches ``--forbid``). Used by the CI jobs that install an optional
package: a green run must mean the test really ran.

Usage: python -m tests.run_strict tests.test_hypothesis [--forbid REGEX]
"""

from __future__ import annotations

import argparse
import re
import sys
import unittest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("modules", nargs="+")
    ap.add_argument("--forbid", default="", help="regex on the skip reason, default: every skip counts")
    args = ap.parse_args(argv)
    suite = unittest.defaultTestLoader.loadTestsFromNames(args.modules)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    forbidden = [(t, why) for t, why in result.skipped if re.search(args.forbid, why)]
    for t, why in forbidden:
        print(f"SKIPPED, not allowed here: {t.id()} ({why})")
    if result.testsRun == 0:
        print("no tests ran")
        return 1
    return 0 if result.wasSuccessful() and not forbidden else 1


if __name__ == "__main__":
    sys.exit(main())
