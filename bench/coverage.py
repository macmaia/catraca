"""Line coverage of the core with the stdlib only.

Usage: python -m bench.coverage [--fail-under 90] [--show-missing]

A small ``sys.settrace`` tracer (also installed on new threads) records which
lines of ``catraca/`` run while the test suite runs. Executable lines come
from the compiled code objects. It's a close approximation of what
``coverage.py`` reports, not a replacement for it: CI runs the real thing.
"""

from __future__ import annotations

import argparse
import dis
import sys
import threading
import types
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "catraca"


def _executable(path: Path) -> set:
    code = compile(path.read_text(encoding="utf-8"), str(path), "exec")
    lines, stack = set(), [code]
    while stack:
        co = stack.pop()
        lines.update(ln for _, ln in dis.findlinestarts(co) if ln)
        stack.extend(c for c in co.co_consts if isinstance(c, types.CodeType))
    # The module docstring line counts as executed on import anyway, drop it for honesty.
    first = code.co_consts[0] if code.co_consts and isinstance(code.co_consts[0], str) else None
    if first:
        lines.discard(code.co_firstlineno)
    return lines


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fail-under", type=float, default=0.0)
    ap.add_argument("--show-missing", action="store_true")
    args = ap.parse_args(argv)

    prefix = str(PKG) + "/"
    hits = defaultdict(set)

    def tracer(frame, event, arg):
        fn = frame.f_code.co_filename
        if not fn.startswith(prefix):
            return None
        if event == "line":
            hits[fn].add(frame.f_lineno)
        return tracer

    # Drop anything already imported so module-level lines get traced too.
    for name in [m for m in sys.modules if m == "catraca" or m.startswith("catraca.")]:
        del sys.modules[name]
    threading.settrace(tracer)
    sys.settrace(tracer)
    try:
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
        result = unittest.TextTestRunner(verbosity=0, stream=open("/dev/null", "w")).run(suite)
    finally:
        sys.settrace(None)
        threading.settrace(None)
    if not result.wasSuccessful():
        print("tests failed, coverage not meaningful")
        return 1

    total_exec = total_hit = 0
    rows = []
    for path in sorted(PKG.rglob("*.py")):
        exe = _executable(path)
        got = hits.get(str(path), set()) & exe
        total_exec += len(exe)
        total_hit += len(got)
        pct = 100.0 * len(got) / len(exe) if exe else 100.0
        rows.append((path.relative_to(ROOT), len(exe), len(exe) - len(got), pct, sorted(exe - got)))
    width = max(len(str(r[0])) for r in rows)
    print(f"{'file':<{width}}  lines  miss   cover")
    for name, n, miss, pct, missing in rows:
        line = f"{str(name):<{width}}  {n:5}  {miss:4}  {pct:5.1f}%"
        if args.show_missing and missing:
            line += "  missing: " + ",".join(map(str, missing))
        print(line)
    overall = 100.0 * total_hit / total_exec if total_exec else 100.0
    print(f"{'TOTAL':<{width}}  {total_exec:5}  {total_exec - total_hit:4}  {overall:5.1f}%")
    if overall < args.fail_under:
        print(f"below the {args.fail_under:.0f}% target")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
