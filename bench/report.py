"""The public benchmark in one command.

Usage::

    python -m bench.report                 # print the tables
    python -m bench.report --check         # also compare with bench/published.json
    python -m bench.report --json out.json # keep the raw figures
    python -m bench.report --write         # refresh bench/published.json (maintainers)

Two kinds of numbers come out of this:

* **Detection figures** from the case banks. They're deterministic, so the
  same commit gives the same numbers on any machine. ``--check`` fails if
  they differ from ``bench/published.json`` in any way.
* **Timing figures** (latency and the ~100k-token window). They depend on
  the machine, so they're printed next to the reference machine's numbers
  and only the latency target (p99 under 1 ms on the reference window) is checked.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

import catraca

from . import latency, propagation, scale

HERE = Path(__file__).parent
PUBLISHED = HERE / "published.json"
P99_TARGET_US = 1000.0


def detection() -> dict:
    """Detection figures per bank. Everything here is deterministic."""
    out = {}
    for name in propagation.BANKS:
        score = propagation.run([HERE / name])
        cases = score["cases"]
        untrusted = [c for c in cases if c["expected"] == "UNTRUSTED"]
        trusted = [c for c in cases if c["expected"] == "TRUSTED"]
        out[name.removesuffix(".json")] = {
            "cases": score["total"],
            "correct": score["correct"],
            "injected_values": len(untrusted),
            "injected_caught": sum(c["ok"] for c in untrusted),
            "trusted_values": len(trusted),
            "trusted_wrongly_flagged": sum(not c["ok"] for c in trusted),
            "known_failures": sorted(c["id"] for c in cases if c["known_failure"]),
            "regressions": score["regressions"],
        }
    return out


def timing(quick: bool = False) -> dict:
    return {
        "latency": latency.measure(calls=500 if quick else 5000),
        "scale": scale.measure(calls=100 if quick else 2000),
    }


def environment() -> dict:
    return {
        "catraca": catraca.__version__,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "machine": platform.machine(),
        "system": platform.system(),
    }


def _pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "n/a"


def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    """95% Wilson score interval for k out of n, as percentages. Small banks
    get wide intervals, which is the point of printing them."""
    if not n:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / den
    return (round(100 * max(0.0, mid - half), 1), round(100 * min(1.0, mid + half), 1))


def render(det: dict, tim: dict, env: dict, ref: dict | None) -> str:
    lines = [f"catraca {env['catraca']}, {env['implementation']} {env['python']}, {env['system']} {env['machine']}", ""]
    lines.append("Detection (deterministic)")
    lines.append(f"{'bank':<20} {'cases':>6} {'correct':>8} {'injected caught':>18} {'trusted flagged':>16}")
    for bank, d in det.items():
        caught = f"{d['injected_caught']}/{d['injected_values']} ({_pct(d['injected_caught'], d['injected_values'])})"
        flagged = f"{d['trusted_wrongly_flagged']}/{d['trusted_values']}"
        lines.append(f"{bank:<20} {d['cases']:>6} {d['correct']:>8} {caught:>18} {flagged:>16}")
        if d["injected_values"]:
            lo, hi = wilson(d["injected_caught"], d["injected_values"])
            lines.append(f"  injected caught, 95% CI {lo} to {hi}%")
        if d["trusted_values"]:
            lo, hi = wilson(d["trusted_wrongly_flagged"], d["trusted_values"])
            lines.append(f"  false positives {_pct(d['trusted_wrongly_flagged'], d['trusted_values'])}, 95% CI {lo} to {hi}%")
        for kf in d["known_failures"]:
            lines.append(f"  known failure: {kf}")
    lines.append("")
    lines.append("Timing (this machine" + (", reference in brackets)" if ref else ")"))
    lat = tim["latency"]
    rl = (ref or {}).get("timing", {}).get("latency", {})

    def _cell(val, key, refd):
        return f"{val}" + (f" [{refd[key]}]" if key in refd else "")

    lines.append(
        f"decide, {lat['docs']} docs x {lat['doc_words']} words: "
        f"p50 {_cell(lat['p50_us'], 'p50_us', rl)} µs, p99 {_cell(lat['p99_us'], 'p99_us', rl)} µs"
    )
    sc = tim["scale"]
    rs = (ref or {}).get("timing", {}).get("scale", {})
    lines.append(
        f"~{sc['tokens']:,}-token window: annotate {_cell(sc['annotate_s'], 'annotate_s', rs)} s, "
        f"memory held {_cell(sc['mem_held_mib'], 'mem_held_mib', rs)} MiB"
    )
    for name, x in sc["decide"].items():
        rx = rs.get("decide", {}).get(name, {})
        lines.append(f"  decide ({name}): p50 {_cell(x['p50_us'], 'p50_us', rx)} µs, p99 {_cell(x['p99_us'], 'p99_us', rx)} µs")
    return "\n".join(lines)


def check(det: dict, tim: dict, ref: dict, *, timing_gate: bool = True) -> list:
    problems = []
    if det != ref.get("detection"):
        for bank in sorted(set(det) | set(ref.get("detection", {}))):
            mine, theirs = det.get(bank), ref.get("detection", {}).get(bank)
            if mine != theirs:
                problems.append(f"detection figures for '{bank}' differ from bench/published.json: {mine} vs {theirs}")
    if timing_gate and tim["latency"]["p99_us"] >= P99_TARGET_US:
        problems.append(f"latency target not met: p99 {tim['latency']['p99_us']} µs (target under {P99_TARGET_US:.0f})")
    if ref.get("catraca") and ref["catraca"] != catraca.__version__:
        problems.append(f"bench/published.json is for catraca {ref['catraca']}, this is {catraca.__version__}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="compare with bench/published.json")
    ap.add_argument("--write", action="store_true", help="refresh bench/published.json")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--quick", action="store_true", help="fewer timing calls, for CI smoke runs")
    ap.add_argument("--timing-warn-only", action="store_true",
                    help="report a missed latency target without failing (shared CI runners are noisy)")
    args = ap.parse_args(argv)

    ref = json.loads(PUBLISHED.read_text(encoding="utf-8")) if PUBLISHED.exists() else None
    det, tim, env = detection(), timing(args.quick), environment()
    print(render(det, tim, env, ref))

    result = {"catraca": catraca.__version__, "environment": env, "detection": det, "timing": tim}
    if args.json:
        args.json.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.write:
        PUBLISHED.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {PUBLISHED.relative_to(HERE.parent)}")
    if args.check:
        if ref is None:
            print("\nbench/published.json is missing")
            return 1
        problems = check(det, tim, ref, timing_gate=not args.timing_warn_only)
        if args.timing_warn_only and tim["latency"]["p99_us"] >= P99_TARGET_US:
            print(f"\nWARNING latency target not met on this machine: p99 {tim['latency']['p99_us']} µs")
        print()
        for p in problems:
            print("MISMATCH", p)
        print("matches the published numbers" if not problems else f"{len(problems)} mismatch(es)")
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
