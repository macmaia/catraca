"""Runs the propagation case bank and prints the scoreboard.

Usage: python -m bench.propagation [--json out.json] [--quiet]

Runs the hand-written bank and the AgentDojo-derived one together.

Exits 1 if an expected case fails (a regression) or if a known failure starts
passing without being reclassified (the published score would be wrong).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from catraca import ChannelConfig, ContextRegistry, Integrity

HERE = Path(__file__).parent
CFG = ChannelConfig.from_dict(
    {
        "version": 1,
        "channels": {
            "user": {"integrity": "TRUSTED", "confidentiality": "*"},
            "kb": {"integrity": "UNTRUSTED", "confidentiality": "*"},
        },
    }
)


BANKS = ("propagation_cases.json", "agentdojo_cases.json", "benign_cases.json")


def run(paths=None) -> dict:
    cases = []
    for p in paths or [HERE / name for name in BANKS]:
        cases.extend(json.loads(Path(p).read_text(encoding="utf-8"))["cases"])
    results = []
    for case in cases:
        reg = ContextRegistry(CFG)
        for channel, text in case["context"]:
            if channel == "new_turn":
                reg.new_turn()
            else:
                reg.annotate(text, channel)
        if "summary" in case:
            reg.summarise(case["summary"], [s.id for s in reg.snippets])
        for text in case.get("forgotten_untrusted", []):
            reg.forget(reg.annotate(text, "kb").id, reason="history truncated")
        res = reg.resolve(case["argument"], consequential=bool(case.get("consequential")))
        results.append(
            {
                "id": case["id"],
                "expected": case["expected"],
                "got": res.label.integrity.name,
                "rule": res.rule.value,
                "ok": res.label.integrity is Integrity[case["expected"]],
                "known_failure": bool(case.get("known_failure")),
            }
        )
    return {
        "total": len(results),
        "correct": sum(r["ok"] for r in results),
        "known_failures": sum(r["known_failure"] for r in results),
        "regressions": [r["id"] for r in results if not r["ok"] and not r["known_failure"]],
        "known_failures_now_passing": [r["id"] for r in results if r["ok"] and r["known_failure"]],
        "cases": results,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--json", type=Path)
    p.add_argument("--quiet", action="store_true", help="only print cases that didn't pass")
    args = p.parse_args(argv)
    score = run()
    for r in score["cases"]:
        mark = "ok " if r["ok"] else ("KF " if r["known_failure"] else "ERR")
        if args.quiet and r["ok"]:
            continue
        print(f"{mark} {r['id']:<42} expected={r['expected']:<10} got={r['got']:<10} rule={r['rule']}")
    print(
        f"\n{score['correct']}/{score['total']} correct, "
        f"{score['known_failures']} known failures published, "
        f"{len(score['regressions'])} regressions"
    )
    if args.json:
        args.json.write_text(json.dumps(score, ensure_ascii=False, indent=2), encoding="utf-8")
    return 1 if score["regressions"] or score["known_failures_now_passing"] else 0


if __name__ == "__main__":
    sys.exit(main())
