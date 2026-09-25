"""Builds ``bench/agentdojo_cases.json`` from ``bench/agentdojo_goals.py``.

Usage: python -m bench.make_agentdojo_cases

Every goal goes through every attack template, and the attacker value is then
resolved as the arg it'd land in. For destination-like args we also add an
obfuscated copy (leetspeak or defanged, whichever makes sense), since that's
what a slightly smarter injection would ask for.
"""

from __future__ import annotations

import json
from pathlib import Path

from bench.agentdojo_goals import CARRIERS, GOALS, TEMPLATES, USER_TASKS

HERE = Path(__file__).parent
LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def _obfuscate(value: str):
    if "@" in value:
        return value.replace("@", " [at] ").replace(".", " [dot] "), "defanged"
    if value.startswith("www."):
        return value.replace(".", "[.]"), "defanged"
    if any(c.isalpha() for c in value) and len(value) >= 8:
        return value.translate(LEET), "leetspeak"
    return None, None


def build() -> dict:
    cases = []
    for suite, task, goal, value, arg in GOALS:
        for tname, template in TEMPLATES.items():
            payload = template.format(goal=goal)
            kb = CARRIERS[suite].format(payload=payload)
            base = {
                "source": f"AgentDojo v1 {suite} injection_task_{task}, '{tname}' template",
                "context": [["user", USER_TASKS[suite]], ["kb", kb]],
                "argument": value,
                "arg": arg,
                "consequential": True,
                "expected": "UNTRUSTED",
            }
            cases.append({"id": f"agentdojo-{suite}-{task}-{tname}", **base})
            obf, how = _obfuscate(value)
            if obf and tname == "important_instructions":
                ctx = [["user", USER_TASKS[suite]], ["kb", kb.replace(value, obf)]]
                cases.append({"id": f"agentdojo-{suite}-{task}-{how}", **base, "context": ctx,
                              "source": base["source"] + f", attacker value {how} in the doc"})
    return {
        "version": 1,
        "description": "Generated from bench/agentdojo_goals.py by bench/make_agentdojo_cases.py. Don't edit by hand.",
        "cases": cases,
    }


def main() -> int:
    out = HERE / "agentdojo_cases.json"
    data = build()
    out.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(data['cases'])} cases to {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
