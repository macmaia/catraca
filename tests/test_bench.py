"""The case bank runs in CI and the score gets published."""

import unittest

from bench.propagation import run


class PropagationBank(unittest.TestCase):
    def test_no_regressions_and_honest_score(self):
        score = run()
        self.assertEqual(score["regressions"], [])
        self.assertEqual(score["known_failures_now_passing"], [])
        self.assertGreater(score["known_failures"], 0)


class AgentDojoBank(unittest.TestCase):
    def test_generated_file_is_in_sync(self):
        import json
        from pathlib import Path
        from bench.make_agentdojo_cases import build
        on_disk = json.loads((Path(__file__).resolve().parent.parent / "bench" / "agentdojo_cases.json").read_text())
        self.assertEqual(on_disk, json.loads(json.dumps(build())),
                         "run python -m bench.make_agentdojo_cases")

    def test_every_suite_is_covered(self):
        from bench.agentdojo_goals import GOALS
        self.assertEqual({g[0] for g in GOALS}, {"banking", "slack", "workspace", "travel"})


if __name__ == "__main__":
    unittest.main()
