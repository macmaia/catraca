"""The published material stays in step with the code."""

import json
import re
import unittest
from pathlib import Path

import catraca
from bench import report

try:
    import tomllib
except ImportError:  # Python 3.10, the packaging job still checks the metadata
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent


DOCS = [
    "README.md", "README.pt-BR.md", "BENCHMARK.md", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "docs/architecture.md", "docs/threat-model.md", "docs/reference.md",
    "docs/reference.pt-BR.md", "docs/audit-and-privacy.md", "docs/related-work.md", "docs/decisions.md",
]

class PublishedNumbers(unittest.TestCase):
    def setUp(self):
        self.published = json.loads((ROOT / "bench" / "published.json").read_text(encoding="utf-8"))

    def test_detection_matches_published(self):
        self.assertEqual(report.detection(), self.published["detection"])

    def test_benchmark_page_quotes_the_published_figures(self):
        page = (ROOT / "BENCHMARK.md").read_text(encoding="utf-8")
        for bank, d in self.published["detection"].items():
            row = next((line for line in page.splitlines() if line.startswith(f"| `{bank}`")), None)
            self.assertIsNotNone(row, f"no row for {bank} in BENCHMARK.md")
            cells = [c.strip() for c in row.strip("|").split("|")]
            self.assertEqual(cells[1], str(d["cases"]), bank)
            self.assertEqual(cells[2], str(d["correct"]), bank)
            if d["injected_values"]:
                self.assertTrue(cells[3].startswith(f"{d['injected_caught']} of {d['injected_values']}"), bank)
            if d["trusted_values"]:
                self.assertTrue(cells[4].startswith(f"{d['trusted_wrongly_flagged']} of {d['trusted_values']}"), bank)
            for kf in d["known_failures"]:
                self.assertIn(f"`{kf}`", page)
        self.assertIn(f"catraca {self.published['catraca']}", page)

    def test_check_passes_and_catches_drift(self):
        det = report.detection()
        tim = {"latency": {"p99_us": 1.0}}
        self.assertEqual(report.check(det, tim, self.published), [])
        tampered = json.loads(json.dumps(self.published))
        tampered["detection"]["agentdojo_cases"]["correct"] -= 1
        self.assertTrue(report.check(det, tim, tampered))
        self.assertTrue(report.check(det, {"latency": {"p99_us": 5000.0}}, self.published))


@unittest.skipIf(tomllib is None, "tomllib needs Python 3.11")
class Packaging(unittest.TestCase):
    def setUp(self):
        self.meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    def test_version_in_one_place(self):
        self.assertEqual(self.meta["version"], catraca.__version__)

    def test_no_runtime_dependencies(self):
        self.assertEqual(self.meta["dependencies"], [])

    def test_every_subpackage_ships(self):
        find = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"]["packages"]["find"]
        self.assertIn("catraca.*", find["include"])

    def test_licence_files_exist(self):
        for f in self.meta["license-files"]:
            self.assertTrue((ROOT / f).is_file(), f)
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text()[:200])

    def test_changelog_has_this_version(self):
        base = re.sub(r"\.dev\d+$", "", catraca.__version__)
        self.assertIn(f"## [{base}]", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))


class Docs(unittest.TestCase):
    def test_mode_b_limits_come_before_usage(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertLess(readme.index("## Read this first"), readme.index("## Quick start"))
        readme_pt = (ROOT / "README.pt-BR.md").read_text(encoding="utf-8")
        self.assertLess(readme_pt.index("## Leia antes"), readme_pt.index("## Início rápido"))

    def test_relative_links_resolve(self):
        for doc in DOCS:
            path = ROOT / doc
            for target in re.findall(r"\]\(([^)#]+?)(?:#[^)]*)?\)", path.read_text(encoding="utf-8")):
                if target.startswith("http"):
                    continue
                self.assertTrue((path.parent / target).exists(), f"{doc} links to missing {target}")

    def test_no_dash_or_semicolon_in_prose(self):
        # House style for the published docs.
        for doc in DOCS:
            text = (ROOT / doc).read_text(encoding="utf-8")
            prose = re.sub(r"```.*?```", "", text, flags=re.S)
            prose = re.sub(r"`[^`]*`", "", prose)
            self.assertNotIn("—", prose, doc)
            self.assertNotIn(";", prose, doc)


if __name__ == "__main__":
    unittest.main()


class ReadmeSnippetsRun(unittest.TestCase):
    """The README examples must run as written and print what they say."""

    def run_blocks(self, readme):
        import contextlib
        import io
        import os
        import re
        import tempfile
        import warnings
        text = (ROOT / readme).read_text(encoding="utf-8")
        blocks = re.findall(r"```python\n(.*?)```", text, flags=re.S)
        self.assertGreaterEqual(len(blocks), 2, readme)
        outputs = []
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                for code in blocks:
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out), warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        exec(compile(code, readme, "exec"), {"__name__": "__readme__"})
                    outputs.append(out.getvalue())
                    # every "# expected" comment on a print line has to match what printed
                    for line in code.splitlines():
                        m = re.match(r"\s*print\(.*\)\s*#\s*(.+)$", line)
                        if m:
                            self.assertIn(m.group(1).strip(), out.getvalue(), f"{readme}: {line.strip()}")
            finally:
                os.chdir(cwd)
        return outputs

    def test_english(self):
        quick, tool = self.run_blocks("README.md")[:2]
        self.assertIn("CONFIRMED_BY_USER", quick)
        self.assertIn("refused: UNTRUSTED_ARGUMENT", tool)

    def test_portuguese(self):
        self.run_blocks("README.pt-BR.md")
