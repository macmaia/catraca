"""The curated TLD list and its check against IANA (docs/testing.md)."""

import contextlib
import io
import os
import tempfile
import unittest

from catraca import tlds


def iana_file(labels, header="# Version 2026100200, Last Updated Fri Oct  2 07:07:01 2026 UTC"):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(header + "\n" + "\n".join(labels) + "\n")
    return path


def complete(extra=()):
    """Every curated label, padded past the 500-entry sanity check, upper case like IANA."""
    labels = {t.upper() for t in tlds.GENERIC} - {"EXAMPLE", "TEST", "INVALID", "LOCALHOST", "ONION"}
    labels |= {f"ZZ{i}" for i in range(500)} | set(extra)
    return sorted(labels)


class Check(unittest.TestCase):
    def run_check(self, labels):
        path = iana_file(labels)
        self.addCleanup(os.remove, path)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = tlds.main(["check", path])
        return code, out.getvalue()

    def test_complete_list_passes(self):
        self.assertEqual(self.run_check(complete())[0], 0)

    def test_a_missing_curated_label_fails(self):
        code, out = self.run_check([t for t in complete() if t != "COM"])
        self.assertEqual(code, 1)
        self.assertIn("com", out)

    def test_undelegated_labels_dont_fail_the_check(self):
        labels = complete()
        for t in tlds.RESERVED_OR_UNDELEGATED:
            self.assertNotIn(t.upper(), labels)
        self.assertEqual(self.run_check(labels)[0], 0)

    def test_an_undelegated_label_back_in_iana_is_reported(self):
        code, out = self.run_check(complete(extra=["MAIL"]))
        self.assertEqual(code, 0)
        self.assertIn("mail", out)

    def test_bad_usage(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(tlds.main([]), 2)
            self.assertEqual(tlds.main(["verify", "x.txt"]), 2)
            self.assertEqual(tlds.main(["check"]), 2)


class LoadIana(unittest.TestCase):
    def load(self, labels, **kw):
        path = iana_file(labels, **kw)
        self.addCleanup(os.remove, path)
        return tlds.load_iana(path)

    def test_header_skipped_and_lower_cased(self):
        got = self.load(complete())
        self.assertIn("com", got)
        self.assertFalse(any(t.startswith("#") for t in got))

    def test_too_short_to_be_the_iana_list(self):
        with self.assertRaises(ValueError):
            self.load([f"Z{i}" for i in range(499)], header="# x")
        self.assertEqual(len(self.load([f"Z{i}" for i in range(500)], header="# x")), 500)


class Counting(unittest.TestCase):
    def test_undelegated_labels_still_count(self):
        for t in tlds.RESERVED_OR_UNDELEGATED:
            with self.subTest(t=t):
                self.assertTrue(tlds.is_tld(t))
        self.assertTrue(tlds.counts_as_host(["files", "home"], False))

    def test_dropped_labels_dont_count(self):
        for t in ("cyber", "hotel", "pets", "reports", "server", "silver"):
            with self.subTest(t=t):
                self.assertFalse(tlds.is_tld(t))
        self.assertFalse(tlds.counts_as_host(["db", "server"], False))

    def test_every_reserved_entry_says_when_it_was_checked(self):
        for t, why in tlds.RESERVED_OR_UNDELEGATED.items():
            with self.subTest(t=t):
                self.assertRegex(why, r"checked \d{4}-\d{2}-\d{2}")
                self.assertNotIn(t, tlds.GENERIC)


if __name__ == "__main__":
    unittest.main()
