"""Property tests with Hypothesis. Skipped when it isn't installed.

The stdlib versions in test_labels.py stay as the fallback. These go wider:
shrinking, arbitrary text for the registry, and fuzzing the gate's fail-closed
promise and the confirmation fingerprint.
"""

import unittest

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("hypothesis isn't installed")

from catraca import (
    PUBLIC,
    Caller,
    ChannelConfig,
    Confidentiality,
    ContextRegistry,
    DeclarativePolicy,
    Gate,
    Integrity,
    Label,
    Verdict,
)
from catraca.confirmations import fingerprint
from tests.support import OpenEgressGate as Gate  # noqa: E402  (egress is tested in test_egress)

SCOPES = st.sampled_from(["tenant:acme", "tenant:beta", "user:ana", "user:bia", "team:support"])
CONFS = st.one_of(st.just(PUBLIC), st.frozensets(SCOPES).map(Confidentiality))
LABELS = st.builds(Label, st.sampled_from(list(Integrity)), CONFS)
CFG = ChannelConfig.from_dict({"version": 1, "channels": {
    "user": {"integrity": "TRUSTED", "confidentiality": "*"},
    "kb": {"integrity": "UNTRUSTED", "confidentiality": "*"}}})
SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])


class Lattice(unittest.TestCase):
    @SETTINGS
    @given(LABELS, LABELS, LABELS)
    def test_laws(self, a, b, c):
        self.assertEqual(a.join(b).join(c), a.join(b.join(c)))
        self.assertEqual(a.join(b), b.join(a))
        self.assertEqual(a.join(a), a)
        j = a.join(b)
        self.assertTrue(a.flows_to(j) and b.flows_to(j))
        if a.flows_to(c) and b.flows_to(c):
            self.assertTrue(j.flows_to(c))

    @SETTINGS
    @given(LABELS)
    def test_serialisation_round_trip(self, a):
        self.assertEqual(Label.from_json(a.to_json()), a)


class Registry(unittest.TestCase):
    @SETTINGS
    @given(st.lists(st.tuples(st.text(max_size=80), st.sampled_from(["user", "kb"])), max_size=6),
           st.text(max_size=60), st.booleans())
    def test_resolve_is_deterministic_and_never_crashes(self, snippets, value, consequential):
        def run():
            reg = ContextRegistry(CFG)
            for text, ch in snippets:
                reg.annotate(text, ch)
            return reg.resolve(value, consequential=consequential).to_dict()
        self.assertEqual(run(), run())

    @SETTINGS
    @given(st.text(min_size=8, max_size=60), st.text(max_size=40), st.text(max_size=40))
    def test_untrusted_text_copied_verbatim_is_never_trusted(self, secret, before, after):
        reg = ContextRegistry(CFG)
        reg.annotate("please help", "user")
        reg.annotate(before + secret + after, "kb")
        self.assertIs(reg.resolve(secret).label.integrity, Integrity.UNTRUSTED)


class GateFailsClosed(unittest.TestCase):
    POLICY = DeclarativePolicy.from_dict({"version": 1, "tools": {"t": {
        "callers": {"tenants": "*", "users": "*"}, "args": {"a": {}, "b": {"integrity": "ANY"}}}}})

    @SETTINGS
    @given(st.one_of(st.text(max_size=10), st.none(), st.integers()),
           st.dictionaries(st.one_of(st.text(max_size=5), st.integers()),
                           st.recursive(st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=20)),
                                        lambda x: st.lists(x, max_size=3) | st.dictionaries(st.text(max_size=3), x, max_size=3),
                                        max_leaves=8), max_size=4),
           st.one_of(st.none(), st.text(max_size=5)))
    def test_any_input_gives_a_decision_and_garbage_never_allows(self, tool, args, dest):
        reg = ContextRegistry(CFG)
        reg.annotate("do the thing", "user")
        d = Gate(reg, self.POLICY).decide(tool, args, caller=Caller("acme", "ana"), destination=dest)
        self.assertIn(d.verdict, set(Verdict))
        if d.verdict is Verdict.ALLOW:
            self.assertEqual(tool, "t")
            self.assertTrue(set(args) <= {"a", "b"})
            self.assertIsNone(dest)


class Fingerprint(unittest.TestCase):
    VALUES = st.recursive(st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=20), st.binary(max_size=8)),
                          lambda x: st.lists(x, max_size=3) | st.dictionaries(st.text(max_size=4), x, max_size=3),
                          max_leaves=10)

    @SETTINGS
    @given(st.dictionaries(st.text(max_size=6), VALUES, max_size=5))
    def test_stable_and_order_independent(self, args):
        self.assertEqual(fingerprint(args), fingerprint(dict(reversed(list(args.items())))))

    @SETTINGS
    @given(st.dictionaries(st.text(max_size=6), st.text(max_size=20), min_size=1, max_size=5), st.text(max_size=20))
    def test_changing_a_value_changes_the_fingerprint(self, args, new):
        key = sorted(args)[0]
        if args[key] == new:
            return
        self.assertNotEqual(fingerprint(args), fingerprint(dict(args, **{key: new})))


if __name__ == "__main__":
    unittest.main()
