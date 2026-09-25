"""Property tests with random generation (stdlib only, fixed and reproducible seed)."""

import os
import random
import unittest

from catraca import PUBLIC, Confidentiality, Integrity, Label, LabelError
from catraca.labels import BLOCKED, BOTTOM, join_all

N = int(os.environ.get("CATRACA_N_PROPERTY", "3000"))
SEED = int(os.environ.get("CATRACA_SEED", "20260922"))
SCOPES = ["tenant:acme", "tenant:beta", "user:ana", "user:bia", "user:caio", "team:support"]


def gen_conf(rng):
    if rng.random() < 0.25:
        return PUBLIC
    return Confidentiality.of(rng.sample(SCOPES, rng.randint(0, len(SCOPES))))


def gen_label(rng):
    return Label(rng.choice(list(Integrity)), gen_conf(rng))


class LatticeProperties(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(SEED)

    def triples(self):
        for _ in range(N):
            yield gen_label(self.rng), gen_label(self.rng), gen_label(self.rng)

    def test_associative(self):
        for a, b, c in self.triples():
            self.assertEqual(a.join(b).join(c), a.join(b.join(c)))

    def test_commutative(self):
        for a, b, _ in self.triples():
            self.assertEqual(a.join(b), b.join(a))

    def test_idempotent(self):
        for a, _, _ in self.triples():
            self.assertEqual(a.join(a), a)

    def test_neutral_element(self):
        for a, _, _ in self.triples():
            self.assertEqual(a.join(BOTTOM), a)

    def test_join_never_less_restrictive(self):
        """Joining two labels never gives a less restrictive one."""
        for a, b, _ in self.triples():
            j = a.join(b)
            self.assertTrue(a.flows_to(j), (a, b, j))
            self.assertTrue(b.flows_to(j), (a, b, j))
            for scope in SCOPES:
                if j.confidentiality.may_flow_to(scope):
                    self.assertTrue(a.confidentiality.may_flow_to(scope))
                    self.assertTrue(b.confidentiality.may_flow_to(scope))

    def test_join_is_least_upper_bound(self):
        for a, b, c in self.triples():
            if a.flows_to(c) and b.flows_to(c):
                self.assertTrue(a.join(b).flows_to(c))

    def test_order_matches_join(self):
        for a, b, _ in self.triples():
            self.assertEqual(a.flows_to(b), a.join(b) == b)

    def test_join_all_order_independent(self):
        for _ in range(N // 10):
            labels = [gen_label(self.rng) for _ in range(self.rng.randint(0, 8))]
            shuffled = labels[:]
            self.rng.shuffle(shuffled)
            self.assertEqual(join_all(labels), join_all(shuffled))


class IntegrityTotalOrder(unittest.TestCase):
    def test_order(self):
        self.assertLess(Integrity.TRUSTED, Integrity.STRUCTURED)
        self.assertLess(Integrity.STRUCTURED, Integrity.UNTRUSTED)

    def test_totality(self):
        for a in Integrity:
            for b in Integrity:
                self.assertTrue(a <= b or b <= a)
                self.assertEqual(a.join(b), max(a, b))


class ConfidentialityCases(unittest.TestCase):
    def test_intersection(self):
        a = Confidentiality.of(["tenant:acme", "user:ana"])
        b = Confidentiality.of(["tenant:acme"])
        self.assertEqual(a.join(b), b)

    def test_public_is_top(self):
        a = Confidentiality.of(["user:ana"])
        self.assertEqual(PUBLIC.join(a), a)
        self.assertTrue(PUBLIC.may_flow_to("any:thing"))

    def test_E1_2b_star_in_intersection(self):
        """{"*"} ∩ X gives X. "*" is never a literal scope."""
        x = Confidentiality.of(["tenant:acme"])
        self.assertEqual(Confidentiality.from_json("*").join(x), x)
        self.assertEqual(x.join(Confidentiality.from_json("*")), x)
        self.assertFalse(Confidentiality.from_json("*").is_blocked)
        with self.assertRaises(LabelError):
            Confidentiality.of(["*"])
        with self.assertRaises(LabelError):
            Confidentiality.from_json(["*"])

    def test_empty_blocks(self):
        a = Confidentiality.of(["user:ana"]).join(Confidentiality.of(["user:bia"]))
        self.assertTrue(a.is_blocked)
        self.assertEqual(a, BLOCKED)
        self.assertFalse(a.may_flow_to("user:ana"))

    def test_bad_scope(self):
        for bad in ["", "nocolon", "Upper:x", "a: b", "a:b,c", 3]:
            with self.assertRaises(LabelError):
                Confidentiality.of([bad])


class Serialisation(unittest.TestCase):
    def test_round_trip(self):
        rng = random.Random(SEED)
        for _ in range(N):
            label = gen_label(rng)
            self.assertEqual(Label.from_json(label.to_json()), label)
            self.assertEqual(Label.from_dict(label.to_dict()), label)

    def test_stable(self):
        a = Label(Integrity.UNTRUSTED, Confidentiality.of(["user:ana", "tenant:acme"]))
        b = Label(Integrity.UNTRUSTED, Confidentiality.of(["tenant:acme", "user:ana"]))
        self.assertEqual(a.to_json(), b.to_json())
        self.assertEqual(
            a.to_json(), '{"confidentiality":["tenant:acme","user:ana"],"integrity":"UNTRUSTED","v":1}'
        )
        self.assertEqual(BOTTOM.to_json(), '{"confidentiality":"*","integrity":"TRUSTED","v":1}')

    def test_rejects_bad_input(self):
        for bad in [
            "not json",
            "[]",
            '{"v":2,"integrity":"TRUSTED","confidentiality":"*"}',
            '{"v":1,"integrity":"MAYBE","confidentiality":"*"}',
            '{"v":1,"integrity":"TRUSTED","confidentiality":"everyone"}',
            '{"v":1,"integrity":"TRUSTED","confidentiality":"*","extra":1}',
            '{"v":1,"integrity":"TRUSTED"}',
        ]:
            with self.assertRaises(LabelError, msg=bad):
                Label.from_json(bad)

    def test_immutable(self):
        label = Label()
        with self.assertRaises(AttributeError):
            label.integrity = Integrity.UNTRUSTED  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
