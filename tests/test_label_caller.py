"""Signed MCP labels are bound to the caller the server sees (0.3.0)."""

import asyncio
import types
import unittest

from catraca import Caller, DeclarativePolicy, Egress, Gate
from catraca.adapters.mcp import META_KEY, LabelChecker, catraca_middleware, derive_label_key, sign_labels
from catraca.labels import Integrity

KEY = b"k" * 32
ARGS = {"to": "ana@acme.com.br"}
ACME_ANA = Caller("acme", "ana")


def integrity(checker, claimed, caller, tool="send_email"):
    return checker.edges(tool, dict(ARGS), {META_KEY: claimed}, caller=caller)["to"].label.integrity


def signed(caller, **kw):
    return sign_labels({"to": "TRUSTED"}, dict(ARGS), KEY, tool="send_email", caller=caller, **kw)


class BoundToCaller(unittest.TestCase):
    def test_same_caller_is_trusted(self):
        self.assertIs(integrity(LabelChecker(label_key=KEY), signed(ACME_ANA), ACME_ANA), Integrity.TRUSTED)

    def test_other_tenant_or_user_is_untrusted(self):
        for other in (Caller("globex", "ana"), Caller("acme", "bob")):
            with self.subTest(other=other):
                self.assertIs(integrity(LabelChecker(label_key=KEY), signed(ACME_ANA), other), Integrity.UNTRUSTED)

    def test_tenant_and_user_dont_run_together(self):
        self.assertIs(integrity(LabelChecker(label_key=KEY), signed(Caller("ab", "c")), Caller("a", "bc")),
                      Integrity.UNTRUSTED)

    def test_wrong_caller_doesnt_use_up_the_nonce(self):
        checker, label = LabelChecker(label_key=KEY), signed(ACME_ANA)
        self.assertIs(integrity(checker, label, Caller("globex", "ana")), Integrity.UNTRUSTED)
        self.assertIs(integrity(checker, label, ACME_ANA), Integrity.TRUSTED)
        self.assertIs(integrity(checker, label, ACME_ANA), Integrity.UNTRUSTED)  # and then it's spent

    def test_no_caller_is_untrusted(self):
        self.assertIs(integrity(LabelChecker(label_key=KEY), signed(ACME_ANA), None), Integrity.UNTRUSTED)

    def test_format_version_must_match(self):
        for v in (None, 1, 3, True, "2"):
            label = signed(ACME_ANA)
            if v is None:
                del label["v"]
            else:
                label["v"] = v
            with self.subTest(v=v):
                self.assertIs(integrity(LabelChecker(label_key=KEY), label, ACME_ANA), Integrity.UNTRUSTED)

    def test_claimed_tool_is_ignored(self):
        label = signed(ACME_ANA)
        label["tool"] = "search"  # informational only, the server's tool is what counts
        self.assertIs(integrity(LabelChecker(label_key=KEY), label, ACME_ANA), Integrity.TRUSTED)
        self.assertIs(integrity(LabelChecker(label_key=KEY), signed(ACME_ANA), ACME_ANA, tool="search"),
                      Integrity.UNTRUSTED)

    def test_signing_needs_a_real_caller(self):
        for bad in (None, ("acme", "ana"), Caller("acme", 7), Caller(None, "ana")):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                sign_labels({"to": "TRUSTED"}, dict(ARGS), KEY, tool="send_email", caller=bad)


class WireFormat(unittest.TestCase):
    """The exact bytes a client in another language has to sign (format 2)."""

    BODY = (b'{"args":{"to":"ana@acme.com.br"},"caller":{"tenant":"acme","user":"ana"},"iat":1000,'
            b'"labels":{"to":"TRUSTED"},"nonce":"' + b"n" * 32 + b'","tool":"send_email","v":2}')

    def test_known_answer(self):
        import hashlib
        import hmac
        from unittest import mock
        claimed = {"v": 2, "labels": {"to": "TRUSTED"}, "tool": "send_email", "iat": 1000, "nonce": "n" * 32,
                   "mac": hmac.new(KEY, self.BODY, hashlib.sha256).hexdigest()}
        with mock.patch("catraca.adapters.mcp.time.time", return_value=1000):
            edge = LabelChecker(label_key=KEY).edges("send_email", dict(ARGS), {META_KEY: claimed},
                                                     caller=ACME_ANA)["to"]
        self.assertIs(edge.label.integrity, Integrity.TRUSTED)
        self.assertEqual(edge.origin, "mcp-client-signed")

    def test_unsigned_and_trusted_origins(self):
        edge = LabelChecker(label_key=KEY).edges("send_email", dict(ARGS), {}, caller=ACME_ANA)["to"]
        self.assertEqual((edge.label.integrity, edge.origin), (Integrity.UNTRUSTED, "mcp-client"))
        edge = LabelChecker(trust_client=True).edges("send_email", dict(ARGS), {}, caller=ACME_ANA)["to"]
        self.assertEqual((edge.label.integrity, edge.origin), (Integrity.TRUSTED, "mcp-client"))


class Middleware(unittest.TestCase):
    POLICY = {"version": 1, "tools": {"send_email": {"callers": {"tenants": ["acme", "globex"], "users": "*"},
                                                     "args": {"to": {}}}}}

    def run_mw(self, caller_for, label):
        gate = Gate(None, DeclarativePolicy.from_dict(self.POLICY),
                    egress=Egress.from_dict({"version": 1, "tools": {"send_email": {"emails": ["@acme.com.br"]}}}),
                    evidence=None)
        mw = catraca_middleware(gate, caller_for=caller_for, label_key=KEY, error=PermissionError)
        ctx = types.SimpleNamespace(method="tools/call", params={"name": "send_email", "arguments": dict(ARGS),
                                                                 "_meta": {META_KEY: label}})

        async def call_next(c):
            return "tool ran"
        return asyncio.run(mw(ctx, call_next))

    def test_allowed_for_its_caller_only(self):
        self.assertEqual(self.run_mw(lambda ctx: ACME_ANA, signed(ACME_ANA)), "tool ran")
        with self.assertRaises(PermissionError):
            self.run_mw(lambda ctx: Caller("globex", "ana"), signed(ACME_ANA))

    def test_caller_for_returning_none_never_runs_the_tool(self):
        with self.assertRaises(Exception):
            self.run_mw(lambda ctx: None, signed(ACME_ANA))

    def test_caller_for_raising_never_runs_the_tool(self):
        def boom(ctx):
            raise RuntimeError("no session")
        with self.assertRaises(RuntimeError):
            self.run_mw(boom, signed(ACME_ANA))


class DerivedKeys(unittest.TestCase):
    MASTER = bytes(range(32))

    def test_one_key_per_tenant(self):
        a, b = derive_label_key(self.MASTER, "acme"), derive_label_key(self.MASTER, "globex")
        self.assertEqual(len(a), 32)
        self.assertNotEqual(a, b)
        self.assertEqual(a, derive_label_key(self.MASTER, "acme"))
        self.assertNotEqual(a, derive_label_key(bytes(range(1, 33)), "acme"))

    def test_rfc5869_expand_step(self):
        # Spelled out from RFC 5869 section 2, so a change to the derivation shows up here.
        import hashlib
        import hmac
        prk = hmac.new(bytes(32), self.MASTER, hashlib.sha256).digest()
        want = hmac.new(prk, b"catraca/labels/acme\x01", hashlib.sha256).digest()
        self.assertEqual(derive_label_key(self.MASTER, "acme"), want)

    def test_a_derived_key_doesnt_verify_another_tenant(self):
        key_a = derive_label_key(self.MASTER, "acme")
        label = sign_labels({"to": "TRUSTED"}, dict(ARGS), key_a, tool="send_email", caller=ACME_ANA)
        other = LabelChecker(label_key=derive_label_key(self.MASTER, "globex"))
        self.assertIs(integrity(other, label, ACME_ANA), Integrity.UNTRUSTED)

    def test_master_key_length_edge(self):
        self.assertEqual(len(derive_label_key(bytes(16), "acme")), 32)
        with self.assertRaises(ValueError):
            derive_label_key(bytes(15), "acme")

    def test_bad_input(self):
        for master, tenant in ((b"short", "acme"), (self.MASTER, ""), (self.MASTER, None)):
            with self.subTest(master=master, tenant=tenant), self.assertRaises(ValueError):
                derive_label_key(master, tenant)


if __name__ == "__main__":
    unittest.main()
