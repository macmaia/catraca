"""The confirmation round trip, single-use tokens bound to the call."""

import itertools
import threading
import unittest

from catraca import (
    Caller,
    ChannelConfig,
    ConfirmationRequired,
    ConfirmationStore,
    ContextRegistry,
    Gate,
    Reason,
    Verdict,
)

CFG = ChannelConfig.from_dict(
    {
        "version": 1,
        "channels": {
            "user": {"integrity": "TRUSTED", "confidentiality": "*"},
            "kb": {"integrity": "UNTRUSTED", "confidentiality": "*"},
        },
    }
)
ANA = Caller("acme", "ana")
BIA = Caller("acme", "bia")
from tests.support import policy, tool
from tests.support import OpenEgressGate as Gate  # noqa: E402  (egress is tested in test_egress)

POLICY = policy(
    send_email=tool(strict=("to", "cc"), loose=("body", "attachment", "tags"), destinations=("smtp", "smtp-2")),
    search=tool(loose=("body",), strict=("to",), destinations=("smtp",)),
)
ARGS = {"to": "ana@acme.com.br", "body": "Here's the summary."}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def coincidence_gate(**kw):
    reg = ContextRegistry(CFG)
    reg.annotate("Send the summary to ana@acme.com.br", "user", origin="prompt")
    reg.annotate("signature: ana@acme.com.br", "kb")
    tokens = (f"tok{i}" for i in itertools.count())
    store = kw.pop("store", None)
    if store is None:
        store = ConfirmationStore(new_token=lambda: next(tokens), **kw)
    return reg, Gate(reg, POLICY, confirmations=store)


class RoundTrip(unittest.TestCase):
    def test_yes_turns_into_allow(self):
        _, gate = coincidence_gate()
        first = gate.decide("send_email", ARGS, caller=ANA)
        self.assertIs(first.verdict, Verdict.REQUIRE_CONFIRMATION)
        self.assertTrue(first.confirmation_token)
        second = gate.decide("send_email", ARGS, caller=ANA, confirmation=first.confirmation_token)
        self.assertIs(second.verdict, Verdict.ALLOW)
        self.assertIs(second.reason, Reason.CONFIRMED_BY_USER)
        self.assertEqual(second.call_id, first.call_id)
        self.assertTrue(second.rule_id.endswith("+confirmed"))

    def test_token_is_single_use(self):
        _, gate = coincidence_gate()
        tok = gate.decide("send_email", ARGS, caller=ANA).confirmation_token
        gate.decide("send_email", ARGS, caller=ANA, confirmation=tok)
        again = gate.decide("send_email", ARGS, caller=ANA, confirmation=tok)
        self.assertIs(again.verdict, Verdict.DENY)
        self.assertIs(again.reason, Reason.CONFIRMATION_INVALID)

    def test_value_swapped_after_confirmation_is_denied_and_burns_token(self):
        _, gate = coincidence_gate()
        tok = gate.decide("send_email", ARGS, caller=ANA).confirmation_token
        swapped = dict(ARGS, to="thief@evil.io")
        d = gate.decide("send_email", swapped, caller=ANA, confirmation=tok)
        self.assertIs(d.reason, Reason.CONFIRMATION_MISMATCH)
        # And you can't then retry with the original values on the same token.
        self.assertIs(gate.decide("send_email", ARGS, caller=ANA, confirmation=tok).reason,
                      Reason.CONFIRMATION_INVALID)

    def test_any_binding_change_is_a_mismatch(self):
        changes = [
            dict(tool="search"),
            dict(caller=BIA),
            dict(destination="smtp-2"),
            dict(call_id="someone-elses-call"),
            dict(args=dict(ARGS, body="Different body.")),
            dict(args=dict(ARGS, cc="extra@acme.com.br")),
        ]
        for change in changes:
            _, gate = coincidence_gate()
            tok = gate.decide("send_email", ARGS, caller=ANA, destination="smtp").confirmation_token
            call = dict(tool="send_email", args=ARGS, caller=ANA, destination="smtp")
            call.update(change)
            d = gate.decide(call.pop("tool"), call.pop("args"), confirmation=tok, **call)
            self.assertIs(d.verdict, Verdict.DENY, change)
            self.assertIs(d.reason, Reason.CONFIRMATION_MISMATCH, change)

    def test_expired_token(self):
        clock = FakeClock()
        _, gate = coincidence_gate(clock=clock, ttl_seconds=60)
        tok = gate.decide("send_email", ARGS, caller=ANA).confirmation_token
        clock.now += 61
        self.assertIs(gate.decide("send_email", ARGS, caller=ANA, confirmation=tok).reason,
                      Reason.CONFIRMATION_INVALID)

    def test_unknown_or_garbage_token(self):
        _, gate = coincidence_gate()
        for tok in ("nope", "", 42, b"tok0", object()):
            d = gate.decide("send_email", ARGS, caller=ANA, confirmation=tok)
            self.assertIs(d.verdict, Verdict.DENY, tok)

    def test_decline(self):
        _, gate = coincidence_gate()
        tok = gate.decide("send_email", ARGS, caller=ANA).confirmation_token
        self.assertTrue(gate.decline(tok))
        self.assertFalse(gate.decline(tok))
        self.assertIs(gate.decide("send_email", ARGS, caller=ANA, confirmation=tok).reason,
                      Reason.CONFIRMATION_INVALID)

    def test_window_changed_since_confirmation(self):
        """Re-evaluated from scratch. If it's no longer a pure coincidence, it's a deny."""
        reg, gate = coincidence_gate()
        tok = gate.decide("send_email", ARGS, caller=ANA).confirmation_token
        prompt = next(s for s in reg.snippets if s.origin == "prompt")
        reg.forget(prompt.id, reason="history truncated")
        d = gate.decide("send_email", ARGS, caller=ANA, confirmation=tok)
        self.assertIs(d.verdict, Verdict.DENY)
        self.assertIs(d.reason, Reason.UNTRUSTED_ARGUMENT)

    def test_token_when_no_confirmation_needed_any_more(self):
        """If the value's now plainly trusted, the call's allowed on its own merits."""
        reg, gate = coincidence_gate()
        tok = gate.decide("send_email", ARGS, caller=ANA).confirmation_token
        kb = next(s for s in reg.snippets if s.channel == "kb")
        reg.forget(kb.id, reason="doc dropped from context")
        d = gate.decide("send_email", ARGS, caller=ANA, confirmation=tok)
        self.assertIs(d.verdict, Verdict.ALLOW)
        self.assertIs(d.reason, Reason.ALLOWED_BY_POLICY)

    def test_token_never_leaks_into_logs(self):
        _, gate = coincidence_gate()
        d = gate.decide("send_email", ARGS, caller=ANA)
        self.assertNotIn(d.confirmation_token, repr(d))
        self.assertNotIn(d.confirmation_token, str(d.to_dict()))

    def test_bounded_store_drops_oldest(self):
        _, gate = coincidence_gate(max_pending=2)
        toks = [gate.decide("send_email", ARGS, caller=ANA, call_id=f"c{i}").confirmation_token
                for i in range(3)]
        self.assertIs(gate.decide("send_email", ARGS, caller=ANA, call_id="c0", confirmation=toks[0]).reason,
                      Reason.CONFIRMATION_INVALID)
        self.assertIs(gate.decide("send_email", ARGS, caller=ANA, call_id="c2", confirmation=toks[2]).verdict,
                      Verdict.ALLOW)

    def test_check_carries_the_token(self):
        _, gate = coincidence_gate()
        with self.assertRaises(ConfirmationRequired) as ctx:
            gate.check("send_email", ARGS, caller=ANA)
        tok = ctx.exception.decision.confirmation_token
        self.assertIs(gate.check("send_email", ARGS, caller=ANA, confirmation=tok).verdict, Verdict.ALLOW)

    def test_non_json_values_fingerprint_safely(self):
        _, gate = coincidence_gate()
        args = dict(ARGS, attachment=b"\x00\x01", tags={"a", "b"})
        tok = gate.decide("send_email", args, caller=ANA).confirmation_token
        self.assertIs(gate.decide("send_email", dict(args), caller=ANA, confirmation=tok).verdict, Verdict.ALLOW)

    def test_race_on_one_token_allows_exactly_once(self):
        _, gate = coincidence_gate()
        tok = gate.decide("send_email", ARGS, caller=ANA).confirmation_token
        results, barrier = [], threading.Barrier(16)

        def go():
            barrier.wait()
            results.append(gate.decide("send_email", ARGS, caller=ANA, confirmation=tok).verdict)

        threads = [threading.Thread(target=go) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(Verdict.ALLOW), 1)
        self.assertEqual(results.count(Verdict.DENY), 15)

    def test_store_rejects_bad_settings(self):
        with self.assertRaises(ValueError):
            ConfirmationStore(ttl_seconds=0)
        with self.assertRaises(ValueError):
            ConfirmationStore(max_pending=0)


if __name__ == "__main__":
    unittest.main()


class SharedBackend(unittest.TestCase):
    """A token issued by one worker must work on another when
    they share a backend, and still only once."""

    class DictBackend:
        """Stands in for Redis: a dict shared by two 'workers'."""

        def __init__(self):
            self.data = {}
            self.lock = threading.Lock()

        def put(self, token, record, ttl_seconds):
            self.data[token] = record

        def take(self, token):
            with self.lock:
                return self.data.pop(token, None)

        def drop(self, token):
            return self.data.pop(token, None) is not None

    def test_token_crosses_workers_once(self):
        from catraca.confirmations import PendingBackend
        shared = self.DictBackend()
        _, worker_a = coincidence_gate(store=ConfirmationStore(backend=shared))
        _, worker_b = coincidence_gate(store=ConfirmationStore(backend=shared))
        first = worker_a.decide("send_email", ARGS, caller=ANA)
        self.assertIs(first.verdict, Verdict.REQUIRE_CONFIRMATION)
        second = worker_b.decide("send_email", ARGS, caller=ANA, call_id=first.call_id,
                                 confirmation=first.confirmation_token)
        self.assertIs(second.verdict, Verdict.ALLOW)
        again = worker_a.decide("send_email", ARGS, caller=ANA, call_id=first.call_id,
                                confirmation=first.confirmation_token)
        self.assertIs(again.reason, Reason.CONFIRMATION_INVALID)
        self.assertTrue(PendingBackend)

    def test_expired_and_garbled_records_are_invalid(self):
        clock = FakeClock()
        shared = self.DictBackend()
        _, g = coincidence_gate(store=ConfirmationStore(backend=shared, clock=clock, ttl_seconds=10))
        tok = g.decide("send_email", ARGS, caller=ANA).confirmation_token
        clock.now += 11
        self.assertIs(g.decide("send_email", ARGS, caller=ANA, confirmation=tok).reason, Reason.CONFIRMATION_INVALID)
        tok = g.decide("send_email", ARGS, caller=ANA).confirmation_token
        shared.data[tok] = "{not json"
        self.assertIs(g.decide("send_email", ARGS, caller=ANA, confirmation=tok).reason, Reason.CONFIRMATION_INVALID)
