"""The stdio proxy in front of a third-party MCP server."""

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from catraca import Caller, DeclarativePolicy, Egress, Gate
from catraca.adapters.mcp import META_KEY, LabelChecker, sign_labels
from catraca.adapters.mcp_proxy import McpProxy, main, run

KEY = b"client-and-proxy-share-this-key!"
POLICY = {"version": 1, "tools": {"send_email": {
    "callers": {"tenants": ["acme"], "users": "*"}, "args": {"to": {}, "body": {"integrity": "ANY"}}}}}
EGRESS = {"version": 1, "tools": {"send_email": {"emails": ["@acme.com.br"]}}}
SERVER = str(Path(__file__).with_name("fake_mcp_server.py"))


def proxy(**kw):
    gate = Gate(None, DeclarativePolicy.from_dict(POLICY), egress=Egress.from_dict(EGRESS), evidence=None)
    return McpProxy(gate, Caller("acme", "agent"), labels=LabelChecker(**kw))


def call(i, to, meta=None):
    args = {"to": to, "body": "hi"}
    params = {"name": "send_email", "arguments": args}
    if meta is not None:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": params}


def signed(i, to):
    args = {"to": to, "body": "hi"}
    return call(i, to, {META_KEY: sign_labels({"to": "TRUSTED", "body": "UNTRUSTED"}, args, KEY, tool="send_email")})


class ThirdPartyServer(unittest.TestCase):
    def converse(self, messages, **kw):
        with tempfile.TemporaryDirectory() as d:
            calls_log = Path(d) / "calls.jsonl"
            calls_log.touch()
            stdin = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
            stdout = io.StringIO()
            code = run(proxy(**kw), [sys.executable, SERVER, str(calls_log)], stdin=stdin, stdout=stdout)
            replies = {r["id"]: r for r in map(json.loads, stdout.getvalue().splitlines())}
            received = [json.loads(x) for x in calls_log.read_text().splitlines()]
        self.assertEqual(code, 0)
        return replies, received

    def test_denied_call_never_reaches_the_server_and_the_connection_stays_up(self):
        replies, received = self.converse([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            signed(3, "thief@evil.io"),      # destination not allowed
            call(4, "ana@acme.com.br"),      # unsigned, so UNTRUSTED
            signed(5, "ana@acme.com.br"),    # signed and allowed
        ], label_key=KEY)
        self.assertIn("result", replies[1])
        self.assertEqual(replies[2]["result"]["tools"][0]["name"], "send_email")
        self.assertEqual(replies[3]["error"]["code"], -32001)
        self.assertIn("EGRESS_NOT_ALLOWED", replies[3]["error"]["message"])
        self.assertIn("UNTRUSTED_ARGUMENT", replies[4]["error"]["message"])
        self.assertEqual(replies[5]["result"]["content"][0]["text"], "sent")
        self.assertEqual([c["arguments"]["to"] for c in received], ["ana@acme.com.br"])

    def test_a_replayed_signed_call_is_refused(self):
        good = signed(1, "ana@acme.com.br")
        again = dict(good, id=2)
        replies, received = self.converse([good, again], label_key=KEY)
        self.assertIn("result", replies[1])
        self.assertIn("error", replies[2])
        self.assertEqual(len(received), 1)


class WhatGetsChecked(unittest.TestCase):
    def test_duplicate_keys_and_bad_json_are_refused(self):
        # The allowed address comes last, where Python's parser would look, and the
        # attacker's comes first, where some other parsers look. It mustn't pass.
        p = proxy(trust_client=True)
        line = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email",'
                '"arguments":{"to":"thief@evil.io","to":"ana@acme.com.br","body":"hi"}}}')
        forward, reply = p.from_client(line)
        self.assertIsNone(forward)
        self.assertIn("error", json.loads(reply))
        forward, reply = p.from_client("{not json")
        self.assertIsNone(forward)

    def test_batches_with_a_tool_call_are_refused(self):
        p = proxy(trust_client=True)
        forward, reply = p.from_client(json.dumps([call(1, "ana@acme.com.br"), {"jsonrpc": "2.0", "id": 2,
                                                                                "method": "tools/list"}]))
        self.assertIsNone(forward)
        self.assertEqual(len(json.loads(reply)), 2)

    def test_what_is_forwarded_is_what_was_checked(self):
        p = proxy(trust_client=True)
        forward, reply = p.from_client(json.dumps(call(1, "ana@acme.com.br")) + "  ")
        self.assertIsNone(reply)
        self.assertEqual(json.loads(forward)["params"]["arguments"]["to"], "ana@acme.com.br")


class Robustness(unittest.TestCase):
    def test_bad_text_doesnt_end_the_session(self):
        p = proxy(trust_client=True)
        forward, reply = p.from_client('{"jsonrpc":"2.0","id":1,"method":"ping","x":"\\ud800"}')
        forward.encode("utf-8")  # forwarded as escaped ASCII, so it can always be written
        self.assertTrue(forward.isascii())

    def test_odd_method_spellings_and_falsy_arguments_are_refused(self):
        p = proxy(trust_client=True)
        for msg in ({"jsonrpc": "2.0", "id": 1, "method": "Tools/call", "params": {"name": "send_email"}},
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call ", "params": {"name": "send_email"}},
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "send_email", "arguments": []}}):
            forward, reply = p.from_client(json.dumps(msg))
            self.assertIsNone(forward, msg)
            self.assertIn("error", json.loads(reply))
        forward, reply = p.from_client(json.dumps([[call(1, "ana@acme.com.br")]]))
        self.assertIsNone(forward)

    def test_nan_and_infinity_are_refused(self):
        p = proxy(trust_client=True)
        for bad in ('{"jsonrpc":"2.0","id":1,"method":"ping","x":NaN}',
                    '{"jsonrpc":"2.0","id":1,"method":"ping","x":Infinity}'):
            forward, reply = p.from_client(bad)
            self.assertIsNone(forward)

    def test_a_short_label_key_is_refused_up_front(self):
        import os
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(POLICY, f)
        os.environ["CATRACA_TEST_KEY"] = "00ff"
        try:
            with self.assertRaises(SystemExit):
                main(["--policy", f.name, "--tenant", "acme", "--user", "a", "--no-evidence",
                      "--label-key-env", "CATRACA_TEST_KEY", "--", "true"])
        finally:
            del os.environ["CATRACA_TEST_KEY"]

    def test_a_refused_notification_gets_no_answer(self):
        msg = call(1, "thief@evil.io")
        del msg["id"]
        self.assertEqual(proxy(trust_client=True).from_client(json.dumps(msg)), (None, None))

    def test_non_json_lines_from_the_server_dont_reach_the_agent(self):
        with tempfile.TemporaryDirectory() as d:
            noisy = Path(d) / "noisy.py"
            noisy.write_text("import sys\nprint('added 39 packages')\nprint()\n"
                             "sys.stdout.flush()\nsys.argv = sys.argv[1:]\nexec(open(sys.argv[0]).read())\n")
            log = Path(d) / "calls"
            log.touch()
            stdin = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
            stdout = io.StringIO()
            import contextlib
            with contextlib.redirect_stderr(io.StringIO()):
                run(proxy(), [sys.executable, str(noisy), SERVER, str(log)], stdin=stdin, stdout=stdout)
        lines = stdout.getvalue().splitlines()
        self.assertTrue(lines)
        for line in lines:
            json.loads(line)

    def test_session_survives_bad_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "calls"
            log.touch()
            stdin = io.StringIO("\ufffd\n" + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n")
            stdout = io.StringIO()
            run(proxy(), [sys.executable, SERVER, str(log)], stdin=stdin, stdout=stdout)
        replies = [json.loads(x) for x in stdout.getvalue().splitlines()]
        self.assertTrue(any(r.get("id") == 2 and "result" in r for r in replies))



class Limits(unittest.TestCase):
    def test_message_size_limit_is_inclusive(self):
        from catraca.adapters.mcp_proxy import MAX_LINE
        head, tail = '{"jsonrpc":"2.0","id":1,"method":"ping","x":"', '"}'
        at_limit = head + "a" * (MAX_LINE - len(head) - len(tail)) + tail
        p = proxy(trust_client=True)
        forward, reply = p.from_client(at_limit)
        self.assertIsNotNone(forward)
        forward, reply = p.from_client(at_limit[:-2] + 'a"}')
        self.assertIsNone(forward)
        self.assertEqual(json.loads(reply)["error"]["code"], -32600)

    def test_bad_json_is_a_parse_error(self):
        forward, reply = proxy().from_client("{nope")
        self.assertEqual(json.loads(reply)["error"]["code"], -32700)

    def test_a_batch_without_tool_calls_goes_through(self):
        batch = [{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        forward, reply = proxy().from_client(json.dumps(batch))
        self.assertIsNone(reply)
        self.assertEqual(json.loads(forward), batch)

    def test_malformed_tool_calls_are_refused(self):
        p = proxy(label_key=KEY)
        for params in ([], {"arguments": {}}, {"name": 5},
                       {"name": "send_email", "arguments": {"to": "ana@acme.com.br"}, "_meta": []}):
            msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
            forward, reply = p.from_client(json.dumps(msg))
            self.assertIsNone(forward, params)
            self.assertEqual(json.loads(reply)["error"]["code"], -32001, params)

class Cli(unittest.TestCase):
    def test_needs_a_decision_log_or_an_explicit_no(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(POLICY, f)
        with self.assertRaises(SystemExit):
            main(["--policy", f.name, "--tenant", "acme", "--user", "a", "--", "true"])
        self.assertEqual(main(["--policy", f.name]), 2)


if __name__ == "__main__":
    unittest.main()
