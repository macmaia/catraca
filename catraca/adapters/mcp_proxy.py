"""A stdio proxy that puts the gate in front of any MCP server, yours or not.

    catraca-mcp-proxy --policy policy.json --egress egress.json \\
        --tenant acme --user agent --evidence decisions.jsonl -- npx some-mcp-server

The agent starts the proxy instead of the server. The proxy starts the server,
passes every message through, and checks each ``tools/call`` with the gate
before the server sees it. A call that isn't allowed never reaches the server:
the agent gets a JSON-RPC error (code -32001, reason code in the message) and
the connection stays up.

What gets checked is exactly what gets forwarded: the proxy parses each
message, refuses one with duplicate keys, and sends the server its own
re-encoding, so the server can't read a different call from the same bytes.

Like the middleware, a proxy can't see the agent's context, so every arg is
UNTRUSTED unless the client signs its labels (``--label-key-env``) or you pass
``--trust-client``. Only the stdio transport is covered.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import threading
from typing import IO, Any, Dict, List, Optional, Sequence, Tuple

from ..channels import ChannelConfig
from ..egress import Egress
from ..evidence import EvidenceLog, JsonlFileSink
from ..gate import Caller, Gate, Verdict
from ..policy import DeclarativePolicy
from ..registry import ContextRegistry
from .mcp import DENIED_CODE, LabelChecker


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _DuplicateKey("a JSON object has the same key twice")
    return dict(pairs)


MAX_LINE = 16 * 1024 * 1024  # bytes, per message


def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _encode(msg: Any) -> str:
    # ASCII only: lone surrogates and line separators are escaped, so what the
    # server reads is exactly what was checked, and nothing breaks the framing.
    return json.dumps(msg, ensure_ascii=True, separators=(",", ":"))


def _is_call(m: Any) -> bool:
    return isinstance(m, dict) and isinstance(m.get("method"), str) and \
        m["method"].strip().lower() == "tools/call"


class McpProxy:
    """The checking part, with no I/O, so it can be tested on its own."""

    def __init__(self, gate: Gate, caller: Caller, *, labels: Optional[LabelChecker] = None) -> None:
        self._gate = gate
        self._caller = caller
        self._labels = labels or LabelChecker()

    def from_client(self, line: str) -> Tuple[Optional[str], Optional[str]]:
        """One line from the agent. Returns (line for the server, line back to the agent)."""
        if len(line) > MAX_LINE:
            return None, _encode(_error(None, -32600, "catraca: refused, message too large"))
        try:
            msg = json.loads(line, object_pairs_hook=_no_duplicates)
        except (ValueError, RecursionError):
            # Can't be checked, so it doesn't go through. No id to answer to.
            return None, _encode(_error(None, -32700, "catraca: refused, not valid JSON"))
        if isinstance(msg, list):
            # A tools/call can't ride along in a batch, and nested lists aren't JSON-RPC.
            if any(_is_call(m) or isinstance(m, list) for m in msg):
                return None, _encode([_error(m.get("id") if isinstance(m, dict) else None, DENIED_CODE,
                                             "catraca: refused, tools/call inside a batch") for m in msg])
            return _encode(msg), None
        if not _is_call(msg):
            return _encode(msg), None
        refusal = self._check(msg)
        if refusal is not None:
            if "id" not in msg:
                return None, None  # a notification gets no answer, it just doesn't go through
            return None, _encode(_error(msg.get("id"), DENIED_CODE, refusal))
        return _encode(msg), None

    def _check(self, msg: Dict[str, Any]) -> Optional[str]:
        if msg.get("method") != "tools/call":
            return "catraca: refused, method name isn't exactly tools/call"
        params = msg.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return "catraca: refused, tools/call without a tool name"
        args = params.get("arguments", {})
        meta = params.get("_meta", {})
        if not isinstance(args, dict) or not isinstance(meta, dict):
            return "catraca: refused, malformed tools/call"
        tool = params["name"]
        decision = self._gate.decide(tool, args, caller=self._caller, labels=self._labels.edges(tool, args, meta))
        if decision.verdict is not Verdict.ALLOW:
            return f"catraca: {decision.reason.value} ({decision.rule_id})"
        return None


def run(proxy: McpProxy, server_cmd: Sequence[str], *, stdin: IO[str] = sys.stdin,
        stdout: IO[str] = sys.stdout) -> int:
    """Start the server and relay until the agent closes its side."""
    server = subprocess.Popen(list(server_cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                              encoding="utf-8", errors="replace", bufsize=1)
    assert server.stdin is not None and server.stdout is not None
    out_lock = threading.Lock()

    def to_agent(line: str) -> None:
        with out_lock:
            stdout.write(line.rstrip("\n") + "\n")
            stdout.flush()

    def pump_server() -> None:
        assert server.stdout is not None
        try:
            for line in server.stdout:
                if not line.strip():
                    continue
                try:
                    json.loads(line)
                except ValueError:
                    # stdout is only for MCP messages. Some servers (or the tools
                    # they install on first use) print other things there, which
                    # would break the agent's parser. Send those to stderr.
                    sys.stderr.write(f"catraca-mcp-proxy: server printed a non-JSON line: {line[:200]}")
                    continue
                to_agent(line)
        except (OSError, ValueError):
            pass  # the agent's side is gone, nothing left to relay to

    reader = threading.Thread(target=pump_server, daemon=True)
    reader.start()
    try:
        for line in stdin:
            if not line.strip():
                continue
            try:
                forward, reply = proxy.from_client(line)
            except Exception:  # the gate fails closed, the proxy does too, and keeps the session up
                forward, reply = None, _encode(_error(None, DENIED_CODE, "catraca: refused, internal error"))
            if reply is not None:
                to_agent(reply)
            if forward is not None:
                server.stdin.write(forward + "\n")
                server.stdin.flush()
    finally:
        try:
            server.stdin.close()
        except OSError:
            pass
        code = server.wait()
        reader.join(timeout=5)
        server.stdout.close()
    return code


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        print("usage: catraca-mcp-proxy [options] -- server command", file=sys.stderr)
        return 2
    cut = argv.index("--")
    ap = argparse.ArgumentParser(prog="catraca-mcp-proxy")
    ap.add_argument("--policy", required=True, help="policy JSON file")
    ap.add_argument("--egress", help="egress JSON file (default: no destination allowed)")
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--evidence", help="JSONL decision log (required unless --no-evidence)")
    ap.add_argument("--no-evidence", action="store_true", help="run without a decision log")
    ap.add_argument("--label-key-env", help="environment variable holding the label key, in hex")
    ap.add_argument("--trust-client", action="store_true", help="treat every arg as TRUSTED")
    args = ap.parse_args(argv[:cut])
    server_cmd = argv[cut + 1:]
    if not server_cmd:
        ap.error("give the server command after --")
    if not args.evidence and not args.no_evidence:
        ap.error("give --evidence FILE, or --no-evidence if you really mean it")
    key = None
    if args.label_key_env:
        try:
            key = bytes.fromhex(os.environ[args.label_key_env])
        except (KeyError, ValueError):
            ap.error(f"{args.label_key_env} must hold the label key in hex")
    # The proxy never sees the agent's context, so the registry stays empty and
    # every arg's label comes from LabelChecker.
    registry = ContextRegistry(ChannelConfig.from_dict(
        {"version": 1, "channels": {"mcp-client": {"integrity": "UNTRUSTED", "confidentiality": "*"}}}))
    gate = Gate(registry, DeclarativePolicy.from_file(args.policy),
                egress=Egress.from_file(args.egress) if args.egress else Egress.strict(),
                evidence=EvidenceLog(JsonlFileSink(args.evidence)) if args.evidence else None)
    proxy = McpProxy(gate, Caller(tenant=args.tenant, user=args.user),
                     labels=LabelChecker(label_key=key, trust_client=args.trust_client))
    # Bytes that aren't UTF-8 become U+FFFD instead of ending the session.
    stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    return run(proxy, server_cmd, stdin=stdin)


if __name__ == "__main__":
    sys.exit(main())
