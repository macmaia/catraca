"""End to end against the installed MCP SDK.

Run: python -m examples.mcp_server   (needs: pip install mcp)

The middleware hook is new in the SDK and marked provisional. If the installed
server exposes it, the example registers there; either way it drives the
middleware the way the server would and checks the SDK's own error comes back.
"""

import asyncio
import types

from catraca import Caller, DeclarativePolicy, Egress, Gate
from catraca.adapters.mcp import META_KEY, catraca_middleware, sign_labels
from examples._common import check

KEY = b"client-and-server-share-this-key"


def main() -> None:
    import mcp  # noqa: F401  (fail loudly if the SDK isn't there)

    policy = DeclarativePolicy.from_dict({"version": 1, "tools": {"send_email": {
        "callers": {"tenants": ["acme"], "users": "*"}, "args": {"to": {}, "body": {"integrity": "ANY"}}}}})
    gate = Gate(None, policy, egress=Egress.from_dict({"version": 1, "default": {"emails": ["@acme.com.br"]}}),
                evidence=None)
    mw = catraca_middleware(gate, caller_for=lambda ctx: Caller("acme", "svc"), label_key=KEY)

    async def call_next(ctx):
        return "tool ran"

    def ctx(args, meta=None):
        return types.SimpleNamespace(method="tools/call",
                                     params={"name": "send_email", "arguments": args, "_meta": meta or {}})

    args = {"to": "ana@acme.com.br", "body": "hi"}
    signed = {META_KEY: sign_labels({"to": "TRUSTED", "body": "UNTRUSTED"}, args, KEY, tool="send_email")}
    check(asyncio.run(mw(ctx(args, signed), call_next)) == "tool ran", "signed trusted recipient goes through")
    try:
        asyncio.run(mw(ctx(args), call_next))
        check(False, "unsigned call should be refused")
    except Exception as exc:
        check(type(exc).__module__.startswith("mcp"), f"refusal is the SDK's own error ({type(exc).__name__})")

    try:
        from mcp.server.lowlevel import Server
        server = Server("catraca-example")
        hook = getattr(server, "middleware", None)
        if isinstance(hook, list):
            hook.append(mw)
            print("ok  registered on the server's middleware list")
        else:
            print("--  this SDK version has no server middleware list yet, drove the middleware directly")
    except ImportError:
        print("--  lowlevel Server not found in this SDK version")


if __name__ == "__main__":
    main()
