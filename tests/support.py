"""Small helpers for building policies in tests."""

from catraca import DeclarativePolicy


def spec(**tools):
    return {"version": 1, "tools": tools}


def tool(strict=(), loose=(), *, confirm=True, integrity="STRUCTURED", destinations=(), tenants="*", users="*"):
    args = {a: {"integrity": integrity} for a in strict}
    args.update({a: {"integrity": "ANY"} for a in loose})
    return {
        "callers": {"tenants": tenants, "users": users},
        "args": args,
        "destinations": list(destinations),
        "confirm_on_coincidence": confirm,
    }


def policy(cls=DeclarativePolicy, **tools):
    return cls.from_dict(spec(**tools))


from catraca import Egress
from catraca import Gate as _Gate

OPEN_EGRESS = Egress.from_dict({"version": 1, "default": {"hosts": ["*"], "emails": ["*"]}})
"""Any host or address is allowed, but provenance is still checked (TRUSTED).
Used by tests that are about something other than egress."""


class OpenEgressGate(_Gate):
    def __init__(self, registry, policy, **kw):
        kw.setdefault("egress", OPEN_EGRESS)
        super().__init__(registry, policy, **kw)
