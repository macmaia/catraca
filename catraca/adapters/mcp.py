"""Middleware for an MCP server (official Python SDK).

    server = ...  # your MCP server
    server.middleware.append(catraca_middleware(gate, caller_for=lambda ctx: Caller("acme", "svc")))

The SDK's middleware is ``async (ctx, call_next)``, it runs on the *server*,
and its docs mark it provisional (it may change in a 2.x minor release), so
this adapter keeps the SDK at arm's length: everything it needs from ``ctx`` is
read in one place (``_call_of``) and the error class is looked up at runtime.

A server can't see the client's context window, so it can't know where the
args came from. Strict default: every arg from the client is UNTRUSTED. Two
ways to loosen, both explicit:

* ``label_key=`` : a client running catraca signs its labels
  (``sign_labels``) and sends them in ``params._meta["catraca/labels"]``. The
  server checks the HMAC, which covers the tool, the arg values, the time it was
  signed (``max_age``, 300 s by default) and a nonce. Each nonce is accepted
  once, so a captured call can't be sent again. That holds per process unless
  the workers share a ``nonces=`` store. Bad, stale, replayed or missing
  signature means UNTRUSTED.
* ``trust_client=True`` : every arg counts as TRUSTED. Only for a client you
  fully control.

Denials are raised as the SDK's MCP error with code -32001 and a message that
names the reason code, so the connection stays up.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Tuple

from ..gate import Caller, EdgeLabel, Gate, Verdict
from ..labels import Integrity, Label

META_KEY = "catraca/labels"
DENIED_CODE = -32001


def sign_labels(labels: Mapping[str, str], args: Mapping[str, Any], key: bytes, *, tool: str,
                issued_at: Optional[int] = None) -> dict:
    """Client side. ``labels`` maps arg name to integrity name. The signature
    covers the tool name, the arg values, the time it was made and a fresh
    nonce, so labels can't be moved onto other values or another tool, or
    sent again."""
    iat = int(time.time()) if issued_at is None else int(issued_at)
    nonce = os.urandom(16).hex()
    body = _signed_body(labels, args, tool, iat, nonce)
    return {"labels": dict(labels), "tool": tool, "iat": iat, "nonce": nonce,
            "mac": hmac.new(key, body, hashlib.sha256).hexdigest()}


def _signed_body(labels: Mapping[str, str], args: Mapping[str, Any], tool: str, iat: int, nonce: str) -> bytes:
    # No default=repr: a value that isn't plain JSON can't be signed, so it
    # stays UNTRUSTED instead of colliding with its own string form.
    return json.dumps({"labels": dict(labels), "args": args, "tool": tool, "iat": iat, "nonce": nonce},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


class NonceStore(Protocol):
    """Where used nonces are kept. ``first_use`` must be atomic: True the first
    time a nonce is seen within ``ttl`` seconds, False after that. With several
    workers or proxies, share one store between them (Redis ``SET NX EX``, say),
    or a nonce is only used once per process."""

    def first_use(self, nonce: str, ttl: int) -> bool: ...


class MemoryNonces:
    """The default store: one process, oldest entries dropped as they expire."""

    def __init__(self) -> None:
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._lock = threading.Lock()

    def first_use(self, nonce: str, ttl: int) -> bool:
        now = time.time()
        with self._lock:
            while self._seen and now - next(iter(self._seen.values())) > ttl:
                self._seen.popitem(last=False)
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


def _mcp_error(message: str) -> Exception:
    for mod, name in (("mcp", "MCPError"), ("mcp.shared.exceptions", "MCPError"),
                      ("mcp.shared.exceptions", "McpError")):
        try:
            cls = getattr(importlib.import_module(mod), name)
        except (ImportError, AttributeError):
            continue
        for build in (lambda cls=cls: cls(code=DENIED_CODE, message=message),
                      lambda cls=cls: cls(DENIED_CODE, message),
                      lambda cls=cls: cls(_error_data(message))):
            try:
                err = build()
            except (TypeError, AttributeError, ImportError, ValueError):
                continue
            if message in str(err) or message in str(getattr(getattr(err, "error", None), "message", "")):
                return err
    return PermissionError(message)


def _error_data(message: str) -> Any:
    # SDK 1.x: McpError(ErrorData(code, message)).
    return importlib.import_module("mcp.types").ErrorData(code=DENIED_CODE, message=message)


def _call_of(ctx: Any) -> Optional[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    """(tool name, arguments, _meta) for a tools/call, None for anything else."""
    method = getattr(ctx, "method", None) or getattr(getattr(ctx, "request", None), "method", None)
    if method != "tools/call":
        return None
    outer = getattr(ctx, "params", None)
    inner = getattr(getattr(ctx, "request", None), "params", None)
    if outer is not None and inner is not None and outer is not inner and outer != inner:
        # Two different calls in one context: check neither, refuse.
        raise ValueError("ctx carries two different sets of params")
    params = outer if outer is not None else inner
    get = (lambda k: params.get(k)) if isinstance(params, Mapping) else (lambda k: getattr(params, k, None))
    meta = get("_meta") or get("meta") or {}
    if not isinstance(meta, Mapping):
        meta = getattr(meta, "__dict__", {}) or {}
    return str(get("name") or ""), dict(get("arguments") or {}), dict(meta)


class LabelChecker:
    """Turns a call's ``_meta`` into per-arg labels, the same way for the
    middleware and the proxy. Strict default: everything UNTRUSTED."""

    def __init__(self, *, label_key: Optional[bytes] = None, trust_client: bool = False, max_age: int = 300,
                 nonces: Optional[NonceStore] = None) -> None:
        if label_key is not None and len(label_key) < 16:
            raise ValueError("label_key must be at least 16 bytes.")
        self._key = label_key
        self._trust_client = trust_client
        self._max_age = max_age
        self._seen: NonceStore = nonces if nonces is not None else MemoryNonces()

    def edges(self, tool: str, args: Mapping[str, Any], meta: Mapping[str, Any]) -> Dict[str, EdgeLabel]:
        if self._trust_client:
            return {k: EdgeLabel(Label(Integrity.TRUSTED), "mcp-client") for k in args}
        claimed = meta.get(META_KEY) if self._key is not None else None
        ok = False
        if isinstance(claimed, Mapping) and isinstance(claimed.get("labels"), Mapping) \
                and isinstance(claimed.get("iat"), int) and not isinstance(claimed.get("iat"), bool) \
                and isinstance(claimed.get("nonce"), str) and len(claimed["nonce"]) >= 16:
            iat = claimed["iat"]
            fresh = -30 <= time.time() - iat <= self._max_age  # 30 s of clock skew the other way
            try:
                body = _signed_body(claimed["labels"], args, tool, iat, claimed["nonce"])
            except (TypeError, ValueError):
                body = None  # not plain JSON, can't have been signed
            if body is not None and self._key is not None:
                want = hmac.new(self._key, body, hashlib.sha256).hexdigest()
                # Check the nonce last, so only a valid, fresh signature uses it up.
                ok = fresh and hmac.compare_digest(want, str(claimed.get("mac", ""))) \
                    and self._seen.first_use(claimed["nonce"], self._max_age + 60)
        signed: Mapping[str, Any] = claimed["labels"] if ok and isinstance(claimed, Mapping) else {}
        out = {}
        for k in args:
            level = signed.get(k)
            integrity = Integrity[level] if isinstance(level, str) and level in Integrity.__members__ \
                else Integrity.UNTRUSTED
            out[k] = EdgeLabel(Label(integrity), "mcp-client-signed" if ok else "mcp-client")
        return out


def catraca_middleware(gate: Gate, *, caller_for: Callable[[Any], Caller], label_key: Optional[bytes] = None,
                       trust_client: bool = False, max_age: int = 300, nonces: Optional[NonceStore] = None,
                       error: Callable[[str], Exception] = _mcp_error) -> Callable[..., Any]:
    checker = LabelChecker(label_key=label_key, trust_client=trust_client, max_age=max_age, nonces=nonces)

    async def middleware(ctx: Any, call_next: Callable[[Any], Any]) -> Any:
        try:
            call = _call_of(ctx)
        except ValueError as exc:
            raise error(f"catraca: refused, {exc}") from None
        if call is None:
            return await call_next(ctx)
        tool, args, meta = call
        decision = await gate.adecide(tool, args, caller=caller_for(ctx), labels=checker.edges(tool, args, meta))
        if decision.verdict is not Verdict.ALLOW:
            raise error(f"catraca: {decision.reason.value} ({decision.rule_id})")
        return await call_next(ctx)

    return middleware
