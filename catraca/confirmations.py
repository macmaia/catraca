"""Single-use confirmation tokens.

When the gate says REQUIRE_CONFIRMATION it also hands out a token. The token is
bound to exactly what the person is about to see and approve: the call id, the
tool, the caller, the destination, a fingerprint of every arg value, and the
list of args that needed confirming. To go ahead, the app calls the gate again
with the same call and the token. Change anything and the token's no good.

Tokens are single use. Redeeming one always burns it, whether it matches or
not, so a wrong guess can't be retried against the same token. They also
expire, and the store is bounded, so a flood of pending confirmations can't
grow memory without limit (the oldest just get dropped, which means "ask again").

Tokens are bearer secrets. They never show up in ``Decision.to_dict()`` or in
a repr, so they don't leak into logs by accident.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, FrozenSet, Mapping, Optional, Protocol, Tuple

DEFAULT_TTL_SECONDS = 300.0
DEFAULT_MAX_PENDING = 1024


def fingerprint(args: Mapping[str, Any]) -> str:
    """Stable digest of the arg values.

    Anything that isn't plain JSON gets a typed repr. If a value's repr isn't
    stable between two calls, the fingerprints won't match and the gate
    denies, which is the safe way round.
    """
    blob = json.dumps(args, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=_fallback)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _fallback(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes__": bytes(value).hex()}
    if isinstance(value, (set, frozenset)):
        return {"__set__": sorted(repr(v) for v in value)}
    return {"__repr__": f"{type(value).__module__}.{type(value).__qualname__}:{value!r}"}


@dataclass(frozen=True)
class Binding:
    call_id: str
    tool: str
    caller: Tuple[str, str]
    destination: Optional[str]
    args_digest: str


@dataclass(frozen=True)
class _Pending:
    binding: Binding
    confirmed_args: FrozenSet[str]
    expires_at: float


class Redemption:
    """Result of trying to use a token. Exactly one of the three flags is set."""

    __slots__ = ("ok", "invalid", "mismatch", "confirmed_args", "call_id")

    def __init__(self, *, ok=False, invalid=False, mismatch=False, confirmed_args=frozenset(), call_id=None):
        self.ok = ok
        self.invalid = invalid
        self.mismatch = mismatch
        self.confirmed_args = confirmed_args
        self.call_id = call_id


class PendingBackend(Protocol):
    """Where pending tokens live. The default keeps them in memory, which is
    fine for one process. For several workers, back it with a shared store.
    ``take`` must read and delete in one atomic step (Redis ``GETDEL``, or
    ``DELETE ... RETURNING`` in SQL), or a token could be used twice.
    """

    def put(self, token: str, record: str, ttl_seconds: float) -> None: ...

    def take(self, token: str) -> Optional[str]: ...

    def drop(self, token: str) -> bool: ...


class MemoryBackend:
    """In-process, bounded. The oldest pending token goes first when it's full."""

    def __init__(self, max_pending: int = DEFAULT_MAX_PENDING) -> None:
        if max_pending <= 0:
            raise ValueError("max_pending must be positive.")
        self._max = int(max_pending)
        self._items: "OrderedDict[str, str]" = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def put(self, token: str, record: str, ttl_seconds: float) -> None:
        with self._lock:
            while len(self._items) >= self._max:
                self._items.popitem(last=False)
            self._items[token] = record

    def take(self, token: str) -> Optional[str]:
        with self._lock:
            return self._items.pop(token, None)

    def drop(self, token: str) -> bool:
        with self._lock:
            return self._items.pop(token, None) is not None

    def sweep(self, expired: Callable[[str], bool]) -> None:
        with self._lock:
            for t in [t for t, rec in self._items.items() if expired(rec)]:
                del self._items[t]


class ConfirmationStore:
    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_pending: int = DEFAULT_MAX_PENDING,
        clock: Optional[Callable[[], float]] = None,
        new_token: Callable[[], str] = lambda: secrets.token_urlsafe(32),
        backend: Optional[PendingBackend] = None,
    ) -> None:
        """``backend`` defaults to memory. With a shared backend the clock
        defaults to wall time, since a monotonic clock means nothing to
        another process."""
        if ttl_seconds <= 0 or max_pending <= 0:
            raise ValueError("ttl_seconds and max_pending must be positive.")
        self._ttl = float(ttl_seconds)
        self._backend = backend if backend is not None else MemoryBackend(max_pending)
        self._clock = clock or (time.monotonic if backend is None else time.time)
        self._new_token = new_token

    def __len__(self) -> int:
        return len(self._backend) if hasattr(self._backend, "__len__") else 0

    def __bool__(self) -> bool:
        # An empty store is still a store. Without this, ``store or default``
        # would quietly swap a shared store for a fresh in-memory one.
        return True

    def issue(self, binding: Binding, confirmed_args: FrozenSet[str]) -> str:
        token = str(self._new_token())
        sweep = getattr(self._backend, "sweep", None)
        if sweep is not None:
            now = self._clock()
            sweep(lambda rec: _decode(rec).expires_at <= now)
        pending = _Pending(binding, frozenset(confirmed_args), self._clock() + self._ttl)
        self._backend.put(token, _encode(pending), self._ttl)
        return token

    def redeem(self, token: Any, binding_for: Callable[[str], Binding]) -> Redemption:
        """Burn the token and say whether it matches the call being made.

        ``binding_for(call_id)`` builds the binding of the current call. It gets
        the call id stored with the token, since the retry reuses the original id.
        """
        if not isinstance(token, str):
            return Redemption(invalid=True)
        record = self._backend.take(token)
        now = self._clock()
        try:
            pending = _decode(record) if record is not None else None
        except (ValueError, KeyError, TypeError):
            pending = None  # a garbled record is just an invalid token
        if pending is None or pending.expires_at <= now:
            return Redemption(invalid=True)
        if not secrets.compare_digest(_key(binding_for(pending.binding.call_id)), _key(pending.binding)):
            return Redemption(mismatch=True, call_id=pending.binding.call_id)
        return Redemption(ok=True, confirmed_args=pending.confirmed_args, call_id=pending.binding.call_id)

    def decline(self, token: Any) -> bool:
        """The person said no. Drops the token. Returns whether it was pending."""
        if not isinstance(token, str):
            return False
        return self._backend.drop(token)


def _encode(p: _Pending) -> str:
    b = p.binding
    return json.dumps({"call_id": b.call_id, "tool": b.tool, "caller": list(b.caller),
                       "destination": b.destination, "args_digest": b.args_digest,
                       "confirmed_args": sorted(p.confirmed_args), "expires_at": p.expires_at},
                      sort_keys=True, separators=(",", ":"))


def _decode(record: str) -> _Pending:
    d = json.loads(record)
    b = Binding(str(d["call_id"]), str(d["tool"]), (str(d["caller"][0]), str(d["caller"][1])),
                None if d["destination"] is None else str(d["destination"]), str(d["args_digest"]))
    return _Pending(b, frozenset(d["confirmed_args"]), float(d["expires_at"]))


def _key(b: Binding) -> str:
    return json.dumps([b.call_id, b.tool, list(b.caller), b.destination, b.args_digest], separators=(",", ":"))
