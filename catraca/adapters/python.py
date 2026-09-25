"""Decorator for plain Python functions.

    @guarded(gate, caller=lambda: current_caller())
    def send_email(to: str, body: str = "") -> None:
        ...

Every call binds its args by name (defaults included), asks the gate, and
only runs the function on ALLOW. ``CallDenied`` or ``ConfirmationRequired``
is raised otherwise, and the function never runs. Pass ``approve`` to handle
confirmation inline. Works for ``async def`` too.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, Optional, Tuple

from ..gate import Caller, Gate
from ._guard import Approve, aauthorise, authorise


def guarded(gate: Gate, *, caller: Callable[[], Caller], tool: Optional[str] = None,
            destination: Optional[str] = None,
            approve: Optional[Approve] = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
        # A functools.partial hides its pre-bound args from the signature, so
        # unwrap it and check the call the underlying function really gets.
        base: Any = fn
        pre_args: Tuple[Any, ...] = ()
        pre_kwargs: Dict[str, Any] = {}
        while isinstance(base, functools.partial):
            pre_args = tuple(base.args) + pre_args
            pre_kwargs = {**base.keywords, **pre_kwargs}
            base = base.func
        sig = inspect.signature(base)
        name = tool or getattr(base, "__name__", None) or repr(base)
        if any(p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in sig.parameters.values()):
            raise TypeError(f"{name}: *args/**kwargs can't be checked arg by arg, give it named params.")

        def bound(args, kwargs):
            b = sig.bind(*pre_args, *args, **{**pre_kwargs, **kwargs})
            b.apply_defaults()
            return dict(b.arguments)

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                await aauthorise(gate, name, bound(args, kwargs), caller=caller(), destination=destination,
                                 approve=approve)
                return await fn(*args, **kwargs)
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            authorise(gate, name, bound(args, kwargs), caller=caller(), destination=destination, approve=approve)
            return fn(*args, **kwargs)
        return wrapper
    return wrap
