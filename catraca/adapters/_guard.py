"""The bit every adapter shares: ask the gate, handle confirmation, raise on no."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Mapping, Optional, Union

from ..errors import CallDenied, ConfirmationRequired
from ..gate import Caller, Decision, Gate, Verdict

Approve = Callable[[Decision], bool]
"""Shows ``decision.confirmation`` to the person and returns True only on an explicit yes."""


def authorise(gate: Gate, tool: str, args: Mapping[str, Any], *, caller: Caller,
              destination: Optional[str] = None, approve: Optional[Approve] = None) -> Decision:
    """Returns the ALLOW decision, or raises ``CallDenied``/``ConfirmationRequired``.

    On a yes, the call is decided again with the token rather than just let
    through. That's on purpose: the token is only good for the exact call it
    was issued for, and the second decision is what checks that.
    """
    decision = gate.decide(tool, args, caller=caller, destination=destination)
    if decision.verdict is Verdict.ALLOW:
        return decision
    if decision.verdict is Verdict.REQUIRE_CONFIRMATION:
        if approve is None:
            raise ConfirmationRequired(decision)
        if approve(decision) is not True:
            gate.decline(decision.confirmation_token)
            raise CallDenied(decision)
        second = gate.decide(tool, args, caller=caller, destination=destination, call_id=decision.call_id,
                             confirmation=decision.confirmation_token)
        if second.verdict is Verdict.ALLOW:
            return second
        raise CallDenied(second)
    raise CallDenied(decision)


async def aauthorise(gate: Gate, tool: str, args: Mapping[str, Any], *, caller: Caller,
                     destination: Optional[str] = None,
                     approve: Optional[Callable[[Decision], Union[bool, Awaitable[bool]]]] = None) -> Decision:
    """``authorise`` for async code. ``approve`` may be sync or async."""
    decision = await gate.adecide(tool, args, caller=caller, destination=destination)
    if decision.verdict is Verdict.ALLOW:
        return decision
    if decision.verdict is Verdict.REQUIRE_CONFIRMATION:
        if approve is None:
            raise ConfirmationRequired(decision)
        answer = approve(decision)
        if inspect.isawaitable(answer):
            answer = await answer
        if answer is not True:
            gate.decline(decision.confirmation_token)
            raise CallDenied(decision)
        second = await gate.adecide(tool, args, caller=caller, destination=destination, call_id=decision.call_id,
                                    confirmation=decision.confirmation_token)
        if second.verdict is Verdict.ALLOW:
            return second
        raise CallDenied(second)
    raise CallDenied(decision)
