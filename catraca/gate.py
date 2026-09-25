"""The gate. This is the decision point.

It takes a call intent (tool + args), builds a decision request with the
provenance of every arg, asks the policy, and hands back a verdict. Three
verdicts, not two: ALLOW, DENY and REQUIRE_CONFIRMATION. The return type
deliberately isn't a bool, and ``Decision`` refuses to be used as one, so
callers can't quietly read "needs confirmation" as "go ahead".

Fail closed by construction: anything that goes wrong inside the gate, or a
policy that returns rubbish, ends up as DENY. There's exactly one place that
can return ALLOW, and it's only reached after the policy result's been checked.

Confirmation is a round trip. REQUIRE_CONFIRMATION comes with a single-use
token bound to the call id, tool, caller, destination and a fingerprint of the
arg values (see ``confirmations``). Once the person says yes, call ``decide``
again with the same call and ``confirmation=token``. The gate re-evaluates from
scratch against the current window, and only if it still lands on the same
coincidence, for the same args the person saw, does it turn into ALLOW with
reason CONFIRMED_BY_USER. Anything else is a deny.

After the policy, the egress gate (``catraca.egress``) digs every
destination out of the args, including ones hidden in free text, and checks
each against its allowlist and its provenance. With no egress config, any
destination at all denies the call.

Every arg is consequential (the whole-match rule) unless the policy lists
it in ``relaxed_args``. Forgetting to declare something makes it stricter,
never looser. The policy itself lives in ``catraca.policy``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import logging
import threading
import time
import uuid
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Protocol, Tuple, runtime_checkable

from .confirmations import DEFAULT_MAX_PENDING, DEFAULT_TTL_SECONDS, Binding, ConfirmationStore, fingerprint
from .egress import Egress, Target
from .errors import CallDenied, ConfirmationRequired
from .labels import Integrity, Label
from .registry import ContextRegistry, Resolution, Rule

_NO_EVIDENCE = object()


class Verdict(enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


class Reason(enum.Enum):
    """Stable, machine-readable reason codes. Don't rename these, add new ones."""

    ALLOWED_BY_POLICY = "ALLOWED_BY_POLICY"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    UNTRUSTED_ARGUMENT = "UNTRUSTED_ARGUMENT"
    COINCIDENCE = "COINCIDENCE"
    NO_POLICY_MATCH = "NO_POLICY_MATCH"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INVALID_POLICY_RESULT = "INVALID_POLICY_RESULT"
    CONFIRMATION_NOT_ELIGIBLE = "CONFIRMATION_NOT_ELIGIBLE"
    CONFIRMED_BY_USER = "CONFIRMED_BY_USER"
    CONFIRMATION_INVALID = "CONFIRMATION_INVALID"
    CONFIRMATION_MISMATCH = "CONFIRMATION_MISMATCH"
    CALLER_NOT_ALLOWED = "CALLER_NOT_ALLOWED"
    UNDECLARED_ARGUMENT = "UNDECLARED_ARGUMENT"
    ARGUMENT_CONSTRAINT = "ARGUMENT_CONSTRAINT"
    CONFIDENTIALITY_VIOLATION = "CONFIDENTIALITY_VIOLATION"
    DESTINATION_NOT_ALLOWED = "DESTINATION_NOT_ALLOWED"
    EGRESS_NOT_ALLOWED = "EGRESS_NOT_ALLOWED"
    EGRESS_BAD_SCHEME = "EGRESS_BAD_SCHEME"
    EGRESS_IP_LITERAL = "EGRESS_IP_LITERAL"
    EGRESS_PRIVATE_NETWORK = "EGRESS_PRIVATE_NETWORK"
    EGRESS_UNTRUSTED = "EGRESS_UNTRUSTED"
    EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"


@dataclass(frozen=True)
class EdgeLabel:
    """Mode A: a label fixed where a value entered the plan, plus where that was."""

    label: Label
    origin: str


@dataclass(frozen=True)
class Caller:
    tenant: str
    user: str

    def to_dict(self) -> dict:
        return {"tenant": self.tenant, "user": self.user}


@dataclass(frozen=True)
class ArgProvenance:
    name: str
    value: Any
    consequential: bool
    resolution: Resolution

    @property
    def label(self) -> Label:
        return self.resolution.label

    def to_dict(self, *, include_values: bool = False) -> dict:
        """Values stay out by default, so a dump of a request can't leak them
        into a log. ``include_values=True`` puts them back for debugging."""
        out = {
            "name": self.name,
            "consequential": self.consequential,
            "resolution": self.resolution.to_dict(),
        }
        if include_values:
            out["value"] = self.value
        return out


@dataclass(frozen=True)
class DecisionRequest:
    call_id: str
    turn: int
    caller: Caller
    tool: str
    args: Tuple[ArgProvenance, ...]
    destination: Optional[str]
    context: Mapping[str, Any]
    mode: str = "B"
    targets: Tuple[Tuple[Target, Resolution], ...] = ()
    """Egress targets found in the call, each with its provenance."""

    def arg(self, name: str) -> ArgProvenance:
        for a in self.args:
            if a.name == name:
                return a
        raise KeyError(name)

    def to_dict(self, *, include_values: bool = False) -> dict:
        return {
            "call_id": self.call_id,
            "turn": self.turn,
            "caller": self.caller.to_dict(),
            "tool": self.tool,
            "args": [a.to_dict(include_values=include_values) for a in self.args],
            "destination": self.destination,
            "context": dict(self.context),
            "mode": self.mode,
            "targets": [dict(t.to_dict(), integrity=r.label.integrity.name) for t, r in self.targets],
        }


@dataclass(frozen=True)
class PolicyResult:
    verdict: Verdict
    reason: Reason
    rule_id: str
    arguments: Tuple[str, ...] = ()
    """Args the result is about, e.g. the ones that need confirming."""


@runtime_checkable
class Policy(Protocol):
    def relaxed_args(self, tool: str) -> Iterable[str]:
        """Args that may be resolved with partial cover. Everything else gets
        the whole-match rule. Return () when in doubt."""

    def evaluate(self, request: DecisionRequest) -> PolicyResult:
        ...


@dataclass(frozen=True)
class Confirmation:
    """What to show a person before they say yes."""

    argument: str
    value: Any
    trusted_origins: Tuple[str, ...]

    def to_dict(self) -> dict:
        return {"argument": self.argument, "value": self.value, "trusted_origins": list(self.trusted_origins)}


@dataclass(frozen=True)
class Decision:
    call_id: str
    tool: str
    verdict: Verdict
    reason: Reason
    rule_id: str
    elapsed_us: int
    confirmation: Tuple[Confirmation, ...] = ()
    request: Optional[DecisionRequest] = field(default=None, compare=False, repr=False)
    detail: str = ""
    confirmation_token: Optional[str] = field(default=None, compare=False, repr=False)
    """Only set on REQUIRE_CONFIRMATION. A bearer secret, so it's kept out of
    ``to_dict`` and repr on purpose."""
    flagged: Tuple[str, ...] = ()
    """Args the policy pointed at when it said no (or asked for confirmation)."""

    def __bool__(self) -> bool:
        raise TypeError(
            "a Decision isn't a bool. Check decision.verdict against Verdict.ALLOW, "
            "Verdict.DENY and Verdict.REQUIRE_CONFIRMATION, and handle all three."
        )

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "tool": self.tool,
            "verdict": self.verdict.value,
            "reason": self.reason.value,
            "rule_id": self.rule_id,
            "elapsed_us": self.elapsed_us,
            "confirmation": [c.to_dict() for c in self.confirmation],
            "detail": self.detail,
            "flagged": list(self.flagged),
        }


_log = logging.getLogger("catraca")
_log.addHandler(logging.NullHandler())  # the app decides where logs go


class Gate:
    def __init__(
        self,
        registry: ContextRegistry,
        policy: Policy,
        *,
        clock: Callable[[], int] = time.perf_counter_ns,
        new_call_id: Callable[[], str] = lambda: uuid.uuid4().hex,
        confirmations: Optional[ConfirmationStore] = None,
        egress: Optional[Egress] = None,
        evidence: Any = _NO_EVIDENCE,
        confirmation_ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_pending_confirmations: int = DEFAULT_MAX_PENDING,
        on_decision: Optional[Callable[["Decision"], None]] = None,
    ) -> None:
        """``on_decision`` is called with every final decision, after it's
        recorded: feed it to your metrics or alerting. It can't change the
        verdict, and if it raises the error is logged and ignored."""
        self._registry = registry
        self._on_decision = on_decision
        self._counts: Dict[str, int] = {}
        self._counts_lock = threading.Lock()
        self._policy = policy
        self._clock = clock
        self._new_call_id = new_call_id
        self._egress = egress if egress is not None else Egress.strict()
        if evidence is _NO_EVIDENCE:
            warnings.warn(
                "Gate built without an evidence log, so decisions aren't being recorded. "
                "Pass evidence=EvidenceLog(...) or, if you really mean it, evidence=None.",
                RuntimeWarning, stacklevel=2)
            evidence = None
        if evidence is not None and not callable(getattr(evidence, "record", None)):
            # A sink passed straight in would deny every call as
            # EVIDENCE_UNAVAILABLE. Say so now instead.
            raise TypeError(f"evidence must be an EvidenceLog (or have record()), got {type(evidence).__name__}. "
                            "Wrap a sink like this: evidence=EvidenceLog(sink).")
        self._evidence = evidence
        self._confirmations = confirmations if confirmations is not None else ConfirmationStore(
            ttl_seconds=confirmation_ttl_seconds, max_pending=max_pending_confirmations
        )

    # ---- public API ------------------------------------------------------
    def decide(
        self,
        tool: str,
        args: Mapping[str, Any],
        *,
        caller: Caller,
        destination: Optional[str] = None,
        call_id: Optional[str] = None,
        confirmation: Optional[str] = None,
        labels: Optional[Mapping[str, "EdgeLabel"]] = None,
    ) -> Decision:
        """Always returns a Decision, never raises. Errors turn into DENY.

        ``labels`` is for mode A (sealed plan, ``catraca.plan``): each arg's
        label was assigned at the edge where the value came from, so the
        registry isn't consulted. Every arg must have one, or the call's denied.

        Pass ``confirmation`` (the token from an earlier REQUIRE_CONFIRMATION)
        once the person has said yes. The call must be identical to the one
        they confirmed.

        Every decision, including every denial, is written to the evidence
        log. If writing fails, the decision becomes a DENY with reason
        EVIDENCE_UNAVAILABLE: a call we can't account for doesn't go ahead.
        """
        decision = self._decide(tool, args, caller=caller, destination=destination,
                                call_id=call_id, confirmation=confirmation, labels=labels)
        if self._evidence is not None:
            try:
                self._evidence.record(decision, caller=caller)
            except Exception as exc:
                decision = Decision(decision.call_id, decision.tool, Verdict.DENY, Reason.EVIDENCE_UNAVAILABLE,
                                    "gate.evidence", decision.elapsed_us, (), decision.request,
                                    detail=type(exc).__name__)
        self._observe(decision)
        return decision

    def _observe(self, decision: Decision) -> None:
        with self._counts_lock:
            key = decision.reason.value
            self._counts[key] = self._counts.get(key, 0) + 1
        if decision.reason in (Reason.INTERNAL_ERROR, Reason.EVIDENCE_UNAVAILABLE, Reason.INVALID_POLICY_RESULT):
            # These mean the gate itself is unhealthy, not that a call was bad.
            _log.error("catraca gate: %s on %s (%s) %s", decision.reason.value, decision.tool,
                       decision.rule_id, decision.detail)
        if self._on_decision is not None:
            try:
                self._on_decision(decision)
            except Exception:
                _log.exception("catraca gate: on_decision hook raised, ignored")

    def counts(self) -> Dict[str, int]:
        """Decisions so far by reason code, e.g. for a metrics endpoint."""
        with self._counts_lock:
            return dict(self._counts)

    def _decide(self, tool: Any, args: Any, *, caller: Any, destination: Any, call_id: Any,
                confirmation: Any, labels: Any = None) -> Decision:
        started = self._now()
        cid = str(call_id) if call_id is not None else None
        tool_name = tool if isinstance(tool, str) else repr(tool)
        try:
            granted: Optional[frozenset] = None
            if confirmation is not None:
                redemption = self._confirmations.redeem(
                    confirmation,
                    lambda stored_id: self._binding(cid if cid is not None else stored_id, tool, caller,
                                                    destination, args),
                )
                cid = redemption.call_id if cid is None else cid
                if redemption.invalid:
                    return self._early_deny(cid, tool_name, Reason.CONFIRMATION_INVALID,
                                            "gate.confirmation_invalid", started)
                if redemption.mismatch:
                    return self._early_deny(cid, tool_name, Reason.CONFIRMATION_MISMATCH,
                                            "gate.confirmation_mismatch", started)
                granted = redemption.confirmed_args
            if cid is None:
                cid = self._safe_call_id()
            request = self._build_request(cid, tool, args, caller, destination, labels)
            result = self._policy.evaluate(request)
            return self._finish(request, result, started, granted, args)
        except Exception as exc:  # fail closed, whatever it was
            return Decision(
                cid if cid is not None else "unknown",
                tool_name,
                Verdict.DENY,
                Reason.INTERNAL_ERROR,
                "gate.fail_closed",
                self._elapsed(started),
                detail=type(exc).__name__,
            )

    async def adecide(self, tool: str, args: Mapping[str, Any], **kw: Any) -> Decision:
        """``decide`` for async code. Runs in a worker thread, because resolving
        long args is CPU work and holds the registry lock, and that shouldn't
        stall the event loop."""
        return await asyncio.to_thread(self.decide, tool, args, **kw)

    async def acheck(self, tool: str, args: Mapping[str, Any], **kw: Any) -> Decision:
        """``check`` for async code, see ``adecide``."""
        return await asyncio.to_thread(self.check, tool, args, **kw)

    def decline(self, token: str) -> bool:
        """The person said no. Drops the pending confirmation."""
        return self._confirmations.decline(token)

    def check(self, tool: str, args: Mapping[str, Any], **kw: Any) -> Decision:
        """Like ``decide`` but raises on anything other than ALLOW."""
        decision = self.decide(tool, args, **kw)
        if decision.verdict is Verdict.ALLOW:
            return decision
        if decision.verdict is Verdict.REQUIRE_CONFIRMATION:
            raise ConfirmationRequired(decision)
        raise CallDenied(decision)

    # ---- internals -------------------------------------------------------
    def _build_request(
        self, cid: str, tool: Any, args: Any, caller: Any, destination: Any, labels: Any = None
    ) -> DecisionRequest:
        if not isinstance(tool, str) or not tool:
            raise TypeError("tool must be a non-empty str")
        if not isinstance(args, Mapping) or not all(isinstance(k, str) for k in args):
            raise TypeError("args must be a mapping with str keys")
        if not isinstance(caller, Caller):
            raise TypeError("caller must be a Caller")
        if destination is not None and not isinstance(destination, str):
            raise TypeError("destination must be a str or None")

        relaxed = {r for r in self._policy.relaxed_args(tool) if isinstance(r, str)}
        cons = {name for name in args if name not in relaxed}
        if labels is not None:
            return self._build_edge_request(cid, tool, args, caller, destination, labels, cons)
        # One snapshot for args, window summary and turn, so a concurrent
        # annotate can't land between them.
        targets = self._egress.targets(tool, args, destination)
        settled_fn = getattr(self._policy, "settled_by_window", None)
        settled: Optional[Callable[[Label], Iterable[str]]] = None
        if callable(settled_fn):
            settled = lambda window_label: settled_fn(tool, caller, window_label)  # noqa: E731
        resolved, window, turn, target_res = self._registry.resolve_request(
            args, relaxed=relaxed, extra=[t.raw for t in targets], settled=settled)
        provenance = tuple(
            ArgProvenance(name, args[name], name in cons, resolved[name]) for name in sorted(args)
        )
        return DecisionRequest(cid, turn, caller, tool, provenance, destination, window,
                               targets=tuple(zip(targets, target_res, strict=True)))

    @staticmethod
    def _binding(call_id: str, tool: Any, caller: Any, destination: Any, args: Any) -> Binding:
        if not isinstance(caller, Caller) or not isinstance(args, Mapping):
            raise TypeError("bad caller or args")
        return Binding(str(call_id), str(tool), (caller.tenant, caller.user), destination, fingerprint(args))

    def _early_deny(self, cid: Optional[str], tool: str, reason: Reason, rule_id: str, started: int) -> Decision:
        return Decision(cid if cid is not None else "unknown", tool, Verdict.DENY, reason, rule_id,
                        self._elapsed(started))

    def _build_edge_request(self, cid: Any, tool: Any, args: Any, caller: Any, destination: Any,
                            labels: Any, cons: Any) -> DecisionRequest:
        if not isinstance(labels, Mapping) or set(labels) != set(args) \
                or not all(isinstance(v, EdgeLabel) for v in labels.values()):
            raise TypeError("mode A needs an EdgeLabel for every arg, and nothing else")

        def resolution(edge: "EdgeLabel") -> Resolution:
            trusted = edge.label.integrity is not Integrity.UNTRUSTED
            return Resolution(edge.label, Rule.EXACT if trusted else Rule.CONSERVATIVE, (), (edge.origin,),
                              1.0 if trusted else 0.0, (), False, (edge.origin,) if trusted else ())

        provenance = tuple(ArgProvenance(n, args[n], n in cons, resolution(labels[n])) for n in sorted(args))
        targets = self._egress.targets(tool, args, destination)
        # A target inside an arg carries that arg's edge label. The destination
        # field has no edge of its own, so it's untrusted unless it's a plain name.
        dest_label = EdgeLabel(Label(Integrity.UNTRUSTED), "destination")
        checked = tuple((t, resolution(labels.get(t.arg, dest_label))) for t in targets)
        window = {"mode": "A", "edges": sorted({e.origin for e in labels.values()})}
        return DecisionRequest(cid, 0, caller, tool, provenance, destination, window, mode="A", targets=checked)

    def _finish(
        self,
        request: DecisionRequest,
        result: Any,
        started: int,
        granted: Optional[frozenset] = None,
        args: Optional[Mapping[str, Any]] = None,
    ) -> Decision:
        if not isinstance(result, PolicyResult) or not isinstance(result.verdict, Verdict) \
                or not isinstance(result.reason, Reason):
            return self._deny(request, Reason.INVALID_POLICY_RESULT, "gate.invalid_policy_result", started)

        if result.verdict is Verdict.DENY:
            d = self._deny(request, result.reason, result.rule_id, started)
            return dataclasses.replace(d, flagged=tuple(a for a in result.arguments if isinstance(a, str)))

        reason, rule_id = result.reason, result.rule_id
        conf: Optional[Tuple[Confirmation, ...]] = None
        names: FrozenSet[str] = frozenset()
        if result.verdict is Verdict.REQUIRE_CONFIRMATION:
            conf = self._confirmation(request, result)
            if conf is None:
                return self._deny(request, Reason.CONFIRMATION_NOT_ELIGIBLE, "gate.confirmation_guard", started)
            names = frozenset(c.argument for c in conf)

        # The policy's happy, now check where things are going.
        failure = self._egress.check(request.tool, request.targets, confirming=names)
        if failure is not None:
            code, egress_rule, detail = failure
            return Decision(request.call_id, request.tool, Verdict.DENY, Reason(code), egress_rule,
                            self._elapsed(started), (), request, detail=detail)

        if result.verdict is Verdict.REQUIRE_CONFIRMATION:
            if granted is None:
                token = self._confirmations.issue(
                    self._binding(request.call_id, request.tool, request.caller, request.destination, args),
                    names,
                )
                return Decision(
                    request.call_id, request.tool, Verdict.REQUIRE_CONFIRMATION, reason,
                    rule_id, self._elapsed(started), conf or (), request, confirmation_token=token,
                )
            if not names <= granted:
                # Something now needs confirming that the person never saw.
                return self._deny(request, Reason.CONFIRMATION_MISMATCH, "gate.confirmation_scope", started)
            reason, rule_id = Reason.CONFIRMED_BY_USER, f"{rule_id}+confirmed"

        # The only ALLOW in the module.
        return Decision(
            request.call_id, request.tool, Verdict.ALLOW, reason,
            rule_id, self._elapsed(started), (), request,
        )

    def _confirmation(self, request: DecisionRequest, result: PolicyResult) -> Optional[Tuple[Confirmation, ...]]:
        """Confirmation is only on the table for a pure coincidence.

        Every arg the result points at (or, if it points at none, every
        consequential UNTRUSTED arg) has to be a coincidence. Otherwise it's a deny.
        """
        names = result.arguments or tuple(
            a.name for a in request.args if a.consequential and a.label.integrity is Integrity.UNTRUSTED
        )
        if not names:
            return None
        out = []
        for name in names:
            try:
                a = request.arg(name)
            except KeyError:
                return None
            if not a.resolution.only_coincidence or not a.resolution.trusted_origins:
                return None
            out.append(Confirmation(a.name, a.value, a.resolution.trusted_origins))
        return tuple(out)

    def _deny(self, request: DecisionRequest, reason: Reason, rule_id: str, started: int) -> Decision:
        return Decision(request.call_id, request.tool, Verdict.DENY, reason, rule_id, self._elapsed(started),
                        (), request)

    def _now(self) -> int:
        try:
            return int(self._clock())
        except Exception:
            return 0

    def _elapsed(self, started: int) -> int:
        try:
            return max(0, (int(self._clock()) - started) // 1000)
        except Exception:
            return -1

    def _safe_call_id(self) -> str:
        try:
            return str(self._new_call_id())
        except Exception:
            return "unknown"


__all__ = [
    "EdgeLabel",
    "ArgProvenance",
    "Caller",
    "Confirmation",
    "Decision",
    "DecisionRequest",
    "Gate",
    "Policy",
    "PolicyResult",
    "Reason",
    "Verdict",
]
