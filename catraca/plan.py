"""Mode A, the sealed plan.

Mode B (the registry) reduces risk. Mode A gives a structural guarantee:
untrusted content can't change which tools run, in which order, or where
anything goes. It's the Plan-Then-Execute and Dual-LLM patterns, done so the
guarantee comes from how the code is built rather than from the model behaving.

How it works:

1. A plan is made from trusted input only (the user's request and the tool
   list). Nothing retrieved has been read yet. Each step names a tool and gives
   every arg as an expression:

   * ``lit(value)`` a literal, fixed now. Trusted.
   * ``ref(step, *path)`` the output of an earlier step. Untrusted.
   * ``ask(instruction, source, schema)`` a value pulled out of untrusted data
     by the *quarantine*: a model call that sees the data but can't call tools,
     and whose answer must fit ``schema``. Untrusted.
   * ``confirm(expr)`` a value the person has to approve before it's used.
     Once approved it counts as trusted, with origin ``confirmed-by-user``.

2. Consequential args (everything the policy doesn't relax) must be ``lit`` or
   ``confirm(...)``. So destinations are fixed before any untrusted content is
   read, or a human signs them off. Building a plan that breaks this fails.

3. ``plan.seal(key)`` freezes it: a canonical encoding, its SHA-256 and an HMAC.
   The runner works from its own decoded copy of the sealed bytes, checks the
   HMAC before starting and the digest before every step, and has no way back
   to the planner. There's no replanning after data comes in.

4. Every step still goes through the gate, in mode A: labels come from the
   edges above, then policy, egress and evidence run as usual.

Limits, stated up front: plans are straight-line (no loops or branches that
depend on data), so an agent that needs to decide its next action from what it
just read doesn't fit mode A. That's the price, and the CaMeL numbers (77% of
AgentDojo tasks with the guarantee against 84% without) are the yardstick. Side
channels (how many steps ran, timing, whether a step failed) aren't covered.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .errors import CallDenied, CatracaError
from .gate import Caller, Decision, EdgeLabel, Gate, Verdict
from .labels import Integrity, Label

PLAN_VERSION = 1
_TOOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
_ARG_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
TRUSTED = Label(Integrity.TRUSTED)
UNTRUSTED = Label(Integrity.UNTRUSTED)


class PlanError(CatracaError, ValueError):
    """The plan breaks a mode A rule. It never gets sealed."""


class PlanTampered(CatracaError):
    """The sealed plan changed after sealing, or the seal doesn't check out."""


class QuarantineError(CatracaError):
    """The quarantine's answer didn't fit the schema. The run stops there."""


# ---- schemas for quarantine answers ----------------------------------------------


@dataclass(frozen=True)
class Schema:
    """What a quarantine answer is allowed to look like. Narrow is good."""

    kind: str  # "text", "enum", "number", "integer", "boolean", "pattern"
    max_length: int = 2000
    values: Tuple[str, ...] = ()
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    pattern: str = ""

    @staticmethod
    def text(max_length: int = 2000) -> "Schema":
        return Schema("text", max_length=max_length)

    @staticmethod
    def enum(*values: str) -> "Schema":
        if not values:
            raise PlanError("enum needs at least one value.")
        return Schema("enum", values=tuple(values))

    @staticmethod
    def number(minimum: Optional[float] = None, maximum: Optional[float] = None) -> "Schema":
        return Schema("number", minimum=minimum, maximum=maximum)

    @staticmethod
    def integer(minimum: Optional[int] = None, maximum: Optional[int] = None) -> "Schema":
        return Schema("integer", minimum=minimum, maximum=maximum)

    @staticmethod
    def boolean() -> "Schema":
        return Schema("boolean")

    @staticmethod
    def matching(pattern: str, max_length: int = 256) -> "Schema":
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PlanError(f"bad pattern: {exc}") from None
        return Schema("pattern", pattern=pattern, max_length=max_length)

    def check(self, value: Any) -> Any:
        k = self.kind
        if k in ("text", "pattern", "enum"):
            if not isinstance(value, str):
                raise QuarantineError(f"expected a string, got {type(value).__name__}")
            if k == "enum":
                if value not in self.values:
                    raise QuarantineError("answer isn't one of the allowed values")
                return value
            if len(value) > self.max_length:
                raise QuarantineError(f"answer is longer than {self.max_length} chars")
            if k == "pattern" and not re.fullmatch(self.pattern, value):
                raise QuarantineError("answer doesn't match the pattern")
            return value
        if k == "boolean":
            if not isinstance(value, bool):
                raise QuarantineError("expected true or false")
            return value
        if k in ("number", "integer"):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise QuarantineError("expected a number")
            if not math.isfinite(value):
                raise QuarantineError("expected a finite number")
            if k == "integer" and not float(value).is_integer():
                raise QuarantineError("expected a whole number")
            if self.minimum is not None and value < self.minimum:
                raise QuarantineError("answer is below the minimum")
            if self.maximum is not None and value > self.maximum:
                raise QuarantineError("answer is above the maximum")
            return int(value) if k == "integer" else value
        raise QuarantineError(f"unknown schema kind {k!r}")

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {"kind": self.kind}
        if self.kind in ("text", "pattern"):
            d["max_length"] = self.max_length
        if self.values:
            d["values"] = list(self.values)
        if self.minimum is not None:
            d["minimum"] = self.minimum
        if self.maximum is not None:
            d["maximum"] = self.maximum
        if self.pattern:
            d["pattern"] = self.pattern
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Schema":
        if not isinstance(d, Mapping) or d.get("kind") not in ("text", "enum", "number", "integer", "boolean",
                                                               "pattern"):
            raise PlanError(f"bad schema {d!r}")
        extra = set(d) - {"kind", "max_length", "values", "minimum", "maximum", "pattern"}
        if extra:
            raise PlanError(f"unknown schema keys {sorted(extra)}")
        s = Schema(d["kind"], int(d.get("max_length", 2000)), tuple(d.get("values", ())),
                   d.get("minimum"), d.get("maximum"), d.get("pattern", ""))
        if s.kind == "enum" and not s.values:
            raise PlanError("enum needs values")
        if s.kind == "pattern":
            Schema.matching(s.pattern, s.max_length)
        return s


# ---- expressions -----------------------------------------------------------------


@dataclass(frozen=True)
class Lit:
    value: Any


@dataclass(frozen=True)
class Ref:
    step: int
    path: Tuple[Union[str, int], ...] = ()


@dataclass(frozen=True)
class Ask:
    instruction: str
    source: Union[Ref, Lit]
    schema: Schema


@dataclass(frozen=True)
class Confirm:
    inner: Union[Ref, Ask]


Expr = Union[Lit, Ref, Ask, Confirm]


def lit(value: Any) -> Lit:
    json.dumps(value)  # literals must be plain JSON
    return Lit(value)


def ref(step: int, *path: Union[str, int]) -> Ref:
    return Ref(step, tuple(path))


def ask(instruction: str, source: Union[Ref, Lit], schema: Schema = Schema.text()) -> Ask:
    return Ask(instruction, source, schema)


def confirm(inner: Union[Ref, Ask]) -> Confirm:
    return Confirm(inner)


def _expr_to_json(e: Expr) -> Any:
    if isinstance(e, Lit):
        return {"lit": e.value}
    if isinstance(e, Ref):
        return {"ref": e.step, "path": list(e.path)}
    if isinstance(e, Ask):
        return {"ask": e.instruction, "source": _expr_to_json(e.source), "schema": e.schema.to_dict()}
    if isinstance(e, Confirm):
        return {"confirm": _expr_to_json(e.inner)}
    raise PlanError(f"not a plan expression: {e!r}")


def _expr_from_json(d: Any) -> Expr:
    if not isinstance(d, Mapping) or len(set(d) & {"lit", "ref", "ask", "confirm"}) != 1:
        raise PlanError(f"bad expression {d!r}")
    if "lit" in d:
        if set(d) != {"lit"}:
            raise PlanError("lit takes nothing else")
        return lit(d["lit"])
    if "ref" in d:
        if set(d) - {"ref", "path"} or not isinstance(d["ref"], int) or isinstance(d["ref"], bool):
            raise PlanError(f"bad ref {d!r}")
        path = d.get("path", [])
        if not isinstance(path, list) or not all(isinstance(p, (str, int)) and not isinstance(p, bool)
                                                  for p in path):
            raise PlanError("ref path must be a list of keys and indexes")
        return Ref(d["ref"], tuple(path))
    if "ask" in d:
        if set(d) - {"ask", "source", "schema"} or not isinstance(d["ask"], str):
            raise PlanError(f"bad ask {d!r}")
        src = _expr_from_json(d.get("source"))
        if not isinstance(src, (Ref, Lit)):
            raise PlanError("ask's source must be a ref or a lit")
        return Ask(d["ask"], src, Schema.from_dict(d.get("schema", {"kind": "text"})))
    if set(d) != {"confirm"}:
        raise PlanError("confirm takes nothing else")
    inner = _expr_from_json(d["confirm"])
    if not isinstance(inner, (Ref, Ask)):
        raise PlanError("confirm wraps a ref or an ask")
    return Confirm(inner)


def _refs(e: Expr) -> List[Ref]:
    if isinstance(e, Ref):
        return [e]
    if isinstance(e, Ask):
        return _refs(e.source)
    if isinstance(e, Confirm):
        return _refs(e.inner)
    return []


# ---- the plan ----------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    tool: str
    args: Mapping[str, Expr] = field(default_factory=dict)
    destination: Optional[str] = None


class Plan:
    """A plan that's been checked against the mode A rules. Seal it to run it."""

    def __init__(self, steps: Sequence[Step], *, policy: Any, request: str = "") -> None:
        self.steps: Tuple[Step, ...] = tuple(steps)
        self.request = request
        self._policy = policy
        _validate(self.steps, policy)

    @classmethod
    def from_json(cls, data: Any, *, policy: Any, request: str = "") -> "Plan":
        """Build from a planner's JSON answer: ``{"steps": [{"tool", "args", "destination"?}]}``."""
        if isinstance(data, (str, bytes)):
            try:
                data = json.loads(data)
            except json.JSONDecodeError as exc:
                raise PlanError(f"plan isn't valid JSON: {exc}") from None
        if not isinstance(data, Mapping) or set(data) - {"steps"} or not isinstance(data.get("steps"), list):
            raise PlanError("a plan is {\"steps\": [...]}")
        steps = []
        for i, st in enumerate(data["steps"]):
            if not isinstance(st, Mapping) or set(st) - {"tool", "args", "destination"}:
                raise PlanError(f"step {i}: bad step")
            args = st.get("args", {})
            if not isinstance(args, Mapping):
                raise PlanError(f"step {i}: args must be an object")
            dest = st.get("destination")
            if dest is not None and not isinstance(dest, str):
                raise PlanError(f"step {i}: destination must be a string")
            steps.append(Step(st.get("tool"), {k: _expr_from_json(v) for k, v in args.items()}, dest))
        return cls(steps, policy=policy, request=request)

    def to_json(self) -> dict:
        return {"steps": [
            {"tool": s.tool, "args": {k: _expr_to_json(v) for k, v in sorted(s.args.items())},
             **({"destination": s.destination} if s.destination is not None else {})}
            for s in self.steps]}

    def seal(self, key: bytes) -> "SealedPlan":
        """Freeze the plan. Give the runner the same key, and keep it away from
        anything that handles untrusted content."""
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise PlanError("seal key must be at least 16 bytes.")
        # Steps are plain objects and could have been edited since the plan was
        # built, so check again right before sealing.
        _validate(self.steps, self._policy)
        body = json.dumps({"v": PLAN_VERSION, "request": self.request, **self.to_json()},
                          sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(body).hexdigest()
        mac = hmac.new(bytes(key), body, hashlib.sha256).hexdigest()
        return SealedPlan(body, digest, mac)


def _validate(steps: Tuple[Step, ...], policy: Any) -> None:
    if not steps:
        raise PlanError("a plan needs at least one step.")
    for i, st in enumerate(steps):
        if not isinstance(st, Step) or not isinstance(st.tool, str) or not _TOOL_RE.match(st.tool):
            raise PlanError(f"step {i}: bad tool name")
        relaxed = set(policy.relaxed_args(st.tool))
        for name, e in st.args.items():
            if not isinstance(name, str) or not _ARG_RE.match(name):
                raise PlanError(f"step {i}: bad arg name {name!r}")
            _expr_to_json(e)  # rejects anything that isn't a plan expression
            for r in _refs(e):
                if not 0 <= r.step < i:
                    raise PlanError(f"step {i}.{name}: can only refer to an earlier step, not {r.step}")
            if name not in relaxed and not isinstance(e, (Lit, Confirm)):
                raise PlanError(
                    f"step {i}.{name} is consequential, so it must be fixed now (lit) or approved by the "
                    f"person (confirm). Data read later can't pick where things go.")


@dataclass(frozen=True)
class SealedPlan:
    body: bytes
    digest: str
    mac: str

    @property
    def plan_id(self) -> str:
        return self.digest[:16]


# ---- running it --------------------------------------------------------------------


@dataclass(frozen=True)
class StepRecord:
    index: int
    tool: str
    decision: Decision
    ran: bool


@dataclass
class RunResult:
    status: str  # "done", "denied", "declined", "quarantine_error", "tool_error"
    steps: List[StepRecord]
    outputs: List[Any]
    stopped_at: Optional[int] = None
    detail: str = ""

    @property
    def tools_run(self) -> List[str]:
        return [s.tool for s in self.steps if s.ran]


Quarantine = Callable[[str, Any, Schema], Any]
"""``quarantine(instruction, data, schema) -> value``. A model call with no tools."""

Approver = Callable[[int, str, Any], bool]
"""``approve(step, arg, value) -> bool``. Shows the literal value to the person."""


class PlanRunner:
    def __init__(self, gate: Gate, tools: Mapping[str, Callable[..., Any]], *, caller: Caller, seal_key: bytes,
                 quarantine: Optional[Quarantine] = None, approve: Optional[Approver] = None) -> None:
        if not isinstance(seal_key, (bytes, bytearray)) or len(seal_key) < 16:
            raise PlanError("seal_key must be at least 16 bytes.")
        self._key = bytes(seal_key)
        self._gate = gate
        self._tools = dict(tools)
        self._caller = caller
        self._quarantine = quarantine
        self._approve = approve

    def run(self, sealed: SealedPlan) -> RunResult:
        _check_seal(sealed, self._key)
        data = json.loads(sealed.body.decode("utf-8"))
        steps = [(st["tool"], {k: _expr_from_json(v) for k, v in st["args"].items()}, st.get("destination"))
                 for st in data["steps"]]
        # The seal proves who wrote the plan, not that it's well formed. Check
        # the consequential-arg rule against the gate's own policy too.
        _validate(tuple(Step(t, a, d) for t, a, d in steps), self._gate._policy)
        outputs: List[Any] = []
        records: List[StepRecord] = []
        for i, (tool, args, destination) in enumerate(steps):
            _check_seal(sealed, self._key)  # before every step, not just once
            try:
                values, edges = self._resolve(i, tool, args, outputs)
            except QuarantineError as exc:
                return RunResult("quarantine_error", records, outputs, i, str(exc))
            except _Declined as exc:
                return RunResult("declined", records, outputs, i, str(exc))
            decision = self._gate.decide(tool, values, caller=self._caller, destination=destination,
                                         call_id=f"{sealed.plan_id}:{i}", labels=edges)
            if decision.verdict is not Verdict.ALLOW:
                records.append(StepRecord(i, tool, decision, False))
                return RunResult("denied", records, outputs, i, decision.reason.value)
            fn = self._tools.get(tool)
            if fn is None:
                records.append(StepRecord(i, tool, decision, False))
                return RunResult("tool_error", records, outputs, i, f"no implementation for {tool!r}")
            try:
                out = fn(**values)
            except Exception as exc:
                records.append(StepRecord(i, tool, decision, False))
                return RunResult("tool_error", records, outputs, i, type(exc).__name__)
            records.append(StepRecord(i, tool, decision, True))
            outputs.append(out)
        return RunResult("done", records, outputs)

    def _resolve(self, i: int, tool: str, args: Mapping[str, Expr], outputs: List[Any]):
        values: Dict[str, Any] = {}
        edges: Dict[str, EdgeLabel] = {}
        for name, e in sorted(args.items()):
            value, edge = self._eval(i, name, e, outputs)
            values[name], edges[name] = value, edge
        return values, edges

    def _eval(self, i: int, name: str, e: Expr, outputs: List[Any]) -> Tuple[Any, EdgeLabel]:
        if isinstance(e, Lit):
            return e.value, EdgeLabel(TRUSTED, "plan")
        if isinstance(e, Ref):
            return _follow(outputs[e.step], e.path), EdgeLabel(UNTRUSTED, f"step:{e.step}")
        if isinstance(e, Ask):
            if self._quarantine is None:
                raise QuarantineError("the plan asks the quarantine, but no quarantine was given")
            data, _ = self._eval(i, name, e.source, outputs)
            answer = e.schema.check(self._quarantine(e.instruction, data, e.schema))
            return answer, EdgeLabel(UNTRUSTED, f"quarantine:{i}.{name}")
        if isinstance(e, Confirm):
            value, _ = self._eval(i, name, e.inner, outputs)
            if self._approve is None or self._approve(i, name, value) is not True:
                raise _Declined(f"step {i}.{name} wasn't approved")
            return value, EdgeLabel(TRUSTED, "confirmed-by-user")
        raise PlanError(f"not a plan expression: {e!r}")


class _Declined(Exception):
    pass


def _check_seal(sealed: SealedPlan, key: bytes) -> None:
    if not isinstance(sealed, SealedPlan):
        raise PlanTampered("not a sealed plan")
    if hashlib.sha256(sealed.body).hexdigest() != sealed.digest:
        raise PlanTampered("the plan changed after it was sealed")
    if not hmac.compare_digest(hmac.new(key, sealed.body, hashlib.sha256).hexdigest(), sealed.mac):
        raise PlanTampered("the seal doesn't check out")


def _follow(value: Any, path: Tuple[Union[str, int], ...]) -> Any:
    cur = value
    for p in path:
        try:
            cur = cur[p]
        except (KeyError, IndexError, TypeError):
            raise QuarantineError(f"step output has no {p!r}") from None
    return cur


def plan_with(planner: Callable[[str, List[dict]], Any], request: str, *, policy: Any,
              tools: Sequence[Mapping[str, Any]]) -> Plan:
    """Ask a planner (a model call) for a plan. It only ever sees ``request``
    and the tool list, never retrieved content, so it can't be injected."""
    return Plan.from_json(planner(request, [dict(t) for t in tools]), policy=policy, request=request)


__all__ = ["Plan", "PlanError", "PlanRunner", "PlanTampered", "QuarantineError", "RunResult", "Schema",
           "SealedPlan", "Step", "StepRecord", "ask", "confirm", "lit", "plan_with", "ref", "CallDenied"]
