"""The policy evaluator. Declarative, deterministic, no dependencies.

Every default here is the strict one. If you want something looser you have to
write it down, so reading the policy tells you exactly where it's been relaxed.

What you get without saying anything:

* A tool that isn't in the policy is denied.
* ``callers`` is required. There's no implicit "anyone".
* An arg the tool gets but the policy doesn't declare is denied.
* A declared arg must be TRUSTED and must match a single trusted snippet whole
  (``match: "whole"``). STRUCTURED, ANY and partial matching are opt-in.
* Every arg must be readable by the caller's tenant (``flow_to:
  ["tenant:{tenant}"]``).
* ``destination`` must be empty unless the tool lists allowed destinations.
* A coincidence is denied, not sent for confirmation. Confirmation is opt-in
  with ``confirm_on_coincidence: true``.

Format (JSON)::

    {
      "version": 1,
      "tools": {
        "send_email": {
          "callers": {"tenants": ["acme"], "users": "*"},
          "destinations": ["smtp"],
          "confirm_on_coincidence": true,
          "args": {
            "to":      {"pattern": "[^@]+@acme\\\\.com\\\\.br"},
            "subject": {"integrity": "ANY"},
            "body":    {"integrity": "ANY", "flow_to": ["tenant:{tenant}", "user:{user}"]}
          }
        }
      }
    }

``Policy.lint()`` points out the places where you've relaxed things on args
that look like destinations, by name and, if you pass some sample calls, by
value too. It doesn't block anything, it's for review.
"""

from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Pattern, Tuple, Union

from .errors import ConfigError
from .gate import DecisionRequest, PolicyResult, Reason, Verdict
from .labels import Integrity, check_scope

POLICY_VERSION = 1
_TOOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
_ARG_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_PLACEHOLDERS = {"tenant", "user"}
_TOOL_KEYS = {"callers", "args", "destinations", "confirm_on_coincidence", "description"}
_ARG_KEYS = {"integrity", "match", "flow_to", "one_of", "pattern", "type", "min", "max", "description"}
_TYPES = ("integer", "number", "boolean", "date")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_INTEGRITY_LEVELS = {"TRUSTED": Integrity.TRUSTED, "STRUCTURED": Integrity.STRUCTURED, "ANY": Integrity.UNTRUSTED}
_DEFAULT_FLOW_TO = ("tenant:{tenant}",)

# Values that usually mean "where it goes". Only used by lint.
_DESTINATION_VALUE = (
    ("an email address", re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")),
    ("a URL", re.compile(r"(?i)\b(?:https?|ftp|wss?|file|s3|gs)://|\bwww\.[a-z0-9-]+\.")),
    ("an IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b")),
    ("a file path", re.compile(r"(?:^|\s)(?:/[\w.-]+){2,}|\b[A-Za-z]:\\[\w.-]")),
    ("a phone number", re.compile(r"\+\d[\d\s().-]{7,}\d")),
)

# Names that usually mean "where it goes" or "who it's about". Only used by lint.
_DESTINATION_LIKE = re.compile(
    r"(^|_)(to|cc|bcc|recipients?|email|address|url|uri|link|href|path|file|filename|iban|account|"
    r"dest|destination|target|host|domain|phone|webhook|endpoint|channel|user_?id|owner)($|_)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ArgRule:
    name: str
    max_integrity: Integrity = Integrity.TRUSTED
    whole_match: bool = True
    flow_to: Tuple[str, ...] = _DEFAULT_FLOW_TO
    one_of: Optional[FrozenSet[str]] = None
    pattern: Optional[Pattern[str]] = field(default=None, compare=False)
    type: Optional[str] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None

    @property
    def relaxed(self) -> bool:
        """True if this arg is allowed partial cover in the registry."""
        return not self.whole_match or self.max_integrity is Integrity.UNTRUSTED


@dataclass(frozen=True)
class Callers:
    tenants: Optional[FrozenSet[str]]  # None means "*"
    users: Optional[FrozenSet[str]]

    def allows(self, tenant: str, user: str) -> bool:
        return (self.tenants is None or tenant in self.tenants) and (self.users is None or user in self.users)


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    callers: Callers
    args: Mapping[str, ArgRule]
    destinations: FrozenSet[str] = frozenset()
    confirm_on_coincidence: bool = False


@dataclass(frozen=True)
class LintWarning:
    tool: str
    arg: Optional[str]
    message: str

    def __str__(self) -> str:
        where = f"{self.tool}.{self.arg}" if self.arg else self.tool
        return f"{where}: {self.message}"


class DeclarativePolicy:
    """Implements the ``Policy`` protocol the gate expects."""

    def __init__(self, tools: Mapping[str, ToolPolicy]) -> None:
        self._tools: Dict[str, ToolPolicy] = dict(tools)

    # ---- loading --------------------------------------------------
    @classmethod
    def empty(cls) -> "DeclarativePolicy":
        """A policy with no tools. Denies everything."""
        return cls({})

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DeclarativePolicy":
        if not isinstance(data, Mapping):
            raise ConfigError("policy must be a JSON object.")
        _no_extra(data, {"version", "tools", "description"}, "policy")
        if data.get("version") != POLICY_VERSION:
            raise ConfigError(f"policy version must be {POLICY_VERSION}, got {data.get('version')!r}.")
        tools = data.get("tools", {})
        if not isinstance(tools, Mapping):
            raise ConfigError("'tools' must be an object mapping tool names to rules.")
        return cls({name: _parse_tool(name, spec) for name, spec in tools.items()})

    @classmethod
    def from_json(cls, text: str) -> "DeclarativePolicy":
        try:
            data = json.loads(text, object_pairs_hook=_no_dupes)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"policy isn't valid JSON: {exc}") from None
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "DeclarativePolicy":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    @property
    def tools(self) -> Tuple[str, ...]:
        return tuple(sorted(self._tools))

    # ---- Policy protocol ---------------------------------------------------
    def relaxed_args(self, tool: str) -> Iterable[str]:
        t = self._tools.get(tool)
        if t is None:
            return ()
        return tuple(name for name, rule in t.args.items() if rule.relaxed)

    def evaluate(self, request: DecisionRequest, *, constraints_ok=None, caller_ok=None) -> PolicyResult:
        """``constraints_ok(arg_rule, arg)`` and ``caller_ok(callers, caller)``
        override the value and caller checks. Only the evidence replay uses
        them, since it doesn't have the values or the real user ids."""
        check = constraints_ok or (lambda rule, a: _constraints_ok(rule, a.value))
        tool = self._tools.get(request.tool)
        if tool is None:
            return _deny(Reason.UNKNOWN_TOOL, "policy.unknown_tool")
        rid = f"policy.{tool.name}"

        caller_check = caller_ok or (lambda callers, c: callers.allows(c.tenant, c.user))
        if not caller_check(tool.callers, request.caller):
            return _deny(Reason.CALLER_NOT_ALLOWED, f"{rid}.callers")

        undeclared = sorted(a.name for a in request.args if a.name not in tool.args)
        if undeclared:
            return _deny(Reason.UNDECLARED_ARGUMENT, f"{rid}.undeclared", tuple(undeclared))

        if request.destination is not None and request.destination not in tool.destinations:
            return _deny(Reason.DESTINATION_NOT_ALLOWED, f"{rid}.destination")

        for a in request.args:
            if not check(tool.args[a.name], a):
                return _deny(Reason.ARGUMENT_CONSTRAINT, f"{rid}.args.{a.name}.constraint", (a.name,))

        to_confirm: List[str] = []
        for a in request.args:
            rule = tool.args[a.name]
            label = a.resolution.label
            for template in rule.flow_to:
                scope = template.format(tenant=request.caller.tenant, user=request.caller.user)
                if not label.confidentiality.may_flow_to(scope):
                    return _deny(Reason.CONFIDENTIALITY_VIOLATION, f"{rid}.args.{a.name}.flow_to", (a.name,))
            if label.integrity > rule.max_integrity:
                if tool.confirm_on_coincidence and a.resolution.only_coincidence:
                    to_confirm.append(a.name)
                    continue
                return _deny(Reason.UNTRUSTED_ARGUMENT, f"{rid}.args.{a.name}.integrity", (a.name,))

        if to_confirm:
            return PolicyResult(Verdict.REQUIRE_CONFIRMATION, Reason.COINCIDENCE, f"{rid}.coincidence",
                                tuple(to_confirm))
        return PolicyResult(Verdict.ALLOW, Reason.ALLOWED_BY_POLICY, rid)

    # ---- review ------------------------------------------------------------
    def lint(self, samples: Optional[Mapping[str, Iterable[Mapping[str, Any]]]] = None) -> List[LintWarning]:
        """Review warnings. ``samples`` maps a tool name to example arg dicts
        (say, a few logged calls), so relaxed args can be checked by value."""
        out: List[LintWarning] = []
        for tname in sorted(self._tools):
            t = self._tools[tname]
            if t.callers.tenants is None:
                out.append(LintWarning(tname, None, "any tenant can call this tool."))
            for aname in sorted(t.args):
                rule = t.args[aname]
                looks_like_dest = bool(_DESTINATION_LIKE.search(aname))
                if looks_like_dest and rule.max_integrity is Integrity.UNTRUSTED:
                    out.append(LintWarning(tname, aname, "looks like a destination but accepts any integrity."))
                elif looks_like_dest and not rule.whole_match:
                    out.append(LintWarning(tname, aname, "looks like a destination but allows partial matching."))
                if rule.type in ("integer", "number") and rule.max_integrity is Integrity.UNTRUSTED \
                        and (rule.minimum is None or rule.maximum is None):
                    out.append(LintWarning(tname, aname, "typed number from any source without both min and max."))
                if not rule.flow_to:
                    out.append(LintWarning(tname, aname, "confidentiality isn't checked (flow_to is empty)."))
        for tname in sorted(samples or {}):
            t = self._tools.get(tname)
            if t is None:
                out.append(LintWarning(tname, None, "samples given for a tool that isn't in the policy."))
                continue
            flagged = set()
            for call in samples[tname]:
                if not isinstance(call, Mapping):
                    continue
                for aname, value in call.items():
                    rule = t.args.get(aname)
                    if rule is None or not rule.relaxed or aname in flagged:
                        continue
                    kind = _destination_value(value)
                    if kind:
                        flagged.add(aname)
                        how = "accepts any integrity" if rule.max_integrity is Integrity.UNTRUSTED \
                            else "allows partial matching"
                        out.append(LintWarning(tname, aname, f"sample value looks like {kind} but the arg {how}."))
        return out


# ---- helpers ------------------------------------------------------------------


def _deny(reason: Reason, rule_id: str, args: Tuple[str, ...] = ()) -> PolicyResult:
    return PolicyResult(Verdict.DENY, reason, rule_id, args)


def _destination_value(value: Any) -> Optional[str]:
    items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
    for item in items:
        if not isinstance(item, str):
            continue
        for kind, rx in _DESTINATION_VALUE:
            if rx.search(item):
                return kind
    return None


def _typed_ok(rule: ArgRule, item: Any) -> bool:
    """``type``, ``min`` and ``max``. Strings are accepted when they parse cleanly,
    since models often send numbers as text."""
    t = rule.type
    if t == "boolean":
        return isinstance(item, bool) or (isinstance(item, str) and item.lower() in ("true", "false"))
    if t == "date":
        if not isinstance(item, str) or not _DATE_RE.fullmatch(item):
            return False
        try:
            num = float(datetime.date.fromisoformat(item).toordinal())
        except ValueError:
            return False
        lo = None if rule.minimum is None else rule.minimum
        hi = None if rule.maximum is None else rule.maximum
        return (lo is None or num >= lo) and (hi is None or num <= hi)
    if isinstance(item, bool):
        return False
    if isinstance(item, (int, float)) and not isinstance(item, bool):
        num = item
    elif isinstance(item, str) and re.fullmatch(r"-?\d+(\.\d+)?", item.strip()):
        num = float(item)
    else:
        return False
    if isinstance(num, float) and num != num:  # NaN
        return False
    if t == "integer" and float(num) != int(float(num)):
        return False
    if t == "integer" and isinstance(item, str) and "." in item:
        return False
    return (rule.minimum is None or float(num) >= rule.minimum) and (rule.maximum is None or float(num) <= rule.maximum)


def _constraints_ok(rule: ArgRule, value: Any) -> bool:
    if rule.one_of is None and rule.pattern is None and rule.type is None:
        return True
    items = value if isinstance(value, (list, tuple)) else [value]
    if not items:
        return True
    for item in items:
        if isinstance(item, (Mapping, list, tuple, set, frozenset)):
            return False  # constraints only make sense on scalars
        if rule.type is not None and not _typed_ok(rule, item):
            return False
        text = item if isinstance(item, str) else str(item)
        if rule.one_of is not None and text not in rule.one_of:
            return False
        if rule.pattern is not None and not rule.pattern.fullmatch(text):
            return False
    return True


def _no_extra(data: Mapping[str, Any], allowed: set, where: str) -> None:
    extra = set(data) - allowed
    if extra:
        raise ConfigError(f"{where}: unknown keys {sorted(extra)}. Allowed: {sorted(allowed)}.")


def _names(value: Any, where: str) -> Optional[FrozenSet[str]]:
    if value == "*":
        return None
    if isinstance(value, list) and value and all(isinstance(v, str) and v for v in value):
        return frozenset(value)
    raise ConfigError(f"{where}: use \"*\" or a non-empty list of names.")


def _parse_tool(name: Any, spec: Any) -> ToolPolicy:
    where = f"tool {name!r}"
    if not isinstance(name, str) or not _TOOL_RE.match(name):
        raise ConfigError(f"{where}: bad tool name.")
    if not isinstance(spec, Mapping):
        raise ConfigError(f"{where}: the rule must be an object.")
    _no_extra(spec, _TOOL_KEYS, where)

    callers_spec = spec.get("callers")
    if not isinstance(callers_spec, Mapping):
        raise ConfigError(
            f"{where}: 'callers' is required, e.g. {{\"tenants\": [\"acme\"], \"users\": \"*\"}}. "
            "There's no implicit 'anyone'."
        )
    _no_extra(callers_spec, {"tenants", "users"}, f"{where}.callers")
    for key in ("tenants", "users"):
        if key not in callers_spec:
            raise ConfigError(f"{where}.callers: '{key}' is required (use \"*\" for any).")
    callers = Callers(_names(callers_spec["tenants"], f"{where}.callers.tenants"),
                      _names(callers_spec["users"], f"{where}.callers.users"))

    dests = spec.get("destinations", [])
    if not isinstance(dests, list) or not all(isinstance(d, str) and d for d in dests):
        raise ConfigError(f"{where}: 'destinations' must be a list of non-empty strings.")

    confirm = spec.get("confirm_on_coincidence", False)
    if not isinstance(confirm, bool):
        raise ConfigError(f"{where}: 'confirm_on_coincidence' must be true or false.")

    args_spec = spec.get("args", {})
    if not isinstance(args_spec, Mapping):
        raise ConfigError(f"{where}: 'args' must be an object.")
    args = {aname: _parse_arg(f"{where}.args", aname, aspec) for aname, aspec in args_spec.items()}
    return ToolPolicy(name, callers, args, frozenset(dests), confirm)


def _parse_arg(where: str, name: Any, spec: Any) -> ArgRule:
    where = f"{where}.{name}"
    if not isinstance(name, str) or not _ARG_RE.match(name):
        raise ConfigError(f"{where}: bad arg name.")
    if not isinstance(spec, Mapping):
        raise ConfigError(f"{where}: the rule must be an object ({{}} means the strict defaults).")
    _no_extra(spec, _ARG_KEYS, where)

    level = spec.get("integrity", "TRUSTED")
    if level not in _INTEGRITY_LEVELS:
        raise ConfigError(f"{where}: integrity must be one of {sorted(_INTEGRITY_LEVELS)}.")

    match = spec.get("match", "whole")
    if match not in ("whole", "partial"):
        raise ConfigError(f"{where}: match must be \"whole\" or \"partial\".")

    flow_to = spec.get("flow_to", list(_DEFAULT_FLOW_TO))
    if not isinstance(flow_to, list) or not all(isinstance(t, str) for t in flow_to):
        raise ConfigError(f"{where}: flow_to must be a list of scope templates.")
    for template in flow_to:
        for ph in _PLACEHOLDER_RE.findall(template):
            if ph not in _PLACEHOLDERS:
                raise ConfigError(f"{where}: unknown placeholder {{{ph}}} in flow_to. Use {{tenant}} or {{user}}.")
        try:
            check_scope(template.format(tenant="x", user="x"))
        except (ValueError, KeyError, IndexError) as exc:
            raise ConfigError(f"{where}: bad flow_to scope {template!r}: {exc}") from None

    one_of = spec.get("one_of")
    if one_of is not None:
        if not isinstance(one_of, list) or not one_of or not all(isinstance(v, str) for v in one_of):
            raise ConfigError(f"{where}: one_of must be a non-empty list of strings.")
        one_of = frozenset(one_of)

    pattern = spec.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str) or not pattern:
            raise ConfigError(f"{where}: pattern must be a non-empty regex string.")
        try:
            pattern = re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"{where}: pattern doesn't compile: {exc}") from None

    typ = spec.get("type")
    if typ is not None and typ not in _TYPES:
        raise ConfigError(f"{where}: type must be one of {list(_TYPES)}.")
    bounds = []
    for key in ("min", "max"):
        v = spec.get(key)
        if v is not None:
            if typ not in ("integer", "number", "date"):
                raise ConfigError(f"{where}: {key} needs type integer, number or date.")
            if typ == "date":
                if not isinstance(v, str):
                    raise ConfigError(f"{where}: {key} for a date is an ISO date string like \"2026-01-31\".")
                try:
                    v = float(datetime.date.fromisoformat(v).toordinal())
                except ValueError:
                    raise ConfigError(f"{where}: {key} isn't a valid ISO date.") from None
            elif isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ConfigError(f"{where}: {key} must be a number.")
        bounds.append(None if v is None else float(v))
    if bounds[0] is not None and bounds[1] is not None and bounds[0] > bounds[1]:
        raise ConfigError(f"{where}: min is above max.")

    return ArgRule(name, _INTEGRITY_LEVELS[level], match == "whole", tuple(flow_to), one_of, pattern,
                   typ, bounds[0], bounds[1])


def _no_dupes(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ConfigError(f"duplicate key in policy: {key!r}.")
        seen[key] = value
    return seen
