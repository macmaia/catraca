"""Label core.

Two independent lattices. Joining two labels always keeps the more restrictive
side of each axis.

Integrity is a total order, TRUSTED < STRUCTURED < UNTRUSTED. Join is max.

Confidentiality is the set of scopes allowed to read a value. Join is set
intersection, so here "more restrictive" means a *smaller* set. The top of the
lattice (least restrictive) is PUBLIC, written ``"*"``, and it stands for the
universal set, i.e. {"*"} ∩ X gives X. The bottom is the empty set, which
means the value can't go anywhere at all.

Everything in here is pure and immutable.
"""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass
from typing import Any, FrozenSet, Iterable, Mapping, Optional

from .errors import LabelError

SERIAL_VERSION = 1

_SCOPE_RE = re.compile(r"^[a-z0-9_.-]+:[^\s,]+$")


class Integrity(enum.IntEnum):
    """Can this value influence an action? Higher means more restrictive."""

    TRUSTED = 0
    STRUCTURED = 1
    UNTRUSTED = 2

    def join(self, other: "Integrity") -> "Integrity":
        return self if self >= other else other

    @classmethod
    def from_name(cls, name: str) -> "Integrity":
        try:
            return cls[name]
        except (KeyError, TypeError):
            valid = ", ".join(m.name for m in cls)
            raise LabelError(f"unknown integrity {name!r}. Valid values: {valid}.") from None


def check_scope(scope: str) -> str:
    if not isinstance(scope, str) or not _SCOPE_RE.match(scope):
        raise LabelError(
            f"invalid scope {scope!r}. Use 'key:value' with a lower-case key, e.g. 'tenant:acme'. "
            "'*' isn't a scope, it's the whole public top, so pass PUBLIC instead."
        )
    return scope


@dataclass(frozen=True)
class Confidentiality:
    """Scopes allowed to read the value. ``scopes is None`` means PUBLIC."""

    scopes: Optional[FrozenSet[str]] = None

    def __post_init__(self) -> None:
        scopes: Any = self.scopes  # callers may pass any iterable, whatever the annotation says
        if scopes is not None:
            scopes = frozenset(scopes)
            object.__setattr__(self, "scopes", scopes)
            for s in scopes:
                check_scope(s)

    @classmethod
    def of(cls, scopes: Iterable[str]) -> "Confidentiality":
        return cls(frozenset(scopes))

    @property
    def is_public(self) -> bool:
        return self.scopes is None

    @property
    def is_blocked(self) -> bool:
        return self.scopes is not None and not self.scopes

    @classmethod
    def _unchecked(cls, scopes: FrozenSet[str]) -> "Confidentiality":
        # Only for sets built from scopes that were already validated.
        obj = object.__new__(cls)
        object.__setattr__(obj, "scopes", scopes)
        return obj

    def join(self, other: "Confidentiality") -> "Confidentiality":
        # "*" is handled here on purpose. Treating it as a literal scope would
        # turn the top of the lattice into its bottom without anyone noticing.
        if self.scopes is None or self is other:
            return other
        if other.scopes is None:
            return self
        return Confidentiality._unchecked(self.scopes & other.scopes)

    def may_flow_to(self, scope: str) -> bool:
        return self.scopes is None or scope in self.scopes

    def flows_to(self, other: "Confidentiality") -> bool:
        """Lattice order: True if ``other`` is at least as restrictive as ``self``."""
        if self.scopes is None:
            return True
        if other.scopes is None:
            return False
        return other.scopes <= self.scopes

    def to_json(self) -> Any:
        return "*" if self.scopes is None else sorted(self.scopes)

    @classmethod
    def from_json(cls, data: Any) -> "Confidentiality":
        if data == "*":
            return PUBLIC
        if isinstance(data, list) and all(isinstance(s, str) for s in data):
            return cls(frozenset(data))
        raise LabelError(f"invalid confidentiality {data!r}. Use '*' for public or a list of scopes.")


PUBLIC = Confidentiality(None)
BLOCKED = Confidentiality(frozenset())


@dataclass(frozen=True)
class Label:
    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Confidentiality = PUBLIC

    def join(self, other: "Label") -> "Label":
        if self is other or self == other:
            return self
        return Label(
            self.integrity.join(other.integrity),
            self.confidentiality.join(other.confidentiality),
        )

    def flows_to(self, other: "Label") -> bool:
        return self.integrity <= other.integrity and self.confidentiality.flows_to(other.confidentiality)

    # Stable serialisation: sorted keys, sorted scopes, explicit version.
    def to_dict(self) -> dict:
        return {
            "v": SERIAL_VERSION,
            "integrity": self.integrity.name,
            "confidentiality": self.confidentiality.to_json(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Label":
        if not isinstance(data, Mapping):
            raise LabelError(f"serialised label must be an object, got {type(data).__name__}.")
        if data.get("v") != SERIAL_VERSION:
            raise LabelError(f"unsupported serial version {data.get('v')!r}, expected {SERIAL_VERSION}.")
        extra = set(data) - {"v", "integrity", "confidentiality"}
        if extra:
            raise LabelError(f"unknown fields in label: {sorted(extra)}.")
        return cls(
            Integrity.from_name(data.get("integrity", "")),
            Confidentiality.from_json(data.get("confidentiality")),
        )

    @classmethod
    def from_json(cls, text: str) -> "Label":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LabelError(f"serialised label isn't valid JSON: {exc}") from None
        return cls.from_dict(data)


BOTTOM = Label(Integrity.TRUSTED, PUBLIC)
"""Neutral element for join (bottom of the product lattice)."""


def join_all(labels: Iterable[Label]) -> Label:
    out = BOTTOM
    for label in labels:
        out = out.join(label)
    return out
