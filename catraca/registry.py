"""Context registry (mode B, provenance by registry).

We don't wrap values. Every snippet that lands in the model's context window
gets annotated with its channel, origin and label. When a tool call reaches
the boundary, each argument is resolved against the registry.

Invariant: the registry has an entry for every snippet that's still in
the model's context. It follows the context window, not the turn. Moving to a
new turn never forgets anything. ``forget`` is an explicit, audited act by the
app, and if you're not sure what's left the context, don't forget.

Summaries carry labels: ``summarise`` records the summary with the join
of everything in the window, and only then forgets the snippets it replaces.

Resolution rules:

EXACT
    The arg's canonical form equals a whole snippet's canonical form.
SUBSTRING
    Every char of the canonical form is covered by windows of ``min_length``
    chars found in annotated snippets. Anything shorter never counts as cover.
PARTIAL
    Coverage map: covered segments inherit the label of whatever covered them,
    uncovered segments get the residual.
CONSERVATIVE
    Nothing matched. The arg gets the residual, i.e. the join of everything in
    the window, on both axes.
NO_FULL_MATCH
    Consequential position (destination, URL, path, data-subject id) without a
    contiguous, whole match against a single trusted snippet. UNTRUSTED, full stop.

Decoded variants (URL, HTML, escapes, base64, punycode, rot13) can only add
origins, so they can only make a label stricter. Leetspeak is folded into the
canonical form itself, see ``normalise``.

Threads: every public method takes the registry's lock, and
``resolve_request`` resolves a whole call plus the window summary as one
consistent snapshot. Safe to share between threads and between asyncio tasks
(nothing in here awaits). Not shared across processes.

Index layout: each live snippet gets a slot, and the index maps every
``min_length`` window to an int bitmask of slots. Masks are interned so the
common single-owner case costs one shared int, not a set per window.

Known limit, stated up front: paraphrase, translation and re-encoding outside
the variants above won't match. The conservative rule catches a lot of that
when the window's tainted, but it's risk reduction, not a structural guarantee.
"""

from __future__ import annotations

import enum
import functools
import hashlib
import hmac
import html
import itertools
import json
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple
from urllib.parse import unquote

from .channels import ChannelConfig
from .errors import RegistryError
from .labels import BOTTOM, Confidentiality, Integrity, Label, join_all
from .normalise import variants as _variants

DEFAULT_MIN_LENGTH = 8
MIN_CONSEQUENTIAL_LENGTH = 4
MAX_FORGET_LOG = 10_000
_FIELD_NAME = re.compile(r"[A-Za-z_]{1,64}")
"""The forget log keeps the latest entries only. The evidence log is the
durable record, this is for inspecting a live session."""
SUMMARY_CHANNEL = "summary"


class Rule(enum.Enum):
    EXACT = "EXACT"
    SUBSTRING = "SUBSTRING"
    PARTIAL = "PARTIAL"
    CONSERVATIVE = "CONSERVATIVE"
    NO_FULL_MATCH = "NO_FULL_MATCH"


_STRENGTH = {
    Rule.EXACT: 0,
    Rule.SUBSTRING: 1,
    Rule.PARTIAL: 2,
    Rule.CONSERVATIVE: 3,
    Rule.NO_FULL_MATCH: 4,
}


@dataclass(frozen=True)
class Snippet:
    id: str
    turn: int
    channel: str
    origin: str
    label: Label
    text: str
    forms: Tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class ForgetRecord:
    snippet_id: str
    turn: int
    reason: str


@dataclass(frozen=True)
class Segment:
    """A contiguous run of the arg's canonical form, with its provenance."""

    start: int
    end: int
    snippets: Tuple[str, ...]
    """Empty when the segment wasn't covered and got the residual."""
    label: Label

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "snippets": list(self.snippets), "label": self.label.to_dict()}


@dataclass(frozen=True)
class Resolution:
    label: Label
    rule: Rule
    snippets: Tuple[str, ...]
    """Ids of the snippets behind the label, in a stable order."""
    origins: Tuple[str, ...]
    coverage: float
    """Share of the canonical form covered by annotated snippets (0 to 1)."""
    segments: Tuple[Segment, ...] = ()
    only_coincidence: bool = False
    """True when the whole value has trusted provenance and it's only UNTRUSTED
    because the same value also shows up in untrusted content. This feeds the
    REQUIRE_CONFIRMATION verdict."""
    trusted_origins: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "label": self.label.to_dict(),
            "rule": self.rule.value,
            "snippets": list(self.snippets),
            "origins": list(self.origins),
            "coverage": round(self.coverage, 4),
            "segments": [s.to_dict() for s in self.segments],
            "only_coincidence": self.only_coincidence,
            "trusted_origins": list(self.trusted_origins),
        }


def _locked(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class ContextRegistry:
    def __init__(self, channels: ChannelConfig, *, min_length: int = DEFAULT_MIN_LENGTH) -> None:
        if not isinstance(min_length, int) or min_length < 4:
            raise RegistryError("min_length must be an int of at least 4.")
        if SUMMARY_CHANNEL in channels:
            raise RegistryError(f"channel name {SUMMARY_CHANNEL!r} is reserved for history summaries.")
        self._lock = threading.RLock()
        self._channels = channels
        self._k = min_length
        self._turn = 0
        self._counter = itertools.count(1)
        self._snippets: Dict[str, Snippet] = {}
        self._slot_of: Dict[str, int] = {}
        self._sid_at: List[Optional[str]] = []
        self._free_slots: List[int] = []
        self._index: Dict[str, int] = {}
        self._exact: Dict[str, int] = {}
        self._masks: Dict[int, int] = {}
        self._trusted_mask = 0
        self._label_cache: Dict[int, Label] = {}
        self._ids_cache: Dict[int, Tuple[str, ...]] = {}
        self._forgotten: List[ForgetRecord] = []
        self._forgotten_since_summary: Label = BOTTOM

    # ---- lifecycle -------------------------------------------------------
    @property
    def turn(self) -> int:
        return self._turn

    @_locked
    def new_turn(self) -> int:
        """Just bumps the counter. Forgets nothing, the history's still in the window."""
        self._turn += 1
        return self._turn

    @_locked
    def forget(self, snippet_id: str, *, reason: str) -> None:
        """Drop a snippet that has provably left the model's context.

        If the content is still there inside a summary, use ``summarise`` instead.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise RegistryError("forget needs a reason, it's an audited act.")
        snip = self._snippets.pop(snippet_id, None)
        if snip is None:
            raise RegistryError(f"unknown snippet {snippet_id!r}.")
        slot = self._slot_of.pop(snippet_id)
        keep = ~(1 << slot)
        for form in snip.forms:
            self._clear(self._exact, form, keep)
            for g in self._windows(form):
                self._clear(self._index, g, keep)
        self._trusted_mask &= keep
        self._sid_at[slot] = None
        self._free_slots.append(slot)
        self._label_cache.clear()
        self._ids_cache.clear()
        self._forgotten.append(ForgetRecord(snippet_id, self._turn, reason.strip()))
        self._forgotten_since_summary = self._forgotten_since_summary.join(snip.label)
        if len(self._forgotten) > MAX_FORGET_LOG:
            del self._forgotten[: len(self._forgotten) - MAX_FORGET_LOG]
        self._compact_masks()

    @property
    def forget_log(self) -> Tuple[ForgetRecord, ...]:
        with self._lock:
            return tuple(self._forgotten)

    @_locked
    def summarise(self, summary_text: str, replaces: Iterable[str], *, reason: str = "history summary") -> Snippet:
        """Record the summary, then forget the snippets it replaces.

        The summary's label is the join of the whole window at the time it was
        written, since whatever wrote it saw the whole window. A summary of a
        tainted window is born UNTRUSTED. Happens under one lock, so nobody can
        resolve against a window that has lost the originals but not yet gained
        the summary.
        """
        ids = list(dict.fromkeys(replaces))
        unknown = [s for s in ids if s not in self._snippets]
        if unknown:
            raise RegistryError(f"unknown snippets in summary: {unknown}.")
        # Whatever wrote the summary may still remember snippets forgotten
        # since the last summary, so their labels go into it as well.
        label = self._residual().join(self._forgotten_since_summary)
        summary = self._insert(summary_text, SUMMARY_CHANNEL, f"summary:{','.join(ids)}", label)
        for s in ids:
            self.forget(s, reason=f"{reason} ({summary.id})")
        self._forgotten_since_summary = BOTTOM
        return summary

    # ---- state across processes ------------------------------------------
    @_locked
    def export_state(self, *, key: Optional[bytes] = None) -> dict:
        """The window as plain JSON-able data, to keep a conversation's registry
        in a shared store (so another worker or a resumed graph picks it up).

        It holds the snippet texts, so store it like the conversation itself.
        With ``key``, the state carries an HMAC and ``from_state`` checks it:
        whoever can edit stored state could otherwise relabel an untrusted
        snippet as trusted.
        """
        state = {
            "version": 1,
            "min_length": self._k,
            "turn": self._turn,
            "next_id": max([_id_key(s) for s in self._snippets]
                           + [_id_key(f.snippet_id) for f in self._forgotten], default=0) + 1,
            "snippets": [
                {"id": sn.id, "turn": sn.turn, "channel": sn.channel, "origin": sn.origin,
                 "label": sn.label.to_dict(), "text": sn.text}
                for sn in sorted(self._snippets.values(), key=lambda x: _id_key(x.id))
            ],
            "forgotten": [{"snippet_id": f.snippet_id, "turn": f.turn, "reason": f.reason} for f in self._forgotten],
        }
        if key is not None:
            _check_key(key)
            state["mac"] = _state_mac(key, state)
        return state

    @classmethod
    def from_state(cls, channels: ChannelConfig, state: Mapping[str, Any], *, key: Optional[bytes] = None,
                   trust_unsigned: bool = False) -> "ContextRegistry":
        """Rebuild a registry from ``export_state``. Needs the same ``key``, or
        ``trust_unsigned=True`` if the store is one only you can write to."""
        if not isinstance(state, Mapping) or state.get("version") != 1:
            raise RegistryError("unknown registry state version.")
        if key is not None:
            _check_key(key)
            body = {k: v for k, v in state.items() if k != "mac"}
            if not hmac.compare_digest(_state_mac(key, body), str(state.get("mac", ""))):
                raise RegistryError("registry state signature doesn't match.")
        elif not trust_unsigned:
            raise RegistryError("registry state needs key= to be checked (or trust_unsigned=True).")
        try:
            reg = cls(channels, min_length=int(state["min_length"]))
            reg._turn = int(state["turn"])
            for sn in state["snippets"]:
                channel = sn["channel"]
                if channel != SUMMARY_CHANNEL and channel not in channels:
                    raise RegistryError(f"state names channel {channel!r}, which isn't configured.")
                label = Label.from_dict(sn["label"])
                if channel != SUMMARY_CHANNEL:
                    # Never looser than the channel is configured today, even if
                    # the config was tightened after the state was saved.
                    label = label.join(channels[channel].label)
                reg._insert(sn["text"], channel, sn["origin"], label, sid=sn["id"], turn=int(sn["turn"]))
            reg._forgotten = [ForgetRecord(f["snippet_id"], int(f["turn"]), f["reason"]) for f in state["forgotten"]]
            reg._counter = itertools.count(int(state["next_id"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise RegistryError(f"bad registry state: {exc}") from None
        return reg

    # ---- annotation -------------------------------------------------
    @_locked
    def annotate(
        self,
        text: str,
        channel: str,
        *,
        origin: str = "",
        scopes: Optional[Iterable[str]] = None,
    ) -> Snippet:
        """Record a snippet that just entered the context.

        ``scopes`` narrows the channel's declared confidentiality (it's joined
        in), it can never widen it.
        """
        label = self._channels[channel].label
        if scopes is not None:
            label = label.join(Label(Integrity.TRUSTED, Confidentiality.of(scopes)))
        return self._insert(text, channel, origin or channel, label)

    def _insert(self, text: str, channel: str, origin: str, label: Label, *,
                sid: Optional[str] = None, turn: Optional[int] = None) -> Snippet:
        if not isinstance(text, str):
            raise RegistryError(f"annotated text must be a str, got {type(text).__name__}.")
        # Work out the forms before touching any state, so a failure here leaves nothing half-done.
        forms = tuple(f for f in _variants(text, for_index=True) if f)
        sid = sid or f"s{next(self._counter)}"
        slot = self._free_slots.pop() if self._free_slots else len(self._sid_at)
        if slot == len(self._sid_at):
            self._sid_at.append(sid)
        else:
            self._sid_at[slot] = sid
        bit = 1 << slot
        self._label_cache.clear()
        self._ids_cache.clear()
        snip = Snippet(sid, self._turn if turn is None else turn, channel, origin, label, text, forms)
        self._snippets[sid] = snip
        self._slot_of[sid] = slot
        if label.integrity is not Integrity.UNTRUSTED:
            self._trusted_mask |= bit
        index, masks = self._index, self._masks
        for form in forms:
            self._set(self._exact, form, bit)
            for g in self._windows(form):
                old = index.get(g, 0)
                new = old | bit
                if new != old:
                    index[g] = masks.setdefault(new, new)
        self._compact_masks()
        return snip

    def _compact_masks(self) -> None:
        """Masks are interned so identical ones share memory, but a mask
        nobody points at any more would otherwise stay forever. Rebuild the
        table from the live entries once dead ones outnumber the live ones."""
        live = len(self._index) + len(self._exact)
        if len(self._masks) > 2 * live + 1024:
            fresh: Dict[int, int] = {}
            for table in (self._index, self._exact):
                for key, m in table.items():
                    table[key] = fresh.setdefault(m, m)
            self._masks = fresh

    def _set(self, table: Dict[str, int], key: str, bit: int) -> None:
        new = table.get(key, 0) | bit
        table[key] = self._masks.setdefault(new, new)

    def _clear(self, table: Dict[str, int], key: str, keep: int) -> None:
        old = table.get(key)
        if old is None:
            return
        new = old & keep
        if new:
            table[key] = self._masks.setdefault(new, new)
        else:
            del table[key]

    def _windows(self, form: str) -> Iterator[str]:
        k = self._k
        return (form[i : i + k] for i in range(len(form) - k + 1))

    def _ids(self, mask: int) -> Tuple[str, ...]:
        mask_in = mask
        cached = self._ids_cache.get(mask)
        if cached is not None:
            return cached
        out = []
        while mask:
            low = mask & -mask
            out.append(self._sid_at[low.bit_length() - 1])
            mask ^= low
        result = tuple(sorted(out, key=_id_key))
        if len(self._ids_cache) < 65536:  # bounded, cleared on every write anyway
            self._ids_cache[mask_in] = result
        return result

    def _mask_label(self, mask: int) -> Label:
        """Join of the labels of every snippet in ``mask``, memoised per mask."""
        label = self._label_cache.get(mask)
        if label is None:
            label = join_all(self._snippets[s].label for s in self._ids(mask))
            self._label_cache[mask] = label
        return label

    # ---- queries ---------------------------------------------------------
    @property
    def snippets(self) -> Tuple[Snippet, ...]:
        with self._lock:
            return tuple(self._snippets.values())

    @_locked
    def residual_label(self) -> Label:
        """Join of everything in the window. Used for whatever didn't match."""
        return self._residual()

    def _residual(self) -> Label:
        return join_all(s.label for s in self._snippets.values())

    @_locked
    def is_tainted(self) -> bool:
        return self._trusted_mask != sum(1 << self._slot_of[s] for s in self._snippets)

    @_locked
    def summary(self) -> dict:
        """Window summary for the decision request (section 5.4)."""
        return self._summary()

    def _summary(self) -> dict:
        return {
            "turn": self._turn,
            "snippets": len(self._snippets),
            "channels": sorted({s.channel for s in self._snippets.values()}),
            "untrusted_channels": sorted(
                {s.channel for s in self._snippets.values() if s.label.integrity is Integrity.UNTRUSTED}
            ),
            "forgotten": len(self._forgotten),
            "residual_label": self._residual().to_dict(),
        }

    # ---- resolution ------------------------------------------------------
    @_locked
    def resolve(self, value: Any, *, consequential: bool = True) -> Resolution:
        """Work out where an argument value came from.

        By default every value is treated as consequential: it needs a whole,
        contiguous match against one trusted snippet to come out trusted.
        Pass ``consequential=False`` to allow partial cover, which is looser, so
        only do it for free-text args where that's fine. Containers resolve
        each item and join them.
        """
        return self._resolve(value, consequential, self._residual())

    @_locked
    def resolve_args(self, args: Mapping[str, Any], *, relaxed: Iterable[str] = ()) -> Dict[str, Resolution]:
        """Resolve every arg. All of them are consequential except the ones in ``relaxed``."""
        return self._resolve_args(args, relaxed)

    @_locked
    def resolve_request(
        self, args: Mapping[str, Any], *, relaxed: Iterable[str] = (), extra: Iterable[str] = ()
    ) -> Tuple[Dict[str, Resolution], dict, int, Tuple[Resolution, ...]]:
        """Resolve a whole call against one consistent snapshot of the window.

        ``extra`` are more values to resolve in the same snapshot, always with
        the whole-match rule. The gate uses it for the egress targets it finds
        inside args.

        Returns ``(resolutions, window_summary, turn, extra_resolutions)``.
        """
        residual = self._residual()
        more = tuple(self._resolve(v, True, residual) for v in extra)
        return self._resolve_args(args, relaxed), self._summary(), self._turn, more

    def _resolve_args(self, args: Mapping[str, Any], relaxed: Iterable[str]) -> Dict[str, Resolution]:
        loose = set(relaxed)
        residual = self._residual()
        return {name: self._resolve(v, name not in loose, residual) for name, v in args.items()}

    def _resolve(self, value: Any, consequential: bool, residual: Label) -> Resolution:
        # Containers: keys count as much as values (a dict keyed by account
        # number carries the account number), and an empty container resolves
        # like an empty string, never as trusted by default.
        if isinstance(value, Mapping):
            if not value:
                return self._resolve_text("", consequential, residual)
            parts = []
            for k, v in value.items():
                if not (isinstance(k, str) and _FIELD_NAME.fullmatch(k)):
                    # A plain field name ("status", "first_name") is structure.
                    # Anything else (digits, @, dots) may be data and gets resolved.
                    parts.append(self._resolve(k, consequential, residual))
                parts.append(self._resolve(v, consequential, residual))
            return self._combine(parts)
        if isinstance(value, (list, tuple, set, frozenset)):
            if not value:
                return self._resolve_text("", consequential, residual)
            items = sorted(value, key=repr) if isinstance(value, (set, frozenset)) else value
            return self._combine([self._resolve(v, consequential, residual) for v in items])
        return self._resolve_text(self._as_text(value), consequential, residual)

    @staticmethod
    def _as_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _combine(self, parts: List[Resolution]) -> Resolution:
        if not parts:
            return Resolution(BOTTOM, Rule.EXACT, (), (), 1.0)
        snips = tuple(sorted({s for p in parts for s in p.snippets}, key=_id_key))
        return Resolution(
            join_all(p.label for p in parts),
            max((p.rule for p in parts), key=_STRENGTH.__getitem__),
            snips,
            self._origins(snips),
            min(p.coverage for p in parts),
            (),
            all(p.only_coincidence or p.label.integrity is not Integrity.UNTRUSTED for p in parts)
            and any(p.only_coincidence for p in parts),
            tuple(sorted({o for p in parts for o in p.trusted_origins})),
        )

    def _origins(self, snips: Iterable[str]) -> Tuple[str, ...]:
        return tuple(sorted({self._snippets[s].origin for s in snips}))

    def _resolve_text(self, text: str, consequential: bool, residual: Label) -> Resolution:
        forms = _variants(text)
        primary, extras = forms[0], [f for f in forms[1:] if f]
        k, index = self._k, self._index
        n = len(primary)

        # Coverage map: one bitmask of slots per position of the canonical form.
        exact = self._exact.get(primary, 0) if primary else 0
        if exact:
            by_pos = [exact] * n
        else:
            # A position is covered by every window that starts in [pos-k+1, pos].
            starts = [index.get(primary[i : i + k], 0) for i in range(n - k + 1)]
            by_pos = [0] * n
            for i, m in enumerate(starts):
                if m:
                    for j in range(i, i + k):
                        by_pos[j] |= m

        matched = 0
        for m in by_pos:
            matched |= m
        # Extra variants add origins, never coverage. If the label's already as
        # strict as it can get (UNTRUSTED and blocked everywhere), they can't
        # change the verdict, so skip them. The evidence then lists fewer
        # origins, which is fine: the label's the same.
        if not self._saturated(matched, n, by_pos, residual):
            for f in extras:
                matched |= self._exact.get(f, 0)
                for i in range(len(f) - k + 1):
                    matched |= index.get(f[i : i + k], 0)

        covered = sum(1 for m in by_pos if m)
        coverage = covered / n if n else 0.0
        whole = n > 0 and covered == n
        segments = self._segments(by_pos, residual)

        if matched:
            ids = tuple(self._ids(matched))
            label = self._mask_label(matched)
            rule = Rule.EXACT if exact else (Rule.SUBSTRING if whole else Rule.PARTIAL)
            if not whole:
                label = label.join(residual)
        else:
            ids, label, rule = (), residual, Rule.CONSERVATIVE

        # Coincidence: every position has a trusted origin, and something untrusted matched too.
        trusted = self._trusted_mask
        coincidence = whole and all(m & trusted for m in by_pos) and bool(matched & ~trusted)
        trusted_origins = tuple(sorted({self._snippets[s].origin for s in self._ids(matched & trusted)}))

        if consequential:
            anchor = self._contiguous_trusted_match(primary, text)
            if anchor is None:
                label = label.join(Label(Integrity.UNTRUSTED, residual.confidentiality))
                rule = Rule.NO_FULL_MATCH
                coincidence = False
            else:
                # Under the whole-match rule a value's provenance is the set of
                # snippets that contain *all* of it. Snippets that only share a
                # fragment (say, the same email domain) didn't produce it, so
                # they don't taint it. An untrusted snippet that does contain
                # the whole value makes it a coincidence.
                holders = self._whole_holders(primary, extras)
                ids = tuple(sorted(holders, key=_id_key))
                label = join_all(self._snippets[s].label for s in ids)
                rule = Rule.EXACT if exact else Rule.SUBSTRING
                untrusted_holders = [s for s in ids if not self._trusted_id(s)]
                coincidence = bool(untrusted_holders)
                trusted_origins = tuple(sorted({self._snippets[s].origin for s in ids if self._trusted_id(s)}))
        coincidence = coincidence and label.integrity is Integrity.UNTRUSTED

        return Resolution(label, rule, ids, self._origins(ids), coverage, segments, coincidence, trusted_origins)

    def _saturated(self, matched: int, n: int, by_pos: List[int], residual: Label) -> bool:
        if not matched:
            return False
        label = self._mask_label(matched)
        if n and not all(by_pos):
            label = label.join(residual)
        return label.integrity is Integrity.UNTRUSTED and label.confidentiality.is_blocked

    def _trusted_id(self, sid: str) -> bool:
        return self._snippets[sid].label.integrity is not Integrity.UNTRUSTED

    def _whole_holders(self, primary: str, extras: List[str]) -> List[str]:
        """Snippets whose forms contain the value, or a decoded variant of it, in one piece."""
        wanted = [f for f in [primary] + list(extras) if f and (len(f) >= MIN_CONSEQUENTIAL_LENGTH or f == primary)]
        out = set()
        k, index = self._k, self._index
        for w in wanted:
            if len(w) >= k:
                # Only snippets that have every window of w can hold all of it.
                mask = -1
                for i in range(0, len(w) - k + 1):
                    mask &= index.get(w[i : i + k], 0)
                    if not mask:
                        break
                candidates = self._ids(mask) if mask > 0 else ()
            else:
                candidates = tuple(self._snippets)
            for sid in candidates:
                if sid not in out and any(w in f for f in self._snippets[sid].forms):
                    out.add(sid)
        return list(out)

    def _contiguous_trusted_match(self, primary: str, raw: str) -> Optional[str]:
        """One trusted snippet that holds the value as whole tokens.

        Finding a value uses the aggressive normaliser (leetspeak, no
        punctuation), which is right for spotting untrusted content. Granting
        trust with it isn't: "10000" would match a trusted "100.00" and "b0b@"
        a trusted "bob@". So the aggressive forms only pick the candidates, and
        the value must then appear in the trusted text as whole tokens, with
        only case, width and grouping spaces folded.
        """
        if not primary:
            return None
        short = len(primary) < MIN_CONSEQUENTIAL_LENGTH
        if unicodedata.normalize("NFKC", raw) != raw:
            # The tool gets the raw value. If it only matches after folding
            # (full-width letters, ligatures), the user didn't type that string.
            return None
        want = _light_value(raw)
        if not want:
            return None
        for sid in self._ids(self._trusted_mask):
            snip = self._snippets[sid]
            if not any(primary in f for f in snip.forms):
                continue
            for view in _light_views(snip.text):
                if short:
                    # Too short to be told apart inside a sentence: the whole snippet must be it.
                    if view.strip(_EDGE) == want:
                        return sid
                elif _token_match(want, view):
                    return sid
        return None

    def _segments(self, by_pos: List[int], residual: Label) -> Tuple[Segment, ...]:
        out: List[Segment] = []
        start = 0
        n = len(by_pos)
        for i in range(1, n + 1):
            if i == n or by_pos[i] != by_pos[start]:
                mask = by_pos[start]
                ids = tuple(self._ids(mask))
                label = self._mask_label(mask) if mask else residual
                out.append(Segment(start, i, ids, label))
                start = i
        return tuple(out)


_EDGE = ".,;:!?()[]{}<>\"'`*_~|"


def _light(text: str) -> str:
    """Case and width folded, whitespace collapsed, edges trimmed. Nothing else."""
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split()).strip(_EDGE)


def _light_value(text: str) -> str:
    """Like ``_light`` but nothing is trimmed off the ends: punctuation around
    the value the tool gets (``../``, quotes, pipes) is part of the value, and
    the user has to have typed it."""
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _light_views(text: str) -> List[str]:
    out = [_light(text)]
    for t in (unquote(text), html.unescape(text)):
        lt = _light(t)
        if lt not in out:
            out.append(lt)
    return out


def _token_match(want: str, text: str) -> bool:
    """``want`` appears in ``text`` as a run of whole tokens.

    Tokens are split on whitespace. The run's outer edges may carry
    punctuation in the text (a trailing comma, brackets round an email).
    A value without spaces also matches a run written in groups, the way
    IBANs and card numbers usually are ("DE89 3704 0044 ...").
    """
    toks = text.split()
    parts = want.split()
    m = len(parts)
    for i in range(len(toks) - m + 1):
        run = toks[i : i + m]
        if m == 1:
            if run[0].strip(_EDGE) == parts[0]:
                return True
        elif run[0].lstrip(_EDGE) == parts[0] and run[-1].rstrip(_EDGE) == parts[-1] and run[1:-1] == parts[1:-1]:
            return True
    if m == 1 and len(parts[0]) >= 8 and _groupable(parts[0]):
        target = parts[0]
        for i in range(len(toks)):
            # "(+44) 20 7946 0958": brackets round a group are how people write it.
            acc = toks[i].lstrip(_EDGE).rstrip(")")
            if not _GROUP.fullmatch(acc) or not target.startswith(acc) or acc == target:
                continue
            for j in range(i + 1, min(len(toks), i + 12)):
                nxt = toks[j].strip("()")
                if not _GROUP.fullmatch(nxt):
                    nxt = toks[j].rstrip(_EDGE)
                if not _GROUP.fullmatch(nxt):
                    break
                if acc + nxt == target:
                    return True
                acc += nxt
                if not target.startswith(acc):
                    break
    return False


# One block of a grouped number: IBANs, cards and phones are written in short
# runs of letters and digits ("GB29 NWBK 6016 ...", "+44 20 7946 0958"). Words don't qualify, so
# "bob at example.com" never adds up to "bobatexample.com".
_GROUP = re.compile(r"\+?[A-Za-z0-9]{1,6}")


def _groupable(value: str) -> bool:
    """Only mostly-numeric values are matched across grouping spaces."""
    body = value[1:] if value.startswith("+") else value
    return body.isascii() and body.isalnum() and 2 * sum(c.isdigit() for c in body) >= len(body)


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise RegistryError("the state key must be at least 16 bytes.")


def _state_mac(key: bytes, state: Mapping[str, Any]) -> str:
    body = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hmac.new(bytes(key), body, hashlib.sha256).hexdigest()


def _id_key(sid: str) -> int:
    return int(sid[1:])
