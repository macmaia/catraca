"""Evidence. Every decision, allowed or not, written down in a way you can
audit later without ever seeing the data that was in the call.

What goes in a record:

* who (tenant and user, both as keyed digests by default), what tool, when, which turn;
* the verdict, the stable reason code, the rule that decided and how long it took;
* for every arg: its label, the resolution rule, coverage, origins, whether it
  was consequential and whether it was a coincidence, plus a keyed digest and
  the length of the value, never the value itself;
* the egress targets (kind, host, integrity), with addresses as digests;
* a summary of the context window (channels and residual label, free text redacted);
* the destination, cut down to scheme and host when it's a URL (no path or query);
* ``seq``, ``prev`` and ``hash``, chaining each record to the one before, so a
  deleted or edited line shows up in ``verify``.

Strict by default: no values, no previews, tenants and users pseudonymised
(including ``tenant:``/``user:`` scopes in labels), free text in ``detail``,
``destination`` and the window redacted. You loosen by passing
``include_preview=True`` (a redacted preview of each value, and the whole
redacted destination URL) or ``pseudonymise_users=False`` (tenant and user in
clear). Target hosts are kept as they are, they're what an audit needs.

Digests are HMAC-SHA256. Without a ``key`` a random one is made per process,
so digests only line up within one run. Pass your own key (and keep it out of
the log) to correlate across runs. ``key_id`` in each record says which key.

Redaction uses a small built-in regex scrubber (``redact``) for structured
identifiers and secrets: emails, CPF, CNPJ, RG, CEP, phones, card numbers,
IBANs, IPs, API keys, tokens and passwords in ``key=value`` pairs, plus any
long run of digits. It does NOT catch names, street addresses or other
free-form personal data. If those can turn up in your text, pass ``redactor=``
a proper PII tool. ``tarja_redactor()`` plugs in Tarja (experimental, optional).

Export for SIEMs: ``to_ecs`` (Elastic Common Schema) and ``to_cef`` (ArcSight
CEF). CLI::

    python -m catraca.evidence verify decisions.jsonl
    python -m catraca.evidence stats  decisions.jsonl
    python -m catraca.evidence export --format ecs decisions.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

EVIDENCE_VERSION = 1
GENESIS = "0" * 64

# ---- redaction ------------------------------------------------------------------
#
# The built-in scrubber runs a fixed list of rules in order. Each rule either
# replaces a match with a tag like ``[CPF]`` or hands it back untouched so a
# later, more generic rule can have a go. Tags contain no digits, so later
# rules never chew on earlier output. The last rule masks any long run of
# digits as ``[NUMBER]``, so something that looks like an id but fails every
# check still doesn't land in the log.


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total, alt = total + d, not alt
    return total % 10 == 0


def _cpf_ok(d: str) -> bool:
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        total = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        check = total * 10 % 11 % 10
        if check != int(d[n]):
            return False
    return True


def _cnpj_ok(d: str) -> bool:
    if len(d) != 14 or d == d[0] * 14:
        return False
    for n in (12, 13):
        weights = list(range(n - 7, 1, -1)) + list(range(9, 1, -1))
        total = sum(int(x) * w for x, w in zip(d[:n], weights, strict=True))
        check = 0 if total % 11 < 2 else 11 - total % 11
        if check != int(d[n]):
            return False
    return True


def _br_mobile(d: str) -> bool:
    return len(d) == 11 and d[0] != "0" and d[1] != "0" and d[2] == "9"


def _ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _cpf(m: "re.Match[str]") -> str:
    d = _digits(m.group(0))
    if _cpf_ok(d):
        return "[CPF]"
    return "[PHONE]" if _br_mobile(d) else m.group(0)


def _plus_phone(m: "re.Match[str]") -> str:
    return "[PHONE]" if 8 <= len(_digits(m.group(0))) <= 15 else m.group(0)


_Rule = Tuple["re.Pattern[str]", Union[str, Callable[["re.Match[str]"], str]]]

# Every repeat is bounded and every rule can only start where its token starts
# (lookbehind), so each rule is one linear pass. Unbounded repeats here are what
# made a long run of digits or dots take seconds.
_SECRET_KEY = r"(?<![\w.-])[\w.-]{0,32}?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)[\w.-]{0,32}"
_RULES: Tuple[_Rule, ...] = (
    # secrets first, so their digits don't get picked up as phones or numbers
    (re.compile(rf"(?i)({_SECRET_KEY})(\s{{0,8}}[=:]\s{{0,8}})(\"[^\"]{{0,512}}\"|'[^']{{0,512}}'|[^\s&,;\"']{{1,512}})"), r"\1\2[SECRET]"),
    (re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{0,4096}"), "[JWT]"),
    (re.compile(r"(?i)\bBearer\s{1,8}[A-Za-z0-9._~+/=-]{8,4096}"), "Bearer [TOKEN]"),
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,512}"), "[API_KEY]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})"), "[TOKEN]"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[AWS_KEY]"),
    (re.compile(r"(?i)(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,8}\.[a-z]{2,24}"), "[EMAIL]"),
    (re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b"), "[IBAN]"),
    (re.compile(r"(?i)(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%\w+)?(?![\w:])"),
     lambda m: "[IP]" if _ip(m.group(0).split("%")[0]) else m.group(0)),
    (re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
     lambda m: "[IP]" if _ip(m.group(0)) else m.group(0)),
    (re.compile(r"(?<![\w.])\d{2}[.\s]?\d{3}[.\s]?\d{3}[/\s]?\d{4}[-\s]?\d{2}(?![\w])"),
     lambda m: "[CNPJ]" if _cnpj_ok(_digits(m.group(0))) else m.group(0)),
    (re.compile(r"(?<![\w.])\d{3}[.\s]?\d{3}[.\s]?\d{3}[-\s/.]?\d{2}(?![\w])"), _cpf),
    (re.compile(r"(?<![\w.])\d{1,2}\.\d{3}\.\d{3}-[\dXx](?![\w])"), "[RG]"),
    (re.compile(r"(?i)\b(CEP[:\s]*)\d{5}-?\d{3}(?![\w])"), r"\1[CEP]"),
    (re.compile(r"(?<![\w.\-/])\d{5}-\d{3}(?![\w-])"), "[CEP]"),
    (re.compile(r"(?<![\w+])\+\d[\d\s().-]{6,20}\d(?![\w])"), _plus_phone),
    (re.compile(r"(?<![\w])(?:\d[ -]?){12,18}\d(?![\w])"),
     lambda m: "[CARD]" if _luhn(_digits(m.group(0))) else "[NUMBER]"),
    (re.compile(r"(?:\(\d{2,3}\)\s?|(?<![\w.\-/])\d{2,3}[\s.-])9?\d{4}[\s.-]?\d{4}(?![\w-])"), "[PHONE]"),
    (re.compile(r"(?<![\w.\-/])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w-])"), "[PHONE]"),
    (re.compile(r"(?<![\w.\-/])9?\d{4}-\d{4}(?![\w-])"), "[PHONE]"),
    (re.compile(r"(?<![\w])\d(?:[ .\-/]?\d){9,4096}(?![\w])"), "[NUMBER]"),
)


def redact(text: str) -> str:
    """Built-in scrubber for structured identifiers and secrets.

    Catches: emails (plus-addressing too), CPF and CNPJ (only tagged when the
    check digits are right), RG, CEP (with a dash or after the word 'CEP'),
    phones (international, with area code, and local ``1234-5678`` style),
    IPv4 and IPv6 addresses, IBANs, card numbers (Luhn-checked), API keys
    (``sk-``, GitHub tokens, AWS access key ids), JWTs, ``Bearer`` tokens and
    the value in ``password=...``, ``token: ...`` style pairs. Any other run
    of 10 or more digits is masked as ``[NUMBER]``.

    It does NOT catch names, street addresses or other free-form personal
    data. Regexes can't do that reliably. If your text may hold those, pass
    ``redactor=`` a proper PII tool.
    """
    if len(text) > MAX_REDACT_CHARS:
        # Nobody needs 100 KB of free text in an audit record, and a bound keeps
        # the cost of a decision bounded whatever an attacker puts in a value.
        text = text[:MAX_REDACT_CHARS] + f" [TRUNCATED {len(text) - MAX_REDACT_CHARS} chars]"
    if not _MAYBE_SENSITIVE.search(text):
        return text  # nothing any rule could match: no digits, @, separators or key prefixes
    key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()
    hit = _REDACT_CACHE.get(key)
    if hit is None:
        hit = _redact_uncached(text)
        if len(_REDACT_CACHE) >= 1024:
            _REDACT_CACHE.clear()
        _REDACT_CACHE[key] = hit
    return hit


# Every rule needs a digit, an @, a key/value separator or a known key prefix.
_MAYBE_SENSITIVE = re.compile(r"(?i)[0-9@=:]|sk-|gh[pousr]_|github_pat_|akia|asia|eyj|bearer")


MAX_REDACT_CHARS = 4096

# Keyed by a digest of the input, so the cache never holds unredacted text.
_REDACT_CACHE: Dict[bytes, str] = {}


def _redact_uncached(text: str) -> str:
    out = text
    for rx, repl in _RULES:
        out = rx.sub(repl, out)
    return out


def tarja_redactor(module: Any = None) -> Callable[[str], str]:
    """Use Tarja for redaction. Needs the ``tarja`` package (optional).

    Experimental: Tarja's API isn't published yet, so this looks for a
    ``redact()`` or ``anonymize()`` function and may change when it is.
    """
    if module is None:
        try:
            module = importlib.import_module("tarja")
        except ImportError:
            raise ImportError("tarja_redactor() needs the 'tarja' package. Without it, the built-in "
                              "redact() is used, which covers structured identifiers and secrets "
                              "but not names or addresses.") from None
    fn = getattr(module, "redact", None) or getattr(module, "anonymize", None)
    if not callable(fn):
        raise TypeError("the tarja module has no redact() or anonymize() function.")

    def run(text: str) -> str:
        out = fn(text)
        if not isinstance(out, str):
            raise TypeError("tarja returned something that isn't a string.")
        return out

    return run


# ---- sinks ----------------------------------------------------------------------


class MemorySink:
    """Keeps records in a list. Handy for tests and for short-lived processes."""

    def __init__(self) -> None:
        self.records: List[dict] = []

    def last(self) -> Optional[dict]:
        return self.records[-1] if self.records else None

    def append(self, record: dict) -> None:
        self.records.append(record)


class JsonlFileSink:
    """Append-only JSON Lines file. Opened with O_APPEND, one line per record,
    fsync after each write by default. The file is created 0600.

    ``fsync_every`` (seconds) is a loosening for throughput: the line is still
    written before the call goes ahead, so a crashed process loses nothing,
    but a power cut can lose up to that many seconds of records. The default,
    0, syncs every record.
    """

    def __init__(self, path: Union[str, Path], *, fsync: bool = True, fsync_every: float = 0.0) -> None:
        self.path = Path(path)
        self._fsync = _FsyncPolicy(fsync, fsync_every)
        _repair_tail(self.path)
        self._last = _read_last(self.path)

    def last(self) -> Optional[dict]:
        return self._last

    def append(self, record: dict) -> None:
        _append_line(self.path, _line(record), self._fsync.now())
        self._last = record


class _FsyncPolicy:
    def __init__(self, enabled: bool, every: float) -> None:
        if every < 0:
            raise ValueError("fsync_every can't be negative.")
        self._enabled, self._every = bool(enabled), float(every)
        self._last: Optional[float] = None

    def now(self) -> bool:
        if not self._enabled:
            return False
        if self._every == 0:
            return True
        t = time.monotonic()
        if self._last is None or t - self._last >= self._every:
            self._last = t
            return True
        return False


def _line(record: Mapping[str, Any]) -> bytes:
    return (json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


_OPEN_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _append_line(path: Path, line: bytes, fsync: bool) -> int:
    """Append one line and return the file's new size.

    ``O_NOFOLLOW`` refuses a symlink planted where the log should be, so the
    writes can't be redirected to another file. If the write fails halfway
    (disk full, say), the file is cut back to where it was: a torn line would
    otherwise sit in the log and every later record would land on the same line.
    """
    fd = os.open(path, _OPEN_FLAGS, 0o600)
    try:
        before = os.fstat(fd).st_size
        try:
            written = os.write(fd, line)
            if written != len(line):
                raise OSError("short write to the evidence log")
            if fsync:
                os.fsync(fd)
        except BaseException:
            try:
                os.ftruncate(fd, before)
            except OSError:
                pass  # _repair_tail cleans it up on the next start
            raise
        return before + len(line)
    finally:
        os.close(fd)


def _repair_tail(path: Path) -> None:
    """If the last line has no newline (the process died mid-write), move the
    fragment to ``<name>.torn`` and cut the log back to the last full line.
    That record was never acknowledged, since a failed write denies the call."""
    try:
        fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            return
        os.lseek(fd, size - 1, os.SEEK_SET)
        if os.read(fd, 1) == b"\n":
            return
        pos = size
        while pos > 0:
            step = min(pos, 1 << 16)
            os.lseek(fd, pos - step, os.SEEK_SET)
            chunk = os.read(fd, step)
            nl = chunk.rfind(b"\n")
            if nl >= 0:
                pos = pos - step + nl + 1
                break
            pos -= step
        os.lseek(fd, pos, os.SEEK_SET)
        fragment = os.read(fd, size - pos)
        torn = path.with_name(path.name + ".torn")
        tfd = os.open(torn, _OPEN_FLAGS, 0o600)
        try:
            os.write(tfd, fragment + b"\n")
        finally:
            os.close(tfd)
        os.ftruncate(fd, pos)
        os.fsync(fd)
    finally:
        os.close(fd)


class RotatingJsonlSink:
    """Like ``JsonlFileSink``, but starts a new file once the current one
    reaches ``max_bytes``. Files are ``<prefix>-000001.jsonl``,
    ``<prefix>-000002.jsonl`` and so on. The hash chain runs straight across
    files: the first record of a new file points at the last one of the old.
    Verify them together with ``verify(read_many(files(directory)))`` or
    ``python -m catraca.evidence verify <dir>/*.jsonl``.
    """

    def __init__(self, directory: Union[str, Path], *, prefix: str = "decisions",
                 max_bytes: int = 64 * 1024 * 1024, fsync: bool = True, fsync_every: float = 0.0) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", prefix):
            raise ValueError("prefix must be letters, digits, '_', '.' or '-'.")
        if max_bytes < 4096:
            raise ValueError("max_bytes must be at least 4096.")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._prefix = prefix
        self._max = max_bytes
        self._fsync = _FsyncPolicy(fsync, fsync_every)
        existing = files(self.directory, prefix)
        self._n = _file_number(existing[-1]) if existing else 1
        if existing:
            _repair_tail(existing[-1])
        self._size: Optional[int] = None
        self._last = None
        for path in reversed(existing):
            self._last = _read_last(path)
            if self._last is not None:
                break

    @property
    def current(self) -> Path:
        return self.directory / f"{self._prefix}-{self._n:06d}.jsonl"

    def last(self) -> Optional[dict]:
        return self._last

    def append(self, record: dict) -> None:
        line = _line(record)
        if self._size is None:
            try:
                st = os.lstat(self.current)
                self._size = st.st_size
            except FileNotFoundError:
                self._size = 0
        if self._size > 0 and self._size + len(line) > self._max:
            self._n += 1
            self._size = 0
        self._size = _append_line(self.current, line, self._fsync.now())
        self._last = record


def files(directory: Union[str, Path], prefix: str = "decisions") -> List[Path]:
    """The rotated files in a directory, in order."""
    found = [p for p in Path(directory).glob(f"{prefix}-*.jsonl") if re.fullmatch(rf"{re.escape(prefix)}-\d{{6}}\.jsonl", p.name)]
    return sorted(found, key=_file_number)


def _file_number(path: Path) -> int:
    return int(path.stem.rsplit("-", 1)[1])


def _read_last(path: Path) -> Optional[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        chunk = min(size, 1 << 16)
        fh.seek(size - chunk)
        tail = fh.read().decode("utf-8", errors="replace").rstrip("\n").split("\n")[-1]
    return json.loads(tail)


def read_many(paths: Iterable[Union[str, Path]]) -> Iterator[dict]:
    """Records from several files, in the order given (rotated logs)."""
    for p in paths:
        yield from read(p)


def read(path: Union[str, Path]) -> Iterator[dict]:
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"line {n} isn't valid JSON: {exc}") from None


# ---- the log --------------------------------------------------------------------


def _canonical(record: Mapping[str, Any]) -> bytes:
    body = {k: v for k, v in record.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _hash(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


class EvidenceLog:
    def __init__(
        self,
        sink: Any = None,
        *,
        key: Optional[bytes] = None,
        redactor: Callable[[str], str] = redact,
        include_preview: bool = False,
        pseudonymise_users: bool = True,
        policy_id: str = "",
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._sink = sink if sink is not None else MemorySink()
        if key is not None and (not isinstance(key, (bytes, bytearray)) or len(key) < 16):
            raise ValueError("key must be at least 16 bytes.")
        self._key = bytes(key) if key is not None else secrets.token_bytes(32)
        self.key_id = hashlib.sha256(b"catraca-evidence-key:" + self._key).hexdigest()[:16]
        self._redact = redactor
        self._preview = include_preview
        self._pseudo = pseudonymise_users
        self._policy_id = policy_id
        self._clock = clock
        self._lock = threading.Lock()
        last = self._sink.last()
        self._seq = int(last["seq"]) if last else 0
        self._prev = last["hash"] if last else GENESIS

    @property
    def sink(self) -> Any:
        return self._sink

    def checkpoint(self, anchor_key: bytes) -> dict:
        """A signed pointer to the chain's current head, to keep somewhere
        else (a ticket, a bucket with object lock, a signed timestamp).

        Later, ``verify(records, anchor=cp, anchor_key=...)`` proves the log
        still contains that exact record, so rewriting the whole file (which
        the chain alone can't catch) shows up. Use a key that isn't the digest
        key and doesn't live next to the log.
        """
        if not isinstance(anchor_key, (bytes, bytearray)) or len(anchor_key) < 16:
            raise ValueError("anchor_key must be at least 16 bytes.")
        with self._lock:
            seq, head = self._seq, self._prev
        cp = {"v": EVIDENCE_VERSION, "seq": seq, "hash": head,
              "ts": self._clock().astimezone(timezone.utc).isoformat(timespec="microseconds"),
              "anchor_key_id": hashlib.sha256(b"catraca-anchor-key:" + bytes(anchor_key)).hexdigest()[:16]}
        cp["mac"] = _anchor_mac(bytes(anchor_key), cp)
        return cp

    def digest(self, value: Any) -> str:
        text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=repr)
        return hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def record(self, decision: Any, *, caller: Any = None) -> dict:
        body = self._build(decision, caller)
        with self._lock:
            body["seq"] = self._seq + 1
            body["prev"] = self._prev
            body["hash"] = _hash(body)
            self._sink.append(body)
            self._seq, self._prev = body["seq"], body["hash"]
        return body

    # -- building a record --
    def _build(self, d: Any, caller: Any) -> dict:
        req = d.request
        tenant = getattr(caller, "tenant", None)
        user = getattr(caller, "user", None)
        pseudo = self._pseudo
        rec: Dict[str, Any] = {
            "v": EVIDENCE_VERSION,
            "ts": self._clock().astimezone(timezone.utc).isoformat(timespec="microseconds"),
            "key_id": self.key_id,
            "policy_id": self._policy_id,
            "call_id": str(d.call_id),
            "tool": str(d.tool),
            "verdict": d.verdict.value,
            "reason": d.reason.value,
            "rule_id": d.rule_id,
            "elapsed_us": d.elapsed_us,
            "detail": self._redact(d.detail) if d.detail else "",
            "flagged": list(getattr(d, "flagged", ())),
            "caller": {
                "tenant": self._who(tenant),
                "user": self._who(user),
                "tenant_pseudonymised": bool(pseudo and tenant is not None),
                "user_pseudonymised": bool(pseudo and user is not None),
            },
            "confirmation": [
                {"argument": c.argument, "value_digest": self.digest(c.value),
                 "trusted_origins": list(c.trusted_origins)}
                for c in d.confirmation
            ],
        }
        if req is None:
            rec.update({"turn": None, "mode": None, "destination": None, "args": [], "targets": [], "window": None})
            return rec
        rec["turn"] = req.turn
        rec["mode"] = req.mode
        dest = self._destination(req.destination)
        rec["destination"] = dest
        rec["destination_reduced"] = dest != req.destination
        rec["args"] = [self._arg(a) for a in req.args]
        rec["targets"] = [self._target(t, r) for t, r in req.targets]
        rec["window"] = self._scrub(_jsonable(dict(req.context)))
        return rec

    def _who(self, name: Any) -> Optional[str]:
        if name is None:
            return None
        return self.digest(str(name)) if self._pseudo else str(name)

    def _destination(self, dest: Optional[str]) -> Optional[str]:
        if dest is None:
            return None
        if not self._preview and re.match(r"(?i)^[a-z][a-z0-9+.-]*://", dest):
            try:
                parts = urlsplit(dest)
                host = parts.hostname or ""
                port = f":{parts.port}" if parts.port is not None else ""
            except ValueError:
                return "[URL]"
            if ":" in host:
                host = f"[{host}]"
            return f"{parts.scheme}://{host}{port}"
        return self._redact(dest)

    def _scope(self, scope: str) -> str:
        kind, sep, name = scope.partition(":")
        if self._pseudo and sep and kind in ("tenant", "user"):
            return f"{kind}:{self.digest(name)}"
        return scope

    def _scrub(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self._redact(self._scope(obj))
        if isinstance(obj, list):
            return [self._scrub(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self._scrub(v) for k, v in obj.items()}
        return obj

    def _label(self, label: Any) -> dict:
        out = label.to_dict()
        scopes = out.get("confidentiality")
        if isinstance(scopes, list):
            out["confidentiality"] = sorted(self._scope(x) for x in scopes)
        return out

    def _arg(self, a: Any) -> dict:
        res = a.resolution
        value = a.value
        text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=repr)
        out = {
            "name": a.name,
            "consequential": bool(a.consequential),
            "value": {"digest": self.digest(value), "length": len(text), "type": type(value).__name__},
            "label": self._label(res.label),
            "rule": res.rule.value,
            "coverage": round(res.coverage, 4),
            "origins": list(res.origins),
            "trusted_origins": list(res.trusted_origins),
            "only_coincidence": bool(res.only_coincidence),
        }
        if self._preview:
            out["value"]["preview"] = self._redact(text[:200])
        return out

    def _target(self, t: Any, res: Any) -> dict:
        out = {"arg": t.arg, "kind": t.kind, "host": t.host, "integrity": res.label.integrity.name}
        if t.address:
            out["address_digest"] = self.digest(t.address)
        if t.scheme:
            out["scheme"] = t.scheme
        if t.port is not None:
            out["port"] = t.port
        if t.via:
            out["nested"] = True
        return out


def _jsonable(obj: Any) -> Any:
    return json.loads(json.dumps(obj, sort_keys=True, default=repr))


# ---- verification, stats, replay ---------------------------------------------------


def _anchor_mac(key: bytes, cp: Mapping[str, Any]) -> str:
    msg = f"{cp['v']}|{cp['seq']}|{cp['hash']}|{cp['ts']}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify(records: Iterable[Mapping[str, Any]], *, anchor: Optional[Mapping[str, Any]] = None,
           anchor_key: Optional[bytes] = None, trust_unsigned_anchor: bool = False,
           ) -> Tuple[bool, Optional[int], str]:
    """Check the hash chain, and optionally that it still holds a checkpoint.

    A checkpoint without ``anchor_key`` could have been written by whoever
    rewrote the log, so it's refused unless you pass
    ``trust_unsigned_anchor=True`` (say, it came from a store only you can write).

    Returns ``(ok, bad_seq, message)``.
    """
    if anchor_key is not None and len(anchor_key) < 16:
        raise ValueError("anchor_key must be at least 16 bytes.")
    records = list(records)
    ok, bad, msg = _verify_chain(records)
    if not ok or anchor is None:
        return ok, bad, msg
    if anchor_key is None and not trust_unsigned_anchor:
        return False, None, "a checkpoint needs anchor_key to be trusted (or trust_unsigned_anchor=True)"
    if anchor_key is not None and not hmac.compare_digest(_anchor_mac(anchor_key, anchor), str(anchor.get("mac", ""))):
        return False, None, "the checkpoint's signature doesn't match, so it can't be trusted"
    seq = anchor.get("seq")
    if seq == 0:
        return True, None, msg + ", checkpoint is from an empty log"
    by_seq = {r.get("seq"): r for r in records}
    if seq not in by_seq:
        first = records[0]["seq"] if records else None
        if first is not None and seq < first:
            return False, seq, f"checkpoint {seq} is older than the first record given ({first}); pass the earlier files too"
        return False, seq, f"record {seq} from the checkpoint is missing, the log was cut or rewritten"
    if by_seq[seq].get("hash") != anchor.get("hash"):
        return False, seq, f"record {seq} doesn't match the checkpoint, the log was rewritten"
    return True, None, msg + f", checkpoint at {seq} matches"


def _verify_chain(records: List[Mapping[str, Any]]) -> Tuple[bool, Optional[int], str]:
    prev, expected_seq, n = GENESIS, None, 0
    for rec in records:
        n += 1
        seq = rec.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            return False, None, f"record {n} has no valid seq"
        if expected_seq is None:
            expected_seq = seq
            prev = rec.get("prev", GENESIS) if seq != 1 else GENESIS
        if seq != expected_seq:
            return False, seq, f"expected seq {expected_seq}, found {seq} (a record's missing or out of order)"
        if rec.get("prev") != prev:
            return False, seq, f"record {seq} doesn't point at the one before it"
        if _hash(rec) != rec.get("hash"):
            return False, seq, f"record {seq} was changed after it was written"
        prev, expected_seq = rec["hash"], seq + 1
    return True, None, f"{n} records, chain intact"


def _coincidence_driven(rec: Mapping[str, Any]) -> bool:
    if rec["reason"] == "COINCIDENCE":
        return True
    if rec["reason"] not in ("UNTRUSTED_ARGUMENT", "EGRESS_UNTRUSTED"):
        return False
    flagged = set(rec.get("flagged") or [])
    args = {a["name"]: a for a in rec.get("args", [])}
    names = flagged or {a for a, v in args.items() if v["label"]["integrity"] == "UNTRUSTED" and v["consequential"]}
    return bool(names) and all(args.get(n, {}).get("only_coincidence") for n in names)


def stats(records: Iterable[Mapping[str, Any]]) -> dict:
    """Counts per verdict and reason, plus the coincidence rate.

    ``coincidence_rate`` is the share of all decisions where a denial or a
    confirmation was caused only by coincidence. If it's high, the policy's
    written wrong, not the world. It's a product metric, not a security one.
    """
    verdicts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    total = coincidence = 0
    for rec in records:
        total += 1
        verdicts[rec["verdict"]] += 1
        reasons[rec["reason"]] += 1
        tools[rec["tool"]] += 1
        if rec["verdict"] != "ALLOW" and _coincidence_driven(rec):
            coincidence += 1
    return {
        "decisions": total,
        "verdicts": dict(verdicts),
        "reasons": dict(reasons),
        "tools": dict(tools),
        "coincidence_driven": coincidence,
        "coincidence_rate": round(coincidence / total, 4) if total else 0.0,
    }


def _replay_destination(record: Mapping[str, Any]) -> Optional[str]:
    dest = record.get("destination")
    if dest is None or not record.get("destination_reduced"):
        return dest
    # The recorded destination was cut down or redacted, so it can't be
    # matched against the policy. Same trick as for callers: the reason says
    # how that check went. None skips it, an impossible name fails it.
    return "\x00redacted" if record["reason"] == "DESTINATION_NOT_ALLOWED" else None


class _Redacted:
    def __repr__(self) -> str:
        return "<redacted>"


def replay(record: Mapping[str, Any], policy: Any) -> Any:
    """Re-run the policy stage from a record alone.

    Rebuilds the decision request from the recorded labels, rules and flags,
    with every value replaced by a placeholder. one_of/pattern checks can't
    see the value, so they're taken from the record: an arg flagged under
    ARGUMENT_CONSTRAINT failed its check, every other arg passed.

    Returns the policy's ``PolicyResult``. Egress, confirmation and evidence
    outcomes happen after the policy, so for those the record's own reason
    is the answer and the replay should show the policy let the call through.
    """
    from .gate import ArgProvenance, Caller, DecisionRequest
    from .labels import Label
    from .registry import Resolution, Rule

    if record.get("mode") is None:
        raise ValueError("this record was denied before a request was built; its reason is the whole story.")
    failed = set(record.get("flagged") or []) if record["reason"] == "ARGUMENT_CONSTRAINT" else set()
    args = []
    for a in record["args"]:
        res = Resolution(Label.from_dict(a["label"]), Rule(a["rule"]), (), tuple(a["origins"]), a["coverage"],
                         (), a["only_coincidence"], tuple(a["trusted_origins"]))
        args.append(ArgProvenance(a["name"], _Redacted(), a["consequential"], res))
    caller = Caller(record["caller"]["tenant"] or "", record["caller"]["user"] or "")
    request = DecisionRequest(record["call_id"], record["turn"], caller, record["tool"], tuple(args),
                              _replay_destination(record), record["window"] or {}, record["mode"])
    kwargs = {"constraints_ok": lambda rule, a: a.name not in failed}
    if record["caller"].get("user_pseudonymised") or record["caller"].get("tenant_pseudonymised"):
        # The real tenant or user id isn't in the record, but the check order is fixed and
        # callers come first, so the recorded reason says how that check went.
        caller_failed = record["reason"] == "CALLER_NOT_ALLOWED"
        kwargs["caller_ok"] = lambda callers, c: not caller_failed
    return policy.evaluate(request, **kwargs)


# ---- SIEM export --------------------------------------------------------------------


def to_ecs(rec: Mapping[str, Any]) -> dict:
    """Elastic Common Schema. catraca-specific fields live under ``catraca.*``."""
    return {
        "@timestamp": rec["ts"],
        "event": {
            "kind": "event",
            "category": ["iam"],
            "type": ["allowed"] if rec["verdict"] == "ALLOW" else ["denied"],
            "action": "tool_call",
            "outcome": "success" if rec["verdict"] == "ALLOW" else "failure",
            "reason": rec["reason"],
            "id": rec["call_id"],
            "sequence": rec["seq"],
            "hash": rec["hash"],
            "duration": rec["elapsed_us"] * 1000 if isinstance(rec["elapsed_us"], int) and rec["elapsed_us"] >= 0 else None,
        },
        "rule": {"id": rec["rule_id"], "ruleset": rec.get("policy_id") or None},
        "organization": {"id": rec["caller"]["tenant"]},
        "user": {"id": rec["caller"]["user"]},
        "catraca": {k: rec[k] for k in ("verdict", "tool", "turn", "flagged", "args", "targets", "detail")},
    }


def _cef_escape(value: Any, header: bool = False) -> str:
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|") if header else s.replace("=", "\\=")
    return s.replace("\n", "\\n").replace("\r", "\\r")


def to_cef(rec: Mapping[str, Any]) -> str:
    """ArcSight CEF, one line per decision."""
    severity = {"ALLOW": 1, "REQUIRE_CONFIRMATION": 5, "DENY": 7}.get(rec["verdict"], 5)
    ext = {
        "rt": rec["ts"],
        "act": rec["verdict"],
        "reason": rec["reason"],
        "cs1Label": "rule_id", "cs1": rec["rule_id"],
        "cs2Label": "tool", "cs2": rec["tool"],
        "cs3Label": "tenant", "cs3": rec["caller"]["tenant"],
        "suser": rec["caller"]["user"],
        "externalId": rec["call_id"],
        "cn1Label": "seq", "cn1": rec["seq"],
        "msg": rec.get("detail") or "",
    }
    head = "|".join(_cef_escape(x, header=True) for x in
                    ("CEF:0", "Micah 6 AI", "catraca", "1", rec["reason"], f"tool call {rec['verdict'].lower()}",
                     severity))
    return head + "|" + " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items() if v is not None)


# ---- CLI ------------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m catraca.evidence")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("verify", help="check the chain, across rotated files if you pass several")
    p.add_argument("paths", nargs="+")
    p.add_argument("--anchor", help="checkpoint JSON file made with EvidenceLog.checkpoint()")
    p.add_argument("--anchor-key-env", help="env var holding the checkpoint key (hex)")
    p = sub.add_parser("stats")
    p.add_argument("paths", nargs="+")
    p = sub.add_parser("export")
    p.add_argument("--format", choices=("ecs", "cef"), default="ecs")
    p.add_argument("paths", nargs="+")
    args = ap.parse_args(argv)
    paths = sorted(args.paths, key=lambda x: (_file_number(Path(x)) if re.search(r"-\d{6}\.jsonl$", x) else 0, x))
    try:
        records = list(read_many(paths))
    except (OSError, ValueError) as exc:
        print(f"can't read the log: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "verify":
        anchor = key = None
        try:
            if args.anchor:
                anchor = json.loads(Path(args.anchor).read_text(encoding="utf-8"))
                if not isinstance(anchor, dict):
                    raise ValueError("the checkpoint file isn't a JSON object")
            if args.anchor_key_env:
                raw = os.environ.get(args.anchor_key_env)
                if not raw:
                    print(f"{args.anchor_key_env} isn't set", file=sys.stderr)
                    return 2
                key = bytes.fromhex(raw)
            ok, _, msg = verify(records, anchor=anchor, anchor_key=key)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"can't check the checkpoint: {exc}", file=sys.stderr)
            return 2
        print(("ok: " if ok else "BROKEN: ") + msg)
        return 0 if ok else 1
    if args.cmd == "stats":
        print(json.dumps(stats(records), indent=2, sort_keys=True))
        return 0
    for rec in records:
        print(json.dumps(to_ecs(rec), sort_keys=True) if args.format == "ecs" else to_cef(rec))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
