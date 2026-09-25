"""The egress gate. Where is this call actually sending things?

The policy looks at args one by one. That misses the classic exfil move,
which is hiding the destination inside something else: a link in an email
body, a Markdown image the client will fetch, a redirector with the real URL
tucked into its query string. This module digs the destinations out, parses
them properly, and checks each one against an allowlist and against where it
came from.

What counts as a destination (a *target*):

* URLs with a scheme, ``www.`` hosts, scheme-relative ``//host`` links in
  Markdown and HTML, and bare hostnames (see ``catraca.tlds`` for what counts).
* Email addresses.
* An arg whose whole value is a hostname or an IP.
* Anything inside another URL's query string or path that itself looks like a
  URL (redirectors, preview proxies, e.g. EchoLeak's Teams proxy). Nested
  targets are checked too, three levels deep.

Text is scanned as-is and again after URL-decoding, HTML-unescaping and
refanging (``[at]``, ``[dot]``, ``hxxp``), so the usual disguises don't help.

Hosts are compared the way a client would see them: userinfo dropped
(``https://acme.com@evil.io`` is evil.io), backslashes read as slashes, case
and trailing dots folded, IDN turned into punycode (so a Cyrillic lookalike
never matches the real domain), and IPs recognised in dotted, decimal, hex and
octal forms.

Strict by default. With no config at all, *any* target denies the call. Every
loosening has to be written down::

    {
      "version": 1,
      "default": { ... rules for tools not listed ... },
      "tools": {
        "send_email": {
          "emails": ["@acme.com.br"],
          "hosts": ["acme.com.br", "*.acme.com.br"]
        }
      }
    }

Rules and their strict defaults:

=====================  ============  ==========================================
key                    default       to loosen
=====================  ============  ==========================================
``hosts``              ``[]``        ``"acme.com"``, ``"*.acme.com"``, ``"*"``
``emails``             ``[]``        ``"@acme.com"``, ``"@*.acme.com"``,
                                     ``"ana@acme.com"``, ``"*"``
``schemes``            ``["https"]`` add ``"http"`` and friends
``ports``              scheme's own  list extra ports
``ip_literals``        ``false``     ``true``
``private_networks``   ``false``     ``true`` (localhost, RFC 1918, .local...)
``provenance``         ``TRUSTED``   ``STRUCTURED`` or ``ANY``
``skip_args``          ``[]``        args not to scan at all
=====================  ============  ==========================================

``provenance``: a target that came from untrusted content is denied
even when its host is on the allowlist. The one exception is a pure
coincidence that the policy is already sending to the person for
confirmation.
"""

from __future__ import annotations

import contextvars
import html
import ipaddress
import json
import re
import unicodedata
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple, Union
from urllib.parse import parse_qsl, unquote, urlsplit

from .errors import ConfigError
from .labels import Integrity
from .normalise import _refang
from .tlds import GENERIC, counts_as_host

EGRESS_VERSION = 1
_MAX_DEPTH = 3
_MAX_TARGETS = 64  # per call, so a giant body can't blow up the check
# Host of a target we couldn't read to the end: too deep, too many, or
# unparseable. Nothing can allow it, so the call is denied.
UNKNOWN_HOST = "unparseable"
_TLDS: "contextvars.ContextVar[FrozenSet[str]]" = contextvars.ContextVar("catraca_tlds", default=GENERIC)

_KEYS = {"hosts", "emails", "schemes", "ports", "ip_literals", "private_networks", "provenance",
         "skip_args", "description"}
_LEVELS = {"TRUSTED": Integrity.TRUSTED, "STRUCTURED": Integrity.STRUCTURED, "ANY": Integrity.UNTRUSTED}
_DEFAULT_PORTS = {"https": 443, "http": 80, "ftp": 21, "ws": 80, "wss": 443}

_URL_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15})://(?:[^\s<>\"'`)\]}\[@/]*@)?(?:\[[0-9a-f:.]+\])?[^\s<>\"'`)\]}]*")
# "https:evil.io" and "https:/evil.io": WHATWG parsers read both as https://evil.io.
_LOOSE_URL_RE = re.compile(r"(?i)\b(https?|wss?|ftp):[/\\]?(?![/\\])[^\s<>\"'`)\]}]+")
# Schemes that carry no host at all. They can't be allowlisted by host, so they
# only pass if the operator adds the scheme and... there's still no host to allow.
_OPAQUE_RE = re.compile(r"(?i)\b(file|data|javascript|vbscript|blob|filesystem|jar):[^\s<>\"'`)\]}]*")
_WWW_RE = re.compile(r"(?i)(?<![\w.@/-])www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:[/?#][^\s<>\"'`)\]}]*)?")
_SCHEMELESS_RE = re.compile(
    r"(?i)(?:\]\(|\]:\s*|href\s*=\s*[\"']?|src\s*=\s*[\"']?)(//[^\s<>\"'`)\]}]+)")
# A bare "//evil.io/x" on its own or in free text (a dotted host, an IP in
# any form, localhost, or a single label followed by a port or a path). Browsers and most HTTP
# clients resolve it against the current scheme, so it's a destination too.
_BARE_SCHEMELESS_RE = re.compile(
    r"(?i)(?<![\w:/\\.-])([/\\]{2}(?:[^\s/\\@<>\"'`]*@)?(?:\[[0-9a-f:.]+\]|\.?[a-z0-9_-]+\.[a-z0-9]|localhost\b|0x[0-9a-f]+\b|\d+\b|[a-z0-9_-]+(?=[:/\\?#]))[^\s<>\"'`)\]}]*)")
# Signs that a value still holds another URL once the depth limit is reached.
_STILL_NESTED_RE = re.compile(r"(?i)[/\\]{2}|%2f%2f|%5c%5c|%3a%2f|%3a%5c|%252f")
_EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[a-z0-9._%+-]{1,64}@[a-z0-9.-]+\.[a-z]{2,}(?![\w-])")
# For scanning, wider than the config form: quoted local parts, non-ASCII
# (IDN) domains, punycode TLDs and IP-literal domains all reach real mail servers.
_EMAIL_SCAN_RE = re.compile(
    r"(?i)(?:(?<![\w.+%-])[\w.%+-]{1,64}|\"[^\"\r\n]{1,64}\")"
    r"@(?:\[[0-9a-f:.]+\]|[\w-]+(?:\.[\w-]+)*\.(?:[^\W\d_]{2,}|xn--[a-z0-9-]+))(?![\w-])")
# Dots that IDNA folds into "." (ideographic, fullwidth, halfwidth, one-dot leader).
_UNICODE_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": ".", "\u2024": "."})
_BARE_HOST_RE = re.compile(
    r"(?i)(?<![\w.@/:-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?![\w-])"
    r"([/?#][^\s<>\"'`)\]}]*)?")
_HOSTNAME_ONLY_RE = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}\.?$")
_NUMERIC_HOST_RE = re.compile(r"(?i)^[0-9a-fx.]+$")
_PRIVATE_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp")


# ---- targets ------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    """One destination found in a call."""

    arg: str  # arg it came from, or "<destination>" for the call's destination
    kind: str  # "url", "email" or "host"
    raw: str  # as it appeared (after decoding), used for provenance
    host: str  # normalised, punycode; for emails, the domain
    scheme: Optional[str] = None
    port: Optional[int] = None
    address: Optional[str] = None  # full address for emails
    ip: Optional[str] = None
    via: Optional[str] = None  # the outer URL if this one was nested inside it

    def to_dict(self) -> dict:
        out = {"arg": self.arg, "kind": self.kind, "host": self.host}
        for k in ("scheme", "port", "address", "ip", "via"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        return out


def normalise_host(host: str) -> str:
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        return h
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        # Mixed scripts or labels too long for IDNA. Keep something that will
        # never match a real allowlist entry.
        return "invalid-idn." + h.encode("punycode").decode("ascii")


def as_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if _NUMERIC_HOST_RE.match(h) and any(c.isdigit() for c in h):
        try:  # decimal, hex and octal IPv4 forms, the way inet_aton reads them
            return ipaddress.IPv4Address(socket.inet_aton(h))
        except (OSError, ValueError):
            return None
    return None


def _std_ip(text: str):
    try:
        return ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None


def _url_targets(arg: str, text: str, via: Optional[str]) -> List[Target]:
    """Targets for one URL. A backslash is read both ways: WHATWG parsers treat it
    as a slash, Python's ``urlsplit`` doesn't. If the two disagree on the host,
    both hosts are returned and both must be allowed."""
    raw = text.rstrip(".,;:!?")
    readings = [raw.replace("\\", "/")]
    if "\\" in raw:
        readings.append(raw)
    out: List[Target] = []
    for cleaned in readings:
        if cleaned.startswith("//"):
            cleaned = "https:" + cleaned
        elif cleaned.lower().startswith("www."):
            cleaned = "https://" + cleaned
        m = re.match(r"(?i)(https?|wss?|ftp):[/\\]?(?![/\\])", cleaned)
        if m:
            cleaned = m.group(1) + "://" + cleaned[m.end():]
        try:
            parts = urlsplit(cleaned)
            port = parts.port
        except ValueError:
            # Unparseable port or host. Treat as its own host so it can't match anything.
            out.append(Target(arg, "url", text, UNKNOWN_HOST, scheme=None, via=via))
            continue
        scheme = (parts.scheme or "https").lower()
        host = parts.hostname or ""
        if not host:
            # file:///, data:, javascript: and friends. No host means nothing can allow it.
            out.append(Target(arg, "url", text, "", scheme=scheme, via=via))
            continue
        ip = as_ip(host)
        norm = str(ip) if ip is not None else normalise_host(host)
        t = Target(arg, "url", text, norm, scheme=scheme, port=port,
                   ip=str(ip) if ip is not None else None, via=via)
        if t not in out:
            out.append(t)
    return out


def _url_target(arg: str, text: str, via: Optional[str]) -> Optional[Target]:
    ts = _url_targets(arg, text, via)
    return ts[0] if ts else None


def _nested(arg: str, url: Target, text: str, depth: int, out: List[Target]) -> None:
    if depth >= _MAX_DEPTH:
        # Deeper than we unwrap. If there's still a URL inside, the final host
        # is unknown, so it's reported as one that nothing can allow.
        inner = re.sub(r"(?i)^(?:[a-z][a-z0-9+.-]*:)?[/\\]*", "", text)
        if _STILL_NESTED_RE.search(inner):
            _mark_unknown(arg, text, url.raw, out)
        return
    if "://" not in text[:20]:
        text = "https://" + text.lstrip("/")
    # Query values first (redirect=, url=, u=...), then anything after the host.
    try:
        parts = urlsplit(text.replace("\\", "/"))
        values = [v for _, v in parse_qsl(parts.query, keep_blank_values=False)]
        rest = parts.path + "?" + parts.query + "#" + parts.fragment
    except ValueError:
        return
    # A query value is a whole value, so a bare host there counts ("?u=evil.io").
    for chunk in values:
        _scan_text(arg, chunk, out, depth + 1, via=url.raw, bare_hosts=True)
    _scan_text(arg, unquote(rest), out, depth + 1, via=url.raw, bare_hosts=False)


def _mark_unknown(arg: str, raw: str, via: Optional[str], out: List[Target]) -> None:
    """Add, once, a target nothing can allow. It may go one past the cap."""
    if not any(t.host == UNKNOWN_HOST and t.arg == arg for t in out):
        out.append(Target(arg, "url", raw[:200], UNKNOWN_HOST, scheme=None, via=via))


def _scan_text(arg: str, text: str, out: List[Target], depth: int = 0, via: Optional[str] = None,
               bare_hosts: bool = True) -> None:
    seen = {(t.kind, t.raw, t.host) for t in out}

    def add(t: Optional[Target]) -> bool:
        if t is None or (t.kind, t.raw, t.host) in seen:
            return False
        if len(out) >= _MAX_TARGETS:
            # Too many to check one by one. Don't drop the rest in silence.
            _mark_unknown(arg, text, via, out)
            return False
        seen.add((t.kind, t.raw, t.host))
        out.append(t)
        return True

    spans: List[Tuple[int, int]] = []
    for rx in (_URL_RE, _LOOSE_URL_RE, _OPAQUE_RE, _SCHEMELESS_RE, _BARE_SCHEMELESS_RE, _WWW_RE):
        for m in rx.finditer(text):
            grouped = rx is _SCHEMELESS_RE or rx is _BARE_SCHEMELESS_RE
            g = m.group(1) if grouped else m.group(0)
            start = m.start(1) if grouped else m.start()
            if any(a <= start < b for a, b in spans):
                continue
            spans.append((start, start + len(g)))
            if rx is _URL_RE and m.group(1).lower() == "mailto":
                continue  # handled by the email scan
            ts = _url_targets(arg, g, via)
            first = True
            for t in ts:
                if add(t) and first and t.host:
                    _nested(arg, t, g, depth, out)
                first = False
    for m in _EMAIL_SCAN_RE.finditer(text):
        if any(a <= m.start() < b for a, b in spans):
            # Part of a URL (userinfo or query). The URL's already been checked.
            continue
        addr = m.group(0)
        local, domain = addr.rsplit("@", 1)
        ip = _std_ip(domain) if domain.startswith("[") else None
        if ip is not None:
            add(Target(arg, "email", addr, str(ip), address=addr.lower(), ip=str(ip), via=via))
        else:
            host = normalise_host(domain)
            add(Target(arg, "email", addr, host, address=f"{local.lower()}@{host}", via=via))
        spans.append((m.start(), m.end()))
    if bare_hosts:
        for m in _BARE_HOST_RE.finditer(text):
            if any(a <= m.start() < b for a, b in spans):
                continue
            if not counts_as_host(m.group(1).rstrip(".").split("."), bool(m.group(2)), generic=_TLDS.get()):
                continue
            t = _url_target(arg, "https://" + m.group(0), via)
            if t is not None:
                add(Target(arg, "host", m.group(0), t.host, scheme=None, port=t.port, ip=t.ip, via=via))


def _texts(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, bytes):
        yield value.decode("utf-8", errors="replace")
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield from _texts(k)
            yield from _texts(v)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for v in value:
            yield from _texts(v)


def _decoded_views(text: str) -> List[str]:
    views = [text]
    folded = unicodedata.normalize("NFKC", text).translate(_UNICODE_DOTS)
    if folded != text:
        views.append(folded)
    for t in (unquote(text), html.unescape(text), _refang(text), _refang(html.unescape(unquote(text)))):
        if t not in views:
            views.append(t)
    return views


def extract(arg: str, value: Any) -> List[Target]:
    """Every destination hiding in one arg value."""
    out: List[Target] = []
    for text in _texts(value):
        stripped = text.strip()
        # A whole value that's just a host or an IP is a target even without a TLD we know.
        # Bare numbers like "13" aren't IPs here: only the standard dotted or
        # IPv6 forms count when the whole value stands alone.
        std_ip = _std_ip(stripped)
        if stripped and ((_HOSTNAME_ONLY_RE.match(stripped)
                          and counts_as_host(stripped.rstrip(".").split("."), False, generic=_TLDS.get()))
                         or std_ip is not None) \
                and "@" not in stripped and "/" not in stripped and not stripped.replace(".", "").isdigit() \
                or std_ip is not None:
            ip = std_ip
            out.append(Target(arg, "host", stripped, str(ip) if ip else normalise_host(stripped),
                              ip=str(ip) if ip else None))
        views = _decoded_views(text)
        if stripped and " " not in stripped and re.search(r"[\t\r\n]", stripped):
            # WHATWG and urlsplit both drop tabs and newlines inside a URL, so
            # "https://ok.com\t.evil.io" goes to ok.com.evil.io. Only for values
            # without spaces: in free text a newline is just a newline.
            views += _decoded_views(re.sub(r"[\t\r\n]", "", stripped))
        for view in views:
            _scan_text(arg, view, out)
    return out


# ---- rules --------------------------------------------------------------------


@dataclass(frozen=True)
class EgressRules:
    hosts: Tuple[str, ...] = ()
    emails: Tuple[str, ...] = ()
    schemes: FrozenSet[str] = frozenset({"https"})
    ports: FrozenSet[int] = frozenset()
    ip_literals: bool = False
    private_networks: bool = False
    provenance: Integrity = Integrity.TRUSTED
    skip_args: FrozenSet[str] = frozenset()

    # -- matching --
    def host_allowed(self, host: str) -> bool:
        return any(_host_match(p, host) for p in self.hosts)

    def email_allowed(self, address: str, domain: str) -> bool:
        for p in self.emails:
            if p == "*":
                return True
            if p.startswith("@"):
                if _host_match(p[1:], domain):
                    return True
            elif p == address:
                return True
        return False

    def port_allowed(self, scheme: Optional[str], port: Optional[int]) -> bool:
        return port is None or port == _DEFAULT_PORTS.get(scheme or "https") or port in self.ports


STRICT = EgressRules()


def _host_match(pattern: str, host: str) -> bool:
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base)
    return host == pattern


class Egress:
    """Egress rules for every tool. ``Egress.strict()`` is what you get by default."""

    def __init__(self, default: EgressRules = STRICT, tools: Optional[Mapping[str, EgressRules]] = None,
                 *, tlds: Optional[FrozenSet[str]] = None) -> None:
        self._default = default
        self._tools: Dict[str, EgressRules] = dict(tools or {})
        # Generic TLDs that count for bare hostnames. Pass tlds.load_iana(path)
        # for the full root zone. Can only add to the built-in list, never shrink it.
        self._tlds = GENERIC | frozenset(t.lower() for t in (tlds or ()))

    @classmethod
    def strict(cls) -> "Egress":
        return cls()

    def rules_for(self, tool: str) -> EgressRules:
        return self._tools.get(tool, self._default)

    # -- loading --
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Egress":
        if not isinstance(data, Mapping):
            raise ConfigError("egress config must be a JSON object.")
        extra = set(data) - {"version", "default", "tools", "description"}
        if extra:
            raise ConfigError(f"egress: unknown keys {sorted(extra)}.")
        if data.get("version") != EGRESS_VERSION:
            raise ConfigError(f"egress version must be {EGRESS_VERSION}, got {data.get('version')!r}.")
        default = _parse_rules("egress.default", data.get("default", {}))
        tools = data.get("tools", {})
        if not isinstance(tools, Mapping):
            raise ConfigError("egress.tools must be an object.")
        return cls(default, {name: _parse_rules(f"egress.tools.{name}", spec) for name, spec in tools.items()})

    @classmethod
    def from_json(cls, text: str) -> "Egress":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"egress config isn't valid JSON: {exc}") from None
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "Egress":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    # -- the two things the gate needs --
    def targets(self, tool: str, args: Mapping[str, Any], destination: Optional[str]) -> Tuple[Target, ...]:
        rules = self.rules_for(tool)
        out: List[Target] = []
        token = _TLDS.set(self._tlds)
        try:
            for name in sorted(args):
                if name in rules.skip_args:
                    continue
                out.extend(extract(name, args[name]))
            if destination is not None:
                out.extend(t for t in extract("<destination>", destination))
        finally:
            _TLDS.reset(token)
        if len(out) > _MAX_TARGETS * 4:
            out = out[: _MAX_TARGETS * 4]
            _mark_unknown("<call>", "too many destinations", None, out)
        return tuple(out)

    def check(self, tool: str, checked: Iterable[Tuple[Target, Any]],
              confirming: FrozenSet[str] = frozenset()) -> Optional[Tuple[str, str, str]]:
        """First failure as ``(reason_code, rule_id, detail)``, or None if all's fine.

        ``checked`` pairs each target with its registry ``Resolution``.
        ``confirming`` lists args the policy's already sending to the person
        for confirmation, where a pure coincidence is acceptable.
        """
        rules = self.rules_for(tool)
        rid = f"egress.{tool}"
        for t, res in checked:
            where = f"{t.arg}: {t.address or t.host}"
            if t.host == UNKNOWN_HOST:
                return "EGRESS_NOT_ALLOWED", f"{rid}.hosts", f"{t.arg}: destination can't be read to the end"
            if t.kind == "url" and not t.host and t.ip is None:
                # No host (file:, data:, javascript:...): nothing on a host list can allow it.
                if (t.scheme or "https") not in rules.schemes:
                    return "EGRESS_BAD_SCHEME", f"{rid}.schemes", f"{t.arg}: {t.raw[:40]} ({t.scheme})"
                return "EGRESS_NOT_ALLOWED", f"{rid}.hosts", f"{t.arg}: {t.raw[:40]}"
            if t.ip is not None:
                ip = ipaddress.ip_address(t.ip)
                if not rules.private_networks and _is_private_ip(ip):
                    return "EGRESS_PRIVATE_NETWORK", f"{rid}.private_networks", where
                if not rules.ip_literals:
                    return "EGRESS_IP_LITERAL", f"{rid}.ip_literals", where
            elif not rules.private_networks and _is_private_name(t.host):
                return "EGRESS_PRIVATE_NETWORK", f"{rid}.private_networks", where
            if t.kind == "url" and (t.scheme or "https") not in rules.schemes:
                return "EGRESS_BAD_SCHEME", f"{rid}.schemes", f"{where} ({t.scheme})"
            if t.kind == "url" and not rules.port_allowed(t.scheme, t.port):
                return "EGRESS_NOT_ALLOWED", f"{rid}.ports", f"{where}:{t.port}"
            if t.kind == "email":
                if not rules.email_allowed(t.address or "", t.host):
                    return "EGRESS_NOT_ALLOWED", f"{rid}.emails", where
            elif t.ip is None and not rules.host_allowed(t.host):
                return "EGRESS_NOT_ALLOWED", f"{rid}.hosts", where
            integrity = res.label.integrity
            if integrity > rules.provenance:
                if res.only_coincidence and t.arg in confirming:
                    continue
                return "EGRESS_UNTRUSTED", f"{rid}.provenance", where
        return None


def _is_private_ip(ip: Any) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_unspecified or ip.is_multicast
            or (getattr(ip, "ipv4_mapped", None) is not None and _is_private_ip(ip.ipv4_mapped)))


def _is_private_name(host: str) -> bool:
    return host == "localhost" or host.endswith(_PRIVATE_SUFFIXES) or "." not in host


def _parse_rules(where: str, spec: Any) -> EgressRules:
    if not isinstance(spec, Mapping):
        raise ConfigError(f"{where}: must be an object.")
    extra = set(spec) - _KEYS
    if extra:
        raise ConfigError(f"{where}: unknown keys {sorted(extra)}. Allowed: {sorted(_KEYS)}.")

    def str_list(key: str) -> List[str]:
        v = spec.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            raise ConfigError(f"{where}.{key}: must be a list of non-empty strings.")
        return [x.strip() for x in v]

    hosts = []
    for h in str_list("hosts"):
        if h == "*":
            hosts.append(h)
            continue
        wild = h.startswith("*.")
        base = h[2:] if wild else h
        if "*" in base or "/" in base or "@" in base or ":" in base:
            raise ConfigError(f"{where}.hosts: {h!r} isn't a host. Use 'acme.com', '*.acme.com' or '*'.")
        norm = normalise_host(base)
        hosts.append(("*." + norm) if wild else norm)

    emails = []
    for e in str_list("emails"):
        if e == "*":
            emails.append(e)
        elif e.startswith("@"):
            dom = e[1:]
            wild = dom.startswith("*.")
            base = dom[2:] if wild else dom
            if not base or "*" in base or "@" in base:
                raise ConfigError(f"{where}.emails: {e!r} isn't valid. Use '@acme.com' or '@*.acme.com'.")
            emails.append("@" + (("*." if wild else "") + normalise_host(base)))
        elif _EMAIL_RE.fullmatch(e):
            local, dom = e.rsplit("@", 1)
            emails.append(f"{local.lower()}@{normalise_host(dom)}")
        else:
            raise ConfigError(f"{where}.emails: {e!r} isn't an address, '@domain' or '*'.")

    schemes = [s.lower() for s in str_list("schemes")] if "schemes" in spec else ["https"]
    if not schemes:
        raise ConfigError(f"{where}.schemes: can't be empty.")

    ports = spec.get("ports", [])
    if not isinstance(ports, list) or not all(isinstance(p, int) and not isinstance(p, bool)
                                               and 0 < p < 65536 for p in ports):
        raise ConfigError(f"{where}.ports: must be a list of port numbers.")

    for flag in ("ip_literals", "private_networks"):
        if not isinstance(spec.get(flag, False), bool):
            raise ConfigError(f"{where}.{flag}: must be true or false.")

    level = spec.get("provenance", "TRUSTED")
    if level not in _LEVELS:
        raise ConfigError(f"{where}.provenance: must be one of {sorted(_LEVELS)}.")

    return EgressRules(
        hosts=tuple(hosts),
        emails=tuple(emails),
        schemes=frozenset(schemes),
        ports=frozenset(ports),
        ip_literals=spec.get("ip_literals", False),
        private_networks=spec.get("private_networks", False),
        provenance=_LEVELS[level],
        skip_args=frozenset(str_list("skip_args")),
    )
