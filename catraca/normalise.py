"""Normalisation.

``normalise`` gives the canonical form we compare on. Think of it as a
matching skeleton rather than something to read: Unicode compatibility (NFKC),
invisible format chars stripped, common homoglyphs folded, accents dropped,
case folded, leetspeak folded (0/o, 1/i/l, 3/e, 4/@/a, 5/$/s, 7/t, 8/b), and
anything that isn't a letter or digit thrown away. Both sides of every
comparison go through the same fold, so "th13f@3v1l.io" and "thief@evil.io"
end up identical without any extra index entries.

``variants`` returns the canonical form plus the decoded forms that actually
turn up in attacks: URL percent-encoding, HTML entities, ``\\uXXXX`` and
``\\xXX`` escapes, base64 chunks, punycode labels (``xn--``), defanged
addresses ("name [at] host [dot] com", "hxxp://") and rot13. Extra variants only ever help us find *more* matches. They never grant
trust on their own, so it's fine for them to be a bit greedy.

rot13 is its own inverse, so it's only applied to the value being resolved,
never to indexed snippets. That keeps the index from doubling in size.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from typing import List
from urllib.parse import unquote

# Homoglyphs you actually see in obfuscation (Cyrillic and Greek lookalikes).
# Short list on purpose. NFKC already deals with full-width and maths forms.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
        "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
        "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    }
)

_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}")
_MAX_URL_ROUNDS = 3
_DEFANG_AT = re.compile(r"\s*[\[\(\{<]\s*at\s*[\]\)\}>]\s*|\s+at\s+(?=[\w.-]+\s*(?:[\[\(\{<]\s*dot|\s+dot\s|\.\w))", re.I)
_DEFANG_DOT = re.compile(r"\s*[\[\(\{<]\s*(?:dot|\.)\s*[\]\)\}>]\s*|\s+dot\s+", re.I)
_DEFANG_SCHEME = re.compile(r"\bhxxp(s?)\b", re.I)
_PUNY_RE = re.compile(r"xn--[a-z0-9-]+", re.IGNORECASE)

# Leetspeak fold, applied after case folding. "1", "i" and "l" all collapse to
# "i" because "1" could stand for either letter.
_LEET = str.maketrans({"0": "o", "1": "i", "l": "i", "3": "e", "4": "a", "@": "a",
                       "5": "s", "$": "s", "7": "t", "8": "b"})


_NON_ALNUM_ASCII = re.compile(r"[^a-z0-9]+")


def normalise(text: str) -> str:
    if text.isascii():
        # Fast path. Plain ASCII has no format chars, accents or homoglyphs,
        # and NFKC leaves it alone, so we can skip straight to the fold.
        return _NON_ALNUM_ASCII.sub("", text.lower().translate(_LEET))
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
    t = t.translate(_HOMOGLYPHS)
    t = unicodedata.normalize("NFD", t)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Mn")
    t = t.casefold().translate(_LEET)
    return "".join(ch for ch in t if ch.isalnum())


def _url_decode(text: str) -> str:
    current = text
    for _ in range(_MAX_URL_ROUNDS):
        nxt = unquote(current.replace("+", " "))
        if nxt == current:
            break
        current = nxt
    return current


def _unescape(text: str) -> str:
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(0)[2:], 16)), text)


def _punycode(text: str) -> str:
    """Decode any ``xn--`` label back to Unicode. Bad labels are left as they are."""

    def swap(m: "re.Match[str]") -> str:
        try:
            return m.group(0)[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return m.group(0)

    return _PUNY_RE.sub(swap, text)


def _refang(text: str) -> str:
    """Undo the usual defanging: [at], (dot), [.], " at ... dot ", hxxp."""
    t = _DEFANG_SCHEME.sub(lambda m: "http" + m.group(1), text)
    t = _DEFANG_AT.sub("@", t)
    return _DEFANG_DOT.sub(".", t)


def _base64_chunks(text: str) -> List[str]:
    out = []
    for m in _B64_RE.finditer(text):
        chunk = m.group(0)
        padded = chunk + "=" * (-len(chunk) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(padded)
            except (binascii.Error, ValueError):
                continue
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if decoded and all(ch.isprintable() or ch.isspace() for ch in decoded):
                out.append(decoded)
                break
    return out


def variants(text: str, *, for_index: bool = False) -> List[str]:
    """Canonical form first, then any distinct, non-empty decoded forms.

    ``for_index=True`` is what the registry uses for snippets. It skips the
    variants that only need applying on one side (rot13).

    Each decoder only runs when its trigger shows up in the text, which keeps
    annotation of big documents cheap.
    """
    primary = normalise(text)
    candidates = []
    url = _url_decode(text) if ("%" in text or "+" in text) else text
    if url != text:
        candidates.append(url)
    if "&" in text or "&" in url:
        candidates.append(html.unescape(text))
        candidates.append(html.unescape(url))
    if "\\" in text:
        candidates.append(_unescape(text))
    if "xn--" in url.lower():
        candidates.append(_punycode(url))
    refanged = _refang(text)
    if refanged != text:
        candidates.append(refanged)
    if not for_index:
        candidates.append(codecs.encode(text, "rot13"))
    candidates.extend(_base64_chunks(text))

    seen = [primary]
    for c in candidates:
        if c == text:
            continue
        n = normalise(c)
        if n and n not in seen:
            seen.append(n)
    return seen
