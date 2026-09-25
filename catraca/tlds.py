"""Which dotted words in free text count as hostnames.

A bare ``name.tld`` in a body of text is a destination if the last label is a
real top-level domain. The trouble is that plenty of TLDs look like file
extensions or code (``.py``, ``.md``, ``.sh``, ``.zip``, ``.name``), so:

* Two-letter labels are treated as country codes, all of them. That's the
  strict reading: we'd rather flag ``evil.cc`` than miss it.
* Longer labels count if they're in ``GENERIC``. It's a curated list, not the
  whole IANA root zone, and CI checks it against IANA so it doesn't drift
  (``python -m catraca.tlds check tlds-alpha-by-domain.txt``). You can also load
  the IANA file at runtime with ``load_iana()``.
* Labels in ``LOOKS_LIKE_A_FILE`` (``.py``, ``.md``, ``.zip``...) only count when
  there's a second sign it's a host: a path or query right after it, or a
  subdomain (three labels or more). ``script.py`` stays text,
  ``files.evil.zip`` and ``evil.sh/x`` don't.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import FrozenSet, Iterable, Union

GENERIC: FrozenSet[str] = frozenset("""
com net org edu gov mil int arpa info biz name pro aero asia cat coop jobs mobi museum post tel travel xxx
io ai app dev xyz online site shop store tech cloud link click live top club page email example test invalid
localhost onion blog news media digital network systems solutions services support agency company group
global world today space website web host hosting server domains download download software codes tools
zone center city life love work works art design studio photo photos pics pictures video tube stream
games game fun fan fans chat social community forum wiki review reviews guide guru expert academy school
education college university institute training courses study science technology engineering finance
financial bank money capital fund investments loan loans credit cash insure insurance tax accountant
legal law lawyer attorney health care clinic doctor dental hospital fitness bio eco energy solar green
gold silver diamonds jewelry fashion clothing shoes style beauty hair makeup spa luxury vip shopping
market markets trade trading exchange deals sale discount coupons promo gift gifts cards casino bet poker
lotto win party events tickets travel tours holiday vacations flights cruises hotel hotels rentals
house home homes properties property realty estate land farm garden kitchen restaurant cafe
bar pub pizza food recipes wine beer vodka coffee family kids baby dog pet pets vet horse
auto autos car cars bike motorcycles taxi limo parts repair tires energy computer phone mobile
cyber security safe secure protection audio radio tv film movie mov theater gallery graphics
consulting management marketing partners ventures holdings industries enterprises international
directory company email mail report reports report today one plus pro red blue black pink green
support help info tips how best cool fyi lol wtf rocks ninja zip foo meme page run icu cyou buzz monster
rest cfd sbs quest bond skin hair lat cam bid win vip ltd llc inc gmbh srl sarl
google gle goog youtube android chrome gmail microsoft azure windows office bing xbox skype apple icloud
amazon aws prime kindle facebook netflix visa mastercard amex
""".split())

LOOKS_LIKE_A_FILE: FrozenSet[str] = frozenset("""
py md sh js ts rs rb pl go cs fs hs ml mk ps so cc
zip mov app name pdf txt log csv json yaml yml xml html htm css toml lock ini cfg conf env bak tmp
docx xlsx pptx doc xls ppt png jpg jpeg gif svg mp3 mp4 wav exe dll jar java cpp php sql db bin iso dmg
""".split())


def is_tld(label: str, *, generic: FrozenSet[str] = GENERIC) -> bool:
    t = label.lower()
    if len(t) == 2 and t.isalpha():
        return True
    return t in generic or t.startswith("xn--")


def counts_as_host(labels: Iterable[str], has_path: bool, *, generic: FrozenSet[str] = GENERIC) -> bool:
    parts = [p for p in labels if p]
    if len(parts) < 2 or not is_tld(parts[-1], generic=generic):
        return False
    if parts[-1].lower() in LOOKS_LIKE_A_FILE:
        return has_path or len(parts) >= 3
    return True


def load_iana(path: Union[str, Path]) -> FrozenSet[str]:
    """Read IANA's ``tlds-alpha-by-domain.txt`` into a set of lower-case labels."""
    out = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line.lower())
    if len(out) < 500:
        raise ValueError(f"{path} has only {len(out)} TLDs, doesn't look like the IANA list.")
    return frozenset(out)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "check":
        print("usage: python -m catraca.tlds check tlds-alpha-by-domain.txt", file=sys.stderr)
        return 2
    iana = load_iana(args[1])
    longer = {t for t in iana if len(t) > 2 and not t.startswith("xn--")}
    covered = {t for t in longer if t in GENERIC}
    brand_or_niche = longer - covered
    stale = {t for t in GENERIC if t not in iana and t not in {"example", "test", "invalid", "localhost", "onion"}}
    print(f"IANA: {len(iana)} TLDs, {len(longer)} generic. Curated list covers {len(covered)}.")
    print(f"Not in the curated list (caught only with load_iana): {len(brand_or_niche)}")
    if stale:
        print("In the curated list but not in IANA any more: " + ", ".join(sorted(stale)))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
