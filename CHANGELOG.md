# Changelog

*English (UK) only, it's a log. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [SemVer](https://semver.org/). Before 1.0, a minor bump may break things, and it'll say so here.*

## [Unreleased]

## [0.1.3] - 2026-09-30

### Fixed
- The guard that keeps the tail of an IBAN from being read as a phone number now works whatever the case of the letters ("gb29 nwbk 6016 ..."), and when the country and bank blocks are written together ("GB29NWBK 6016 ..."). Before, those forms let the tail through as a trusted phone number.

### Added
- Regression tests for the three grouped-number fixes in 0.1.2.

### Docs
- The READMEs use full links, so they work on the PyPI page too, and link to the cookbook.
- The README lists three more things still to come: a standalone MCP proxy, the token cost of mode A next to CaMeL, and a reference customer-service agent run with and without catraca.
- Package metadata: a clearer summary, more keywords and classifiers, and links to the documentation, the benchmark and the cookbook.

## [0.1.2] - 2026-09-28

### Changed
- The 0.1.1 change to grouped numbers is withdrawn. It refused a few blocks out of a longer number only when they were passed without spaces, while the same blocks with their spaces were always trusted as whole tokens of the user's text, so it protected nothing and let some legitimate numbers through only in part. A grouped number now matches without its spaces exactly when it would match with them. The threat model and the reference now say plainly that part of a number written in blocks can be picked, which is a case of choosing among trusted values.

### Fixed
- A comma or semicolon between blocks ends a grouped number, so two numbers the user wrote can't be joined into one.
- The phone-number rule no longer reads the tail of a longer grouped number (an IBAN written with dashes or spaces) as a phone number of its own, and no longer mistakes "+44-20-7946-0958" for a date.

## [0.1.1] - 2026-09-28

### Fixed
- A number written in groups (an IBAN, a card, a phone number) is now trusted only as the whole run. Before, a few blocks out of the middle or either end, such as `NWBK60161331` from "GB29 NWBK 6016 1331 9268 19", came out trusted, which contradicted the threat model.

## [0.1.0] - 2026-09-25

First public release.

### Added
- Labels and channels: an integrity lattice, confidentiality scopes, and channel config in JSON, validated on load.
- Context registry (mode B): per-window provenance, normalisation and decoded variants, audited `forget`, and summaries that carry the join of what they replace. A consequential arg is trusted only when the value appears as whole tokens of a trusted snippet, with case, width and grouping spaces folded (grouping only for mostly numeric values such as IBANs, cards and phones). Values that change under NFKC folding are never trusted. Registry state can move between processes with `export_state` and `from_state`, HMAC-checked, and is never restored looser than the current channel config.
- The gate: ALLOW, DENY or REQUIRE_CONFIRMATION, failing closed. Single-use confirmation tokens bound to the call, with a small `PendingBackend` protocol for a shared store. `adecide` and `acheck` for async code, `on_decision` and `counts()` for monitoring, and ERROR logs on the `catraca` logger when the gate itself is unhealthy. Passing something that isn't an evidence log as `evidence=` is refused at construction.
- Declarative policy with strict defaults, typed args (`integer`, `number`, `boolean`, `date`, with `min` and `max`) and `lint()`.
- Egress: URLs, hosts and emails pulled out of every arg, including free text, redirectors (unwrapped three levels deep, anything deeper is denied), scheme-relative `//host` links, bare hosts in redirector queries, host-less schemes, IDN and IP forms, and the ways browsers and `urlsplit` read the same URL differently. More than 64 destinations in one arg are denied rather than checked in part. The allowlist denies everything by default and hosts are never resolved.
- Evidence: hash-chained JSONL with HMAC digests of values, pseudonymised users and tenants, destinations cut to scheme and host, a linear redactor capped at 4,096 characters, signed checkpoints, `verify`, `replay`, `stats`, ECS and CEF export, and the `catraca-evidence` CLI. File sinks refuse symlinks, roll back a failed write and repair a torn last line.
- Adapters: a Python decorator (sync and async, `functools.partial` aware) and MCP server middleware with signed labels that cover the tool, the args and a timestamp.
- Mode A: sealed plans, validated at seal and before every step.
- Docs: architecture, threat model, related work, audit and privacy, reference, security policy, in English and Portuguese.
- Benchmark: `python -m bench.report --check`, with a hand-written bank, a bank generated from AgentDojo injection goals, a benign bank for false positives, and 95% Wilson intervals.
- `ContextRegistry.observe(window)`: checks the registry against the texts the model really has. Text nobody annotated comes in as UNTRUSTED, and `forget` is refused while the text is still visible, so a missing or false annotation makes mode B stricter instead of weaker.
- The host of a URL the user wrote, and a phone number with the same digits re-punctuated, count as the user's own value.
- Relaxed args that can't fail against the whole window's label skip piece-by-piece resolution, which makes long free-text bodies much faster.
- Type hints ship with the package (`py.typed`), checked with mypy in CI, and the code is linted with ruff.
- `docs/decisions.md`: the design decisions, why each was taken and what it costs.

### Not in this release
- Adapters for Cedar, OPA, LangGraph and AgentDojo, and the AgentDojo run with a real model.

### Known limits
- Mode B doesn't catch paraphrase or translation, and can't tell which of the user's own values was meant. See `docs/threat-model.md`.
- The AgentDojo run with a real model hasn't been published yet. See `BENCHMARK.md`.

[Unreleased]: https://github.com/macmaia/catraca/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/macmaia/catraca/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/macmaia/catraca/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/macmaia/catraca/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/macmaia/catraca/releases/tag/v0.1.0
