# Changelog

*English (UK) only, it's a log. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [SemVer](https://semver.org/). Before 1.0, a minor bump may break things, and it'll say so here.*

## [Unreleased]

## [0.1.3] - 2026-09-30

### Fixed
- An IBAN written in lower case, or with its first blocks run together, could have its tail read as a trusted phone number.

### Changed
- READMEs use full links so they work on PyPI. Package metadata links to the docs, the benchmark and the cookbook.

## [0.1.2] - 2026-09-28

### Changed
- Reverted the 0.1.1 change to grouped numbers. A grouped number now matches without spaces exactly when it matches with them. Picking part of such a number is a documented limit (see `docs/threat-model.md`).

### Fixed
- A comma or semicolon ends a grouped number.
- The tail of a grouped IBAN is no longer read as a phone number, and "+44-20-7946-0958" is no longer taken for a date.

## [0.1.1] - 2026-09-28

### Fixed
- Part of a grouped number (an IBAN, a card) was trusted without its spaces.

## [0.1.0] - 2026-09-25

First public release: labels and channels, the context registry (mode B), the gate, declarative policy, egress checks, the evidence log and its CLI, sealed plans (mode A), the Python decorator and MCP server middleware, docs in English and Portuguese, and the benchmark. See the [README](https://github.com/macmaia/catraca/blob/v0.1.0/README.md) for what each part does and its known limits.

[Unreleased]: https://github.com/macmaia/catraca/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/macmaia/catraca/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/macmaia/catraca/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/macmaia/catraca/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/macmaia/catraca/releases/tag/v0.1.0
