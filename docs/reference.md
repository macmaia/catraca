# catraca reference

*English (UK). [Leia em português](reference.pt-BR.md). Back to the [README](../README.md).*

Everything the README leaves out: how each piece behaves, its defaults and how to loosen them.

## The gate

`Gate.decide()` always hands back a `Decision` and never raises. `Gate.check()` does the same thing but raises `CallDenied` or `ConfirmationRequired` for anything that isn't ALLOW.

Three verdicts, not two: `ALLOW`, `DENY`, `REQUIRE_CONFIRMATION`. A `Decision` refuses to act as a bool (`if decision:` raises `TypeError`), so nobody can quietly read "needs confirmation" as "go ahead".

`REQUIRE_CONFIRMATION` only fires in one narrow case: the value has trusted provenance end to end and it's only flagged because the same value also shows up in untrusted content (a coincidence, not a derivation). The decision carries the literal value and the trusted origin behind it. If a policy asks for confirmation on anything else, the gate turns it into a deny.

### Watching the gate

`Gate(..., on_decision=fn)` calls `fn(decision)` after every decision is recorded. Use it for metrics or alerts. It can't change the verdict, and if it raises, the error is logged and ignored. `gate.counts()` gives decisions so far by reason code. The gate also logs to the `catraca` logger at ERROR level whenever it's unhealthy rather than strict: `INTERNAL_ERROR`, `EVIDENCE_UNAVAILABLE` and `INVALID_POLICY_RESULT`. Alert on those. A spike in them means the gate is denying everything because something is broken, not because calls are bad.

### Confirmation round trip

`REQUIRE_CONFIRMATION` comes with `decision.confirmation_token`. It's single use, it expires (5 min by default) and it's bound to the call id, tool, caller, destination and a SHA-256 fingerprint of every arg value. Once the person says yes, call `decide`/`check` again with the same call and `confirmation=token`. The gate re-evaluates from scratch against the current window and only allows it (reason `CONFIRMED_BY_USER`) if it still lands on the same coincidence for the same args. Swap a value, change the destination, reuse the token or let it expire and you get a deny. Redeeming always burns the token, match or no match. `gate.decline(token)` is the "no" button. Tokens never show up in `to_dict()` or repr, so they don't end up in logs.

It fails closed. Any exception inside the gate, or a policy that returns something other than a proper `PolicyResult`, ends up as DENY. There's exactly one place in the code that can return ALLOW.

Each decision carries its own latency in µs (`elapsed_us`). `python -m bench.latency` measures p99 on a realistic window.

### Reason codes

These are stable. We'll add new ones, never rename.

| Code | Meaning |
|---|---|
| `ALLOWED_BY_POLICY` | a policy rule allowed the call |
| `UNKNOWN_TOOL` | the tool isn't in the policy |
| `UNTRUSTED_ARGUMENT` | a consequential arg has untrusted provenance |
| `COINCIDENCE` | the value's trusted but also shows up in untrusted content, so confirmation's needed |
| `NO_POLICY_MATCH` | a custom `Policy` didn't allow it |
| `INTERNAL_ERROR` | something broke inside the gate and it failed closed |
| `INVALID_POLICY_RESULT` | the policy returned something unusable |
| `CONFIRMATION_NOT_ELIGIBLE` | the policy asked for confirmation outside the coincidence case |
| `CONFIRMED_BY_USER` | the person confirmed the literal value and the call still matches |
| `CONFIRMATION_INVALID` | the token's unknown, expired or already used |
| `CONFIRMATION_MISMATCH` | the call isn't the one the person confirmed |
| `CALLER_NOT_ALLOWED` | tenant or user isn't in the tool's `callers` |
| `UNDECLARED_ARGUMENT` | the call has an arg the policy doesn't declare |
| `ARGUMENT_CONSTRAINT` | a value fails `one_of` or `pattern` |
| `CONFIDENTIALITY_VIOLATION` | an arg carries data that can't flow to the required scope |
| `DESTINATION_NOT_ALLOWED` | `destination` isn't in the tool's `destinations` |
| `EGRESS_NOT_ALLOWED` | a host, address or port isn't on the egress allowlist |
| `EGRESS_BAD_SCHEME` | a URL uses a scheme that isn't allowed (`https` only by default) |
| `EGRESS_IP_LITERAL` | a destination is a raw IP |
| `EGRESS_PRIVATE_NETWORK` | a destination is localhost, a private range, cloud metadata or `.internal`-style |
| `EGRESS_UNTRUSTED` | a destination came from untrusted content, even if its host is allowed |
| `EVIDENCE_UNAVAILABLE` | the decision couldn't be written to the evidence log, so the call was denied |

## The policy

`DeclarativePolicy` is the built-in evaluator: JSON in, deterministic verdict out, no deps, nothing over the network. It validates the whole file on load and refuses to start with a message that says what to fix. See `examples/policy.json`.

### Strict by default, loosen on purpose

You only need this section to make things *looser*. Leave a field out and you get the strict behaviour.

| Field | Default (strict) | How to loosen |
|---|---|---|
| tool not listed | denied (`UNKNOWN_TOOL`) | add it under `tools` |
| `callers` | required, no implicit "anyone" | `{"tenants": "*", "users": "*"}` |
| arg the policy doesn't declare | denied (`UNDECLARED_ARGUMENT`) | declare it (`{}` keeps the strict defaults) |
| `integrity` | `"TRUSTED"` | `"STRUCTURED"` or `"ANY"` |
| `match` | `"whole"`, one trusted snippet, contiguous | `"partial"` |
| `flow_to` | `["tenant:{tenant}"]`, data must be readable by the caller's tenant | other scopes, e.g. `["user:{user}"]`, or `[]` to switch it off |
| `destinations` | `[]`, so `destination` has to be empty | list the ones you allow |
| `confirm_on_coincidence` | `false`, a coincidence is denied | `true` to ask the person instead |
| `one_of`, `pattern` | none | these only ever add restrictions |
| `type`, `min`, `max` | none | also restrictions: `"integer"`, `"number"`, `"boolean"` or `"date"` (ISO), with bounds for numbers and dates |

Checks run in a fixed order and the first failure wins: caller, undeclared args, destination, `one_of`/`pattern`/`type`, then per arg `flow_to` and integrity. `pattern` is a full match.

### Harmless args without the provenance check

Strict defaults deny a `limit=10` the model picked itself, or a date it worked out from "tomorrow", because neither appears in the user's words. The tempting fix is `"integrity": "ANY"`, which lets anything through. A typed rule keeps a tight box instead:

```json
"limit": {"integrity": "ANY", "type": "integer", "min": 1, "max": 50},
"day":   {"integrity": "ANY", "type": "date", "min": "2026-01-01", "max": "2027-12-31"},
"urgent": {"integrity": "ANY", "type": "boolean"}
```

Numbers sent as text (`"10"`) are accepted when they parse cleanly. `lint()` warns about a typed number from any source without both bounds. Don't do this for anything that says *where* or *who* (recipients, accounts, URLs): those should keep `TRUSTED`.

### Lint

`policy.lint()` returns warnings for review. It never blocks anything. It flags tools any tenant can call, args whose names look like destinations (`to`, `url`, `iban`, `path` and friends) that accept any integrity or partial matching, and args with `flow_to` switched off. Pass `lint(samples={"tool": [args, ...]})`, say a few logged calls, and it also checks relaxed args by value: emails, URLs, IBANs, file paths and phone numbers.

### Your own evaluator

`Gate` takes anything that follows the `Policy` protocol (`relaxed_args(tool)` and `evaluate(request)`), so an existing policy engine can sit behind it. The gate still applies egress and evidence whatever the evaluator says.

## Egress

The policy looks at args one at a time. The egress gate asks a different question: where does this call actually send things? It runs after the policy, on every call, and it's engine-agnostic, so it sits behind any custom `Policy` too.

It digs destinations out of every arg, including free text the policy relaxed: URLs, `www.` hosts, bare hostnames (any two-letter country code, plus a curated list of generic TLDs that CI checks against IANA, pass `Egress(tlds=tlds.load_iana(path))` for the full root zone, and file-like endings such as `.sh` or `.zip` need a path or a subdomain to count), email addresses, Markdown links and images (reference-style too, which is how EchoLeak got out), HTML `href`/`src`, and URLs tucked inside other URLs (redirectors, preview proxies, three levels deep). Anything it can't read to the end is denied as `EGRESS_NOT_ALLOWED`: a URL nested deeper than that, or more than 64 destinations in one arg (256 in one call), since those are too many to check one by one. Scheme-relative links (`//host/path`) count too, on their own or in free text. It reads text as-is and again after URL-decoding, HTML-unescaping and refanging. Hosts are compared the way a client sees them: userinfo dropped (`https://acme.com@evil.io` is `evil.io`), backslashes read as slashes, IDN turned into punycode (a Cyrillic lookalike never matches the real domain), IPs recognised in dotted, decimal, hex and octal.

Then each destination is checked against the tool's rules and against its provenance. A destination copied from retrieved content is denied even when its host is allowed. The one exception is a pure coincidence the policy is already sending for confirmation.

### Strict by default, loosen on purpose

With no egress config, any destination at all denies the call. See `examples/egress.json`.

| Key | Default (strict) | How to loosen |
|---|---|---|
| `hosts` | `[]` | `"acme.com"`, `"*.acme.com"` (subdomains only), `"*"` |
| `emails` | `[]` | `"@acme.com"`, `"@*.acme.com"`, `"ana@acme.com"`, `"*"` |
| `schemes` | `["https"]` | add `"http"` and so on |
| `ports` | the scheme's own | list extra ports |
| `ip_literals` | `false` | `true` |
| `private_networks` | `false` | `true` (localhost, RFC 1918, link-local incl. `169.254.169.254`, `.local`, `.internal`...) |
| `provenance` | `"TRUSTED"` | `"STRUCTURED"` or `"ANY"` |
| `skip_args` | `[]` | args not to scan |

Rules go per tool under `tools`, with an optional `default` for tools not listed. Loosening the policy (say `"integrity": "STRUCTURED"` on `to`) doesn't loosen egress, and vice versa. Each has to be written down.


A named destination like `"smtp"` in the call's `destination` isn't a network target, so only the policy's `destinations` list applies to it. If `destination` is a URL, host or address, it goes through egress too, provenance included.

## Evidence

Every decision, allowed or denied, goes to the evidence log. If the write fails, the call is denied with `EVIDENCE_UNAVAILABLE`. A gate built without a log warns you, and `evidence=None` switches that off on purpose.

A record holds enough to explain the decision without the data that was in the call: who (tenant, user as a digest), tool, verdict, reason, rule, latency, and for every arg its label, rule, coverage, origins, consequential and coincidence flags, plus a keyed digest and the length of the value. Egress targets keep kind, host and integrity, with addresses as digests. The window shows up as channels and the residual label, no text. `evidence.replay(record, policy)` re-runs the policy stage from a record alone and lands on the same verdict, reason and rule.

Records are chained (`seq`, `prev`, `hash`), so a line deleted, reordered or edited in the middle fails `verify`. Lines cut off the start or the end of the log don't break the chain, and neither does rebuilding the whole thing: that's what checkpoints are for (below). The file sinks append with `O_APPEND`, fsync each write and create files as 0600. `RotatingJsonlSink(dir, max_bytes=...)` starts a new file when one fills up and keeps the chain running across files.

The sinks refuse to write through a symlink (`O_NOFOLLOW`), so nobody with access to the log folder can redirect the records elsewhere. If a write fails halfway (disk full), the file is cut back to where it was and the call is denied. If the process died mid-write, the torn last line is moved to `<file>.torn` when the sink opens, so the log still starts cleanly. Each sink assumes it's the only writer of its file.

`fsync_every=<seconds>` on either sink trades durability for throughput: every record is still written before the call goes ahead, so a crashed process loses nothing, but a power cut can lose up to that many seconds. The default, 0, syncs every record. Free text in a record is capped at 4,096 characters (`[TRUNCATED n chars]`), which also keeps redaction cost bounded whatever an attacker puts in a value.

The chain can't catch someone who rewrites the whole log and rebuilds it. For that, take a checkpoint now and then with `log.checkpoint(anchor_key)` and keep it somewhere else (a ticket, a bucket with object lock, a signed timestamp). `verify(..., anchor=cp, anchor_key=...)` then proves the log still holds that exact record. A checkpoint without `anchor_key` is refused, since whoever rewrote the log could have written it too. `trust_unsigned_anchor=True` accepts it when it came from a store only you can write.

Replay works with pseudonymised users and tenants too: callers are checked first, so the recorded reason says how that check went, and rules that name specific users replay without the real ids. Be clear about what that means: for the caller check (and for a destination cut down to its host) replay reads the outcome from the record rather than recomputing it, so it matches by construction. The integrity, confidentiality and egress checks are recomputed. For privacy, retention and what the log proves, see [audit-and-privacy.md](audit-and-privacy.md).

| Setting | Default (strict) | How to loosen |
|---|---|---|
| arg values | never written, only a keyed digest and the length | `include_preview=True` writes a redacted preview |
| user and tenant ids | keyed digest, and the same for `tenant:`/`user:` names inside labels | `pseudonymise_users=False` |
| `destination` | scheme, host and port only, the rest is dropped | `include_preview=True` |
| digest key | random per process | pass `key=` (16+ bytes, keep it out of the log) to correlate across runs |
| redaction of free text (`detail`, window values) | built-in scrubber: emails, CPF and CNPJ (check digits validated), RG, CEP, phones, IPv4 and IPv6, IBANs, cards (Luhn), API keys, JWTs, bearer tokens, `password=`-style pairs, and any other run of 10+ digits. It does **not** catch names, addresses or other free-form personal data | `redactor=` with a proper PII tool, e.g. `tarja_redactor()` (experimental) |

```
python -m catraca.evidence verify decisions.jsonl
python -m catraca.evidence verify logs/decisions-*.jsonl --anchor cp.json --anchor-key-env CATRACA_ANCHOR_KEY
python -m catraca.evidence stats  decisions.jsonl   # includes the coincidence rate
python -m catraca.evidence export --format ecs decisions.jsonl   # or cef
```

`stats` reports `coincidence_rate`, the share of decisions blocked or sent for confirmation only because of a coincidence. If it's high, the policy's written wrong, not the world. It's a product metric, not a security one.

## Mode A, the sealed plan

```python
from catraca.plan import Plan, PlanRunner, Schema, Step, ask, lit, ref

plan = Plan([
    Step("read_ticket", {"ticket_id": lit("7781")}),
    Step("send_email", {"to": lit("ana@acme.com.br"),
                        "body": ask("Summarise the ticket", ref(0, "text"), Schema.text(300))}),
], policy=policy, request="Summarise ticket 7781 and email it to me")

runner = PlanRunner(Gate(None, policy, egress=egress, evidence=log), tools, caller=caller,
                    seal_key=key, quarantine=q_llm, approve=ask_the_person)
result = runner.run(plan.seal(key))
```

* Args are `lit(...)` (fixed now, trusted), `ref(step, *path)` (an earlier step's output, untrusted), `ask(instruction, source, schema)` (a value pulled out of untrusted data by the quarantine model, which has no tools and whose answer has to fit the schema) or `confirm(...)` (a person approves the literal value, then it counts as trusted).
* Consequential args (anything the policy doesn't relax) must be `lit` or `confirm`. So destinations are fixed before anything untrusted is read, or a human signs them off. A plan that breaks this doesn't build.
* `seal(key)` freezes the plan (canonical encoding, SHA-256, HMAC). The runner decodes its own copy, checks the seal before the run and before every step, and has no way back to the planner.
* Every step still goes through the gate (policy, egress, evidence) with labels fixed at the edges. So an address the quarantine was tricked into writing in a body is stopped by egress.
* `plan_with(planner, request, policy=..., tools=...)` asks a planner model for the plan. It only ever sees the request and the tool list.

Limits: plans are straight-line, no loops or branches that depend on data. Side channels (how many steps ran, timing, which step failed) aren't covered, same as CaMeL. The utility cost on AgentDojo hasn't been measured yet.

## Adapters

| Adapter | Where | Notes |
|---|---|---|
| Python decorator | `catraca.adapters.python.guarded` | `guarded(gate, caller=fn, tool=None, destination=None, approve=None)`. `caller` is a function with no args that returns the `Caller` for the current request, called on every call. `approve(decision)` shows `decision.confirmation` to the person and returns `True` only on an explicit yes (sync or async). Without `approve`, a confirmation raises `ConfirmationRequired`. Args are bound by name, defaults included, and pre-bound `functools.partial` args are checked too. `*args`/`**kwargs` functions are refused. Runs the function only on ALLOW, sync or async |
| MCP server middleware | `catraca.adapters.mcp.catraca_middleware` | `async (ctx, call_next)`. The SDK marks this hook provisional. A server can't see the client's context, so args are UNTRUSTED unless the client signs its labels (`sign_labels`, checked with `label_key=`, bound to the tool, the values and a 5-minute window) or you pass `trust_client=True`. Refusals are the SDK's own error, code -32001 |

Each one has a runnable example in `examples/`, and CI runs them (the MCP one against the real SDK).

## Label model

Integrity: `TRUSTED < STRUCTURED < UNTRUSTED`, and join takes the max.

Confidentiality is a set of read scopes, and join is intersection. So here the **smaller** set is the more restrictive one. `PUBLIC` (`"*"`) is the top and the neutral element, `{"*"} ∩ X = X`. `"*"` is never a literal scope. The empty set is the bottom and blocks any flow.

## Resolution rules

| Rule | When | Label |
|---|---|---|
| EXACT | canonical form equals a whole snippet | join of the snippets |
| SUBSTRING | the whole arg is covered by windows from snippets (8 normalised chars by default) | join of the snippets |
| PARTIAL | some of it's covered, some isn't | coverage map: covered segments inherit their origin, uncovered ones get the residual |
| CONSERVATIVE | nothing matched | residual, the join of everything in the window, on both axes |
| NO_FULL_MATCH | consequential position without a whole, contiguous match against one trusted snippet | UNTRUSTED |

Anything shorter than the threshold never counts as cover. Decoded variants only add origins, they never grant trust. What's handled today: case, spacing, punctuation, accents, invisible chars, full-width and Cyrillic/Greek homoglyphs, leetspeak (folded into the canonical form, so it's free), URL percent-encoding, HTML entities, `\u`/`\x` escapes, base64, punycode (`xn--`), defanged addresses (`[at]`, `[dot]`, `hxxp`) and rot13.

### Every arg is consequential unless you say otherwise

The whole-match rule is the default for every arg. The policy lists the ones that may be looser (`"match": "partial"` or `"integrity": "ANY"`). So forgetting something makes it stricter, never looser. The lint (in the policy section above) points out args that look like destinations and have been relaxed.

What "whole match" means exactly: the value has to appear in one trusted snippet as whole tokens. Case and the spaces people use to group digits (an IBAN in blocks of four) are folded. Nothing else is: the value's own punctuation must be there as typed (`../data` isn't `/data`), and a value that changes under Unicode NFKC folding (full-width letters, ligatures) is never trusted, since the tool would get a string the user didn't type. Inside containers, dict keys that look like data (digits, `@`, dots) are resolved like values, plain field names (`status`, `first_name`) are treated as structure, and an empty list or dict resolves like an empty string.

## Context window

The registry follows the model's context window, not the turn. Invariant: there's an entry for every snippet still in the context.

* `new_turn()` just bumps a counter. It doesn't forget anything.
* `forget(id, reason=...)` is an explicit act and it's logged in `forget_log`. If you're not sure something's left the context, don't forget it.
* `summarise(text, replaces=[ids])` records the summary with the join of the whole window and only then forgets the originals. A summary of a tainted window is born UNTRUSTED.
* `export_state(key=...)` and `ContextRegistry.from_state(channels, state, key=...)` move the window between processes, for example to keep it next to your agent framework's checkpoint. The state holds the snippet texts, so store it like the conversation. Without the key it's refused unless you pass `trust_unsigned=True`, because whoever can edit the state could relabel an untrusted snippet as trusted.

## Threads and scale

Every public method on `ContextRegistry` takes a lock, and the gate resolves a whole call plus the window summary as one snapshot, so it's safe to share across threads and asyncio tasks. Use one registry per conversation, never one per process: every decision takes the registry's lock, so a shared registry serialises all traffic (about 1,200 decisions a second on one core in our measurements). It isn't shared across processes by itself: use `export_state`/`from_state` for the registry, and a shared `PendingBackend` for confirmations (below).

Async code should call `await gate.adecide(...)` (or `acheck`), which runs the decision in a worker thread so a long arg doesn't stall the event loop. The async decorator and the MCP middleware already do.

Confirmation tokens live in memory by default. With several workers, pass `ConfirmationStore(backend=...)` with anything that has `put(token, record, ttl_seconds)`, `take(token)` and `drop(token)`, where `take` reads and deletes in one atomic step. With Redis that's `SET token record EX ttl`, `GETDEL token` and `DEL token`. The clock switches to wall time when a backend is given.

On a ~100k-token window (40 docs, 565k chars, `python -m bench.scale`): about 39 MiB held by the registry, ~38 ms to annotate each doc, and `decide` at p50 ≈ 0.3 to 0.35 ms / p99 ≈ 0.6 to 0.8 ms for a destination arg. A 400-word free-text body costs more, p50 ≈ 4.4 ms / p99 ≈ 6.6 ms, since every char gets a coverage slot. These are the reference machine's figures from [BENCHMARK.md](../BENCHMARK.md), so run it on your own box.

