# Testing

## Mutation testing

CI runs [mutmut](https://github.com/boxed/mutmut) weekly and by hand (`mutation` job). It changes the code one small edit at a time, a `<` into `<=`, a `continue` into `break`, and runs the tests against each change. A change the tests don't notice is a survivor. The job fails if the share of changes caught drops below a floor. After each green run the floor goes up to that run's score minus one point. It never goes down.

### What a test for a survivor must do

* Name the survivor it kills (function and change) in the commit message.
* Assert documented behaviour, never an error message, the order of keys or a private helper when a public call reaches the same code.
* Test an edge from both sides (16 and 15 characters, 300 and 301 seconds).
* Control the clock with a mock, never with `sleep`.
* Pass under both `unittest` and `pytest`.

### Lines kept out of mutation testing

A line ends in `# pragma: no mutate` only with a reason after it, and CI refuses one without. There are two kinds:

* `equivalent:` no input can tell the change apart from the original. The reason names what makes it so.
* `untestable:` the line can't run in the mutation job (none at the moment).

mutmut skips the whole line, so such a line holds only the construct in question.

Current equivalent lines, by function:

| Where | Change that can't be seen | Why |
|---|---|---|
| `egress._scan_text`, `add()` | the `return False` values | Only used to decide whether to scan a URL for nested URLs. A repeat was already scanned, and past the 64-target cap the arg is already `UNKNOWN_HOST`. |
| `egress._scan_text`, span checks | `<` and `<=` at the span edges | No input found where a match starts exactly at the end of an earlier one (4,000 mixed strings fuzzed). Depends on the URL, email and bare-host patterns: re-check if one of them changes. |
| `egress._scan_text`, `mailto` | the `mailto` skip and its `continue` | A `mailto:` URL gives the same email target as the email scan. Depends on `_url_targets` handling `mailto`. |
| `egress._scan_text`, nested URLs | the `first` flag | Nested URLs are scanned only for the first reading of a URL. A hostless first reading (`file:`, `data:`) is always refused, and later readings are deduplicated. |
| `egress._scan_text`, bare hosts | `group(0)` for `group(1)` | The path after a bare host doesn't change the host it resolves to. |
| `adapters.mcp.LabelChecker.edges` | `and` for `or` in the key check | The key is always set when a label is checked. |
| `adapters.mcp.LabelChecker.edges` | the 60 s added to the nonce lifetime | Any margin over the 30 s clock skew gives the same result. |

If a line in this table changes, or something it depends on does, look at the pragma again: it may now hide a real gap.
