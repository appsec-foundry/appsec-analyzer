---
reason: The operator reported another Codex assessment stopped by an unlisted source proposal and explicitly approved bounded correction of safe relative filenames before implementation.
affected_ids: [REQ-016, REQ-031, REQ-034]
compatibility: Keep source admission, receipts, limits, and publication gates unchanged; ordinary refused filename proposals become correctable model errors while unsafe paths and repository identity errors remain fatal. Existing accepted jobs remain subject to normal compatibility and source revalidation.
verification: Offline host and job regressions cover corrected proposals, zero unauthorized retrieval or transmission, bounded repeats and read allowance, accounting and receipt reuse, mixed batches, and fatal paths or repository identities after read exhaustion; run affected controller and provider tests plus specification and Ruff checks.
---

## Requirement and source

The operator supplied the failed `/tmp/141` Juice Shop assessment and approved this scope in the conversation. REQ-016 requires useful recovery; REQ-031 and REQ-034 keep model proposals inside deterministic source authority. Commit `636cd4b0` added source-list instructions and diagnostic categories, but retained immediate fatal handling of any filename absent from the admitted inventory. An offline model returning a guessed relative filename reproduces that failure before a valid correction can be requested. The saved run does not retain the actual requested path, so its specific spelling or origin is unknown.

## Behavior and security decision

The existing assessment engine treats a syntactically valid relative filename in a selected repository as a proposal, not permission. If it is outside the task selection, refuse it before any source lookup or read and provide fixed feedback without echoing the proposed path. The model may select a permitted source or mark missing evidence unresolved within existing limits; do not expand inventory, resolve guessed imports, or weaken artifact validation. Denied proposals consume the read allowance, including in a batch near exhaustion; preloaded jobs retain one further read round.

Reject unsafe paths, unknown repositories and paths paired with the wrong repository immediately. Validate all proposals before serving any batch member, including after read exhaustion. Source changes, receipt integrity, accounting, cancellation and publication checks retain their existing behavior. Only authorized ranges actually served enter receipts, and all correction calls remain budgeted. Required jobs that exhaust their exchanges still fail; optional jobs retain their documented replacement policy.

## Scope and acceptance

Change the exchange host, focused host and job regressions, the controller failure contract, the user recovery guide, and requirement bindings. No baseline text, baseline version, provider isolation, new dependency, or live-model spending is included. A safe unlisted proposal followed by a valid read must succeed without accessing or transmitting the refused file. Repeated refusals must end within existing limits without negative read counts. Traversal, absolute paths, foreign identities, mixed invalid batches and invalid proposals after exhausted reads must fail closed. Receipt tests must preserve total call accounting and include only served ranges.
