---
reason: A Juice Shop assessment recorded 48 Claude DNS failures as server errors and replaced 12 optional verification jobs with coverage gaps while other jobs continued failing.
affected_ids: [REQ-016, REQ-022, REQ-023]
compatibility: Persistent provider connection and server failures now pause required and optional jobs with exit code 3. Accepted receipts, saved formats, resume identities and original spending, call and time limits remain unchanged.
verification: Offline regression tests cover Claude DNS and connection classification, diagnostic redaction, shared cooldown, one recovery call, stale successes, cancellation, paid and subscription retry limits, retained receipts, retry after resumption and controller exit behavior. Run affected consumers, the standalone offline gate, Ruff and documentation link checks; no live model calls.
---

# Pause assessments during provider outages

This fixes recovery under REQ-016 and bounded execution under REQ-023. The user requested verification and repair of the recommendations and chose direct work on main. The requirement outcomes stay unchanged; the technical acceptance rule no longer permits an optional job's infrastructure failure to turn into a coverage gap. REQ-022 keeps the distinction between a paused run and a completed assessment.

Reuse the existing shared admission cooldown for explicit connection failures and server errors. After older calls settle, one existing pending call checks recovery. Do not introduce an extra model probe, destination, credential, or spending allowance. Concurrent failures share the bounded retry schedule. Successful replies from before the outage cannot reopen admission.

Claude reported EAI_AGAIN in each of the 48 failed host results, without an HTTP status. Recognize that DNS failure within the failed host envelope and keep explicit HTTP, account and certificate errors distinct. Raw host text does not enter the shared diagnostics or terminal messages. The CLI's internal retries can still delay the first reported failure; do not shorten healthy analysis calls to hide this limitation.

A paused run retains accepted jobs and leaves failed jobs without receipts so replay can retry them. Optional failures caused by invalid model answers retain their existing correction and fallback behavior. The change does not stop, restart, reinstall or spend more on the user's current assessment.

Lifecycle persistence also records shared infrastructure failures as interrupted, matching paused exit code 3. The resume regression covers every shared failure code and checks reuse without another model dispatch or charge. All 132 state tests pass, including the existing account-error and state-integrity rejection cases.

Verification completed offline: the runtime regression tests and their affected consumers passed after the corrections, including the final HTTP-metadata and controller-pause cases. Replaying classification against the saved host results identifies all 48 failures as dns_unavailable. Ruff lint and formatting, specification comparison against 7c7732b8, diff whitespace and the added local documentation link passed. No live model call or end-to-end assessment was run.

The required make check-analyzer BASE=7c7732b8 gate remains failing: its public-contract phase had 1086 passes and 10 failures. All ten failures reproduce identically in a clean local clone at 7c7732b8: HTML export in tests/test_public_export_cli.py::test_current_composed_report_exports_to_html; private output and legacy host-entry checks in tests/test_public_assessment_operations.py; and that file's quick and thorough budget expectations. These are outside this repair and need separate investigation of export and destination handling, plus comparison of the budget assertions with current depth settings. The gate's remaining specification, requirement-report, context-routing, runtime-documentation, STRIDE-policy and distribution checks were then run separately and passed all 168 cases. This does not establish a green overall gate or live assessment quality.
