---
reason: A discovery call failed after 646 seconds with only a generic transport diagnostic; local CLI replay also demonstrated rejection of a successful turn after a reconnect notice and repeated console heartbeat rows.
affected_ids: [REQ-016, REQ-023, REQ-032]
compatibility: Preserve commands, model selection, authentication, source isolation, and result validation. Use HTTP/SSE with a 60-second idle timeout and no internal CLI request or stream retries. Runtime fingerprints require a new assessment after the update; retain earlier output for diagnosis.
verification: Run adapter, real local CLI wire, diagnostics, controller, console, rate-limit, specification, and Ruff checks. Cover successful reconnect recovery, terminal failures, no hidden retries, idle timeout, diagnostic redaction, and a single live status row. An authorized synthetic Luna call succeeded in 3.4 seconds before the configuration change; an authorized first Juice Shop discovery call with the corrected transport returned a schema-valid read request in 9.7 seconds. A complete live assessment remains unqualified.
---

# Codex transport recovery and visible failures

Codex CLI 0.163.0 emits reconnect notices as top-level `error` events, then can return a valid answer with `turn.completed` and exit 0. Analyzer previously rejected every stream containing such an event. It also classified most failures from stderr alone although the CLI reports provider failures on stdout, reducing useful causes to `transport`.

Accept only the recognized reconnect notice as recoverable; unknown errors, failed turns, nonzero exits, malformed answers and unexpected tools still fail. Classify final errors from both channels using fixed codes. Keep provider bodies, model text and credentials out of diagnostics. Disable CLI request and stream retries so repeated model exchanges remain under controller accounting, and use HTTP/SSE with a finite idle bound. This changes neither source authority nor the ChatGPT login route.

The terminal ticker already owns live call status. Suppress duplicate permanent heartbeat rows there and retain a single missing-update notice per unchanged call state in plain logs. Preserve separate connection and timeout warnings.

The original run's stored diagnostics establish one failed discovery call lasting 646.732 seconds with exit 1. Its raw provider cause was not retained and cannot be reconstructed from that feed. The local recovery bug is independently reproduced; it does not prove the cause of that particular failed call. The corrected transport completed the reconstructed 94,877-byte first discovery request in 9.7 seconds and returned twelve source-read proposals. The probe validated the response schema and stopped before serving those reads or making another model call.

Codex reserves built-in provider IDs, including `openai`. The adapter therefore defines `appsec_chatgpt` with Codex-managed OpenAI authentication and the default ChatGPT route. The wire test preserves this production provider ID and substitutes only local fixture authentication and destination; renaming the provider in the test had concealed an invalid built-in override during development. Configuration failures are classified as `host_configuration`.

The broader controller regression found two failures in `test_controls_overlap_within_the_limit_keep_order_and_reuse_receipts`, both reproduced on unchanged commit `60c0ea46f36e60137cb116d2df35f024f082ea43`. Its four-party barrier conflicts with the default two-worker budget. Update that separate test to explicitly request the concurrency it intends to verify; this transport change leaves it unchanged.

Verification results: `make test-analyzer` passed 884 tests; the final adapter run passed 64 tests; explicit real-CLI loopback qualification passed all seven cases; the targeted progress regression passed six tests; and the specification-checker tests passed 111 tests. The broader controller, adapter, diagnostics and rate-limit run had 164 passes and the two baseline failures above. Ruff lint and formatting, local documentation links, diff whitespace, and the specification gate against the explicit baseline commit passed. These runs overlap and do not qualify a complete live assessment.
