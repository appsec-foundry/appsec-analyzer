---
reason: Prevent parallel model requests and optional fallbacks from continuing an assessment during persistent provider rate limits.
affected_ids: [REQ-016]
compatibility: Persistent rate limits now exit with paused code 3 instead of failed code 1; saved artifact formats and resume compatibility remain unchanged.
verification: Offline shared-admission, cancellation, reset-header validation, retry accounting, optional-job interruption, lifecycle resume, and controller exit tests; specification and Ruff checks.
---

# Shared rate-limit pause

All model jobs in an assessment share its cooldown. A rate limit prevents new admission before the failed call settles its reservation; already admitted calls may complete. Free failures permit three retries using 15, 60, and 180 seconds. Paid failures retain the existing single retry per exchange and run-wide paid retry allowance. Successful calls admitted after the cooldown clear the failure streak. Concurrent refusals share the retry allowance, so they may exhaust it sooner.

The HTTP adapter passes validated numeric or HTTP-date `Retry-After` metadata without exposing provider response text. The controller waits at least the larger of its fallback and provider delay. A delay over 180 seconds or beyond the remaining deadline stops admission until a later compatible resume. CLI hosts do not expose a reliable structured reset field here; no reset time is inferred from error prose. A profile using several providers pauses them together because admission is shared by assessment.

Persistent rate limits stop optional and required work alike, preserve accepted job receipts, and leave lifecycle state interrupted with paused progress and exit code 3. Original spending, call, time, validation, and publication limits remain enforced. Automated consumers that previously classified this outcome as exit code 1 must handle the existing paused code 3. No live calls are required for verification.
