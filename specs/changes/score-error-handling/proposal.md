---
reason: The operator encountered an uncaught Ctrl+C traceback and requested robust score execution with understandable error messages and recovery advice.
affected_ids: [REQ-036]
compatibility: Preserve scoring version 2, structured result fields, source controls, and existing verdict exit codes. Cancellation now exits 130 without a traceback; diagnostic wording becomes actionable and unexpected score failures exit 1 without internal details. The retained direct script and other public commands keep their behavior.
verification: Run public score, summary, retained scoring, installed-package, CLI documentation, specification, and Ruff checks. Exercise real SIGINT at startup, source redaction, scanner dispatch, and revalidation; temporary and remote checkout cleanup; invalid local sources; scanner timeout, absent or malformed output and producer error; unexpected scanner, schema, rendering and storage errors; and a closed stdout pipe. Confirm no result on cancellation or operational failure and a null headline with retained findings on incomplete scanner execution.
---

# Robust score errors and cancellation

Handle KeyboardInterrupt at the public score command boundary and finish progress with `Cancelled by user after ...`. Return 130 while allowing source snapshot, scanner work, remote checkout, and subprocess cleanup to unwind normally. Do not catch the interrupt inside scanners or disable source masking. Cancellation during analysis must not print a partial result.

Explain local selection failures before starting scanners. Use the existing bounded, shell-free Git metadata reader with its hooks and filter protections; require a top-level directory with a readable commit. Keep remote admission, resource limits, credentials, and transport checks intact. Name incomplete scanners with fixed descriptions, distinguish time limits and absent or invalid results, and retain findings from completed scanners without a headline score. Never forward raw scanner diagnostics.

Contain unexpected exceptions at the score CLI boundary with a fixed error and recovery advice. Prepare and serialize the result before declaring computation complete or writing stdout. Handle a closed output pipe without a Python traceback; output already delivered cannot be retracted. Keep detailed exception and source values out of messages.

Verification completed: all 67 public score cases pass, including real SIGINT during startup, redaction, scanner dispatch, an executing scanner subprocess, and source revalidation. Cancellation reaps the scanner subprocess, removes temporary snapshots/work files, leaves the source unchanged, emits no result, and exits 130. Offline real Git retrieval cases verify cleanup after success, failure, and interruption. Failed, missing, invalid, and timed-out scanner cases retain completed findings without a headline score. Unexpected errors and closed stdout pipes produce no traceback or confidential exception detail. The additional summary, retained scoring, installed-package, documentation, and specification groups pass (306 cases in total across focused runs).

The extended source-boundary and remote suite produced 177 passes and six existing failures in the legacy headless/remote-runner tests. Those tests target the replaced wrapper interface; they are unchanged by this work and are not a green release gate. No live model calls or external Git retrieval were used.
