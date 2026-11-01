---
reason: The question after an unfinished run looked the same however far the run came. It named neither the step nor the cause, promised reuse without checking that anything could be reused, and showed a run whose process had died as "Running". The product owner asked for this to be fixed after a run that failed in its second step showed only how many model calls it had spent.
affected_ids: [REQ-016]
compatibility: Requirement wording does not change. Runs now record the step and failure code in `.assessment-state.json` under an optional `stop` field; states without it stay readable and show no step or cause, but an older Analyzer rejects a state that holds the field. A run with no accepted steps and no history no longer asks, and starts the same new scan that Enter would start. `--resume` and `--rebuild` work as before. Non-interactive, quiet, JSON, CI, and followed runs do not change.
verification: tests/test_assessment_state.py checks the shown step and cause, that provider text never reaches the state, that unknown codes stay unnamed, that a state with text in its codes is rejected, that a dead run is not shown as running, that a run with nothing to reuse starts without a question and ignores a waiting answer, that history alone keeps the question without promising reuse, and that a resume clears the record. tests/test_assessment_jobs.py checks that a failed job names its step, and tests/test_codex_cli.py checks the wording of a running call.
---

# Restart question shows how far the run came

## Decision

The question now says how the run ended, in which step, why where a cause was recorded, and how many accepted steps it left. A run with no accepted steps and no history has nothing to decide, so Analyzer says so in one line and starts a new scan. A run whose process ended without recording anything reads "Ended unexpectedly", because its state still says running.

The state stores fixed codes only, never error text. The terminal shows a step or cause only through Analyzer's own tables, so an altered state file cannot put its text on the screen.

## Related wording

The status text "waiting for the model's first response" became "model call is running". Codex reported no activity during its calls, so the text stayed for the whole call and suggested that the model had not started. This changes a message, not an outcome, and needs no acceptance rule.

## Not changed

Option 1 is still offered when the source changed, because that is checked only after the question. A run stopped hard during a model call still shows "an unfinished cost reservation cannot be reconciled", also on a subscription.
