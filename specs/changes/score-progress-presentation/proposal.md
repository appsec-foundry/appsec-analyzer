---
reason: The operator requested a more professional score status display instead of a sequence of unformatted internal-step messages.
affected_ids: [REQ-036]
compatibility: Change only progress presentation on stderr under public interface version 1; keep result formats, scores, source policy, exit codes, immediate startup, and excluded-file omission unchanged. Interactive terminals receive one refreshed row; redirected stderr and TERM=dumb use plain phase logs.
verification: Run public score, retained calculation, installed-package, documentation, and specification tests plus changed-file Ruff checks. Verify real elapsed phase durations, startup before runtime work, visible Git cloning, terminal refresh during waiting, interruption cleanup, stopped/incomplete status, and structured stdout without terminal escapes.
---

# Compact score progress

Group work into Repository, Security checks, and Result. Keep completed phase rows aligned with measured durations and show total time at completion. Interactive terminals refresh the active row with a small activity indicator, current step, and elapsed time, including during long subprocesses. Plain output logs only phase boundaries and explicit Git cloning. Use standard-library timing and threading without adding dependencies or changing scanner execution.

Start progress before runtime preparation and stop its refresh thread before printing the result or an error, including on interruption. Fixed display labels contain no repository paths, URLs, credentials, or source text. A completed phase records elapsed execution rather than a passing security verdict; incomplete or interrupted work retains its corresponding final status. Result output stays on stdout, excluded-file details stay omitted, and the existing source and result validation boundaries remain intact.

Verification completed: 30 public score cases passed, followed by four focused cases after extending the plain-output test to `TERM=dumb` and checking incomplete status. Another 232 retained scoring, installed-wheel, documentation, and specification cases passed. Tests cover immediate piped startup, live scanner details before execution, refresh during waiting, cleanup on interruption, phase/total durations, clone visibility, and parseable result stdout. Specification change coverage validates against `69c2501f14f59746f4d96409135abbff9d30a256`; changed Python files pass Ruff lint and format checks. No dependency downloads, external Git retrieval, or live model calls were needed.
