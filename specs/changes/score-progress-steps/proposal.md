---
reason: The operator found the three compact progress rows too compressed and requested visible detail while source preparation and individual scanners run.
affected_ids: [REQ-036]
compatibility: Expand stderr progress into persistent step lines under the existing three phase headings. Show step durations instead of aggregate phase durations, retain the overall duration and safe repository heading, and preserve result formats, score arithmetic, source controls, and exit codes. Add an optional scanner-completion callback without changing existing collect callers.
verification: Run public score, retained scoring, summary, installed-package, documentation, specification, and Ruff checks. Verify visible steps before work starts, retained completed rows and measured step durations, actual failed/missing/invalid scanner statuses, safe unknown-event rejection, nonanimated redirected and dumb-terminal output, cancellation with no traceback or result, and shutdown of the terminal refresh thread.
---

# Visible security score steps

Keep repository, security checks, and result as spaced section headings. Give runtime loading, repository cloning or reading, redacted snapshot preparation, each of the four scanners, calculation, and source validation their own status line. Refresh only the active step in an interactive terminal and retain each finished line with its measured duration. Plain logs show a running and a final line per step, without cursor controls.

Report each scanner's execution and validated-output status through an optional completion callback. Show done, failed, missing, or invalid explicitly; a failed scanner cannot become done when the next scanner starts. Completing a scanner does not establish an absence of vulnerabilities. The final summary still distinguishes completed calculation, incomplete execution, operational failure, and cancellation.

This supersedes the compact phase rows described in the earlier progress-presentation proposal. The repository label, trusted-event vocabulary, output stream separation, source controls, and scoring policy stay intact.

Verification completed: all 67 public score cases pass with persistent step rows, per-scanner completion/error states, TTY refresh, plain logs, timed steps, and graceful interruption. The 113 retained scoring cases and 126 summary, installed-package, documentation, and specification cases pass. A real local Juice Shop run completed all four scanners through the interactive renderer. Changed-file Ruff checks, local documentation links, diff whitespace checks, and specification change coverage against `69c2501f14f59746f4d96409135abbff9d30a256` pass.
