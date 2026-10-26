---
reason: A user who started `assess` without a depth got `standard` and its spending limit without seeing what the other depths cost, how long they take, or what they verify.
affected_ids: [REQ-002]
compatibility: Only a run in an interactive terminal that names no depth by option, scan profile, or organization profile now waits for an answer; Enter keeps `standard`. Runs with `--assessment-depth`, `--non-interactive`, `--quiet`, `--resume`, a Claude Code dialogue start, CI markers, or no terminal behave as before. No saved artifact, schema, budget, or exit code for a completed choice changes; an unreadable or invalid answer exits with code 2 before any model call.
verification: tests/test_assess_depth_prompt.py covers Enter, number, and name answers, a depth from the command line or a scan profile, a profile without a depth, non-interactive, quiet, resume, and no-terminal runs, cancelled and invalid answers that start nothing, and an answer that is never echoed. `make check-specs` checks the requirement, acceptance contract, and binding.
---

# Ask for the assessment depth

The user approved the wording of REQ-002 on 2026-10-26 and chose to work on `main`.

Raised risks and decisions:

- Model cost: the question costs nothing. A user who used to get `standard` can now pick `thorough` and spend up to the limit shown, only by a deliberate choice. Enter keeps `standard`.
- Data and credentials: nothing new reaches a model or another host, and credential use is unchanged.
- Existing commands: a terminal run without a depth now waits for input. Scripted runs that pass a depth, `--non-interactive`, or run without a terminal do not.
- Runtime: no measured durations exist, so the question names a relative runtime (shortest, medium, longest) and no minutes. It also shows no typical cost; the spending limit is the profile budget that would apply, which is the same for all depths unless a profile sets a depth budget.
- Simpler variant not chosen: a hint line in the `--assessment-depth` help does not show the choice at the start of a run. The help text gained a short note instead.
