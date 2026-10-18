---
reason: The operator asked whether score help and documentation clearly explain repository URLs, quick execution, the existing analysis engine, and prominent score results.
affected_ids: [REQ-036]
compatibility: Clarify help and current documentation without changing scoring, supported sources, options, output schemas, or exit codes. Give no unmeasured runtime guarantee. Preserve unrelated working-tree changes.
verification: Inspect rendered top-level and score help, run existing score argument-parser and runtime documentation checks, validate the installed distribution and specification change coverage, and run Ruff on the changed CLI file. Check local documentation links and keep examples free of real network or model calls.
---

# Explain score use in help and documentation

Make score help describe the existing engine, lack of model calls and charges, local Git and HTTPS/SSH sources, score range, highlighted text result, and progress/error streams. Include local and remote examples and a pointer to the score guide. Keep the limited-check qualifier and operational exit codes visible.

Align the README, score guide, and installed entry skill with that explanation. State which work affects runtime instead of inventing an execution-time promise. Existing parser tests continue to check that help exits without source access; documentation and package checks verify the current command and installed entry.

Verification completed: 12 existing argument-parser and runtime documentation cases pass, rendered score help contains the local/remote examples and intended explanations, Ruff lint and formatting pass for the CLI, changed documentation links resolve, and specification change coverage validates against `9bb67113`. The package test builds and installs the distribution and successfully runs the installed score, then fails in the independently added AuthNZ test harness when importing `runtime.analyst_host` before engine import initialization. That test setup needs its own correction; it was left unchanged. No model calls or external Git retrieval were used.

Commit verification: an isolated export of the seven staged help/documentation files and their committed dependencies passes all 12 selected parser, runtime documentation, and distribution cases, including the installed package. The isolated catalog and changed CLI also pass specification validation and Ruff checks. Unrelated AuthNZ additions remain outside this commit.
