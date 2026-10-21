---
reason: The model-backed full assessment command was called scan even though scanning names the deterministic, model-free analysis (scan-sources). assess matches the product language (assessment, assessment-entry, --assessment-depth) and no longer collides with the removed explicit-profile command of the same name.
affected_ids: [REQ-011, REQ-018, REQ-038, REQ-041]
compatibility: The public scan command is renamed to assess; calls to scan fail with an invalid-choice error and must use assess. The capabilities API key scan is likewise renamed to assess. Behavior is unchanged, including the --non-interactive requirement for --repo and an explicit --profile or legacy --host. The scan-sources command, scan profiles, and scan-named artifact fields keep their names. The internal controller subcommand called assess is not a public command and is unchanged.
verification: Offline tests cover the renamed command across profile, budget, parallelism, abuse-case-file, source-preflight and organization-distribution tests, and the removed scan command rejected by the parser. The specification gate runs against the base commit. No live model call was made.
---

# Rename the scan command to assess

`scan` ran the model-backed full assessment while `scan-sources` runs the deterministic source scan, so the name suggested the wrong cost and data-use class. The command is renamed to `assess`, which already names the workflow everywhere else (assessment-entry, `--assessment-depth`, assessment reports). The recently removed explicit-profile `assess` command does not return: the renamed command keeps the `scan` behavior, including automatic profile selection by default and the `--non-interactive` requirement for an explicit provider. The public capabilities key `scan` is renamed to `assess` in step.
