# Separate requirements audit

`audit-requirements` checks a local YAML requirements catalog against one admitted Git checkout. It sends selected source excerpts to Claude CLI and produces a separate requirements verdict. For a complete security assessment, use `assess`. For fixed source checks without a model, use `scan-sources`.

```sh
mkdir -p /private/audit
appsec-analyzer audit-requirements --repo /checkout \
  --requirements /catalog.yaml --output /private/audit \
  --host claude-cli --budget 5 --md --gate
```

The audit makes paid model calls with a default spending limit of USD 5. Use `--budget USD` to change the limit; `--hard-budget` remains a compatible alias. The CLI prints the selected limit before starting.

The output directory must exist outside the checkout and contain no earlier audit result. The audit writes private `.requirements-audit.json` and, with `--md`, `appsec-requirements-report.md`.

The CLI response uses interface version 1 with `kind: requirements-audit`, `audit_status: complete`, and `assessment_status: not_run`. New verdicts follow version 2 of the [audit schema](../schemas/requirements-audit.schema.json); version-1 verdicts remain readable. They record the catalog hash, Git commit, captured state, file hashes, and exclusions.

Every conclusive result must cite a source line served from the fixed source copy. Missing evidence cannot establish a pass or failure. A changed checkout or invalid result stops publication.

`--category FILTER` selects catalog IDs or categories. `--demo` uses the packaged sample. The command accepts a local regular catalog file and at most 160 selected requirements, with a size-limited source inventory. It cannot fetch remote catalogs or resume an interrupted audit. The [archived guide](history/advisor/security-requirements-audit-skill.md) describes earlier plugin features, including PDF output, that this command does not support.

Before publication, the audit checks both JSON and optional Markdown for recognized unmasked secrets. A match blocks publication of either file. The error identifies the problem without printing the secret. See the [security policy](../SECURITY.md) for handling results.

`--gate` returns exit 1 for MUST failures by default. `--gate-on partial` also blocks on partial results; `--priority-floor SHOULD` or `MAY` includes those priorities. Exit 2 means an operational error or an invalid result. A passing gate means the selected blocking conditions were absent, not that every control was verified. See [configuration](configuration.md) and [full assessment](security-assessment.md) for the other commands.

`UNVERIFIABLE` results remain separate from `PASS` in the summary and report. Neither gate policy blocks on them: even an all-unverifiable audit can return gate `pass`, which only means no selected FAIL/PARTIAL blocker was found. Check coverage and unverifiable counts before treating an audit as evidence of compliance. Before analysis, the command discloses that selected masked source excerpts, the file inventory and catalog requirements are sent to Claude CLI; provider retention is not verified.
