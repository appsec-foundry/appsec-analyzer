# Complete security assessment

`appsec-analyzer scan` analyzes one or several local Git checkouts or explicitly selected Git URLs as one
system. It uses Claude CLI by default, freezes admitted source, runs
semantic roles, checks their output against canonical contracts, verifies
evidence, and publishes a report only after validation. The report covers
components, data flows, trust boundaries, controls, weaknesses, abuse cases,
prioritized findings, and remediation. Repository evidence is a bounded
snapshot; production behavior and business intent require human review.

```sh
appsec-analyzer scan --repo /path/to/project \
  --budget 20 --assessment-depth standard
appsec-analyzer assess --repo /path/to/service --repo /path/to/client \
  --profile claude --budget 30 --output /private/system-assessment
```

The supported depths are `quick`, `standard`, and `thorough`. They change work limits and select the corresponding model configuration within `--profile claude|codex`. With the default `claude` profile, `--model` pins all roles; `--stride-model`, `--triage-model`, and `--merger-model` override specific roles. Check [model selection](model-selection.md) before spending.

The spending limit defaults to USD 20 for both `scan` and `assess`. Use `--budget USD` to override it; `--hard-budget` remains a compatible alias. The CLI prints the selected limit before starting. The controller reserves completion work before optional model calls and records unavailable cost as a conservative charge.

For OpenAI Responses, choose `--profile codex` and a separate `--assessment-depth`. The profile supplies the connection, model, reasoning, and output cap for that depth, so no `--host` is needed. Claude role overrides do not apply. Existing host and depth-profile calls remain compatible as described in [model selection](model-selection.md).

`scan` also accepts the headless export options `--pentest-tasks`,
`--pentest-format strix`, `--pentest-target URL`, and `--slug NAME`.
`--keep-runtime-files` retains intermediate files for debugging; an explicit
`--output` must already be a private directory (mode 0700).

Without `--output`, results go to the application's private user-data directory
under `appsec-analyzer/assessments`. An explicit output directory may not be
inside a selected checkout. The main published files are
`security-assessment.md` and `security-assessment.yaml`; optional flags request
SARIF, Threat Dragon, HTML, PDF, or pentest tasks. Exports run after model and
report validation. Missing external export tools are reported. `--requirements`
enables requirements checking within this full assessment; it does not invoke
the independent Requirements Audit.

Interrupted runs retain accepted steps. `--resume` requires compatible source,
settings, engine, and limits; `--rebuild` discards earlier model work. A source
or runtime change may require a fresh assessment. Inspect `status` or `progress`
with the output directory, request `stop`, and use `results` to verify the
published files. A deterministic `scan-sources` has no semantic assessment status and
uses its [own result schema](../schemas/deterministic-scan-result.schema.json).

The source guide, retained in [history](history/advisor/security-assessment.md),
explains domain concepts and earlier plugin behavior in detail. Its commands
and provider statements are historical.

## Known threats

Place prior findings in `docs/known-threats.yaml`, using the [example](../examples/known-threats.yaml) and [schema](../schemas/known-threats.schema.yaml). The engine validates this declaration and records its repository provenance. A prior finding or accepted-risk statement is input to analysis; it does not establish that an attack works or that a control is effective. `--skip-context` skips business context but keeps known threats available.

## Exports and compatibility

Exports are requested on `scan` or `assess`; there is no public export-existing command. `results` checks the hashes of already published files. Internal names such as `threat-model.yaml` remain in intermediate processing and historical fixtures; the current published model is `security-assessment.yaml`.

Interactive triage, automated code fixes, baseline installation, plugin hooks, and a separate security-score command are not part of the public Analyzer CLI. The focused analyst can preview and check selected abuse cases with `hypothesis --abuse-case`; see the [analyst guide](threat-analyst.md).
