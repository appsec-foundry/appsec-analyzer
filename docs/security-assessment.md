# Complete security assessment

`appsec-analyzer assess` analyzes one or several local Git checkouts as one
system. It selects a model host explicitly, freezes admitted source, runs
semantic roles, checks their output against canonical contracts, verifies
evidence, and publishes a report only after validation. The report covers
components, data flows, trust boundaries, controls, weaknesses, abuse cases,
prioritized findings, and remediation. Repository evidence is a bounded
snapshot; production behavior and business intent require human review.

```sh
appsec-analyzer assess --repo /path/to/project --host claude-cli \
  --hard-budget 20 --assessment-depth standard
appsec-analyzer assess --repo /path/to/service --repo /path/to/client \
  --host claude-cli --hard-budget 30 --output /private/system-assessment
```

The supported depths are `quick`, `standard`, and `thorough`. They change work
limits and the Claude role defaults. `--model` pins all roles; `--stride-model`,
`--triage-model`, and `--merger-model` override specific roles. Check
[model selection](model-selection.md) before spending. A hard USD budget is
required at the public CLI. The controller reserves completion work before
optional model calls and records unavailable cost as a conservative charge.

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
published files. A deterministic `scan` has no semantic assessment status and
uses its [own result schema](../schemas/deterministic-scan-result.schema.json).

The source guide, retained in [history](history/advisor/security-assessment.md),
explains domain concepts and earlier plugin behavior in detail. Its commands
and provider statements are historical.
