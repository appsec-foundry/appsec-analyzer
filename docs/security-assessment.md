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

Report authoring completes the required Security Architecture section first, then uses the remaining allowance for the Management Summary before requirements commentary. The summary can use less than a full estimated call allowance; the host still enforces its spending limit. If cost, time, call limits, or invalid model output prevent the summary, the report keeps its deterministic verdict and the run summary identifies the replacement.

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

## Custom abuse cases

Save business rules as a YAML file anywhere inside the repository being assessed. Select it explicitly; a special directory is not required. For example, save this as `review/abuse-cases.yaml`:

```yaml
schema_version: 2
abuse_cases:
  - id: REPO-AC-001
    kind: descriptive
    title: Requester approves their own expense report
    check: Check whether an employee can approve an expense report they submitted, including through direct API calls.
    exclusions:
      - Reports below the amount that policy lets employees self-approve.
    open_questions:
      - Which amount, if any, may be self-approved?
    scope_qualifier:
      path_patterns: ["*expense*", "*approv*"]
```

Run a model-backed assessment with an authorized budget:

```sh
appsec-analyzer scan --repo /path/to/project --budget 20 \
  --abuse-case-file review/abuse-cases.yaml
```

The path is relative to the selected repository root, not the working directory or profile directory. Repeat `--abuse-case-file` for several files. Files must be admitted repository files with a `.yaml` or `.yml` extension; absolute paths, parent traversal, and links outside the source boundary are rejected. Keep the file in Git so it is also available when assessing a remote checkout. File selection currently supports a single repository per assessment; assess repositories separately when using these inputs.

For recurring runs, put `abuse_case_files: [review/abuse-cases.yaml]` in an operator-owned [scan profile](profiles.md). CLI file selections replace that list. This selects additional cases alongside enabled built-in and organization cases, rather than restricting the whole assessment to the selected file. Organization settings can still disable cases by ID.

Explicit file selection enables abuse-case verification even at quick depth. Up to 16 explicitly requested business cases are selected per run; other applicable business cases have separate limits of three at standard depth and eight at thorough depth. A file selection accepts at most 32 files, each up to 128 KiB. Budget and source limits still apply, and the report distinguishes unchecked or unresolved cases from supported findings and mitigated cases. The deterministic `scan-sources` command does not perform this model-backed check.

Existing files under `docs/security/abuse-cases/` and `.appsec/abuse-cases/` remain automatically discoverable for compatibility. Automatically discovered cases follow depth and applicability limits; explicitly selecting such a file marks its cases as requested and loads them only once. See the [case schema](../schemas/abuse-cases.schema.yaml) for technical attack chains and additional fields, and [organization profiles](org-profiles.md#business-abuse-cases) for shared organization cases.

## Exports and compatibility

Exports are requested on `scan` or `assess`; there is no public export-existing command. `results` checks the hashes of already published files. Internal names such as `threat-model.yaml` remain in intermediate processing and historical fixtures; the current published model is `security-assessment.yaml`.

Interactive triage, automated code fixes, baseline installation, plugin hooks, and a separate security-score command are not part of the public Analyzer CLI. The focused analyst can preview and check selected abuse cases with `hypothesis --abuse-case`; see the [analyst guide](threat-analyst.md).
