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

Use `standard` as a starting point, including for business logic analysis. `thorough` can find additional problems, but more expensive early analysis can leave less budget for verification and combining related findings. More findings or abuse cases do not by themselves establish better coverage. See [the measured standard and thorough comparison](model-selection.md#choosing-standard-or-thorough) for costs and limits, and check the run summary for skipped model work.

For `claude` and `codex`, the spending limit defaults to USD 20 for both `scan` and `assess`. Use `--budget USD` to override it; `--hard-budget` remains a compatible alias. The CLI prints the selected limit before starting. The controller reserves completion work before optional model calls and records unavailable cost as a conservative charge.

Control analysis and STRIDE analysis each process at most two components in parallel by default. Set `max_parallel` in a scan profile or pass `--max-parallel N` to `scan` or `assess`; the CLI value overrides the profile. Values from 1 to 16 are accepted. The run header shows the selected value, and the time reserve uses the same value. Provider rate limits can still interrupt a run; accepted steps remain available for `--resume` with compatible settings.

On a provider rate limit, all new model calls in the assessment wait together; already running calls may finish. Free failures allow up to three retries with delays of 15, 60, and 180 seconds; valid HTTP `Retry-After` delays are respected. Paid failures retain their stricter retry limits. CLI hosts without structured reset metadata use those fallback delays. A wait over three minutes, insufficient remaining time, or exhausted retries pauses the run with exit code 3, including when the affected job is optional. Accepted work is kept. Wait for provider capacity, then rerun the same command with `--resume`; the original deadline and compatibility checks still apply.

When an optional model job cannot run within the remaining budget, normal progress output immediately prints a `Coverage gap` warning naming the job's role and the budget reservation. A model failure that uses a fallback is also reported immediately. These messages do not require `--verbose`. Architect Review totals distinguish reviewed, unreviewed, and unresolved findings; abuse-case totals distinguish checked, partially checked, and unchecked candidates. A checked case can still be inconclusive. The phase completion line repeats those totals, and the final run summary lists omitted work. This also applies to `thorough`: a published report does not mean every optional check ran. `--quiet` suppresses live progress.

Model activity messages reflect the selected host's progress events. Codex CLI events show thinking or writing when available, without displaying model text. `No progress update` means the call is still running without a recent update; it does not establish model inactivity or an API problem. Hosts without activity events say that intermediate activity is unavailable. An exceeded time limit remains a warning.

Use `--verbose` to show job and call identities and detailed sanitized correction reasons. All full-assessment providers write a private diagnostic feed to `.assessment-work/diagnostics/attempt-*/events.jsonl` under the output directory; verbose startup and the completion summary name the file. It records job outcomes, model-call timing, safe host failure codes, and sanitized validation reasons without prompts, source excerpts, model answers, or raw stderr. Reasons are bounded with an explicit truncation marker; each feed stops at 8 MiB with a warning. A failed diagnostic write warns and leaves the analysis decisions unchanged. Resume creates another attempt directory and preserves earlier diagnostics and Claude host-event streams; `--rebuild` removes the earlier work directory. These records help explain execution and validation failures; they do not prove the semantic correctness of an accepted finding. Inspect any diagnostics before sharing them.

If Analyzer code or analysis resources change during a run, a warning explains that results may combine versions and that the assessment continues. If the version check cannot finish, the warning says that a consistent version cannot be confirmed. Keep the Analyzer installation unchanged during assessments; afterwards, use `--rebuild` with a stable installation to regenerate results from one version. Rebuilding discards earlier model work and makes new model calls against your budget or subscription allowance.

In an interactive terminal outside CI, the controller asks before a monetary budget gap skips or stops work. It first waits for running calls to finish and pauses new calls. Enter a higher **total budget in USD**, such as `40` to raise a USD 30 limit to USD 40, or press Enter to keep the current limit. There is no automatic increase. Three invalid answers keep the existing limit; EOF also declines. After declining, no further budget questions appear in that process. A run permits at most 16 explicitly approved increases. More budget does not guarantee completion, and waiting for an answer still counts toward the time limit.

Use `--non-interactive` in CI and unattended scripts. Budget questions are also disabled without input and stderr terminals, when a recognized CI marker is set, or with `--quiet`. The approved limit is saved before further spending; `--resume` with the original command restores the last approved limit for that run, including when resumed noninteractively. Starting a new run uses its configured budget. Time and call limits are never raised by this question.

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

With Codex CLI 0.163.0 installed on Linux/macOS and signed in using `codex login`, use `appsec-analyzer scan --profile codex-cli --max-calls 1000 --max-duration 14400` to use ChatGPT plan allowance. This experimental profile defaults to one component at a time, rejects USD budgets, and reports monetary cost as unavailable. A plan limit stops the run and preserves accepted work; wait for allowance and resume the original output. See [Codex CLI setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli) for model access, data use, local limits, and qualification status.

### Source-read failures

STRIDE jobs receive the exact readable repository IDs and repository-relative paths. They are instructed to report missing evidence when a required file is absent from that list. A file mentioned in an import or earlier analysis does not grant permission to read it.

A well-formed relative filename outside the task selection is refused without reading it. Analyzer asks the model to use permitted sources or report missing evidence as unresolved, within the existing call, time and read limits. Repeated invalid proposals can still exhaust the job; they never expand its source selection.

`Model requested a source outside this task's selection` stops the run for unsafe paths, unknown repository IDs, or paths paired with the wrong repository. Diagnostics identify the category without echoing the model's path. Earlier versions also stopped immediately for an ordinary filename absent from the admitted inventory; their saved diagnostics cannot establish the exact requested file.

Accepted jobs remain in the output directory. After correcting the cause, repeat the original command with the same output and `--resume` while its original limits and compatibility checks permit. If the deadline has expired, repeat the command without `--resume` or `--rebuild` to start a new attempt and reuse compatible accepted jobs. Changed STRIDE inputs require those jobs to run again. Resuming alone does not correct an unchanged model request.

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

The report shows confirmed and partially blocked attack scenarios in detail. Cases that were checked but remain inconclusive appear in a compact table with their unresolved evidence. Cases whose verification did not run appear separately under “Not verified”; an empty verifier result does not count as a completed check. Mitigated and inapplicable cases remain in the coverage overview. Proposed fixes address confirmed steps, but their effectiveness still needs validation; a review task is not a fix.

## Exports and compatibility

Exports are requested on `scan` or `assess`; there is no public export-existing command. `results` checks the hashes of already published files. Internal names such as `threat-model.yaml` remain in intermediate processing and historical fixtures; the current published model is `security-assessment.yaml`.

Interactive triage, automated code fixes, baseline installation, and plugin hooks are not part of the public Analyzer CLI. The separate [security score](security-score.md) gives a limited deterministic indication without model calls. The focused analyst can preview and check selected abuse cases with `hypothesis --abuse-case`; see the [analyst guide](threat-analyst.md). The independent [AuthNZ review](authnz-review.md) checks authentication and authorization through Claude CLI and supports JSON/YAML reports and legacy pentest plans without a prior assessment.
