# Complete security assessment

## Preflight checks

`scan` and `assess` check selected local Git roots, remote repository read access and provider setup before cloning repositories or starting analysis. Failures return exit 2 without starting the assessment. Checks run again on resume; a previous success does not guarantee continued access. `--quiet` suppresses progress; failures and generation-test data-use and spending notices remain visible.

The `preflight` command groups completed checks under one heading and uses the shared terminal colors. Before an assessment, completed checks appear as a `Preflight` phase in the progress grid, under the run summary and before the first analysis phase; a failed check prints at once and stops the run. Each repository and provider check appears once; the provider note states when model access was not tested. Long lines wrap; `--json` keeps the machine-readable result on stdout and progress on stderr.

Run the same checks independently without an assessment or output directory:

```sh
appsec-analyzer preflight --repo /path/to/project --profile claude
appsec-analyzer preflight --repo https://github.com/your-org/your-project.git --profile codex --json
```

Local selections must name top-level Git checkouts. Remote checks use `git ls-remote` for `HEAD`, require Git 2.34+, have a 30-second command timeout, and download no source objects. They use the same credentials, destination restrictions, TLS checks and trusted SSH host keys as cloning. Empty repositories or repositories without a default-branch commit fail. Git often gives the same failure for a missing private repository and insufficient permission, so Analyzer cannot always distinguish those causes. A later clone can still fail.

OpenAI checks each distinct configured role model with an authenticated [model metadata request](https://developers.openai.com/api/reference/resources/models/methods/retrieve). LiteLLM checks the configured gateway's `/v1/models` list with its API key, including a configured endpoint prefix. These requests send model identifiers and credentials to the selected provider, with no source content or generation. Missing models, rejected credentials, inaccessible metadata, malformed replies and connection failures stop startup. Model-list access does not prove inference permission, upstream gateway credentials, quota or assessment quality. Keys that cannot read model metadata can use the explicit standalone generation test below to diagnose the primary model; other roles then receive TLS checks only. Automatic assessment startup still requires metadata access.

Native Bedrock checks credential format and a verified TLS connection to its regional runtime endpoint; server authentication and model access remain unverified. Claude CLI checks local login status or the presence of externally supplied API/OAuth credentials; Codex CLI checks its reviewed version, isolation features and local ChatGPT login. These checks do not prove server authentication, model availability or quota. The output preserves these limits instead of claiming successful model access.

To test actual generation, explicitly authorize one primary STRIDE-model exchange with a separate spending limit:

```sh
appsec-analyzer preflight --repo /path/to/project --profile claude --test-model --budget 0.10
appsec-analyzer preflight --repo /path/to/project --profile codex-cli --test-model --max-calls 1
```

`--test-model` is available only on `preflight`. Monetary profiles require an explicit `--budget` of at least USD 0.01; the profile's default budget is insufficient authorization. Codex CLI requires explicit `--max-calls` and consumes one exchange from ChatGPT plan allowance; monetary cost remains unavailable. The fixed synthetic prompt contains no source excerpts or project context, grants no tools, and uses the selected primary model and reasoning effort. The exchange has a 30-second limit and no automatic retry. API tests bound output to at most 1,024 tokens within the configured model limit and reserve against the supplied test budget; a small budget or token limit may prevent completion. The separate test budget does not increase an assessment's budget. Other role models, assessment quality and future quota remain unverified even after a successful test. `--json` prints a result with `assessment_status: not_run`; it creates no assessment state or report. Ctrl+C returns 130.

## Run an assessment

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

Before model analysis, the startup header groups the effective settings into Run, Scope, and Workflow & results. Run shows the billing mode, a USD budget or subscription call limit, combined depth/time/parallelism settings, and a compact model summary. Models shared by several roles show a role count; single-role assignments keep their role name. Artifacts share one line and long values wrap to the available width. Use `--verbose` for the full role assignments, budget details, and start-check explanation. A skipped trust check remains explicit in both views.

Scope contains four rows describing the effective profile and CLI settings, followed by the trust-check result. For example, a run with three enabled cases from one explicitly selected file shows:

```text
Focus: Security design, code, and configuration
Abuse cases: Built-in + 3 user-supplied (review/abuse-cases.yaml)
Coverage: Depends on models, context, depth, and budget
Excludes: SCA/CVE scanning, comprehensive secret scanning, and runtime testing
```

The abuse-case row describes loaded definitions before applicability matching and verification. It includes organization cases only when enabled definitions are loaded, counts enabled repository and explicitly selected cases as user-supplied, and omits disabled or rejected definitions from those sources. An explicitly selected file already discovered in the repository is counted once. With dedicated verification disabled, the row says `Dedicated verification disabled`; with no active definitions, it says `None loaded`. Model-derived cases can be added later at `thorough` depth and are not counted at startup. Loaded case counts do not establish business-logic coverage; the result distinguishes actual checks, unresolved cases, and omitted work. `--quiet` suppresses the terminal header; the structured progress feed retains the scope rows.

Supply-chain and secret-handling weaknesses can still be found in source and configuration, and secret masking and result checks remain active. These checks do not replace a dependency vulnerability scan or comprehensive repository and Git-history secret scanning. No tests run against the application itself.

Use `standard` as a starting point, including for business logic analysis. `thorough` can find additional problems, but more expensive early analysis can leave less budget for verification and combining related findings. More findings or abuse cases do not by themselves establish better coverage. See [the measured standard and thorough comparison](model-selection.md#choosing-standard-or-thorough) for costs and limits, and check the run summary for skipped model work.

For `claude` and `codex`, the spending limit defaults to USD 20 for both `scan` and `assess`. Use `--budget USD` to override it; `--hard-budget` remains a compatible alias. The CLI prints the selected limit before starting. The controller reserves completion work before optional model calls and records unavailable cost as a conservative charge.

Control analysis and STRIDE analysis each process at most two components in parallel by default. Set `max_parallel` in a scan profile or pass `--max-parallel N` to `scan` or `assess`; the CLI value overrides the profile. Values from 1 to 16 are accepted. The run header shows the selected value, and the time reserve uses the same value. Provider rate limits can still interrupt a run; accepted steps remain available for `--resume` with compatible settings.

On a provider rate limit, all new model calls in the assessment wait together; already running calls may finish. Free failures allow up to three retries with delays of 15, 60, and 180 seconds; valid HTTP `Retry-After` delays are respected. Paid failures retain their stricter retry limits. CLI hosts without structured reset metadata use those fallback delays. A wait over three minutes, insufficient remaining time, or exhausted retries pauses the run with exit code 3, including when the affected job is optional. Accepted work is kept. Wait for provider capacity, then rerun the same command with `--resume`; the original deadline and compatibility checks still apply.

When a provider connection drops or cannot be opened, Analyzer repeats the call after 15 seconds. A failed call without a cost report, such as a Codex subscription call or a failed API call, is repeated at most once, and these paid repeats count toward the stricter retry limits. If the connection stays down for a required job, the run pauses with exit code 3 and keeps accepted work; check connectivity, then rerun the same command with `--resume`. An optional job records a coverage gap instead. Login, quota, certificate, configuration, and request errors are never repeated.

When an optional model job cannot run within the remaining budget, normal progress output immediately prints a `Coverage gap` warning naming the job's role and the budget reservation. A model failure that uses a fallback is also reported immediately. These messages do not require `--verbose`. Architect Review totals distinguish reviewed, unreviewed, and unresolved findings; abuse-case totals distinguish checked, partially checked, and unchecked candidates. A checked case can still be inconclusive. The phase completion line repeats those totals, and the final run summary lists omitted work. This also applies to `thorough`: a published report does not mean every optional check ran. `--quiet` suppresses live progress.

Model activity messages reflect the selected host's progress events. Normal progress shows the role, elapsed time and activity; job, repository and call IDs appear only with `--verbose` and in private diagnostics. Codex CLI events show thinking or writing when available, without displaying model text. `No progress update` means the call is still running without a recent update; it does not establish model inactivity or an API problem. Hosts without activity events say that intermediate activity is unavailable. An exceeded time limit remains a warning.

On an interactive terminal, missing-update messages stay in the single refreshed status row, including with `--verbose`. Plain logs print the notice once until the call changes state. Connection interruptions and timeouts remain visible as separate warnings. Codex transport failures use the fixed classifications described in [Codex CLI setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli).

Use `--verbose` to show job and call identities and detailed sanitized correction reasons. All full-assessment providers write a private diagnostic feed to `.assessment-work/diagnostics/attempt-*/events.jsonl` under the output directory; verbose startup and the completion summary name the file. It records job outcomes, model-call timing, safe host failure codes, and sanitized validation reasons without prompts, source excerpts, model answers, or raw stderr. Reasons are bounded with an explicit truncation marker; each feed stops at 8 MiB with a warning. A failed diagnostic write warns and leaves the analysis decisions unchanged. Resume creates another attempt directory and preserves earlier diagnostics and Claude host-event streams; `--rebuild` removes the earlier work directory. These records help explain execution and validation failures; they do not prove the semantic correctness of an accepted finding. Inspect any diagnostics before sharing them.

Each analysis job has at most six exchanges for source requests, results and corrections. The host requires a complete draft while room remains for up to two corrections, so source requests cannot consume the whole job budget before validation. A valid draft ends the job immediately. If no result passes validation, the job stops; the error reports used exchanges, source-read rounds and rejected drafts, and the private diagnostics retain those counts and the rejection reasons. A larger overall call budget does not increase this per-job limit.

When repeated model answers fail validation, the stop message names the analysis role, component and batch when available. A source-coverage failure distinguishes a source line that was not read from a decision citing the wrong source. Accepted steps remain saved. With unchanged source and settings and time remaining, retry the same command with `--resume` instead of `--rebuild`; investigate a repeated rejection before retrying again. Diagnostics retain the technical job identities and detailed validation reasons.

Discovery rejects interface quotations that do not match the cited source line, and interface addresses, deployment identities and operations that are absent from those quotations. Correction reasons identify the affected fields together without recording their values. For a quotation mismatch, Analyzer first asks for the affected references alone, using small windows from sources already retrieved by the task. That response can change only their line numbers and literal quotations; it cannot change files or interface claims. The complete corrected result then passes the same schema, source, retrieval and semantic checks. If targeted correction cannot produce a valid result, the existing full-result correction can run within the remaining exchange and correction limits. The model must cite an exact identity value or mark it unknown where the contract permits. Unsupported identity values cannot establish a connection; other independently evidenced service bindings may still resolve one. Required message topics still need evidence. Repeated invalid results can stop the run even when the provider responds successfully.

If Analyzer code or analysis resources change during a run, a warning explains that results may combine versions and that the assessment continues. If the version check cannot finish, the warning says that a consistent version cannot be confirmed. Keep the Analyzer installation unchanged during assessments; afterwards, use `--rebuild` with a stable installation to regenerate results from one version. Rebuilding discards earlier model work and makes new model calls against your budget or subscription allowance.

In an interactive terminal outside CI, the controller asks before a monetary budget gap skips or stops work. An evidence review that does not fit while component analysis is still running is postponed without a question and retried after that analysis. It first waits for running calls to finish and pauses new calls. Enter a higher **total budget in USD**, such as `40` to raise a USD 30 limit to USD 40, or press Enter to keep the current limit. There is no automatic increase. Three invalid answers keep the existing limit; EOF also declines. After declining, no further budget questions appear in that process. A run permits at most 16 explicitly approved increases. More budget does not guarantee completion, and waiting for an answer still counts toward the time limit.

Use `--non-interactive` in CI and unattended scripts. Budget questions are also disabled without input and stderr terminals, when a recognized CI marker is set, or with `--quiet`. The approved limit is saved before further spending; `--resume` with the original command restores the last approved limit for that run, including when resumed noninteractively. Starting a new run uses its configured budget. Time and call limits are never raised by this question.

Report authoring completes the required Security Architecture section first, then uses the remaining allowance for the Management Summary before requirements commentary. The summary can use less than a full estimated call allowance; the host still enforces its spending limit. If cost, time, call limits, or invalid model output prevent the summary, the report keeps its deterministic verdict and the run summary identifies the replacement.

Trust-boundary classification groups related crossing signals into bounded batches to reduce repeated model calls. Every signal is still accounted for; uncertain crossings remain visible. Detailed control review and threat analysis follow in their own phases. Additional evidence reads or corrections can require further calls, so batching does not guarantee a fixed duration.

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

With Codex CLI 0.163.0 installed on Linux/macOS and signed in using `codex login`, use `appsec-analyzer scan --profile codex-cli --max-calls 1000 --max-duration 14400` to use ChatGPT plan allowance. This experimental profile defaults to at most two components at a time, rejects USD budgets, and reports monetary cost as unavailable. A plan limit stops the run and preserves accepted work; wait for allowance and resume the original output. See [Codex CLI setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli) for model access, data use, local limits, and qualification status.

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

## Review an assessment with AI

After a scan completes, the next steps include `appsec-analyzer review` with that scan's result directory. The command opens interactive Claude Code or Codex with the existing assessment and the bundled [review skill](../skills/review-assessment/SKILL.md) for evidence-based discussion and remediation planning. No export or new scan is needed.

```sh
appsec-analyzer review /path/to/assessment
appsec-analyzer review /path/to/assessment --with claude
appsec-analyzer review /path/to/assessment --with codex --preview
```

Install and sign in to the chosen assistant first. Analyzer uses `claude` or `codex` from an absolute directory on your PATH. A saved `claude-cli` adapter defaults to Claude Code; `codex-cli` defaults to Codex. API providers, including the `codex` API profile, and older results without adapter metadata require `--with` or an interactive selection. The assistant uses its own configured model and account, independently of the assessment's role models and budget. Further usage can incur charges or consume subscription allowance, and native session-history settings apply.

The result must be a private completed assessment with unchanged recorded artifacts, just as for export. Modified, incomplete, incompatible, linked, or secret-containing results are refused. Preview validates the result and shows the skill and context without launching an assistant; use `--with` if no coding assistant was recorded. Launch requires an interactive terminal and has a four-hour limit. Ctrl+C uses the native assistant's cancellation behavior; exit the assistant to return to Analyzer. Analyzer propagates its exit status; preparation errors return 2.

The skill is supplied to this session with a read-only facts helper for IDs, severity, components, and topics. No global skill installation is needed. Ask, for example, “Explain F-003 and its evidence,” “Which mitigations should we do first?” or “Prepare a fix and tests for F-003.” The helper reads only validated published model data; an omitted requirements catalog is not evidence of compliance. For moved or deleted checkouts, select the appropriate source before asking for implementation; report discussion remains available.

The session starts in a fresh private working directory with references to the original reports. Codex starts in a read-only sandbox with approval prompts; Claude Code starts in plan mode with project settings and automatic CLAUDE.md loading excluded. Repository and result-directory hooks are excluded; native user and managed controls remain active. User and managed assistant configuration and login remain external to the assessment. This is an external assistant session, not an Analyzer job confined to the original admitted source snapshot. For implementation, explicitly request a change and use the assistant's permission workflow after checking current source against the examined revision. Preserve the saved assessment; proposed fixes or risk decisions do not automatically update findings.

Launch arguments follow the [official OpenAI CLI reference](https://developers.openai.com/codex/cli/reference/) and [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference). Offline tests cover artifact validation, selection, skill delivery, invocation, and packaged resources. Live interactive behavior and native assistant enforcement remain unqualified.

## Exports and compatibility

Exports can be requested on `scan` or `assess`, or generated later without model calls:

```sh
appsec-analyzer export --assessment /path/to/assessment \
  --output /path/to/new-export --formats markdown yaml html pdf sarif threatdragon pentest-tasks
```

`export` requires a completed `.assessment-state.json`, a model that passes the current schema, and artifacts matching every recorded digest. The source directory must be owned by the current user and private (mode 0700). The destination must not exist and must be outside Git checkouts and separate from the source; its parent must exist. Analyzer creates it with mode 0700 and publishes files with mode 0600. An interrupted or failed export is not a completed bundle; retry into a new directory. The saved assessment is left unchanged. Older standalone files without compatible state require explicit migration or reassessment.

The default formats are `markdown yaml`. Markdown, HTML and PDF require the recorded Markdown report. HTML requires Pandoc; PDF also requires WeasyPrint. Document conversion embeds only recorded local images or validated embedded SVG and rejects active markup and external image resources. Mermaid source remains a code block, with a warning; it is not rendered by this command. SARIF and pentest tasks retain the existing evidence and CWE filters, and Threat Dragon is a lossy diagram projection. Keep YAML for the complete model. Missing tools, modified inputs or failed validation cause exit 2 without a success result; success returns JSON with artifact digests and `model_calls: 0`.

`results` checks the hashes of already published files. Internal names such as `threat-model.yaml` remain in intermediate processing and historical fixtures; the current published model is `security-assessment.yaml`.

`--resume` never starts a fresh run when the Analyzer runtime changes: it rejects the incompatible state and preserves its accounting and original deadline. To start a new attempt with newly authorized limits, rerun explicitly without `--resume`; compatible accepted jobs may be reused.

Interactive triage, automated code fixes, baseline installation, and plugin hooks are not part of the public Analyzer CLI. The separate [security score](security-score.md) gives a limited deterministic indication without model calls. The focused analyst can preview and check selected abuse cases with `hypothesis --abuse-case`; see the [analyst guide](threat-analyst.md). The independent [AuthNZ review](authnz-review.md) checks authentication and authorization through Claude CLI and supports JSON/YAML reports and legacy pentest plans without a prior assessment.
