# Complete security assessment

## Preflight checks

`assess` checks selected local Git roots, remote repository read access and provider setup before cloning repositories or starting analysis. Failures return exit 2 without starting the assessment. Checks run again on resume; a previous success does not guarantee continued access. `--quiet` suppresses progress; failures and generation-test data-use and spending notices remain visible.

After these checks, `assess` sends one fixed synthetic prompt, with no repository content, to a low-cost model: haiku for the Claude CLI and gpt-luna for OpenAI and the Codex CLI. LiteLLM, Bedrock and Copilot get no model test. The test has its own limit outside the run's budget: at most USD 0.05, usually well below one cent, or one exchange from ChatGPT plan allowance for Codex. Only rejected credentials, a billing error, or exhausted quota stop the run. Any other outcome, such as a rate limit, a timeout, or a limit too small for the model, shows a warning, and the run continues. A passed test shows that the login or key, billing and quota work; it does not show that the run's own models answer.

`assess --skip-preflight` skips the repository access, provider and model test checks for one run. Errors they would find then show up at the clone or the first model call. Source admission, the clone's credential and destination controls, and the host CLI version and isolation checks still run.

The `preflight` command groups completed checks under one heading and uses the shared terminal colors. Before an assessment, completed checks appear as a `Preflight` block under the run summary, above the progress grid; a failed check prints at once and stops the run. Each repository and provider check appears once; the provider note states when model access was not tested. Long lines wrap; `--json` keeps the machine-readable result on stdout and progress on stderr.

Run the same checks independently without an assessment or output directory:

```sh
appsec-analyzer preflight --repo /path/to/project --profile claude
appsec-analyzer preflight --repo https://github.com/your-org/your-project.git --profile codex --json
```

Local selections must name top-level Git checkouts. Remote checks use `git ls-remote` for `HEAD`, require Git 2.34+, have a 30-second command timeout, and download no source objects. They use the same credentials, destination restrictions, TLS checks and trusted SSH host keys as cloning. Empty repositories or repositories without a default-branch commit fail. Git often gives the same failure for a missing private repository and insufficient permission, so Analyzer cannot always distinguish those causes. A later clone can still fail.

OpenAI checks each distinct configured role model with an authenticated [model metadata request](https://developers.openai.com/api/reference/resources/models/methods/retrieve). LiteLLM checks the configured gateway's `/v1/models` list with its API key, including a configured endpoint prefix. These requests send model identifiers and credentials to the selected provider, with no source content or generation. Missing models, rejected credentials, inaccessible metadata, malformed replies and connection failures stop startup. Model-list access does not prove inference permission, upstream gateway credentials, quota or assessment quality. Keys that cannot read model metadata can use the explicit standalone generation test below to diagnose the primary model; other roles then receive TLS checks only. Automatic assessment startup still requires metadata access.

Native Bedrock checks credential format and a verified TLS connection to its regional runtime endpoint; server authentication and model access remain unverified. Claude CLI checks local login status or the presence of externally supplied API/OAuth credentials; Codex CLI checks its reviewed version, isolation features and local ChatGPT login. These checks do not prove server authentication, model availability or quota. The output preserves these limits instead of claiming successful model access.

To test actual generation, explicitly authorize one exchange with the survey's model, the primary model, with a separate spending limit:

```sh
appsec-analyzer preflight --repo /path/to/project --profile claude --test-model --budget 0.10
appsec-analyzer preflight --repo /path/to/project --profile codex-cli --test-model --max-calls 1
```

`--test-model` is available only on `preflight`. Monetary profiles require an explicit `--budget` of at least USD 0.01; the profile's default budget is insufficient authorization. Codex CLI requires explicit `--max-calls` and consumes one exchange from ChatGPT plan allowance; monetary cost remains unavailable. The fixed synthetic prompt contains no source excerpts or project context, grants no tools, and uses the selected primary model and reasoning effort. The exchange has a 30-second limit and no automatic retry. API tests bound output to at most 1,024 tokens within the configured model limit and reserve against the supplied test budget; a small budget or token limit may prevent completion. The separate test budget does not increase an assessment's budget. Other role models, assessment quality and future quota remain unverified even after a successful test. `--json` prints a result with `assessment_status: not_run`; it creates no assessment state or report. Ctrl+C returns 130.

## Run an assessment

`appsec-analyzer assess` analyzes one or several local Git checkouts or explicitly selected Git URLs as one
system. It uses Claude CLI by default, freezes admitted source, runs
semantic roles, checks their output against canonical contracts, verifies
evidence, and publishes a report only after validation. The report covers
components, data flows, trust boundaries, controls, weaknesses, abuse cases,
prioritized findings, and remediation. Repository evidence is a bounded
snapshot; production behavior and business intent require human review.

```sh
appsec-analyzer assess --repo /path/to/project \
  --budget 20 --assessment-depth standard
appsec-analyzer assess --repo /path/to/service --repo /path/to/client \
  --profile claude --budget 30 --output /private/system-assessment
```

The supported depths are `quick`, `standard`, and `thorough`. They change work limits and select the corresponding model configuration within `--profile claude|codex`. With the default `claude` profile, `--model` pins all roles; `--stride-model` (the survey's model), `--triage-model`, and `--merger-model` override specific roles. Check [model selection](model-selection.md) before spending.

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

For `claude` and `codex`, the spending limit defaults to USD 20 for `assess`. Use `--budget USD` to override it; `--hard-budget` remains a compatible alias. The CLI prints the selected limit before starting. The controller reserves completion work before optional model calls and records unavailable cost as a conservative charge.

Control analysis and the survey each process at most two components in parallel by default. Set `max_parallel` in a scan profile or pass `--max-parallel N` to `assess`; the CLI value overrides the profile. Values from 1 to 16 are accepted. The run header shows the selected value, and the time reserve uses the same value. Provider rate limits can still interrupt a run; accepted steps remain available for `--resume` with compatible settings.

On a provider rate limit, all new model calls in the assessment wait together; already running calls may finish. Free failures allow up to three retries with delays of 15, 60, and 180 seconds; valid HTTP `Retry-After` delays are respected. Paid failures retain their stricter retry limits. CLI hosts without structured reset metadata use those fallback delays. A wait over three minutes, insufficient remaining time, or exhausted retries pauses the run with exit code 3, including when the affected job is optional. Accepted work is kept. Wait for provider capacity, then rerun the same command with `--resume`; the original deadline and compatibility checks still apply.

When a provider connection drops or cannot be opened, Analyzer repeats the call after 15 seconds. A failed call without a cost report, such as a Codex subscription call or a failed API call, is repeated at most once, and these paid repeats count toward the stricter retry limits. If the connection stays down for a required job, the run pauses with exit code 3 and keeps accepted work; check connectivity, then rerun the same command with `--resume`. An optional job records a coverage gap instead. Login, quota, certificate, configuration, and request errors are never repeated.

When an optional model job cannot run within the remaining budget, normal progress output immediately prints a `Coverage gap` warning naming the job's role and the budget reservation. A model failure that uses a fallback is also reported immediately. These messages do not require `--verbose`. Architect Review totals distinguish reviewed, unreviewed, and unresolved findings; abuse-case totals distinguish checked, partially checked, and unchecked candidates. A checked case can still be inconclusive. The phase completion line repeats those totals, and the final run summary lists omitted work. This also applies to `thorough`: a published report does not mean every optional check ran. `--quiet` suppresses live progress.

Model activity messages reflect the selected host's progress events. Normal progress shows the role, elapsed time and activity; job, repository and call IDs appear only with `--verbose` and in private diagnostics. Codex CLI events show thinking or writing when available, without displaying model text. `No progress update` means the call is still running without a recent update; it does not establish model inactivity or an API problem. Hosts without activity events say that intermediate activity is unavailable. An exceeded time limit remains a warning.

On an interactive terminal, missing-update messages stay in the single refreshed status row, including with `--verbose`. Plain logs print the notice once until the call changes state. Connection interruptions and timeouts remain visible as separate warnings. Codex transport failures use the fixed classifications described in [Codex CLI setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli).

Use `--verbose` to show job and call identities and detailed sanitized correction reasons. It also lists, below the coverage statement about program files that belong to no component, the first files of each of the ten largest directories; the report keeps the counts per directory. All full-assessment providers write a private diagnostic feed to `.assessment-work/diagnostics/attempt-*/events.jsonl` under the output directory; verbose startup and the completion summary name the file. It records job outcomes, model-call timing, safe host failure codes, and sanitized validation reasons without prompts, source excerpts, model answers, or raw stderr. Reasons are bounded with an explicit truncation marker; each feed stops at 8 MiB with a warning. A failed diagnostic write warns and leaves the analysis decisions unchanged. Resume creates another attempt directory and preserves earlier diagnostics and Claude host-event streams; `--rebuild` removes the earlier work directory. These records help explain execution and validation failures; they do not prove the semantic correctness of an accepted finding. Inspect any diagnostics before sharing them.

Each analysis job has at most six exchanges for source requests, results and corrections. The host requires a complete draft while room remains for up to two corrections, so source requests cannot consume the whole job budget before validation. A valid draft ends the job immediately. If no result passes validation, the job stops; the error reports used exchanges, source-read rounds and rejected drafts, and the private diagnostics retain those counts and the rejection reasons. A larger overall call budget does not increase this per-job limit.

When repeated model answers fail validation, the stop message names the analysis role, component and batch when available. A source-coverage failure distinguishes a source line that was not read from a decision citing the wrong source. Accepted steps remain saved. With unchanged source and settings and time remaining, retry the same command with `--resume` instead of `--rebuild`; investigate a repeated rejection before retrying again. Diagnostics retain the technical job identities and detailed validation reasons.

Discovery rejects interface quotations that do not match the cited source line, and interface addresses, deployment identities and operations that are absent from those quotations. Correction reasons identify the affected fields together without recording their values. For a quotation mismatch, Analyzer first asks for the affected references alone, using small windows from sources already retrieved by the task. That response can change only their line numbers and literal quotations; it cannot change files or interface claims. The complete corrected result then passes the same schema, source, retrieval and semantic checks. If targeted correction cannot produce a valid result, the existing full-result correction can run within the remaining exchange and correction limits. The model must cite an exact identity value or mark it unknown where the contract permits. Unsupported identity values cannot establish a connection; other independently evidenced service bindings may still resolve one. Required message topics still need evidence. Repeated invalid results can stop the run even when the provider responds successfully.

If Analyzer code or analysis resources change during a run, a warning explains that results may combine versions and that the assessment continues. If the version check cannot finish, the warning says that a consistent version cannot be confirmed. Keep the Analyzer installation unchanged during assessments; afterwards, use `--rebuild` with a stable installation to regenerate results from one version. Rebuilding discards earlier model work and makes new model calls against your budget or subscription allowance.

In an interactive terminal outside CI, the controller asks before a monetary budget gap skips or stops work. An evidence review that does not fit while component analysis is still running is postponed without a question and retried after that analysis. It first waits for running calls to finish and pauses new calls. Enter a higher **total budget in USD**, such as `40` to raise a USD 30 limit to USD 40, or press Enter to keep the current limit. Keys pressed before the question appears are discarded, so they neither raise nor keep the limit. There is no automatic increase. Three invalid answers keep the existing limit; EOF also declines. After declining, no further budget questions appear in that process. A run permits at most 16 explicitly approved increases. More budget does not guarantee completion, and waiting for an answer still counts toward the time limit.

Use `--non-interactive` in CI and unattended scripts. Budget questions are also disabled without input and stderr terminals, when a recognized CI marker is set, or with `--quiet`. The approved limit is saved before further spending; `--resume` with the original command restores the last approved limit for that run, including when resumed noninteractively. Starting a new run uses its configured budget. Time and call limits are never raised by this question.

Report authoring completes the required Security Architecture section first, then uses the remaining allowance for the Management Summary before requirements commentary. The summary can use less than a full estimated call allowance; the host still enforces its spending limit. If cost, time, call limits, or invalid model output prevent the summary, the report keeps its deterministic verdict and the run summary identifies the replacement.

Trust-boundary classification groups related crossing signals into bounded batches to reduce repeated model calls. Every signal is still accounted for; uncertain crossings remain visible. Detailed control review and threat analysis follow in their own phases. Additional evidence reads or corrections can require further calls, so batching does not guarantee a fixed duration.

For OpenAI Responses, choose `--profile codex` and a separate `--assessment-depth`. The profile supplies the connection, model, reasoning, and output cap for that depth, so no `--host` is needed. Claude role overrides do not apply. Existing host and depth-profile calls remain compatible as described in [model selection](model-selection.md).

`assess` also accepts the headless export options `--pentest-tasks`,
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
settings, and limits; `--rebuild` discards earlier model work. A source change
may require a fresh assessment. Without either flag, a new
scan reuses compatible accepted steps of an unfinished run in the same output.
What the reused steps cost counts toward the new run's spending or call limit,
so a higher limit for the new run must cover them too.
In an interactive terminal it first asks whether to continue that run, start
such a new scan (the default for Enter or end of input), or rebuild; continuing
is offered only while the run's limits, deadline, and accounting allow it.
Keys pressed before the question appears do not answer it, and the chosen start
is confirmed in one line.
`--non-interactive`, `--quiet`, `--json`, and CI runs never ask. A continued run's
header names its start, working time, spending so far, and deadline; a new scan
names the unfinished run whose accepted steps it reuses. Both run every phase
again, and only steps without a matching accepted result call a model: the
progress display marks reused components, and each phase's end line says
whether its steps were reused. For a continued run, ELAPSED shows the current
attempt and, in parentheses, the working time of all attempts. Earlier results
stay in the output until a new run completes; that run removes the ones it did
not replace. Inspect `status` or `progress`
with the output directory, request `stop`, and use `results` to verify the
published files. A deterministic `scan-sources` has no semantic assessment status and
uses its [own result schema](../schemas/deterministic-scan-result.schema.json).

The source guide, retained in [history](history/advisor/security-assessment.md),
explains domain concepts and earlier plugin behavior in detail. Its commands
and provider statements are historical.

With Codex CLI 0.163.0 installed on Linux/macOS and signed in using `codex login`, use `appsec-analyzer assess --repo /path/to/project --profile codex-cli --max-calls 1000 --max-duration 14400` to use ChatGPT plan allowance. This experimental profile defaults to at most two components at a time, rejects USD budgets, and reports monetary cost as unavailable. A plan limit stops the run and preserves accepted work; wait for allowance and resume the original output. See [Codex CLI setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli) for model access, data use, local limits, and qualification status.

### Source-read failures

Survey jobs receive the exact readable repository IDs and repository-relative paths. They are instructed to report missing evidence when a required file is absent from that list. A file mentioned in an import or earlier analysis does not grant permission to read it.

A well-formed relative filename outside the task selection is refused without reading it. Analyzer asks the model to use permitted sources or report missing evidence as unresolved, within the existing call, time and read limits. Repeated invalid proposals can still exhaust the job; they never expand its source selection.

`Model requested a source outside this task's selection` stops the run for unsafe paths, unknown repository IDs, or paths paired with the wrong repository. Diagnostics identify the category without echoing the model's path. Earlier versions also stopped immediately for an ordinary filename absent from the admitted inventory; their saved diagnostics cannot establish the exact requested file.

Accepted jobs remain in the output directory. After correcting the cause, repeat the original command with the same output and `--resume` while its original limits and compatibility checks permit. If the deadline has expired, repeat the command without `--resume` or `--rebuild` to start a new attempt and reuse compatible accepted jobs. Changed survey inputs require those jobs to run again. Resuming alone does not correct an unchanged model request.

## Survey and verification

An assessment examines the code with two methods. The survey looks at each component openly and reports any weakness it finds. Verification works through a fixed list of questions for selected security aspects, such as authorization, and answers each question at every place in the code where it applies. The survey always runs. Verification runs after it for the aspects that the assessment depth or your profiles select.

### The survey

A model reads one component at a time, such as the API server or the web frontend, and reports the weaknesses it finds. The six STRIDE categories are its checklist, and each finding carries one of them. Older reports and some messages still call the survey the STRIDE analysis.

Because the survey is open, it also finds weaknesses that no list foresees. In the pilot runs on OWASP Juice Shop, it reported weaknesses that the verification catalog has no item for, such as an OAuth login without a `state` parameter and a password reset without throttling. The survey does not go through the code route by route, though. When many routes share one weakness, it often reports one finding with a few examples.

### Verification

The [verification catalog](../data/test-cases.yaml) lists verification items per security aspect. Each item is one question. For authorization, `TC-AUTHZ-01` asks whether access to an object checks its owner, and `TC-AUTHZ-02` whether privileged operations check the caller's role. Each aspect also has a goal item, such as `TC-AUTHZ-06`, which asks whether a caller can read or change data beyond their rights by any path.

Verification takes two steps for each aspect:

1. Without a model, Analyzer collects the places where the items apply. For authorization, these are the application's routes and the hits of the matching scanner rules. For input validation, they are code sites such as raw database queries, shell commands, or HTML output.
2. One model job per component answers every item at every place, with the code of the handlers, middlewares, and guards involved. It records a finding, a control, or another outcome for each item, and it may add places it found itself.

A place that the job could not decide records undecidable. Undecidable, partial, and no finding never count as a control, and comments or documentation are not evidence of one. Catalog IDs still start with `TC-`, and the settings and result fields still say `test_cases`, because the items were called test cases before.

### An example

In a pilot run on Juice Shop, the survey reported that a user can change another user's basket items through `PUT /api/BasketItems/:id`. Verification checked `TC-AUTHZ-01` on every basket item route. It also found that any logged-in user can read and delete other users' basket items through `GET` and `DELETE` on the same path. In the same run, it found that any logged-in user can read every user record through `GET /api/Users/:id` and create products through `POST /api/Products`. The survey reported neither. Of the nine authorization challenges in Juice Shop, verification found eight and the survey seven. Verifying authorization took nine model jobs in that run and cost USD 4.45.

### How the results come together

While they run, the two methods do not see each other's results. Verification starts from the routes and scanner hits, not from survey findings, because a weakness that two methods find independently is better supported than one a model was asked to confirm. After both have finished, Analyzer compares their findings by code line and CWE:

| Case | What the report shows |
| --- | --- |
| Both found the weakness on the same line, with the same CWE or a CWE of the same weakness family, such as CWE-639 and CWE-862 for missing authorization. | One finding. Its card says "Found by: survey and verification" and names the verification items. |
| Verification found a protecting control on the line where the survey reported a weakness with the same CWE. | The survey finding stays and is marked "Contradicted by verification". Check the code before you close it. |
| Only verification found the weakness. | The finding is listed in the section Verification Findings. These findings do not count in the totals of the findings register yet. |
| Only the survey found the weakness, or verification did not examine the location. | The survey finding stays unchanged. |

Findings on neighbouring lines stay separate, because a route table often registers a different route on the next line. The same weakness therefore appears twice when the two methods anchor it on different lines or label it with CWEs of different families, for example missing authorization in verification and information disclosure in the survey.

### What each depth verifies

| Depth | Survey | Verification |
| --- | --- | --- |
| quick | yes | none |
| standard | yes | `AuthZ` |
| thorough | yes | `AuthZ`, `InputVal`, `DataProt`, `AI` |

These are the shipped defaults from [data/assessment-depths.yaml](../data/assessment-depths.yaml). Standard depth verifies authorization only, because in four pilot runs on Juice Shop this aspect added the most for its cost. The run header shows the methods, such as `Survey · Verify AuthZ`.

Each verified aspect adds model jobs after the survey and sends more source code to the model. A component gets one job per aspect, or several when it has more than 40 places to check. It gets no job for an aspect when none of the aspect's items has a place there and the goal item does not apply, so the cost grows with the number of routes and code sites. Before the survey starts, the run names the components it will verify. Before the first verification job, it states the estimated cost of all jobs and whether the remaining budget covers them; jobs with an accepted result of an earlier attempt need no new model call and stay out of the estimate. Until a verification job has finished, the estimate uses the survey's cost per job. If the budget runs out, the remaining jobs do not run, their places record undecidable, and the completion summary and the report mark the aspect incomplete. The progress display counts the verification jobs as part of the threat analysis from its start. It shows the survey and the verification as two steps, each with its own start and end. It lists each component once its verification has finished, with its duration, however many jobs the component needed, and names the jobs without a result.

### Configure verification

You choose the verified aspects per depth in a scan profile, and an organization can set its own defaults in an organization profile. Analyzer starts from the shipped file, applies the organization profile, and then the scan profile. There is no command-line option for it.

To verify input validation as well at standard depth, and authorization already at quick depth, add this to a scan profile:

```yaml
schema_version: 1
depths:
  standard:
    verify: [AuthZ, InputVal]
  quick:
    verify: [AuthZ]
```

`verify: []` runs the survey only at that depth. `test_cases: false` does the same for every depth whose `verify` the profile does not set. To leave out a single item, list it under `test_cases.disable` with a reason, and the report shows it as disabled with that reason. An organization profile can make aspects mandatory with `test_cases.required_aspects`, and a scan profile cannot remove them. Profiles inside an assessed repository are rejected, so repository content cannot select or disable verification. [Verification settings](profiles.md#verification-settings) describes every field, and [what each depth does](profiles.md#what-each-depth-does) the other depth settings.

`test_cases: true` records the catalog without model jobs. Only the nine rule-based items then receive an outcome, from the recorded results of their scanner rules, and the other items are listed as not examined. A rule-based item reports a control only when every applicable rule is satisfied and the scanner recorded a result for each. A control here means that the examined files contain the expected configuration. It does not show that the control works in production.

### Where to find the results

With verification on:

- Findings from scanner rules carry `rule_ids` and `test_case_ids` in `security-assessment.yaml`, and their details link the verification items and rules.
- `security-assessment.yaml` gains a `test_case_results` block, with `incomplete_aspects` when the budget ended verification early.
- Survey findings that verification found too carry `verification`, and those it contradicts carry `verification_contradicted`.
- The report gains the appendix Verification Items, which lists every catalog item and its outcome, with one row per component for model-investigated items.
- With a verified aspect, `security-assessment.yaml` gains `test_case_findings`, and the report the section Verification Findings with those the survey did not report. They do not count in the totals of the findings register yet.
- The completion summary shows a Verification row with the outcome counts.
- In SARIF, a linked finding uses the verification item ID as `ruleId`. The finding ID moves to the result property `findingId`.

The aspects `IAM` and `SessionMgmt` are accepted but not investigated yet. How the places to check are chosen and how outcomes are decided is described in the [orchestration contract](internal/contracts/orchestration-actions.md#verification-jobs). The design and the pilot runs are in the [proposal](internal/analysis/aspect-test-cases-proposal-2026-10-19.md) and the [implementation status](internal/analysis/aspect-test-cases-implementation-status-2026-10-19.md).

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
appsec-analyzer assess --repo /path/to/project --budget 20 \
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

Exports can be requested on `assess`, or generated later without model calls:

```sh
appsec-analyzer export --assessment /path/to/assessment \
  --output /path/to/new-export --formats markdown yaml html pdf sarif threatdragon pentest-tasks
```

`export` requires a completed `.assessment-state.json`, a model that passes the current schema, and artifacts matching every recorded digest. The source directory must be owned by the current user and private (mode 0700). The destination must not exist and must be outside Git checkouts and separate from the source; its parent must exist. Analyzer creates it with mode 0700 and publishes files with mode 0600. An interrupted or failed export is not a completed bundle; retry into a new directory. The saved assessment is left unchanged. Older standalone files without compatible state require explicit migration or reassessment.

The default formats are `markdown yaml`. Markdown, HTML and PDF require the recorded Markdown report. HTML requires Pandoc; PDF also requires WeasyPrint. Document conversion embeds only recorded local images or validated embedded SVG and rejects active markup and external image resources. Mermaid source remains a code block, with a warning; it is not rendered by this command. SARIF and pentest tasks retain the existing evidence and CWE filters, and Threat Dragon is a lossy diagram projection. Keep YAML for the complete model. Missing tools, modified inputs or failed validation cause exit 2 without a success result; success returns JSON with artifact digests and `model_calls: 0`.

`results` checks the hashes of already published files. Internal names such as `threat-model.yaml` remain in intermediate processing and historical fixtures; the current published model is `security-assessment.yaml`.

When only the Analyzer runtime changed since an unfinished run started, `--resume` continues that run with its original deadline, limits, recorded costs, and elapsed time; the run header says so. Accepted jobs whose model request is unchanged are reused without a new call or charge. The others run again at additional cost, and the cost of their earlier answers stays counted. `--resume` never starts a fresh run: a completed run, or changed source, settings, or limits, still need a run without `--resume`, which may reuse compatible accepted jobs.

Interactive triage, automated code fixes, baseline installation, and plugin hooks are not part of the public Analyzer CLI. The separate [security score](security-score.md) gives a limited deterministic indication without model calls. The focused analyst can preview and check selected abuse cases with `hypothesis --abuse-case`; see the [analyst guide](threat-analyst.md). The independent [AuthNZ review](authnz-review.md) checks authentication and authorization through Claude CLI and supports JSON/YAML reports and legacy pentest plans without a prior assessment.

## Claude host integration boundary

The installed engine entry includes `skills/appsec-analyzer/claude-code.md` for the existing Claude Code assessment dialogue. A composed host binds its commands to the exact bundled engine. `scan --interactive-launch` retains the host's quick/standard/thorough hard ceilings of USD 10/20/40, concurrency 3 and width 72, unless explicitly overridden; `--component-workers` retains its 1–4 range. It selects only the Claude CLI adapter and disables budget prompts. This compatibility switch grants no spending authorization. Other CLI workflows retain their defaults.

`assessment-entry` exposes the existing launch helpers without model calls: `destination --repo PATH [--output DIR] [--storage analyzer|advisor]`, `trust --repo PATH`, `holder --output DIR`, `legacy --repo PATH --output DIR`, `context-preview` and `context-save` with that same repository/output selection, and `clean --output DIR [--apply]`. Source selections must name a local top-level Git checkout. Default storage remains Analyzer; the explicit Advisor namespace preserves the plugin's existing application destination. Output paths must be canonical, private and outside checkouts. Context preview/save reuse the existing bounded dialog and validation; only an answered dialog can persist confirmed business context. `clean` defaults to inspection, serializes with launch ownership and refuses active holders before deleting the existing stale-state allowlist. Reports, audit history, caches and accepted receipts remain.

These JSON responses carry `interface_version: 1`, `kind: assessment-entry`, and `operation`. Destination returns `repo` and `output`; holder returns boolean `live` and its `run_id` or null; legacy returns `action: none|offer|incomplete` and an incomplete reason when present; context-preview returns the existing bounded preview object under `preview`; context-save returns the existing save action; clean returns the existing inspection or cleanup record. Trust returns `kind: assessment-trust`, the existing strict preflight report and exit 2 on findings. Missing, unsafe or incompatible selections fail with exit 2. Preparation does not authorize a subsequent assessment or make repository text authoritative.

`progress --output DIR --after N` accepts a nonnegative public event cursor. The response retains the existing progress fields and adds `next_offset` and boolean `events_omitted`; at most 100 events are returned. Bind a cursor to its returned `run_id`, reset it for a new owner and preserve an omission warning. A cleaned feed may be empty while the public state is terminal. A display must never infer successful completion from an empty feed or cancel the owner when the display exits.

`query --output DIR [--id ID|--grep TERM|--severity LEVEL|--component NAME]` uses the same validated saved-result facts as review. Filters compose; `--id` cannot combine with filters. `--summary` instead renders the existing fixed summary and cannot combine with filters. These operations verify completion, saved artifact digests and the current model contract before answering; modified or incomplete results fail. They do not launch an assistant, call models, edit source or authorize triage. Use the existing `export` operation for explicit re-export.

The composed binding selects `--launch-defaults advisor` for the existing depth budgets and concurrency defaults, independently of Claude host selection, unattended operation and display width. `--interactive-launch` remains a compatibility adapter with its original defaults and saved-profile identity. Explicit budgets and parallel limits retain precedence. For a host-default launch with `--output`, the engine creates its public progress feed without the host naming an internal file.
