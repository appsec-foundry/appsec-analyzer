# Complete security assessment

Use `assess` to review a system’s architecture, source code, and configuration. It makes model calls and writes a report. Start with [Run an assessment](#run-an-assessment) for examples. [Preflight checks](#preflight-checks) describes what `assess` verifies before it starts.

## Preflight checks

Before `assess` clones a repository or calls a model, it checks that it can read your repositories and that the provider is set up. A failed check stops the run with exit code 2. The checks run again on `--resume`, because earlier access can be revoked. `--quiet` hides progress, but failures and notices about data use and spending stay visible.

`assess --skip-preflight` skips the repository and provider checks for one run. Errors then appear at the clone or at the first model call. Source admission, the clone's credential and destination controls, and the host CLI version and isolation checks still run.

To run the same checks without an assessment, use `preflight`. It needs no output directory. With `--json`, the result goes to stdout and progress to stderr.

```sh
appsec-analyzer preflight --repo /path/to/project --profile claude
appsec-analyzer preflight --repo https://github.com/your-org/your-project.git --profile codex --json
```

Repository checks:

- A local selection must be a top-level Git checkout or a [directory without Git](#directories-without-git). A `.git` that has content but cannot be read fails the check.
- Remote repositories are checked with `git ls-remote` for `HEAD`. This needs Git 2.34 or later, times out after 30 seconds, and downloads no source. It uses the same credentials, destination restrictions, TLS checks, and trusted SSH host keys as cloning.
- An empty repository, or one without a commit on the default branch, fails.
- A failed check names the cause when Git reports one: a host name that cannot be resolved, an unreachable host, a refusing proxy, a rejected TLS certificate or SSH host key, a refused SSH login, a rejected token, a missing login, a missing repository, refused access, a redirect, a request limit, or a server error.
- If an HTTPS URL without `.git` fails, the check tries it once with `.git` and shows the URL that worked. See [Configuration](configuration.md) for when it skips this attempt.
- Git often reports a missing private repository and missing permission in the same way, so Analyzer cannot always tell them apart. A later clone can still fail.

Provider checks:

- **OpenAI** requests the [metadata](https://developers.openai.com/api/reference/resources/models/methods/retrieve) of each configured role model.
- **LiteLLM** reads the gateway's `/v1/models` list, including a configured endpoint prefix.
- **Bedrock** checks the credential format and a verified TLS connection to the regional endpoint.
- **Claude CLI** checks the login status, or that API or OAuth credentials are present.
- **Codex CLI** checks its minimum version base, required isolation options and features, and the local ChatGPT login.

The OpenAI and LiteLLM requests send model names and credentials to the provider, but no source and no generation request. Missing models, rejected credentials, unreadable metadata, malformed replies, and connection failures stop the start. None of these checks proves that you may run a model, that quota is left, or that the assessment will be good. The output says what was not verified.

`assess` does not run a separate generation test before the analysis.

To test real generation, `preflight --test-model` sends one short synthetic message to the survey model (the primary model). You authorize it with a separate limit:

```sh
appsec-analyzer preflight --repo /path/to/project --profile claude --test-model --budget 0.10
appsec-analyzer preflight --repo /path/to/project --profile codex-cli --test-model --max-calls 1
```

- `--test-model` exists only on `preflight`.
- Profiles with a USD budget need an explicit `--budget` of at least USD 0.01. The default budget does not count. Codex CLI needs `--max-calls 1` and uses one exchange of your ChatGPT plan allowance.
- The message contains no source and no project context, and grants no tools. It uses the primary model and its reasoning effort.
- The exchange has a 30-second limit and is not retried. API tests cap the output at 1,024 tokens. A very small budget or token limit can keep the test from finishing.
- The test budget does not raise the budget of an assessment. Other role models, assessment quality, and future quota stay unverified. `--json` prints `assessment_status: not_run`, and no assessment state or report is created.

Keys that cannot read model metadata can still use this test to diagnose the primary model. Other roles then get only TLS checks. Starting an assessment automatically still needs metadata access.

## Run an assessment

`appsec-analyzer assess` analyzes one or more local Git checkouts, directories without Git, or explicitly selected Git URLs as one system. It uses Claude CLI by default. Analyzer captures a fixed source copy, runs analysis roles, checks their output and evidence, and publishes a report after validation.

The report covers components, data flows, trust boundaries, controls, weaknesses, abuse cases, prioritized findings, and fixes. It describes the captured source. Production behavior and business intent still need human review.

```sh
appsec-analyzer assess --repo /path/to/project \
  --budget 20 --assessment-depth standard
appsec-analyzer assess --repo /path/to/service --repo /path/to/client \
  --profile claude --budget 30 --output /private/system-assessment
```

The supported depths are `quick`, `standard`, and `thorough`. If you give no depth and no profile sets one, `assess` asks in an interactive terminal. The question shows each depth's spending limit, relative cost and runtime, and what it verifies. Enter selects `standard`. With `--non-interactive`, `--quiet`, `--resume`, in CI, or without a terminal, there is no question and `standard` applies.

The depths change work limits and select the matching model configuration within `--profile claude|codex`. With the default `claude` profile, `--model` pins all roles. `--stride-model` (the survey's model), `--triage-model`, and `--merger-model` override single roles. Check [model selection](model-selection.md) before spending.

Before analysis, the startup header shows the effective settings in three groups: Run, Scope, and Workflow & results. It covers billing, budget or call limit, depth, time, parallelism, models, and output formats. `--verbose` adds the role models and budget details. Skipped trust checks are always shown. `--quiet` hides the header, but the structured progress feed keeps the scope information.

The Scope group has four rows, followed by the trust-check result. For a run with three enabled cases from one selected file, it shows:

```text
Focus: Security design, code, and configuration
Abuse cases: Built-in + 3 user-supplied (review/abuse-cases.yaml)
Coverage: Depends on models, context, depth, and budget
Excludes: SCA/CVE scanning, comprehensive secret scanning, and runtime testing
```

The abuse-case row counts the enabled definitions loaded at startup, before Analyzer checks whether they apply. It separates built-in, organization, and user-supplied cases and counts each file once. It says `Dedicated verification disabled` when verification is off and `None loaded` when no definitions are active. Cases that a model derives later at thorough depth are not counted. Loaded definitions do not prove that business logic was checked. The result lists completed checks, unresolved cases, and omitted work separately.

Weaknesses in supply chain and secret handling can still be found in source and configuration, and secret masking and result checks stay active. These checks do not replace a dependency vulnerability scan or a full secret scan of the repository and its Git history. No tests run against the application itself.

Use `standard` as a starting point, also for business logic analysis. `thorough` can find additional problems, but more expensive early analysis can leave less budget for verification and for combining related findings. More findings or abuse cases do not by themselves mean better coverage. See [the measured depth comparison](model-selection.md#choosing-a-depth) for costs and limits, and check the run summary for skipped model work.

For `claude` and `codex`, the spending limit for `assess` is USD 20 by default. Change it with `--budget USD`; `--hard-budget` is an alias. The CLI prints the selected limit before it starts. The controller reserves the cost of completion work before optional model calls, and it records an unavailable cost as a conservative charge.

Control analysis, trust-boundary review, the survey, verification, and abuse-case checks each run up to four jobs in parallel by default. The default is three when the number of components divides by three, and two on Codex and Copilot subscriptions. Set `max_parallel` in a scan profile or pass `--max-parallel N` (1 to 16). The CLI value wins and applies as given. The run header shows the value, and the time reserve uses it. Near the spending limit, calls reserve what their kind of job has cost in this run instead of the full per-call amount, so jobs keep running side by side. The limit itself stays fixed.

For the OpenAI API, use `--profile codex` with `--assessment-depth`. The profile supplies the connection, model, reasoning, and output cap for that depth, so `--host` is not needed. Claude role overrides do not apply. Older `--host` and depth-profile calls still work; see [model selection](model-selection.md).

### Directories without Git

`assess`, `scan-sources`, `score`, and `audit-requirements` accept a local directory without Git. `authnz-review` and `analyze-threats` still need a Git checkout.

A directory counts as without Git when it lies in no Git repository and has no `.git`, or only an empty `.git` directory. A subdirectory of a Git checkout is rejected, and so is a `.git` that has content but cannot be read. Repair or remove such a `.git`.

- **Result directory:** `--output` is required and must be outside the selected directory. Analyzer writes nothing into the selected directory.
- **Which files count:** A `.gitignore` applies as in a Git checkout. Without one, Analyzer prints a notice and nearly every readable file counts as source, including build output and dependencies. This raises cost and sends more to the model. Add a `.gitignore` before you start. Files with secret names, such as `.env` or `*.pem`, stay out in every case.
- **Temporary copy:** Analyzer copies the files into a private temporary directory and removes the copy after the run. After a hard stop the copy stays, and the next run says so.
- **State of the source:** The assessment covers the directory as it was at the start. Later edits do not reach the run. `--resume` continues only if the content is unchanged.
- **Report:** The report names the source as a directory without Git and shows no commit.
- **Limits:** The limits for checkouts apply: 20,000 files and 64 MiB of captured source.

### Rate limits and connection failures

When a provider rate-limits a call, Analyzer pauses all new model calls. Calls already running may finish. A call that failed without a charge is retried up to three times, after 15, 60, and 180 seconds or the provider's valid `Retry-After` delay. Calls that incurred a charge have stricter limits. CLI providers that give no reset information use the default delays.

The run pauses with exit code 3 if a wait would exceed three minutes, time runs short, or the retries are used up. This also applies to optional jobs. Accepted work is saved. Wait for capacity, then repeat the command with `--resume`. The original deadline and compatibility checks still apply.

If rate limits keep returning, run fewer jobs in parallel. Repeat the command without `--resume` and with the smaller `--max-parallel` value that the pause message names. A changed `max_parallel` cannot resume the paused run, but the new run reuses its accepted jobs.

If the connection to the provider drops or cannot open, Analyzer retries once after 15 seconds, also for subscription calls. These retries count toward the stricter retry limits for paid calls. A persistent failure pauses a required job with exit code 3 and saves accepted work. Check your connection, then use `--resume`. A failure in an optional job records a coverage gap instead. Login, quota, certificate, configuration, and request errors are not retried.

### Progress and diagnostics

If the budget cannot cover an optional model job, progress shows a `Coverage gap` warning with the role and the reservation. Failures that use a fallback are also shown without `--verbose`. Phase totals separate work that was checked, left unresolved, or skipped. A checked abuse case can still be inconclusive. The final summary lists omitted work. A published report does not mean that every optional check ran, even at thorough depth. `--quiet` hides live progress.

Progress shows the role, elapsed time, and activity of each model call. `No progress update` means that the call is still running but has sent no recent update. It does not show that the model is idle or that the API has a problem. Hosts without activity events say so. On an interactive terminal, such messages stay in the one refreshed status row. Plain logs print the notice once until the call changes state. Connection interruptions and timeouts are shown as separate warnings. Codex transport failures are described in [Codex CLI setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli).

`--verbose` adds job, repository, and call IDs and the reasons for corrections. For program files outside all components, which the final summary counts in every run, it also shows sample files from the ten largest directories. The report keeps directory counts.

Every assessment writes private diagnostics to `.assessment-work/diagnostics/attempt-*/events.jsonl` in the output directory. They record job outcomes, call timing, failure codes, and validation reasons. They contain no prompts, source excerpts, model answers, or raw stderr. The file stops at 8 MiB. `--resume` keeps earlier diagnostics in separate attempt directories, and `--rebuild` removes the working directory. Diagnostics explain failures of execution. They do not show that a finding is correct. Check them before you share them.

Each analysis job has at most six exchanges with the model, for source requests, the result, and corrections. A valid result ends the job at once. If no result passes validation, the job stops. The error message names the analysis role, the component, and the batch, and gives the number of exchanges, source-read rounds, and rejected results. A source-coverage failure says whether a source line was not read or a decision cited the wrong source. Each `Attempts` row names the Analyzer check that rejected the result, as file, line and function, and the correction that followed. A correction is either a full new result or a fix of only the cited lines. The diagnostics record the same under `attempt_trail`. Other stops name the Analyzer check in a `Check` row. A schema violation names the field, the rule and the schema rule path. A larger overall call budget does not raise the limit per job.

Accepted steps stay saved. With unchanged source and settings and enough time left, repeat the command with `--resume`, not `--rebuild`. If the same rejection repeats, find the cause before you try again.

Discovery accepts claims about interfaces only if the cited source supports them. Repeated invalid answers can stop the run even when the provider responds normally. See the [orchestration contract](internal/contracts/orchestration-actions.md) for the execution rules.

If Analyzer code or analysis resources change during a run, a warning says that results may combine versions and that the run continues. If the version check cannot finish, the warning says that a consistent version cannot be confirmed. Do not change the installation during an assessment. Afterwards, `--rebuild` with a stable installation regenerates the results from one version. It discards earlier model work and makes new model calls against your budget or subscription allowance.

In an interactive terminal outside CI, Analyzer asks before a budget shortfall skips or stops work:

- Enter a higher **total budget in USD**, for example `40` to raise a limit of USD 30 to USD 40, or press Enter to keep the limit. Analyzer never raises it on its own.
- Keys pressed before the question appears are discarded. They neither raise nor keep the limit.
- Three invalid answers or the end of input keep the limit. After you decline, no further budget question appears in that process.
- A run permits at most 16 approved increases. More budget does not guarantee completion, and the time spent waiting for your answer counts toward the time limit.
- An evidence review that does not fit while component analysis is still running is postponed without a question and retried afterwards. Analyzer first waits for running calls to finish and pauses new calls.

There is no budget question without a terminal, in CI, with `--non-interactive`, or with `--quiet`. The approved limit is saved before more is spent. `--resume` with the original command restores it, also when it runs non-interactively. A new run uses its configured budget. Time and call limits are never raised by this question.

Report writing completes the required Security Architecture section first. It then uses the remaining allowance for the Management Summary, before the requirements commentary. If cost, time, call limits, or invalid model output prevent the summary, the report keeps its deterministic verdict, and the run summary names the replacement.

### Output and continuation

Without `--output`, results go to the private user-data directory under `appsec-analyzer/assessments`. An explicit output directory must be outside the selected checkouts and private (mode 0700). A missing directory is created that way, unless its path leads through a link or into a source checkout. The main files are `security-assessment.md` and `security-assessment.yaml`. Optional exports run after model and report validation. Missing tools are reported.

`--requirements` adds requirements checking to this assessment. It takes a file or an HTTPS URL with an Analyzer YAML catalog or an OSCAL catalog (see [catalog formats](security-requirements-audit-skill.md#catalog-formats)). A catalog that needs more than 32 context rows per component is refused before the first model call. It does not run the separate requirements audit. `assess` also accepts the export options `--pentest-tasks`, `--pentest-format strix`, `--pentest-target URL`, and `--slug NAME`. `--keep-runtime-files` keeps intermediate files for debugging.

An interrupted run keeps its accepted steps:

- `--resume` continues the unfinished run in the output directory. If only the Analyzer runtime changed, the run continues with its original deadline, limits, recorded costs, and elapsed time. If the source, settings, limits, or time limit changed too, it starts a new run with the limits of your command and reuses the accepted steps that still match. The header row `Resumed` names the cause. A completed run needs a run without `--resume`.
- `--rebuild` discards earlier model work.
- Without either flag, a new run can reuse compatible accepted steps from an unfinished run in the same output directory. In an interactive terminal, Analyzer asks whether to continue, start a new run with reuse, or rebuild. Enter or the end of input chooses the new run. Continuing is offered only while the earlier limits and deadline allow it. Keys pressed before the question do not answer it. Non-interactive, quiet, JSON, and CI runs do not ask.

In a continued or reused run, every phase runs again, but only steps without a matching accepted result call a model. A step whose model request changed runs again at additional cost, and the cost of its earlier answer stays counted. The cost or call count of reused steps counts toward the new limit. The header shows the earlier time and spending, and progress marks reused steps and includes their time and cost in the totals. Earlier deliverables stay until the new run completes and removes the files it did not replace. Scanner results for identical source and Analyzer are reused, so the first phases of a repeated start go faster.

Use `status` or `progress` with the output directory to inspect a run, `stop` to cancel it, and `results` to verify the published files. The deterministic `scan-sources` command has its [own result schema](../schemas/deterministic-scan-result.schema.json) and no assessment status.

Monetary costs appear by default only with API billing. Subscription runs, including Claude CLI without `ANTHROPIC_API_KEY`, show call and token counts without costs. `--show-costs` shows the available costs in every billing mode. Unknown amounts are labelled unavailable, never estimated or shown as zero. The flag changes no accounting, limits, or model use. Spending limits and budget questions stay visible, and `--quiet` still hides live progress.

To use your ChatGPT plan allowance, install Codex CLI 0.163.0 or newer on Linux or macOS, sign in with `codex login`, and run:

```sh
appsec-analyzer assess --repo /path/to/project --profile codex-cli --max-calls 1000 --max-duration 14400
```

This experimental profile runs at most two components at a time, rejects USD budgets, and reports monetary cost as unavailable. A plan limit stops the run and keeps accepted work. Wait for allowance, then resume with the same output. See [Codex CLI setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli) for model access, data use, local limits, and qualification status.

### Source-read failures

Survey jobs receive the exact repository IDs and repository-relative paths they may read. If a required file is not on that list, they must report missing evidence. A file named in an import or an earlier analysis grants no permission to read it.

When a model asks for a well-formed path outside its selection, Analyzer refuses it without reading the file. It asks the model to use permitted sources or to report the evidence as unresolved, within the existing call, time, and read limits. Repeated invalid requests can exhaust the job, but they never widen its source selection.

The message `Model requested a source outside this task's selection` stops the run for unsafe paths, unknown repository IDs, or a path paired with the wrong repository. Diagnostics name the category but not the path.

Accepted jobs stay in the output directory. After you correct the cause, repeat the original command with the same output and `--resume`. If nothing changed, the run continues with its original deadline and limits. If the deadline has passed or the settings changed, `--resume` starts a new attempt that reuses compatible accepted jobs. Changed survey inputs make those jobs run again. Resuming alone does not fix an unchanged model request.

## Survey and verification

An assessment examines the code with two methods. The survey looks at each component openly and reports any weakness it finds. Verification works through a fixed list of questions for selected security aspects, such as authorization, and answers each question at every place in the code where it applies. The survey always runs. Verification runs after it for the aspects that the assessment depth or your profiles select.

### The survey

A model reads one component at a time, such as the API server or the web frontend, and reports the weaknesses it finds. The six STRIDE categories are its checklist, and each finding carries one of them.

Every program file and server-side template belongs to a component, in any language or framework. Files that discovery did not read go to the component whose code lies closest in the folder tree. Tests, documentation, top-level examples, and vendored code stay out. A component without its own program code, such as a database or a build pipeline, gets no files. If code still belongs to no component, for example because no component holds program code, the final summary says how many files. The report lists them by folder. At quick and standard depth, the survey picks the files with entry points, scanner hits, or security-relevant keywords within a component. Client code has its own signals, such as raw HTML bindings, HTTP interceptors, route guards, and browser storage. The report counts, per component, the files the survey did not examine individually. At thorough depth, the survey also examines every other program file, in extra jobs that run after verification and side by side. These jobs send more source code to the model host and cost more. They stop first when the budget runs short: they leave a share of it for the steps after them and never ask for more. The report names the files they did not reach as unexamined.

Because the survey is open, it also finds weaknesses that no list foresees. In the pilot runs on OWASP Juice Shop, it reported weaknesses that the verification catalog has no item for, such as an OAuth login without a `state` parameter and a password reset without throttling. The survey does not go through the code route by route, though. When many routes share one weakness, it often reports one finding with a few examples.

### Verification

The [verification catalog](../data/test-cases.yaml) lists verification items per security aspect. Each item is one question. For authorization, `TC-AUTHZ-01` asks whether access to an object checks its owner, and `TC-AUTHZ-02` whether privileged operations check the caller's role. Each aspect also has a goal item, such as `TC-AUTHZ-06`, which asks whether a caller can read or change data beyond their rights by any path.

Verification takes two steps for each aspect:

1. Without a model, Analyzer collects the places where the items apply. For authorization, these are the application's routes and the hits of the matching scanner rules. For input validation, they are code sites such as raw database queries, shell commands, or HTML output.
2. One model job per component answers every item at every place, with the code of the handlers, middlewares, and guards involved. It records a finding, a control, or another outcome for each item, and it may add places it found itself.

A place that the job could not decide records undecidable. Undecidable, partial, and no finding never count as a control, and comments or documentation are not evidence of one. Catalog IDs start with `TC-`, and settings and result fields use the name `test_cases`.

### An example

In a pilot run on Juice Shop, the survey reported that a user can change another user's basket items through `PUT /api/BasketItems/:id`. Verification checked `TC-AUTHZ-01` on every basket item route. It also found that any logged-in user can read and delete other users' basket items through `GET` and `DELETE` on the same path. In the same run, it found that any logged-in user can read every user record through `GET /api/Users/:id` and create products through `POST /api/Products`. The survey reported neither. Of the nine authorization challenges in Juice Shop, verification found eight and the survey seven. Verifying authorization took nine model jobs in that run and cost USD 4.45.

### How the results come together

The survey and verification work independently. Verification starts from routes and scanner results, without seeing survey findings. After both finish, Analyzer combines findings and compares source locations and CWE weakness categories:

| Case | What the report shows |
| --- | --- |
| Verification found the weakness on the same line as a survey or scanner finding, with the same CWE or a CWE of the same weakness family, such as CWE-639 and CWE-862 for missing authorization. | One finding. Its card names the methods, such as "Found by: survey and verification", and the verification items. It keeps every location, item, and scanner rule, the severity of its most severe part, and the evidence review verdict of the survey or scanner finding. |
| Verification found a protecting control on the line where the survey reported a weakness with the same CWE. | The survey finding stays and is marked "Contradicted by verification". Check the code before you close it. |
| Only verification found the weakness. | A finding of its own, with an ID, a priority, and a mitigation like any other. Its card says "Found by: verification". If no post-check confirmed it, it passes the same evidence review as a survey finding. Confirmed there, it is scored like a survey finding. Refuted there, it stays unscored and is marked "Contradicted by the evidence review" with the review's reason; check the code before you close it. If the review leaves it open, or the budget does not cover the review, it is labelled as unproven and left unscored. |
| Only the survey found the weakness, or verification did not examine the location. | The survey finding stays unchanged. |

Findings reported only by verification receive an evidence review during consolidation. It uses one or more calls per affected component, with the evidence-review model and the same source that verification used.

Repeated verification findings share one evidence review when they identify the same component, code location, weakness family, routes and mechanism. The report retains every linked verification item and finding ID. Findings with different routes or traces stay separate. Automatically confirmed findings stay separate from unconfirmed ones, so they neither need another review nor confirm an unreviewed finding.

A separate merge-review call writes a combined title, scenario, and remediation from the findings and their locations. It receives no source files. If the call fails, does not fit the budget, or omits a location, Analyzer keeps the text of the most severe part and lists every part’s remediation.

Findings on neighboring lines stay separate, as do findings about different routes registered on one line. The same weakness can therefore appear twice if methods cite different lines or unrelated CWE families. A refuted survey or scanner finding never absorbs a verification finding.

### What each depth verifies

| Depth | Survey | Verification |
| --- | --- | --- |
| quick | yes | none |
| standard | yes | `AuthN`, `AuthZ`, `InputVal`, `AI` |
| thorough | yes | `AuthN`, `AuthZ`, `InputVal`, `DataProt`, `AI` |

These defaults come from [data/assessment-depths.yaml](../data/assessment-depths.yaml). No depth verifies `AuthNRoutes`, the check of every route's authentication. In Juice Shop measurements, authorization verification reported the same unguarded routes, so almost all of its own findings repeated another finding. Standard depth also omits `DataProt`, whose findings mostly overlap the survey's, with few new findings of high severity.

`AI` verification runs only for components identified as calling a language model, through a common JavaScript or Python SDK or an architecture flow. For those components, calls through other SDKs and the source lines cited by the architecture also serve as starting points. The startup header lists the verified aspects under "Threat analysis methods".

Verification adds model calls and sends more source to the model. Each component gets one job per aspect, split into several jobs above 40 locations. An aspect gets no job where none of its items applies. Costs therefore depend on the routes and relevant code locations.

Before the survey, Analyzer names the components selected for verification. Before verification starts, it estimates the job costs and says whether the remaining budget covers them. Reused jobs need no new call and are left out of the estimate. Until a verification job finishes, the estimate uses the survey cost per job.

Jobs that do not fit the remaining budget do not run. Their locations stay undecidable, and the summary and the report mark the aspect incomplete. Progress separates Scanners, Survey, and Verify. It shows each component once verification finishes, with its duration unless reused, and any jobs without a result.

### Configure verification

Analyzer avoids server-route checks for source files it recognizes as text read into a JSON response. This currently covers simple module-relative reads in Express and Flask handlers. Imports and program entry points keep the file eligible for route checks, as do dynamic loading and cases the analysis cannot resolve. File and directory names alone do not exclude code. These files remain available to scanners and source review. This reduces unnecessary route candidates in supported cases; it does not establish that a file can never execute or guarantee lower model costs.

In JavaScript and TypeScript, this includes short local helper chains that return UTF-8 file text, with literal file-name arguments and simple string-built paths. Exported helpers, directory loops, caches and paths that depend on the working directory remain unresolved. The analysis keeps those route candidates.

README files and common JSON, YAML or TOML configuration do not prevent this classification merely by being present. Their file references still count as evidence of other uses, including unquoted launch paths. Grouping candidates by source locality falls back to the previous packing when it would add jobs for the same candidates.

You choose the verified aspects per depth in a scan profile, and an organization can set its own defaults in an organization profile. Analyzer starts from the shipped file, applies the organization profile, and then the scan profile. There is no command-line option for it.

To check every route's authentication and data protection as well at standard depth, and authorization already at quick depth, add this to a scan profile:

```yaml
schema_version: 1
depths:
  standard:
    verify: [AuthN, AuthNRoutes, AuthZ, InputVal, DataProt, AI]
  quick:
    verify: [AuthZ]
```

`verify: []` runs the survey only at that depth. `test_cases: false` does the same for every depth whose `verify` the profile does not set. To leave out a single item, list it under `test_cases.disable` with a reason, and the report shows it as disabled with that reason. An organization profile can make aspects mandatory with `test_cases.required_aspects`, and a scan profile cannot remove them. Profiles inside an assessed repository are rejected, so repository content cannot select or disable verification. [Verification settings](profiles.md#verification-settings) describes every field, and [what each depth does](profiles.md#what-each-depth-does) the other depth settings.

`test_cases: true` records the catalog without model jobs. Only the nine rule-based items then receive an outcome, from the recorded results of their scanner rules, and the other items are listed as not examined. A rule-based item reports a control only when every applicable rule is satisfied and the scanner recorded a result for each. A control here means that the examined files contain the expected configuration. It does not show that the control works in production.

### Where to find the results

With verification on:

- Findings from scanner rules carry `rule_ids` and `test_case_ids` in `security-assessment.yaml`, and their details link the verification items and rules.
- A configuration rule hit counts as an insecure practice, not as a confirmed exploitable weakness, because a setting alone does not show how it is exploited where the system runs. A hit in a file that serves only local development, such as `compose.dev.yaml`, is marked "Development only" when no build or deployment definition of the repository refers to the file. Such a finding stays in the findings register but does not raise the verdict.
- `security-assessment.yaml` gains a `test_case_results` block, with `incomplete_aspects` when the budget ended verification early.
- Every finding names the methods that found it in `found_by`: `survey`, `scanners`, or `verification`. Findings that hold verification findings carry `verification` with their `TCF-` IDs and verification items, and survey or scanner findings that verification contradicts carry `verification_contradicted`. A finding of verification alone that the evidence review refuted carries `evidence_review_contradicted` with the review's reason. It stays in the findings register, but the verdict, the risk distribution, weaknesses, and fix recommendations leave it out; only a manual review task names it.
- The report gains the appendix Verification Items. It opens with the items that show a finding or only partial protection, then the items the source could not settle, then the evidenced controls, each with the component, the reason, and the linked findings. Every other item appears in one line per aspect, with the components it does not apply to. Details follow only for items with a result. Candidate counts and post-check data stay in `security-assessment.yaml`.
- The completion summary shows a Verification row with the outcome counts.
- In SARIF, a linked finding uses the verification item ID as `ruleId`. The finding ID moves to the result property `findingId`.

The aspect `AuthN` (authentication) checks how users and services sign in: token checks, passwords, account recovery, SSO and OAuth integration, and insecure methods such as credentials in URLs. The aspect `AuthNRoutes` checks that every sensitive route, operation, and channel requires authentication. On Juice Shop `AuthN` needs four verification jobs and `AuthNRoutes` six. The aspect `SessionMgmt` is accepted but not investigated yet. The [orchestration contract](internal/contracts/orchestration-actions.md#verification-jobs) describes how the places to check are chosen and how outcomes are decided.

## Sign-in through an identity provider

When users sign in through an OAuth 2.0 or OpenID Connect provider, Figure 1 shows each step the code evidences: the sign-in at the provider, the token request, and the requests that carry the provider's access token to your application. Each numbered hexagon names the method and, where the code states it, the grant: authorization code with or without PKCE, client credentials, or the legacy implicit and password grants. A bearer check reads "access token from" followed by the provider when the check and the provider's configuration sit in the same source file or in the component's configuration file.

Recognition works the same for every provider product, such as Keycloak, Microsoft Entra ID, Okta, Auth0, Google or Amazon Cognito. It reads endpoint paths, configuration keys, settings objects and client-library calls, never dependency names. A provider that runs inside your system, for example a Keycloak container, appears as that component when its service name is the provider's host name. Fetching the provider's discovery document or signing keys appears as a grey `0`, because these are public.

Recognized client setups include Spring Security, ASP.NET Core, passport strategies, openid-client, Authlib, Go `oauth2.Config`, oidc-client-ts, MSAL, angular-oauth2-oidc and keycloak-js. Recognized token and session checks include express-jwt, express-oauth2-jwt-bearer, express-openid-connect, keycloak-connect, `passport.authenticate` with a registered strategy, and a `jwtVerify` that rejects invalid tokens.

Limits: an issuer that only an environment variable supplies is not recognized, so the architecture analysis has to model it. Token checks in Java and C# routes stay unknown, because their handlers are not resolved. A hexagon describes the method, not whether its implementation is correct, for example whether audience and issuer are checked.

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

If a newer Analyzer created the result, an older installation cannot read it and says so. In an interactive terminal outside CI, a pipx installation asks whether to run `pipx upgrade --pip-args=--force-reinstall appsec-analyzer`, naming the installed version and the source it installs from. Nothing is installed without a yes. After the update, the message names the newly installed version, and you run `review` again. Other installations print only the hint to update.

The skill is supplied to this session with a read-only facts helper for IDs, severity, components, and topics. No global skill installation is needed. Ask, for example, “Explain F-003 and its evidence,” “Which mitigations should we do first?” or “Prepare a fix and tests for F-003.” The helper reads only validated published model data; an omitted requirements catalog is not evidence of compliance. For moved or deleted checkouts, select the appropriate source before asking for implementation; report discussion remains available.

The session starts in a fresh private working directory with references to the original reports. Codex starts in a read-only sandbox with approval prompts; Claude Code starts in plan mode with project settings and automatic CLAUDE.md loading excluded. Repository and result-directory hooks are excluded; native user and managed controls remain active. User and managed assistant configuration and login remain external to the assessment. This is an external assistant session, not an Analyzer job confined to the original admitted source snapshot. For implementation, explicitly request a change and use the assistant's permission workflow after checking current source against the examined revision. Preserve the saved assessment; proposed fixes or risk decisions do not automatically update findings.

Offline tests cover the handoff, but live interactive behavior and the assistants' own sandbox and permission enforcement have not been qualified.

## Exports and compatibility

Exports can be requested on `assess`, or generated later without model calls:

```sh
appsec-analyzer export --assessment /path/to/assessment \
  --output /path/to/new-export --formats markdown yaml html pdf sarif threatdragon pentest-tasks
```

`export` requires a completed `.assessment-state.json`, a model that passes the current schema, and artifacts matching every recorded digest. The source directory must be owned by the current user and private (mode 0700). The destination must not exist and must be outside Git checkouts and separate from the source; its parent must exist. Analyzer creates it with mode 0700 and publishes files with mode 0600. An interrupted or failed export is not a completed bundle; retry into a new directory. The saved assessment is left unchanged. Older standalone files without compatible state require explicit migration or reassessment.

The default formats are `markdown yaml`. Markdown, HTML and PDF require the recorded Markdown report. HTML requires Pandoc; PDF also requires WeasyPrint. Document conversion embeds only recorded local images or validated embedded SVG and rejects active markup and external image resources. Mermaid source remains a code block, with a warning; it is not rendered by this command. SARIF and pentest tasks retain the existing evidence and CWE filters, and Threat Dragon is a lossy diagram projection. Keep YAML for the complete model. Missing tools, modified inputs or failed validation cause exit 2 without a success result; success returns JSON with artifact digests and `model_calls: 0`.

`results` checks the hashes of already published files. The published model is `security-assessment.yaml`.

Interactive triage, automated code fixes, baseline installation, and plugin hooks are not part of the public Analyzer CLI. The separate [security score](security-score.md) gives a limited deterministic indication without model calls. The independent [AuthNZ review](authnz-review.md) checks authentication and authorization through Claude CLI without a prior assessment. To check a single abuse case, see the [Threat Analyst guide](threat-analyst.md).
