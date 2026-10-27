# Scan and model profiles

A scan profile saves settings you reuse: models, depth, budget, exports, abuse-case files, and report attributes. A model profile chooses models and reasoning settings for individual analysis roles. Both are local YAML files. The built-in profiles work without either file.

An [organization distribution](organization-distributions.md) can bundle these profiles and select them automatically. You do not need to copy profiles into the assessed repository.

## Start with the defaults

```sh
appsec-analyzer assess --repo /path/to/project --profile claude
appsec-analyzer assess --repo /path/to/project --profile codex
```

`claude` and `codex` use standard depth and a USD 20 budget. `claude` uses the Claude CLI and its configured login or external credentials. `codex` uses the OpenAI Responses API and `OPENAI_API_KEY`; it does not use a Codex CLI login. The API adapter remains experimental and has not passed live assessment qualification.

The built-in `codex` and `codex-cli` model profiles use Luna for `recon_scanner` with low reasoning effort at every depth. All other roles use Sol with low effort at quick depth, medium at standard, and high at thorough. The model aliases resolve through the installed [model catalog](../data/model-catalog.yaml). This split has offline routing coverage; assessment quality with Luna has not passed live qualification. Operator model defaults and role overrides still take precedence.

Profiles apply to `assess`. `scan-sources` remains a deterministic scan without model calls. The separate requirements audit and focused analyst keep their existing options.

Additional built-ins are `lite` for LiteLLM Responses and `bedrock` for native Bedrock Converse. They require a separate operator-owned connection file and external credentials. The model prefix `lite claude` selects a configured gateway model; `bedrock claude` selects a configured Bedrock model. See [provider setup and limits](providers.md). Both remain unqualified for live assessment quality.

## Use your ChatGPT plan with Codex CLI

Select `codex-cli` to run full assessments through the Codex CLI's existing ChatGPT login. It is an experimental connection with offline transport and full-controller tests; live assessment quality has not been qualified. Your account or workspace must allow the selected model and Codex usage. This profile uses ChatGPT plan allowance or available credits; Analyzer cannot report the remaining allowance or enforce a monetary ceiling.

Prerequisites: Linux or macOS, Codex CLI **0.163.0** installed on your `PATH` outside the analyzed repositories, and a working ChatGPT login. Other CLI versions are rejected until their isolation settings have been reviewed. Follow the [official Codex CLI installation instructions](https://developers.openai.com/codex/cli) to install the supported version. An API-key login does not satisfy this profile.

1. Check the installed version and sign in with ChatGPT:

   ```sh
   codex --version
   codex login
   codex login status
   ```

2. Run an assessment, replacing `/path/to/project` with your Git repository:

   ```sh
   appsec-analyzer assess --repo /path/to/project --profile codex-cli \
     --max-calls 1000 --max-duration 14400
   ```

Codex CLI defaults to 1,000 exchanges, four hours total, and at most two components at once. Exchanges include corrections, failures, and retries. You can set:

- `--max-calls N`: 1–47,256 exchanges.
- `--max-duration SECONDS`: 1–43,200 seconds.
- `--max-parallel N`: 1–16 components.

Analyzer reserves calls and time for required analysis and report work. Each exchange also has a timeout and size limits. The connection uses HTTP/SSE with CLI retries disabled. Its 60-second idle timeout resets on incoming events; the controller also enforces a total per-call limit. See the [Codex provider configuration](https://learn.chatgpt.com/docs/config-file/config-reference) for transport settings.

An exchange count does not measure tokens or ChatGPT credits. These limits cannot guarantee completion within your plan allowance.

Codex CLI requests are limited to 320,000 UTF-8 bytes including role instructions and the output contract, so a source packet can reach the same size as on other hosts. Survey source batches account for that overhead before dispatch; further reads and correction packets retain the remaining context limit. Large inputs can therefore require more model exchanges. An input-size error requires a smaller request or an Analyzer fix; `--resume` alone cannot resolve an unchanged oversized request.

Analyzer requests structured JSON from Codex and checks it against the full result schema, source rules, and permissions. Missing optional fields and explicit `null` stay distinct. Duplicate or ambiguous fields are rejected. Results use native JSON values, so text does not need an extra layer of JSON escaping.

Codex may send commentary before its final answer. Analyzer accepts only the last completed agent message from a completed turn, following the [Codex output contract](https://learn.chatgpt.com/docs/non-interactive-mode#make-output-machine-readable). Earlier commentary is not a result.

Stop messages and private diagnostics use fixed codes for malformed streams, incomplete answers, invalid JSON, invalid structured results, and unexpected tools. They do not record model answers. An invalid answer does not prove a login problem. Check CLI compatibility and the reported response format before retrying; unexpected tools require checking isolation. After an Analyzer update, use a new output directory to preserve the failed run for diagnosis.

A Codex reconnect notice does not by itself mean the call failed. Analyzer shows it without provider text, then checks the final outcome. Failure codes distinguish disconnection, timeout, connection failure, TLS failure, and unavailable models. Rate limits and exhausted allowance are separate. Diagnostics classify error events and stderr without retaining their raw text. A generic `transport` error means the cause could not be classified.

Do not pass `--budget` or `--hard-budget` with `codex-cli`; they are rejected, as is a `budget` field in a subscription scan profile. The startup summary identifies ChatGPT subscription use and the call limit. Completion and status show no invented dollar charge: monetary accounting is `null`. For separately billed OpenAI API use, select `codex` and configure `OPENAI_API_KEY`.

Codex CLI sends selected source excerpts, context, and intermediate answers to OpenAI. Analyzer uses fresh private working directories, disables model tools and repository/user agent configuration, and requests temporary sessions. It does not read or copy authentication tokens. Your account or workspace governs provider-side data handling; temporary local sessions do not guarantee provider retention.

The adapter removes API-key environment variables and forces ChatGPT authentication, with no API fallback. Incompatible managed Codex settings stop the run.

If login expires, run `codex login` again. If your allowance is exhausted, wait for it to reset or manage it in ChatGPT, then rerun the original command with the same `--output` and `--resume`. Resume keeps the original call limit and deadline while they hold. If the deadline has expired, or you changed the limits, `--resume` starts a new run with your limits; compatible accepted jobs are reused and their call counts are retained. If the original call limit is exhausted, raise it in the command. Never use `--rebuild` merely to retry a quota error.

To save your limits, create a scan profile under a new name such as `subscription-review.yaml`:

```yaml
schema_version: 1
model_profile: codex-cli
assessment_depth: standard
max_calls: 1000
max_parallel: 2
outputs: [markdown, yaml]
```

Custom model profiles can use `base: codex-cli` and the existing model/role/depth settings. The built-in model and reasoning defaults match `codex`; model names must be in Analyzer's installed catalog and available to your ChatGPT account. `max_output_tokens` is not supported by this adapter. The separate requirements audit and focused analyst do not gain Codex CLI support.

## Use GitHub Copilot CLI

Select `copilot-cli` for full assessments through the GitHub Copilot CLI. This experimental provider uses a fixed model identifier from the Analyzer model profile and remains unqualified for live assessment quality. Focused analysis and requirements audits do not gain Copilot support.

Prerequisites: Linux or macOS, GitHub Copilot CLI **1.0.101** on your `PATH` outside the analyzed repositories, and a working Copilot CLI login. Analyzer checks the CLI version but does not read credentials or claim to verify login or model access during ordinary preflight. Sign in using the [official Copilot CLI setup](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli).

```sh
copilot login
appsec-analyzer preflight --repo /path/to/project --profile copilot-cli
appsec-analyzer assess --repo /path/to/project --profile copilot-cli \
  --max-calls 1000 --max-duration 14400
```

The profile defaults to 1,000 Analyzer CLI exchanges, four hours, one component at a time, and the explicit model `gpt-5.4`. Override model and reasoning settings in an operator-owned model profile; `auto` is rejected so the chosen model remains visible and organization model restrictions can be enforced. Copilot availability for a selected account is checked only when a model call is explicitly made.

Each exchange uses `--max-ai-credits 30`, Copilot CLI's minimum supported session limit. It is a soft per-session limit: a response already in progress can exceed it, and it does not cap cumulative or account-wide usage across exchanges. Analyzer also counts dispatched exchanges, including retries and corrections, and enforces the assessment deadline. Neither limit guarantees completion within the account's allowance. USD budget fields and output-token caps are unavailable; reports show monetary cost as null.

Analyzer sends selected source excerpts, analysis context, and intermediate answers to GitHub Copilot through the signed-in CLI. It launches the CLI from a fresh private temporary directory, supplies no tools, disables custom instructions, built-in MCPs, and remote sharing, and validates the complete JSON response against the requested schema. Analyzer does not copy credentials. Copilot CLI may retain local session data according to its own behavior; neither the temporary work directory nor the CLI's soft credit limit establishes provider retention or an exact spend ceiling.

## Create a scan profile

Save this as `~/.config/appsec-analyzer/profiles/release.yaml`:

```yaml
schema_version: 1
description: Release review
model_profile: codex
assessment_depth: thorough
budget: 20
max_parallel: 2
outputs: [markdown, html, pdf, sarif]
report:
  attributes:
    team: payments
    review_type: release
```

The filename supplies the name `release`. Names use lowercase letters, digits, and hyphens, starting with a letter. Use `.yaml` as the extension. `schema_version` describes the file format; it does not belong in the filename.

`budget` is always USD and is available for `claude` and `codex`; `codex-cli` uses `max_calls` instead. `outputs` selects exports; Markdown and structured YAML are always retained as the base result. Supported formats are `markdown`, `yaml`, `html`, `pdf`, `sarif`, `threatdragon`, and `pentest-tasks`. HTML and PDF still need the export tools described in the [assessment guide](security-assessment.md). An unavailable optional export produces a warning.

`max_parallel` limits how many jobs control analysis, trust-boundary review, the survey, verification, and abuse-case checks each run at once. It defaults to 4, or 2 on Codex and Copilot subscriptions, and accepts integers from 1 to 16. Use 1 for serial processing. While you leave the default, a run whose number of components divides by three uses three jobs at a time; a value you set always applies as given. Higher values can encounter provider rate limits. The controller uses the selected value for both its worker pool and its time reserve for required analysis.

Provider rate limits pause new calls and can pause the run with exit code 3. Accepted work stays saved. Wait for capacity, then repeat the command with `--resume`; the original deadline still applies. If rate limits recur, repeat the command without `--resume` and with the smaller `--max-parallel` value that the pause message names; the new run reuses the accepted jobs. See [retry rules and recovery](security-assessment.md#rate-limits-and-connection-failures).

Persistent connection failures pause required work with exit code 3; optional jobs record a coverage gap. Login, quota, certificate, configuration, and request errors are not retried. See [connection failure recovery](security-assessment.md#rate-limits-and-connection-failures).

Report attributes are text values, with up to 32 keys and 256 characters per value. They appear near the report title and under `meta.report_attributes` in the YAML result. They label the report; they do not change severity, authorize actions, or become analysis instructions. Keep credentials and confidential personal data out of them.

Select the profile and override individual settings when needed:

```sh
appsec-analyzer assess --repo /path/to/project --profile release
appsec-analyzer assess --repo /path/to/project --profile release --budget 30
appsec-analyzer assess --repo /path/to/project --profile release --max-parallel 4
appsec-analyzer assess --repo /path/to/project --profile release --assessment-depth quick --outputs markdown sarif
```

Explicit CLI values take precedence over scan defaults. `--outputs` replaces the profile's export list. Existing flags such as `--pdf` and `--sarif` add their format to that selection. The chosen scan profile controls exports even when an organization profile also supplies export defaults. Other organization settings continue to apply.

### Use your profile by default

Save a scan profile as `~/.config/appsec-analyzer/profiles/default.yaml` to use it for `assess` and `preflight` without `--profile`. This example keeps the Claude CLI and raises the budget of thorough runs:

```yaml
schema_version: 1
model_profile: claude
depths:
  thorough:
    budget: 40
```

The run header names the profile and its file. `--profile`, `--host`, a model prefix such as `lite claude`, and the launcher of an [organization distribution](organization-distributions.md) take precedence. With `--non-interactive`, `assess` still requires an explicit profile, so automation shows its profile and spending limit in the command. An invalid or unsafe `default.yaml` stops the command; Analyzer does not fall back to `claude`.

### What each depth does

Each assessment depth has default settings, which Analyzer ships in [data/assessment-depths.yaml](../data/assessment-depths.yaml):

| Setting | quick | standard | thorough | Meaning |
| --- | --- | --- | --- | --- |
| `verify` | `[]` | `[AuthN, AuthZ, InputVal, AI]` | `[AuthN, AuthZ, InputVal, DataProt, AI]` | Security aspects that [verification](security-assessment.md#survey-and-verification) checks beside the survey; `[]` runs the survey only. |
| `abuse_cases` | 0 | 3 | 8 | Optional business abuse cases checked, that is, attack scenarios against the application's rules. With 0, a run checks abuse cases only when they are asked for. |
| `derived_abuse_cases` | 0 | 0 | 3 | Business abuse cases the model may add from the application's own rules, at most 6. |
| `architect_review` | false | false | true | A second model call reviews the findings. |
| `actor_discovery` | false | true | true | The assessment identifies the users and systems that interact with the application. |
| `budget` | 10 | 20 | 40 | USD of a run started through the Claude Code assessment dialogue without a budget. `assess` uses a depth budget only when your scan profile sets it. |

Each verified aspect, abuse case, and the architect review add model calls. Which model each step uses is set in the model profiles; technical limits, such as how often a model may read more code before it answers, are not settings.

A scan profile changes single values for single depths under `depths`. Values it does not name keep the default:

```yaml
schema_version: 1
depths:
  standard:
    verify: [AuthZ, InputVal]
    abuse_cases: 5
  quick:
    actor_discovery: true
check_abuse_cases: [AC-B-002]
skip_abuse_cases: [AC-T-004]
```

`check_abuse_cases` names cases every run must check, within the limit of 16 requested cases. `skip_abuse_cases` names cases to skip; the report shows the reason. A case cannot appear in both lists. Unknown built-in IDs fail before the first model call. Inactive organization or repository cases are skipped with a warning during matching.

Explicit CLI options for architect review, abuse cases, case selection, and hard budget override depth defaults. `profiles show` lists the effective `depth_settings` and each value’s source.

An [organization profile](org-profiles.md) can set its own defaults under the same `depths` key, which a team's scan profile can still change. The order is the shipped file, the organization profile, the scan profile, and the command line.

For `assess` without `--budget`, a `budget` that the scan profile sets under `depths` applies to that depth, and other depths keep the profile's `budget`. The shipped and organization depth budgets apply only to the Claude Code assessment dialogue. `codex-cli` and `copilot-cli` use call limits instead of a USD budget.

### Verification settings

`test_cases` controls [verification](security-assessment.md#survey-and-verification) beyond the aspects of a depth. Without the setting, each depth verifies its `verify` aspects. `false` runs the survey only at every depth that does not set `verify`. `true` links scanner findings to the verification items of the catalog and records an outcome for each item that scanner results can decide, without additional model calls. A scan profile's `depths.<depth>.verify` wins over `test_cases`.

The `test_cases` object supports two optional fields:

- `aspects`: a nonempty selection of `AuthN`, `AuthNRoutes`, `SessionMgmt`, `AuthZ`, `InputVal`, `DataProt`, and `AI`. It applies to depths whose `verify` the scan profile does not set. Omit it to keep depth defaults. `SessionMgmt` is accepted but not investigated yet.
- `disable`: catalog items to skip, each with a unique `id` and a `reason` of 1–300 printable characters. The report marks the item `disabled` and retains linked scanner findings.

Invalid settings, unknown depths or aspects, unknown catalog IDs, and invalid reasons fail before the host check or repository retrieval.

An organization profile can require items through `test_cases.required` and aspects through `test_cases.required_aspects`. Disabling a required item fails before run-state creation or model calls. Required aspects run at every depth and cannot be removed by a scan profile, even with `test_cases: false`. Profiles inside assessed repositories are rejected.

## Save an abuse-case selection

Add `abuse_case_files` to a scan profile to reuse your case selection:

```yaml
schema_version: 1
model_profile: claude
abuse_case_files:
  - review/abuse-cases.yaml
  - policy/payment-cases.yml
```

Abuse-case paths are relative to the selected repository root. They must identify admitted YAML files and currently support one repository per assessment. Repeat `--abuse-case-file` to replace the profile list. An empty list adds no files; it does not disable automatic or organization cases.

Explicit file selections enable verification even at quick depth, within spending and case limits. See [custom abuse cases](security-assessment.md#custom-abuse-cases) for the format. `profiles show` and `validate` check path declarations without reading case contents; the assessment checks the files in its captured source.

## Adjust models for individual tasks

Most users can keep `model_profile: codex` or `model_profile: claude`. To change selected model settings, create `~/.config/appsec-analyzer/model-profiles/team-sol.yaml`:

```yaml
schema_version: 1
base: codex
defaults:
  model: gpt-sol
  reasoning_effort: medium
roles:
  recon_scanner:
    model: gpt-luna
    reasoning_effort: low
  stride_analyzer:
    reasoning_effort: high
  evidence_verifier:
    reasoning_effort: high
depths:
  thorough:
    roles:
      stride_analyzer:
        reasoning_effort: xhigh
```

Then set `model_profile: team-sol` in the scan profile. This example demonstrates configuration; it is not a tested claim that these models are the best choice for those tasks.

The Recon override above matches the built-in OpenAI profiles. To use Sol for Recon too, set `roles.recon_scanner.model: gpt-sol` in your model profile.

`base` accepts `claude`, `codex`, `codex-cli`, `lite`, or `bedrock`. User profiles cannot inherit from other user profiles. Alternatively, a complete model profile can specify `adapter: openai`, `claude-cli`, `codex-cli`, `lite`, or `bedrock` and supply its own defaults. Do not combine `base` and `adapter`. LiteLLM and Bedrock role models require their provider prefix and an alias in the separate connection file.

The user definition is applied after the built-in definition. Within each definition, settings are applied in this order: `defaults`, `depths.<depth>.defaults`, `roles.<role>`, then `depths.<depth>.roles.<role>`. Each block may set `model`, `reasoning_effort`, and, for OpenAI, an optional `max_output_tokens`. A field you omit retains its earlier value.

Supported roles are `recon_scanner`, `actor_discoverer`, `architecture_analyst`, `trust_boundary_analyst`, `control_analyst`, `stride_analyzer`, `threat_merger`, `triage_validator`, `post_stride_synthesizer`, `evidence_verifier`, `abuse_case_deriver`, `abuse_case_verifier`, `architect_reviewer`, `ms_renderer`, and `secarch_renderer`. `stride_analyzer` is the survey, which keeps its earlier role name; verification uses the survey's model. Choosing a model for a role does not enable that role; the assessment depth still determines the work performed.

Claude retains its existing controller model resolution where a user model profile does not override the model. That includes repository-dependent adjustments and supported environment overrides. Explicit Claude `--model` and per-role model flags take precedence over model-file defaults. Organization restrictions, including the Opus restriction, still apply. `profiles show` describes profile resolution before those runtime adjustments; the stored run snapshot records the actual settings.

The Claude CLI supports reasoning effort through its effort option. This adapter does not expose `max_output_tokens`, so a Claude profile containing that field is rejected. OpenAI options are checked against the installed model catalog. Unknown models, unsupported effort values, unknown roles, and unknown fields stop the run before model calls. Existing OpenAI CLI model flags retain their compatibility checks; use a model profile to choose different models per role.

## Model names and output limits

The Analyzer aliases `gpt-sol`, `gpt-luna`, and `gpt-astra` resolve through the installed [model catalog](../data/model-catalog.yaml). They are Analyzer aliases, not names sent directly to the API. A concrete ID such as `gpt-6.1-sol` selects that model explicitly. Catalog updates include prices and supported parameters; a new entry does not establish assessment quality.

By default, OpenAI requests omit `max_output_tokens`. Analyzer adds no output-token cap below the model's own maximum. Before sending a request, it reserves enough USD for the bounded input and the model's maximum output. A larger model can therefore need a larger available budget even if its eventual response is short. Transport byte limits and execution timeouts still apply.

If you deliberately want a smaller per-call limit, set it for the required role:

```yaml
roles:
  stride_analyzer:
    max_output_tokens: 65536
```

For OpenAI, this includes reasoning and visible output tokens. Reaching it can leave the answer incomplete. Analyzer reports `output_token_limit`; it does not accept a truncated answer as a completed analysis. The cost reservation uses the configured limit, or the model maximum when no limit was supplied. It does not silently reduce the token allowance to fit the remaining USD budget.

## Inspect and share profiles

These commands read configuration without calling a model or retrieving repositories:

```sh
appsec-analyzer profiles list
appsec-analyzer profiles show release
appsec-analyzer profiles show release --assessment-depth quick --budget 10
appsec-analyzer profiles show release --max-parallel 4
appsec-analyzer profiles validate release
```

`show` returns JSON containing the settings, models, resolved aliases, and the source of each profile setting. `list` lists scan and model files. `validate` checks a scan profile together with its model profile at every depth; add `--assessment-depth` to check only that depth.

The default configuration directory is `~/.config/appsec-analyzer`. When `XDG_CONFIG_HOME` is set, Analyzer uses `$XDG_CONFIG_HOME/appsec-analyzer` instead. No profile is discovered automatically in a source repository. Selected profile files must be outside every analyzed repository. Symlinks, hard links, YAML anchors, duplicate keys, and executable YAML tags are rejected.

To share a configuration directory, keep this layout:

```text
team-settings/
  profiles/
    release.yaml
  model-profiles/
    team-sol.yaml
```

Select its scan file explicitly:

```sh
appsec-analyzer assess --repo /path/to/project --profile /private/team-settings/profiles/release.yaml
```

For an explicit scan path, model names resolve from the sibling `model-profiles` directory or the built-ins. Analyzer does not silently substitute a same-named model file from the user's configuration directory. The built-in names `claude`, `codex`, and `codex-cli` are reserved in both directories.

Copyable examples are [developer.yaml](../examples/profiles/developer.yaml), [release.yaml](../examples/profiles/release.yaml), [team-sol.yaml](../examples/model-profiles/team-sol.yaml), and [team-claude.yaml](../examples/model-profiles/team-claude.yaml). The release example uses `team-sol`, so copy both files into their respective directories.

## Resume a run

The private assessment state stores the resolved profile, including each role's model and settings. OpenAI aliases remain fixed to the stored model IDs on `--resume`. The current catalog must still recognize those IDs and their options. Changing the profile, effective configuration, or cost information makes `--resume` continue as a new run that reuses compatible accepted jobs, because the stored model IDs no longer apply.

Runs created before profile snapshots were introduced cannot resume through the new profile path. Start a new assessment when Analyzer reports this incompatibility. Existing `--profile claude`, `--profile codex`, and compatible legacy `--host` commands remain supported for new runs.

Saved configuration includes `test_cases`, depth settings, requested and skipped abuse cases, and the effective verification aspects. Changing them requires a new run. Older snapshots without these settings count as `false`: they can resume at quick depth, but need a new run at standard or thorough depth because those defaults now enable verification.

`max_parallel` is part of the saved configuration. Changing it requires a new run. Snapshots created before this setting was recorded require a new run through the profile path; existing reports remain readable.
