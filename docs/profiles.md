# Scan and model profiles

Profiles can also be shipped inside an [organization distribution](organization-distributions.md). Its launcher selects the bundled scan and organization profiles automatically; the bundled model profile is resolved alongside the scan profile. No profile files need to be copied into the assessed repository.

A scan profile saves the settings you reuse: model selection, analysis depth, budget, output formats, abuse-case files, and report attributes. A model profile chooses models and reasoning settings for individual analysis roles. Both are local YAML files. You can use the built-in profiles without creating either file.

## Start with the defaults

```sh
appsec-analyzer scan --profile claude
appsec-analyzer scan --profile codex
```

`claude` and `codex` use standard depth and a USD 20 budget. `claude` uses the Claude CLI and its configured login or external credentials. `codex` uses the OpenAI Responses API and `OPENAI_API_KEY`; it does not use a Codex CLI login. The API adapter remains experimental and has not passed live assessment qualification.

The built-in `codex` and `codex-cli` model profiles use Luna for `recon_scanner` with low reasoning effort at every depth. All other roles use Sol with low effort at quick depth, medium at standard, and high at thorough. The model aliases resolve through the installed [model catalog](../data/model-catalog.yaml). This split has offline routing coverage; assessment quality with Luna has not passed live qualification. Operator model defaults and role overrides still take precedence.

Profiles apply to `scan` and `assess`. `scan-sources` remains a deterministic scan without model calls. The separate requirements audit and focused analyst keep their existing options.

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
   appsec-analyzer scan --repo /path/to/project --profile codex-cli \
     --max-calls 1000 --max-duration 14400
   ```

The default limits are 1,000 model exchanges including corrections, failed attempts, and retries, four hours of total elapsed time, and at most two components at a time. `--max-calls N` accepts 1–47,256; `--max-duration SECONDS` accepts 1–43,200; `--max-parallel N` accepts 1–16. Required analysis and report work retain the existing call and time reserves. Each CLI exchange also has its own timeout and input/output byte bounds. Analyzer uses HTTP/SSE, disables CLI request and stream retries, and sets a 60-second stream idle timeout. Incoming stream events reset that idle timeout; it is not a 60-second total limit on model reasoning. The controller's per-call limit still applies. The call count measures Analyzer-dispatched CLI invocations, including Analyzer retries. An exchange is not an exact measure of tokens or ChatGPT credits, and these limits do not guarantee that the assessment will finish within your plan allowance. The transport settings use the [official Codex provider configuration](https://learn.chatgpt.com/docs/config-file/config-reference).

Codex CLI requests are limited to 240,000 UTF-8 bytes including role instructions and the output contract. STRIDE source batches account for that overhead before dispatch; further reads and correction packets retain the remaining context limit. Large inputs can therefore require more model exchanges. An input-size error requires a smaller request or an Analyzer fix; `--resume` alone cannot resolve an unchanged oversized request.

Analyzer supplies Codex with a native structured output schema. Results are JSON values rather than JSON documents encoded inside strings, so quotations and backslashes do not require a second layer of JSON escaping. The adapter preserves optional-field absence and explicit `null`, rejects duplicate or ambiguous members, and then passes the decoded result through the existing full schema, source, and permission checks.

Codex can send commentary before its final structured answer. Analyzer validates the last completed agent message from a completed turn; earlier commentary is not an analysis result. This follows the [official Codex output contract](https://learn.chatgpt.com/docs/non-interactive-mode#make-output-machine-readable). Failures distinguish malformed event JSON (`invalid_response_stream`), a missing completed answer (`incomplete_response`), an invalid final JSON envelope (`invalid_response_envelope`), an invalid or ambiguous structured payload (`invalid_response_payload`), and unexpected tool or item output (`unexpected_host_item`). These fixed codes appear in the stop message and private diagnostics without recording model answers. An invalid answer does not establish a login failure. Check CLI compatibility or the indicated response format before retrying; unexpected tools require checking isolation. Runtime changes invalidate resume compatibility, so use a new output directory after updating Analyzer to preserve the failed run for diagnosis.

Codex reconnect notices are intermediate events. If one occurs, Analyzer displays it without provider text and still checks the terminal outcome; a successful completed turn is not rejected solely because it reconnected. Final failures distinguish a disconnected stream (`stream_disconnected`), a stream timeout (`connection_timeout`), a connection failure (`connection_failed`), a certificate failure (`tls_error`), and an unavailable model (`model_unavailable`). Rate limits and exhausted plan allowance remain separate. Diagnostics classify both CLI error events and stderr, without retaining their raw contents. A generic `transport` failure means the available error did not match a known classification; it does not establish the underlying cause.

Do not pass `--budget` or `--hard-budget` with `codex-cli`; they are rejected, as is a `budget` field in a subscription scan profile. The startup summary identifies ChatGPT subscription use and the call limit. Completion and status show no invented dollar charge: monetary accounting is `null`. For separately billed OpenAI API use, select `codex` and configure `OPENAI_API_KEY`.

Analyzer sends selected source excerpts, analysis context, and intermediate answers to OpenAI through the CLI. It uses fresh private work directories, disables model tools and repository/user agent configuration, and requests ephemeral sessions. Analyzer does not read or copy the CLI's authentication tokens. Your ChatGPT account/workspace controls provider-side data handling; ephemeral local sessions do not establish provider retention guarantees. The adapter removes API-key environment variables and forces ChatGPT authentication, with no API fallback. Managed Codex settings must permit its restrictions; incompatible settings stop the run.

If login expires, run `codex login` again. If your allowance is exhausted, wait for it to reset or manage it in ChatGPT, then rerun the original command with the same `--output` and `--resume`. Resume keeps the original call limit and deadline. If those local limits are exhausted, start a new run without `--resume` or `--rebuild`, adjusting the limits if needed; compatible accepted jobs are reused and their call counts are retained. Never use `--rebuild` merely to retry a quota error.

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

`max_parallel` limits how many components control analysis and STRIDE analysis each process at once. It defaults to 2 and accepts integers from 1 to 16. Use 1 for serial processing. Higher values can encounter provider rate limits. The controller uses the selected value for both its worker pool and its time reserve for required analysis.

On a provider rate limit, all new model calls in the assessment wait together; already running calls may finish. Free failures allow up to three retries with delays of 15, 60, and 180 seconds; valid HTTP `Retry-After` delays are respected. Paid failures retain their stricter retry limits. CLI hosts without structured reset metadata use those fallback delays. A wait over three minutes, insufficient remaining time, or exhausted retries pauses the run with exit code 3, including when the affected job is optional. Accepted work is kept. Wait for provider capacity, then rerun the same command with `--resume`; the original deadline and compatibility checks still apply.

When a provider connection drops or cannot be opened, Analyzer repeats the call after 15 seconds. A failed call without a cost report, such as a Codex subscription call or a failed API call, is repeated at most once, and these paid repeats count toward the stricter retry limits. If the connection stays down for a required job, the run pauses with exit code 3 and keeps accepted work; check connectivity, then rerun the same command with `--resume`. An optional job records a coverage gap instead. Login, quota, certificate, configuration, and request errors are never repeated.

Report attributes are text values, with up to 32 keys and 256 characters per value. They appear near the report title and under `meta.report_attributes` in the YAML result. They label the report; they do not change severity, authorize actions, or become analysis instructions. Keep credentials and confidential personal data out of them.

Select the profile and override individual settings when needed:

```sh
appsec-analyzer scan --profile release
appsec-analyzer scan --profile release --budget 30
appsec-analyzer scan --profile release --max-parallel 4
appsec-analyzer scan --profile release --assessment-depth quick --outputs markdown sarif
```

Explicit CLI values take precedence over scan defaults. `--outputs` replaces the profile's export list. Existing flags such as `--pdf` and `--sarif` add their format to that selection. The chosen scan profile controls exports even when an organization profile also supplies export defaults. Other organization settings continue to apply.

## Save an abuse-case selection

Add `abuse_case_files` to a scan profile to reuse your case selection:

```yaml
schema_version: 1
model_profile: claude
abuse_case_files:
  - review/abuse-cases.yaml
  - policy/payment-cases.yml
```

Paths are relative to the selected repository root, regardless of where the profile lives. The files may be anywhere inside that repository, must be admitted YAML files, and currently require a single-repository assessment. Passing one or more `--abuse-case-file` options replaces the profile list. An empty profile list selects no extra files; it does not disable automatically discovered or organization cases. Explicit selections enable verification even at quick depth, within the normal spending and case limits. See [custom abuse cases](security-assessment.md#custom-abuse-cases) for case authoring and compatibility paths. `profiles show` and `validate` check the path declarations without reading case contents; the assessment validates those files against its admitted source snapshot.

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

Supported roles are `recon_scanner`, `actor_discoverer`, `architecture_analyst`, `trust_boundary_analyst`, `control_analyst`, `stride_analyzer`, `threat_merger`, `triage_validator`, `post_stride_synthesizer`, `evidence_verifier`, `abuse_case_deriver`, `abuse_case_verifier`, `architect_reviewer`, `ms_renderer`, and `secarch_renderer`. Choosing a model for a role does not enable that role; the assessment depth still determines the work performed.

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
appsec-analyzer scan --profile /private/team-settings/profiles/release.yaml
```

For an explicit scan path, model names resolve from the sibling `model-profiles` directory or the built-ins. Analyzer does not silently substitute a same-named model file from the user's configuration directory. The built-in names `claude`, `codex`, and `codex-cli` are reserved in both directories.

Copyable examples are [developer.yaml](../examples/profiles/developer.yaml), [release.yaml](../examples/profiles/release.yaml), [team-sol.yaml](../examples/model-profiles/team-sol.yaml), and [team-claude.yaml](../examples/model-profiles/team-claude.yaml). The release example uses `team-sol`, so copy both files into their respective directories.

## Resume a run

The private assessment state stores the resolved profile, including each role's model and settings. OpenAI aliases remain fixed to the stored model IDs on `--resume`. The current catalog must still recognize those IDs and their options. Changing the profile, effective configuration, or cost information requires a new run. Existing lifecycle checks also reject incompatible sources, settings, or runtime updates, including catalog updates.

Runs created before profile snapshots were introduced cannot resume through the new profile path. Start a new assessment when Analyzer reports this incompatibility. Existing `--profile claude`, `--profile codex`, and compatible legacy `--host` commands remain supported for new runs.

`max_parallel` is part of the saved configuration. Changing it requires a new run. Snapshots created before this setting was recorded require a new run through the profile path; existing reports remain readable.
