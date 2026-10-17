# Scan and model profiles

A scan profile saves the settings you reuse: model selection, analysis depth, budget, output formats, abuse-case files, and report attributes. A model profile chooses models and reasoning settings for individual analysis roles. Both are local YAML files. You can use the built-in profiles without creating either file.

## Start with the defaults

```sh
appsec-analyzer scan --profile claude
appsec-analyzer scan --profile codex
```

Both use standard depth and a USD 20 budget. `claude` uses the Claude CLI and its configured login or external credentials. `codex` uses the OpenAI Responses API and `OPENAI_API_KEY`; it does not use a Codex CLI login. The API adapter remains experimental and has not passed live assessment qualification.

Profiles apply to `scan` and `assess`. `scan-sources` remains a deterministic scan without model calls. The separate requirements audit and focused analyst keep their existing options.

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

`budget` is always USD. `outputs` selects exports; Markdown and structured YAML are always retained as the base result. Supported formats are `markdown`, `yaml`, `html`, `pdf`, `sarif`, `threatdragon`, and `pentest-tasks`. HTML and PDF still need the export tools described in the [assessment guide](security-assessment.md). An unavailable optional export produces a warning.

`max_parallel` limits how many components control analysis and STRIDE analysis each process at once. It defaults to 2 and accepts integers from 1 to 16. Use 1 for serial processing. Higher values can encounter provider rate limits. The controller uses the selected value for both its worker pool and its time reserve for required analysis.

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

`base` accepts only `codex` or `claude`. User profiles cannot inherit from other user profiles. Alternatively, a complete model profile can specify `adapter: openai` or `adapter: claude-cli` and supply its own defaults. Do not combine `base` and `adapter`.

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

For an explicit scan path, model names resolve from the sibling `model-profiles` directory or the built-ins. Analyzer does not silently substitute a same-named model file from the user's configuration directory. The built-in names `claude` and `codex` are reserved in both directories.

Copyable examples are [developer.yaml](../examples/profiles/developer.yaml), [release.yaml](../examples/profiles/release.yaml), [team-sol.yaml](../examples/model-profiles/team-sol.yaml), and [team-claude.yaml](../examples/model-profiles/team-claude.yaml). The release example uses `team-sol`, so copy both files into their respective directories.

## Resume a run

The private assessment state stores the resolved profile, including each role's model and settings. OpenAI aliases remain fixed to the stored model IDs on `--resume`. The current catalog must still recognize those IDs and their options. Changing the profile, effective configuration, or cost information requires a new run. Existing lifecycle checks also reject incompatible sources, settings, or runtime updates, including catalog updates.

Runs created before profile snapshots were introduced cannot resume through the new profile path. Start a new assessment when Analyzer reports this incompatibility. Existing `--profile claude`, `--profile codex`, and compatible legacy `--host` commands remain supported for new runs.

`max_parallel` is part of the saved configuration. Changing it requires a new run. Snapshots created before this setting was recorded require a new run through the profile path; existing reports remain readable.
