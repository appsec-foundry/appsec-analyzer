# Organization configuration for a composed plugin

This contract describes `organization-config`, the way a plugin host such as AppSec Advisor passes engine settings to Analyzer. It is not a user guide. Organizations that ship their own command follow the [packaging guide](../../organization-distributions.md).

`organization-config` is separate from the installed distribution launcher. The host passes engine settings through the [organization-config schema](../../../schemas/organization-config.schema.json). The file names the exact `engine_version`, the selected `advisor_core_version`, and an engine-only `profile`. `compatibility.core` applies to the Advisor version. Hooks, MCP declarations, banners, skills, and coaching do not belong in this file.

## Inspection

Use `organization-config validate --config /installed/plugin/org-profile/analyzer-config.yaml` or `organization-config show --config /installed/plugin/org-profile/analyzer-config.yaml --preset release` for model-free inspection. An explicit inspection `--assessment-depth quick` overrides the selected preset default without changing profile-wide policy. Missing or invalid profiles, unsupported fields, incompatible versions, source-owned configuration, and unknown presets fail without upstream fallback. Files use the existing bounded, data-only YAML reader without links, duplicate keys, or aliases.

To inspect a full invocation without source access, credentials, or models, use `organization-config show --config /installed/plugin/org-profile/analyzer-config.yaml -- assess --repo /source/repository --assessment-depth quick`. Inspection resolves the supported profile settings, checks policy, and reports the effective `assessment_profile`. It does not execute an assessment. `validate` accepts the same optional workflow arguments. Invalid arguments and disallowed destinations fail instead of selecting a default workflow. Control option names must be exact. Abbreviations are refused.

## Running a workflow

`organization-config run --config /installed/plugin/org-profile/analyzer-config.yaml -- score /source/repository --json` runs a configured workflow. Version 1 supports `score` and `assess` and declares `profile_source_validation: true`. It accepts base-mode presets plus `policy.disable_opus` and `policy.url_allowlist`. Other profile fields and workflows are rejected. Use the assessment and distribution path for unsupported fields. Spend guidance does not become a hard limit, and agent instructions do not become executable policy. Organization restrictions apply only when this configuration is explicitly selected. Offline configuration checks do not verify real model or platform behavior.

`score` makes no model calls and uses no assessment depth, exports, or branding. A preset depth is visible during inspection but does not change scoring. A nonempty URL allowlist restricts remote Git targets to an exact hostname or dotted subdomain before Git runs or credentials are used. Existing address and redirect checks still apply. Inner score arguments cannot weaken the policy. Output and exit status stay unchanged.

For full assessments, use the same envelope: `organization-config run --config /installed/plugin/org-profile/analyzer-config.yaml -- assess --repo /source/repository`. Running it may use models and requires separate authorization. A selected preset supplies the depth unless the inner CLI explicitly sets `--assessment-depth`. Scan and model profiles and direct CLI budget and export options keep their existing behavior. Opus selections on the Claude path are clamped before host preflight and again by the existing controller. Unknown or Opus-family provider models fail the restriction before credentials are used.

## Profile source and URL policy

Hosts that copy an external Advisor profile must pass its original canonical path as the outer `--profile-source FILE`, before `--`. Analyzer checks that path and the engine configuration against every selected repository. Inner profile or preset options cannot replace the outer selection. Advisor handles its explicit no-profile choice before dispatch.

CLI context and requirements destinations are checked against the URL policy before provider setup. Later context readers receive the effective-profile file. For composed configurations, `APPSEC_URL_ALLOWLIST` cannot widen the mandatory allowlist. Other organization-profile paths keep their earlier behavior.

## Controller handoff

The controller receives validated organization settings as data, with a content hash and no filesystem profile path. A temporary copied profile does not become a resume identity or an actor or abuse-case profile. Context capture saves supported policy in `.org-profile-effective.json`. Changing policy or preset changes session identity. Moving an otherwise identical configuration does not. This handoff does not migrate hooks, UI, or saved-result workflows.
