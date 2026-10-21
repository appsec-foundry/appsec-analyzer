# Org-profile invariants

Scope: the format and resolver are retained by Analyzer, but the plugin build blocks below describe Advisor-only integration. The named plugin packager, hooks, and smoke tool are absent from this repository. Use [current organization profiles](../../org-profiles.md) for supported standalone behavior; do not recreate excluded plugin components merely to satisfy this inherited routing table.

This document maps org-profile changes across schema, resolution, packaging, runtime consumption, and tests. `schemas/org-profile.schema.yaml` is the structural source of truth; this file owns the cross-layer routing rules.

## Standalone organization distributions

The supported standalone packaging path is `appsec_analyzer/organization.py`, `schemas/organization-distribution.schema.yaml`, and the installable example under `examples/organization-distribution/`. An organization's console entry point explicitly identifies its own resource package. The manifest pins the exact engine and public interface and points to packaged scan/org YAML files. The existing scan resolver locates custom model profiles in the sibling `model-profiles/` directory. No source-owned discovery or arbitrary plugin import is added.

The CLI accepts the validated distribution as an explicit argument to `main`. It applies bundled defaults only to `assess`; explicit profile flags and `--no-org-profile` retain their meaning. `organization show` and `organization validate` run without provider calls. Bad package data stops startup instead of falling back. Bundled profiles reject Advisor-only integration declarations rather than implying that hooks, MCP, added skills, skill toggles, baseline installers or agent policy replacements execute in Analyzer.

`tests/test_organization_distribution.py` checks intended and malformed inputs, source-boundary rejection, explicit overrides, preserved CI statuses, wheel/source contents, and an installation whose source checkout has been removed. The example's runtime and build locks are independent of engine source changes. Release provenance must retain engine/org commits because the current preview version is not unique to every source commit. See the [packaging and CI guide](../../organization-distributions.md).

## Change paths

Every org-profile field must have a declared layer and follow that layer's complete path.

### Build-time packaging blocks

Blocks that change the packaged plugin surface span:

- `schemas/org-profile.schema.yaml`
- `scripts/validators/validate_org_profile.py`
- `scripts/package_internal_plugin.py`
- `scripts/smoke_test_package.py`
- `tests/test_package_internal_plugin.py`

For example, org-declared `hooks` are merged into the built `hooks/hooks.json`, recorded under `hooks.org` in `package-surface.json`, and smoke-verified. Preserve declared org hook IDs; do not derive them from `/scripts/<name>` as upstream hook IDs are.

### Preset fields

Fields consumed as preset defaults span the schema, `scripts/runtime/resolve_org_profile.py::flatten_preset`, every consuming skill or runtime, and `tests/test_org_profile_schema.py` / `tests/test_resolve_org_profile.py`.

For example, `requirements.gate` is seeded into both requirements skills and remains CLI-overridable.

### Profile-level fields

Profile-level policy consumed by a hook or guard bypasses `flatten_preset`. It flows through `resolve()` into `.org-profile-effective.json` under `defaults` and is read directly by the consumer.

The inherited plugin-only `security_coach.topics` consumer is excluded from Analyzer. The retained `policy.url_allowlist` reaches `scripts/shared/_url_guard.py` and is guarded by `tests/test_url_guard.py`.

`analyst` is the one profile-level field that does not reach `.org-profile-effective.json`. `resolve()` returns it under `analyst`, and only `scripts/orchestrator/analyst_controller.py` consumes it, by calling `resolve()` itself; `resolve_config` and the assessment never see it. It spans the schema, `scripts/validators/validate_org_profile.py::_check_analyst`, `scripts/runtime/resolve_org_profile.py::analyst_packages`, the controller, and `tests/test_resolve_org_profile.py` / `tests/test_analyst_controller.py`. It adds no packaged surface.

`llm_policy` is the one profile-level field consumed by an agent rather than by Python: `resolve()` carries it into `.org-profile-effective.json`, `resolve_config` exposes it as `org_profile_llm_policy`, the skill emits it as `LLM_POLICY_JSON`, and Phase-9 dispatch forwards it in Group A. It stays in Group A because it is identical for every component; moving it to Group B would pay for it once per dispatch.

### Preset guardrails

Preset guardrails consumed by the orchestrator do pass through `flatten_preset`. For example, `guardrails.fail_on` is resolved into the effective profile and seeded by `scripts/run-headless.sh`; an explicit CLI value wins.

## Packaging verification

After an org-profile schema or packaging change, build and smoke-test the example package. Confirm the org packaging example still builds cleanly and that `package-surface.json` records the intended surface.

User-facing profile behavior is documented in `docs/org-profiles.md`; packaging details live in `docs/internal-plugin-packaging.md`.
