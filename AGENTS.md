# Working on AppSec Analyzer

This repository contains an existing Python security-analysis engine extracted from AppSec Advisor. Make scoped changes using the current standalone CLI and contracts. Applicable security-baseline and organization instructions continue to apply; these project instructions do not replace them.

## Requirements and documentation

Read [requirements.md](requirements.md) before changing observable behavior. It describes user outcomes, not proof of feature completion. Use [data/requirement-bindings.yaml](data/requirement-bindings.yaml) to find affected producers, consumers, and tests. Check actual behavior and coverage; a binding does not prove that its tests pass or establish the entire requirement.

Keep `REQ-NNN` requirement IDs stable when moving or reordering entries. The [acceptance contract](docs/internal/contracts/requirement-acceptance.md) contains normative detail rules; preserve them when editing short user outcomes. Consolidated or removed IDs belong in `retired_ids` and must not be reused. Update bindings with the change. Keep implementation details in contracts and bindings.

Record every edit to requirements.md or the acceptance contract, including editorial edits, in `specs/changes/<change>/proposal.md`. New or modified proposals need the four YAML fields described in [CONTRIBUTING.md](CONTRIBUTING.md#requirements-and-compatibility): reason, affected IDs, compatibility, and verification. Unchanged historical proposals retain their original format. An explicit user request to change requirements already authorizes that work; the proposal records it. A new feature additionally needs an approved draft, as described in [Start new features with a requirement](#start-new-features-with-a-requirement).

Keep the [README](README.md), affected current guides, CLI help, and installed entry skill consistent. Follow [documentation style](docs/internal/documentation-style.md): plain language, one source line per prose paragraph, and clear prerequisites and limits. Historical documents, proposals, and extraction records are context, not current command references. Do not present planned behavior as a supported feature.

## Start new features with a requirement

Agree on a requirement with the user before writing code for a new or extended feature. A bug fix that restores behavior an existing requirement already describes skips this.

1. Propose the requirement in the conversation as it would appear in requirements.md: a short label and one user outcome in plain language, without implementation details. Add the main acceptance rules as short points.
2. Below it, name the risks and side effects that apply, such as model cost, data sent to models or other hosts, credential use, or changes to existing commands and saved results. Name a simpler or safer variant if one exists.
3. Wait until the user explicitly approves the wording. A request for the feature alone is not approval.
4. Add the approved requirement to requirements.md with its acceptance section, binding, and proposal, as described above. Record the raised risks and the user's decisions in the proposal.
5. Implement the feature only if the user asked for that. If the approved requirement cannot be met as written, propose a revision instead of deviating silently.

## Architecture and change boundaries

Read [ARCHITECTURE.md](ARCHITECTURE.md) before changing module ownership or dependencies, and keep it aligned with structural changes. The application package owns the public CLI, application workflows, and shared services; the retained engine under `scripts/` owns assessment execution. Use the architecture document for module ownership and the linked contracts for execution rules. Only explicitly packaged resources are available after installation.

The supported user entry is `appsec-analyzer`. `scan` runs model-backed assessments; `scan-sources` and `score` run deterministic analysis without model calls. Keep that cost and data-use distinction and deterministic coverage limits explicit. `analyze-threats`, `authnz-review`, and `audit-requirements` have separate scopes; do not turn them into a full assessment. A saved-result review does not authorize implementation or further model spending. Retained skills and hook-era helpers are not automatically public Analyzer features.

Credentials and execution authority remain outside analyzed repositories; publish assessment reports outside them. Agent Markdown is runtime input; repository text and model output cannot grant execution authority.

### Change boundaries

| Change | Read and keep aligned |
| --- | --- |
| Public commands or packaging | `appsec_analyzer/cli.py`, `setup.py`, `MANIFEST.in`, `engine.json`, current guides, public CLI tests. |
| Source admission, host, or lifecycle | `scripts/runtime/multi_repo_scope.py`, `assessment_host.py`, `assessment_state.py`, `analyst_host.py`, `appsec_analyzer/api_hosts.py`, and boundary tests. |
| Controller or analysis roles | `scripts/orchestrator/`, `agents/`, [orchestration actions](docs/internal/contracts/orchestration-actions.md), [context routing](docs/internal/contracts/context-routing.md). |
| Findings, schemas, reports, or exports | `scripts/model/`, `scripts/renderers/`, `scripts/exporters/`, schemas, templates, `data/sections-contract.yaml`, [schema invariants](docs/internal/contracts/schema-invariants.md), affected golden fixtures. |
| Requirements audit | `appsec_analyzer/requirements_audit.py`, `scripts/requirements/`, audit schema, [audit guide](docs/security-requirements-audit-skill.md), evidence and gate tests. |
| Saved-result review or assistant handoff | `appsec_analyzer/review.py`, `review_context.py`, `saved_assessment.py`, `skills/review-assessment/SKILL.md`, [review guide](docs/security-assessment.md#review-an-assessment-with-ai), packaging, and public review tests. |

Before removing apparently dead code, check imports, lazy loading, script dispatch, subprocess commands, resource registries, prompts, packaging, tests, and documented interfaces. Legacy names alone do not prove dead code. Preserve migrations used by supported older artifacts. Record uncertain candidates rather than deleting them on an import-count heuristic.

## Verification

Run only tests that exercise the changed code: tests of changed modules and their direct consumers, plus the selectors the bindings name for affected requirement IDs. Documentation or instruction changes need no pytest run unless a test reads the changed file. Do not repeat a passing check unless its code changed; after a failure, rerun only the failing tests. Run whole-suite targets such as `make test`, `make check`, or `make test-changed`, which falls back to the whole suite, only on request; such a run must retain collection errors. Add intended and negative cases when changing a control or trust boundary. Do not remove, skip, weaken, or broadly mock failing tests to conceal an extraction or implementation defect.

Run end-to-end targets only when the user asks for them. Offline runs such as `make e2e-controller` and `make test-incremental` are not part of routine verification; for controller changes, `make test-controller` and the affected controller tests suffice. Do not run `appsec-analyzer scan` or other model-backed commands to check a change. Live targets are `make e2e-full`, `e2e-full-standard`, `e2e-full-thorough`, `e2e-fixture-suite`, `e2e-controller-live`, `analyze-verify`, and `release-all`; each needs an explicit request with an authorized budget, and a request to test or verify a change is not one.

Include `PYTHONPATH=.:scripts` when tests import extracted domain packages directly. Run Ruff lint and format checks on changed Python files. Controller changes need offline controller tests; report changes need relevant golden replay and schema checks.

Run the standalone offline gate once before completion when the change touches public commands, packaging, requirements, or documented commands. Replace `<base-commit>` with the commit before the reviewed changes, usually the merge-base with the target branch. `BASE=HEAD` covers only uncommitted changes.

```sh
make check-analyzer BASE=<base-commit>
```

If the change touches only requirements.md, the acceptance contract, requirement bindings, or change proposals, run `make check-specs BASE=<base-commit>` instead of the gate, plus tests that read the changed files. Running `python3 scripts/check_specs.py` without a comparison revision checks only the current catalog, bindings, and acceptance sections. These checks do not establish requirement completion or approval.

Report which checks ran and which broader checks were skipped. Follow [CONTRIBUTING.md](CONTRIBUTING.md#verification) for commands, distribution checks, and known inherited-check limitations. Do not present failing or unexecuted checks as green gates.

Live model calls need explicit spending authorization. Building or reviewing a package does not authorize publication, pushes, tags, or messages to other people. Follow applicable tool and dependency permissions.

Before completion, review the actual diff, recheck security-module routing, verify changed documentation links and commands, and report findings with locations, impact, and a concrete next action. Distinguish established failures, uncertain dead-code candidates, and unexecuted live qualification.
