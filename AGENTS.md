# Working on AppSec Analyzer

This repository contains an existing Python security-analysis engine extracted from AppSec Advisor. Make scoped changes using the current standalone CLI and contracts. Applicable security-baseline and organization instructions continue to apply; these project instructions do not replace them.

## Requirements and documentation

Read [requirements.md](requirements.md) before changing observable behavior. It describes user outcomes, not proof of feature completion. Use [data/requirement-bindings.yaml](data/requirement-bindings.yaml) to find affected producers, consumers, and tests. Check actual behavior and coverage; a binding does not prove that its tests pass or establish the entire requirement.

Keep `REQ-NNN` requirement IDs stable when moving or reordering entries. The [acceptance contract](docs/internal/contracts/requirement-acceptance.md) contains normative detail rules; preserve them when editing short user outcomes. Consolidated or removed IDs belong in `retired_ids` and must not be reused. Update bindings with the change. Keep implementation details in contracts and bindings.

Record every edit to requirements.md or the acceptance contract, including editorial edits, in `specs/changes/<change>/proposal.md`. New or modified proposals need the four YAML fields described in [CONTRIBUTING.md](CONTRIBUTING.md#requirements-and-compatibility): reason, affected IDs, compatibility, and verification. Unchanged historical proposals retain their original format. An explicit user request to change requirements already authorizes that work; the proposal records it. A new feature additionally needs an approved draft, as described in [Start new features with a requirement](#start-new-features-with-a-requirement).

Keep the [README](README.md), affected current guides, CLI help, and installed entry skill consistent. Follow [documentation style](docs/internal/documentation-style.md): plain language, one source line per prose paragraph, and clear prerequisites and limits. Historical documents, proposals, and extraction records are context, not current command references. Do not present planned behavior as a supported feature.

Write documentation in clear, natural language that the intended reader can understand on the first read. Use short, direct sentences and familiar words. Include technical details only when they help readers understand or complete the task, and explain necessary technical terms. Avoid unnecessary prose, repetition, filler, and stock AI phrases. State what matters and what readers need to do.

## Start new features with a requirement

Agree on a requirement with the user before writing code for a new or extended feature. A feature is a new user outcome or a change to what an outcome in requirements.md promises, such as a new command, analysis, or result, or changed model use, data sent to models or other hosts, or credential use.

Changes that leave every user outcome as it is need no new requirement. Examples are a bug fix that restores behavior an existing requirement already describes, another way to start the same commands, clearer help or messages, technical acceptance rules that weaken no safeguard, refactoring, tests, and documentation; follow the [change boundaries](#change-boundaries) for them. If it is unclear whether a change is a feature, ask the user before drafting a requirement.

1. Propose the requirement in the conversation as it would appear in requirements.md: a short label and one user outcome in plain language, without implementation details such as file, module, or library names. Add up to five acceptance points that users can check. For a changed requirement, show only the changed sentences.
2. Below it, name the risks and side effects that apply, such as model cost, data sent to models or other hosts, credential use, or changes to existing commands and saved results. Name a simpler or safer variant if one exists.
3. Wait until the user explicitly approves the wording. A request for the feature alone is not approval.
4. Add the approved requirement to requirements.md with its acceptance section, binding, and proposal, as described above. Record the raised risks and the user's decisions in the proposal.
5. Implement the feature only if the user asked for that. If the approved requirement cannot be met as written, propose a revision instead of deviating silently.

## Choose the branch before editing

Before the first edit to a tracked file for a change, ask the user whether to create a feature branch from `main` or to work directly on `main`, and wait for the answer. Recommend one option with a short reason, for example a branch for a feature implemented over several steps and `main` for a self-contained change of a few files. If the request already names the branch, use it without asking. The answer applies to that change only; ask again for the next change. Create a feature branch in a separate git worktree, because other sessions may use the shared checkout at the same time. The branch choice does not authorize commits, merges, or pushes.

## Architecture and change boundaries

Read [ARCHITECTURE.md](ARCHITECTURE.md) before changing module ownership or dependencies, and keep it aligned with structural changes. Read the [decision register](docs/internal/decisions.md) before changing a long-lived, cross-cutting technical choice, and follow its rules for adding, changing, or retiring entries. The application package owns the public CLI, application workflows, and shared services; the retained engine under `scripts/` owns assessment execution. Use the architecture document for module ownership and the linked contracts for execution rules. Only explicitly packaged resources are available after installation.

The supported user entry is `appsec-analyzer`. `assess` runs model-backed assessments; `scan-sources` and `score` run deterministic analysis without model calls. Keep that cost and data-use distinction and deterministic coverage limits explicit. `analyze-threats`, `authnz-review`, and `audit-requirements` have separate scopes; do not turn them into a full assessment. A saved-result review does not authorize implementation or further model spending. Retained skills and hook-era helpers are not automatically public Analyzer features.

The main call is `appsec-analyzer assess --repo PATH --output DIR`; from a checkout without installation use `python3 -m appsec_analyzer assess ...`. It makes model calls and needs an authorized budget. The secondary deterministic scan without a rating is `appsec-analyzer scan-sources --repo PATH [--output DIR] [--json]`. It has no public Python function; its logic lives in `_scan_local` in `appsec_analyzer/cli.py`. `assess-sources` is not a command. The user-facing descriptions are in the [README](README.md#commands).

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

Choose verification by what the change affects. Run tests of changed modules and their direct consumers, plus the selectors the bindings name for affected requirement IDs. For purely editorial changes to documentation, changelogs, or contributor instructions, review the diff, formatting, local links, and consistency; do not run pytest or broad gates just because a file mentions commands or has a test route. Run a focused test only when it checks the changed content or behavior. Runtime agent and skill instructions that change application behavior still need the relevant prompt and behavior contract tests.

Do not repeat a passing check unless the content or behavior it checks changed; after a failure, rerun only the failing tests. Run whole-suite targets such as `make test`, `make check`, or `make test-changed`, which falls back to the whole suite, only on request; such a run must retain collection errors. Add intended and negative cases when changing a control or trust boundary. Do not remove, skip, weaken, or broadly mock failing tests to conceal an extraction or implementation defect.

`make test-for FILES="<changed files>"` selects tests from the reviewed routes in `scripts/run_tests.py` and refuses with exit 2 instead of running the whole suite. Files under `appsec_analyzer/` and the Makefile have no reviewed route, and `make audit-test-routes` points at a missing script, so do not derive routes by import scan alone. For such a file, take the bound selectors from `python3 scripts/check_specs.py --for <file>`, add the tests that name the changed module (`grep -l <module> tests/test_*.py`), and report that the selection is not a reviewed route.

Run end-to-end targets only when the user asks for them. Offline runs such as `make e2e-controller` and `make test-incremental` are not part of routine verification; for controller changes, the affected controller tests suffice. Each test in `tests/test_controller_fixture.py` is a full controller run of 45 to 100 seconds, and `make test-controller` runs all of them (about 15 minutes), so select single tests from that file by name and run `make test-controller` only on request. Do not run `appsec-analyzer assess` or other model-backed commands to check a change. Live targets are `make e2e-full`, `e2e-full-standard`, `e2e-full-thorough`, `e2e-fixture-suite`, `e2e-controller-live`, `analyze-verify`, and `release-all`; each needs an explicit request with an authorized budget, and a request to test or verify a change is not one.

Include `PYTHONPATH=.:scripts` when tests import extracted domain packages directly. Run Ruff lint and format checks on changed Python files. Controller changes need offline controller tests; report changes need relevant golden replay and schema checks.

Run the standalone offline gate once before completion when the change affects public command implementation or supported behavior, packaging, or requirements, subject to the specification-only exception below. Documentation-only corrections to command examples need comparison with CLI help or implementation and any focused tests of those examples, not the full gate. Editorial changes, historical command references, and mentions of verification commands do not trigger the gate. Run broader checks only on explicit request or when another applicable rule requires them for the affected behavior. Replace `<base-commit>` with the commit before the reviewed changes, usually the merge-base with the target branch. `BASE=HEAD` covers only uncommitted changes.

```sh
make check-analyzer BASE=<base-commit>
```

If the change touches only requirements.md, the acceptance contract, requirement bindings, or change proposals, run `make check-specs BASE=<base-commit>` instead of the gate, plus tests that read the changed files. Running `python3 scripts/check_specs.py` without a comparison revision checks only the current catalog, bindings, and acceptance sections. These checks do not establish requirement completion or approval.

Report which checks ran and which broader checks were skipped. Follow [CONTRIBUTING.md](CONTRIBUTING.md#verification) for commands, distribution checks, and known inherited-check limitations. Do not present failing or unexecuted checks as green gates.

Live model calls need explicit spending authorization. Building or reviewing a package does not authorize publication, pushes, tags, or messages to other people. Follow applicable tool and dependency permissions.

Before completion, review the actual diff, recheck security-module routing, verify changed documentation links and commands, and report findings with locations, impact, and a concrete next action. Distinguish established failures, uncertain dead-code candidates, and unexecuted live qualification.
