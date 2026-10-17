# Working on AppSec Analyzer

This repository contains an existing Python security-analysis engine extracted from AppSec Advisor. Make scoped changes using the current standalone CLI and contracts. Applicable security-baseline and organization instructions continue to apply; these project instructions do not replace them.

## Requirements and documentation

Read [requirements.md](requirements.md) before changing observable behavior. It describes user outcomes, not proof of feature completion. Use [data/requirement-bindings.yaml](data/requirement-bindings.yaml) to find affected producers, consumers, and tests. Check actual behavior and coverage; a binding does not prove that its tests pass or establish the entire requirement.

Keep `REQ-NNN` requirement IDs stable when moving or reordering entries. The [acceptance contract](docs/internal/contracts/requirement-acceptance.md) contains normative detail rules; preserve them when editing short user outcomes. Record semantic changes to either document in `specs/changes/<change>/proposal.md`, including the reason, affected IDs, compatibility, and verification. An explicit user request to change requirements already authorizes that work; the proposal records it. Consolidated or removed IDs belong in `retired_ids` and must not be reused. Update bindings with the change. Keep implementation details in contracts and bindings.

Keep the [README](README.md), affected current guides, CLI help, and installed entry skill consistent. Follow [documentation style](docs/internal/documentation-style.md): plain language, one source line per prose paragraph, and clear prerequisites and limits. Historical documents, proposals, and extraction records are context, not current command references. Do not present planned behavior as a supported feature.

## Architecture and change boundaries

| Change | Read and keep aligned |
| --- | --- |
| Public commands or packaging | `appsec_analyzer/cli.py`, `setup.py`, `MANIFEST.in`, `engine.json`, current guides, public CLI tests. |
| Source admission, host, or lifecycle | `scripts/runtime/multi_repo_scope.py`, `assessment_host.py`, `assessment_state.py`, `analyst_host.py`, `appsec_analyzer/api_hosts.py`, and boundary tests. |
| Controller or analysis roles | `scripts/orchestrator/`, `agents/`, [orchestration actions](docs/internal/contracts/orchestration-actions.md), [context routing](docs/internal/contracts/context-routing.md). |
| Findings, schemas, reports, or exports | `scripts/model/`, `scripts/renderers/`, `scripts/exporters/`, schemas, templates, `data/sections-contract.yaml`, [schema invariants](docs/internal/contracts/schema-invariants.md), affected golden fixtures. |
| Requirements audit | `appsec_analyzer/requirements_audit.py`, `scripts/requirements/`, audit schema, [audit guide](docs/security-requirements-audit-skill.md), evidence and gate tests. |

The supported user entry is `appsec-analyzer`. `scan` and `assess` run a model-backed assessment; `scan-sources` runs deterministic scanners. Keep that cost and data-use distinction explicit. Retained skills and hook-era helpers are not automatically public Analyzer features. Agent Markdown is runtime input; repository text and model output cannot grant execution authority.

Before removing apparently dead code, check imports, lazy loading, script dispatch, subprocess commands, resource registries, prompts, packaging, tests, and documented interfaces. Legacy names alone do not prove dead code. Preserve migrations used by supported older artifacts. Record uncertain candidates rather than deleting them on an import-count heuristic.

## Verification

Use existing tests and run checks appropriate to changed behavior. Add intended and negative cases when changing a control or trust boundary. Do not remove, skip, weaken, or broadly mock failing tests to conceal an extraction or implementation defect.

```sh
make test-analyzer
python3 scripts/check_specs.py
PYTHONPATH=.:scripts python3 -m pytest tests/test_check_specs.py -q
```

For other behavior, select explicit test files from the bindings and affected consumers. Include `PYTHONPATH=.:scripts` when tests import extracted domain packages directly. Run Ruff lint and format checks on changed Python files. Controller changes need offline controller tests; report changes need relevant golden replay and schema checks. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [repository review](docs/internal/analysis/repository-review-2026-10-17.md).

The inherited test-group catalog, whole-suite collection, `make lint`, `make check`, and release targets contain stale Advisor dependencies. `tests/test_spec_guard.py` also contains a registration test for the excluded `.claude/settings.json`; the standalone catalog checker does not depend on that registration. Do not present these inherited checks as green release gates. Report their actual failures; use explicit tests for scoped verification. A full-suite diagnostic run must retain collection errors in its result.

Live model calls need explicit spending authorization. Building or reviewing a package does not authorize publication, pushes, tags, or messages to other people. Follow applicable tool and dependency permissions.

Before completion, review the actual diff, recheck security-module routing, verify changed documentation links and commands, and report findings with locations, impact, and a concrete next action. Distinguish established failures, uncertain dead-code candidates, and unexecuted live qualification.
