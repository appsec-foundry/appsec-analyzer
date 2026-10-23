# Contributing

AppSec Analyzer is a standalone Python CLI with an extracted analysis engine. Start with [AGENTS.md](AGENTS.md), the [architecture overview](ARCHITECTURE.md), [product requirements](requirements.md), and the [script layout](scripts/README.md). Current user instructions live in the README and current guides; earlier Advisor guides are marked as [history](docs/history/advisor/INDEX.md).

## Development environment

Use an isolated environment. Python 3.10+ and Git are required. Runtime dependencies are declared in `setup.py`; the requirements extra supplies retained catalog tooling. For development:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[requirements]' pytest pytest-cov
```

The Makefile prefers `.venv/bin/python3`. Ruff is configured in `pyproject.toml`; use the project's existing Ruff installation for lint and format checks. No test dependency lock or `tests/requirements-test.txt` is supplied. The inherited shell test wrapper references that missing file when bootstrapping, so use explicit commands below.

## Verification

The public standalone contract checks are offline and use fake model hosts. Set `BASE` to the commit before the changes being reviewed, such as the merge-base with the target branch. The gate requires an explicit revision and fails if its history is unavailable. For uncommitted changes only:

```sh
make check-analyzer BASE=HEAD
```

`check-analyzer` first checks requirements, acceptance sections, proposals, and retired IDs against `BASE`, including committed, staged, unstaged, and untracked changes. It then runs the public contract tests, current prompt and command examples, and a wheel/sdist inventory test. It does not claim the inherited whole-repository suite passes. For a branch or release review, replace `HEAD` with the actual comparison commit; `HEAD` does not review already committed changes.

Choose additional explicit test files for changed producers and consumers. Requirement bindings help locate them but do not prove that the selection is complete. For changed Python files, run `ruff check <files>` and `ruff format --check <files>`.

| Change | Additional verification |
| --- | --- |
| CLI, source selection, state, or provider boundary | Public CLI tests and affected source, state, host, cancellation, and negative-input tests. |
| Controller or deterministic stages | Affected controller tests, selected by name from `tests/test_controller_fixture.py` (each is a full controller run of 45 to 100 seconds); `make test-controller` runs all of them (about 15 minutes) and runs only on request; `make e2e-controller` exercises the CLI with a fake Claude executable and runs only on request. |
| Agent or skill instructions | Relevant prompt contracts and tests of the behavior they influence. These files are runtime inputs. |
| Report, schema, or export | Producer and consumer tests, schema validation, and applicable golden replay. |
| Requirements | Catalog, audit, and affected producer tests; record the change in `specs/changes/<name>/proposal.md`. |
| Documentation | Check commands against CLI help and implementation, local links, and affected contracts. |

The inherited group catalog in `scripts/run_tests.py` still reports missing tests and invalid routes. The inherited `make lint` and `make release-check` targets invoke missing Advisor files; use `make release-check-analyzer BASE=<base-commit>` for the standalone offline distribution gate. These are open extraction defects, not features to recreate automatically. The repository contains no `.github/` workflows or CODEOWNERS; earlier claims about a passing CI matrix did not apply here.

The active context-routing tests build the Analyzer package and run in the standalone gate. Tests dedicated to excluded Advisor hooks, plugin packaging, status helpers, and release tools have been removed. The standalone requirements catalog checker works independently of Claude hook registration.

The whole suite now collects, but execution is not green. The first current failure is a logger test expecting the excluded root `config.json`; the inherited group-catalog tests also fail on missing Advisor entries. For a complete diagnostic run that retains any future collection errors:

```sh
PYTHONPATH=.:scripts python3 -m pytest tests --continue-on-collection-errors -q --tb=short
```

Do not exclude remaining failing modules or reduce coverage thresholds to make that result pass. The inherited coverage configuration measures `scripts/`, not the public `appsec_analyzer/` package. The [repository review](docs/internal/analysis/repository-review-2026-10-17.md) records cleanup work and verification limits. A focused green run does not qualify the complete distribution.

## Live qualification

Live tests call a paid provider and require an explicitly authorized budget. They are not part of offline review:

```sh
make e2e-full BUDGET=<authorized-usd>
make e2e-full-standard BUDGET=<authorized-usd>
make e2e-full-thorough BUDGET=<authorized-usd>
make e2e-fixture-suite BUDGET=<authorized-usd-per-fixture>
make e2e-controller-live BUDGET=<authorized-usd>
```

The driver calls the public CLI and checks published artifact digests. External fixture tests require the sibling fixture checkout; see the [fixture runbook](docs/internal/runbooks/e2e-fixtures.md). Fake-host success establishes pipeline behavior, not live host isolation, model quality, or actual cost accuracy.

## Requirements and compatibility

Write one observable user outcome per requirement, with a short label and a stable `REQ-NNN` ID. Do not renumber IDs when moving or reordering requirements. Keep detailed acceptance rules in the normative [acceptance contract](docs/internal/contracts/requirement-acceptance.md), and paths and exact test selectors in [data/requirement-bindings.yaml](data/requirement-bindings.yaml). Direct, partial, and advisory coverage describe the evidence's scope; they do not assert that a test currently passes.

Record semantic changes to requirements or their acceptance rules and compatibility implications in `specs/changes/`. The [Analyzer scope migration](specs/changes/analyzer-user-requirements/proposal.md) and subsequent [plain-ID migration](specs/changes/plain-requirement-ids/proposal.md) map the inherited catalog to the current one. Binding schema version 2 uses plain IDs for active requirements and permits the earlier format only for retirements. Keep retired IDs so old references cannot acquire a new meaning. Update current guides and public examples when commands or availability change.

Each active requirement needs exactly one nonempty `## REQ-NNN: Title` section in the acceptance contract. The checker rejects missing, duplicate, or inactive sections. Comparing against `BASE` also requires removed requirements to appear in `retired_ids`, preserves earlier retirements, and rejects reuse even if an old retirement was deleted from the current bindings.

Start each new or modified `specs/changes/<name>/proposal.md` with these four YAML fields, replacing the example text and IDs with the actual change:

```yaml
---
reason: Explain the user need or defect behind the change.
affected_ids: [REQ-018]
compatibility: Explain what changes for existing users and saved artifacts.
verification: Name the checks and relevant intended and negative cases.
---
```

The fields must contain nonempty text and a list of unique known IDs. The changed proposals together must name every requirement whose outcome or acceptance text changed, including added and removed IDs. Changed or removed decision-register rows use their decision IDs. Use `affected_ids: []` for changes to introductory text or tooling that alter no requirement or decision entry. Historical proposals that are unchanged relative to `BASE` keep their original format. Deleted, unreadable, or linked proposals cannot satisfy the check.

The checker conservatively requires a proposal for any edit to the requirement catalog or acceptance contract, including editorial edits. It checks structure and declared IDs; reviewers still judge rationale, compatibility, semantic coverage, and authorization. A proposal is not proof of approval or passing tests. Requirements remain product outcomes; introduce individually referenced acceptance criteria for complex requirements when they are next changed rather than renumbering the catalog now.

For the specification checks alone, run `make check-specs BASE=<base-commit>`. The equivalent command is `python3 scripts/check_specs.py --changed-against <base-commit>`. Without that option, `python3 scripts/check_specs.py` checks only the current catalog, bindings, and acceptance sections; it does not check change history. Use `python3 scripts/check_specs.py --for appsec_analyzer/cli.py` to find requirements and test references for a file. These checks do not execute the referenced tests or establish requirement completion.

For report sections, follow the [section runbook](docs/internal/runbooks/adding-a-section.md) and [schema invariants](docs/internal/contracts/schema-invariants.md). Inspect golden changes before regeneration; do not edit expected output to conceal a producer defect.

## Repository layout

| Path | Purpose |
| --- | --- |
| `appsec_analyzer/` | Public CLI, score and focused-analysis workflows, assessment request and console, shared application services, hosts, and profiles; see the [module boundaries](ARCHITECTURE.md#workflow-ownership). |
| `scripts/` | Analysis engine, lifecycle, renderers, validators, maintainer tools. |
| `agents/` | Role instructions and shared contracts consumed by the engine. |
| `skills/` | Current entry skill and retained Advisor material; selected resources enter the wheel. |
| `data/`, `schemas/`, `templates/` | Catalogs, structured contracts, and report assets. |
| `tests/` | Offline tests, fixtures, explicitly enabled live qualification. |
| `docs/` | Current guides, technical contracts, reviews, and marked history. |
| `specs/changes/` | Requirement-change rationale and migration records. |
| `setup.py`, `MANIFEST.in`, `engine.json` | Package contents and version metadata. |

## Build and submit a change

Keep changes focused and describe user-visible behavior and validation in the pull request. Follow [local release preparation](docs/local-release-preparation.md) for wheel and source-archive checks. Build from a fresh checkout to avoid stale build resources, inspect archives, and test the installed CLI independently of source imports. Publication is a separate action.

Follow [SECURITY.md](SECURITY.md) for vulnerabilities. Inspect diagnostic bundles before sharing them; keep confidential source and reports out of public issues.
