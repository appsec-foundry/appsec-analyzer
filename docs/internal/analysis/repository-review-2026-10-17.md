# AppSec Analyzer repository review

Reviewed starting revision: `88fa84d0edee98a749e4cfa78e8027e31362ebef`, 2026-10-17. The checkout was clean before this review. The standalone CLI has working offline coverage, but the extraction is not ready for a clean whole-repository release gate. The main remaining work is to reconcile inherited tests and resources, make package staging reproducible, and complete the independent audit's publication and provenance controls.

## Scope and method

The inventory covered all 1,332 tracked files, including 422,089 Python source/test lines, package manifests, scripts, role instructions, skills, schemas, templates, examples, current documentation, and historical references. Checks included Python syntax/import structure, references from code and subprocess dispatch, Markdown links and commands, package-copy behavior, CLI boundaries, requirement bindings, test collection, lint, and focused behavioral tests. Static scans found no statements directly following an unconditional return/raise/break/continue in the same statement list; that does not prove all code reachable.

This is a repository-wide structural and behavioral review, not a claim that every source line was manually audited. Dynamic dispatch and script interfaces were considered when classifying legacy code. No real model call, live target scan, credential inspection, package upload, or publication was performed. Offline fake hosts were used for the reproductions below.

## Open findings

Priorities describe maintenance urgency: P1 blocks a trustworthy release workflow; P2 is a concrete defect or missing product guarantee; P3 is a bounded cleanup or usability issue. They are not vulnerability severity scores.

### P1 The inherited test and release workflow cannot validate this distribution

`python3 -m pytest --collect-only -q` collected 17,675 tests but failed on six modules: `test_audit_test_routes`, `test_check_release_meta`, `test_context_routing`, `test_session_banner`, `test_smoke_test_package`, and `test_version_status`. They import excluded tools or read the absent `.claude-plugin/plugin.json`. The initial `scripts/run_tests.py --check-groups` audit reported 113 diagnostics, including 24 missing group entries, four unassigned public test modules, and invalid routes. These counts describe the starting revision, before the new documentation and scan-example test.

The [Makefile](../../../Makefile) also sends lint to an absent `hooks/` directory and release checks to missing `scripts/run-interruptible.sh` and `scripts/check_release_meta.py`. [scripts/run-tests.sh](../../../scripts/run-tests.sh) cannot bootstrap because `tests/requirements-test.txt` is absent. No `.github/` workflows were imported. `tests/test_spec_guard.py::test_spec_guard_registration_and_decisions` separately fails because `.claude/settings.json` is absent.

**Next action:** classify each inherited test as an active engine contract, an integration to migrate, or an excluded Advisor feature; then reconcile explicit routes, test dependency setup, and release targets together. Keep behavior checks for active controls. Removing tests merely because they fail would conceal gaps. The corrected contributor guide uses the functioning public test target and reports the inherited failures explicitly.

### P2 Reused package staging preserves files that the package now excludes

[setup.py](../../../setup.py), `BuildAnalyzer.run` at lines 36–57, overlays resources with `copytree(..., dirs_exist_ok=True)`. Its ignore rules prevent new copies but do not remove stale destination files. Reproduction: create a harmless `appsec_analyzer/scripts/runtime/plugin_read_gate.py` sentinel under a temporary build directory, run `setup.py build_py --build-lib <that directory>`, and observe exit 0 with the excluded sentinel still present. The resulting build tree can carry retired files into a wheel.

**Next action:** build resources into an empty controlled staging tree or reconcile its contents against an explicit manifest, and add an incremental-build regression. Until then, follow the existing fresh-checkout release procedure; an allow-list in `_ignore` alone does not establish archive contents.

### P2 The independent requirements audit has no final secret-output check

[requirements_audit.py](../../../appsec_analyzer/requirements_audit.py), lines 200–222, copies catalog and model prose into the result, checks its schema, and publishes JSON/Markdown. Unlike the full assessment's final redaction and `unmasked_secrets` checks, this path does not reject or mask recognized secret patterns in the final output.

A valid fake-host audit with served source evidence and a synthetic AWS-key-shaped marker in its finding returned `audit_status: complete` and persisted that marker in both artifacts. This used no real credential. Source redaction reduces input exposure but does not validate model-generated or catalog-derived report text. Reports are private files; disclosure occurs if operators distribute the apparently completed report containing a real value copied from an unmasked input.

**Next action:** apply an explicit final secret-publication gate to all audit artifacts before publishing any of them, with intended-output and secret-bearing negative tests. The current audit guide and security policy now state this limitation. This review does not fix the runtime path.

### P2 Audit results do not identify the exact catalog and source snapshot

[requirements_audit.py](../../../appsec_analyzer/requirements_audit.py), lines 208–214, records the repository basename and `requirements_source: local|demo`, but omits the catalog digest, source HEAD/state digest, and detailed admitted scope. Those values are available during the run; the successful fake-host reproduction confirmed they are absent from its verdict. Two revisions or two catalogs can produce reports with indistinguishable source metadata, preventing a reviewer from reproducing a particular verdict.

**Next action:** version the audit result schema and record immutable catalog and admitted-source provenance. Preserve those identifiers alongside reports until the schema carries them. This remains a gap against `REQ-REQ-002`, not a reason to weaken that requirement.

### P2 A broken Advisor version helper still enters the package

[scripts/runtime/version_status.py](../../../scripts/runtime/version_status.py), lines 39–40, imports `baseline.baseline_check` and `baseline.baseline_release`; neither package exists. `setup.py` excludes the old status tool and banner but does not exclude this helper. The temporary package build confirmed `version_status.py` was copied. Its import error also prevents test collection.

The supported `appsec-analyzer version` and `status` commands do not depend on this helper. **Next action:** retire the detached Advisor helper and its obsolete integration tests from the Analyzer surface, or move it with its actual consumer to Advisor; do not restore the baseline subsystem merely to make the import succeed.

### P2 The runtime-document test misses the current script layout

[tests/test_runtime_doc_cli_contract.py](../../../tests/test_runtime_doc_cli_contract.py), `_SCRIPT_CALL`, recognizes only flat `scripts/name.py` paths. Runtime scripts now live under domain directories, and the public entry skill invokes `appsec-analyzer`. The guard over nonempty invocations therefore fails instead of exercising those current commands. Its extractor unit tests cover flat sample paths only.

**Next action:** support the actual domain paths and public CLI, then validate extracted invocations through their real parsers. Keep the nonempty guard. The new source-scan entry-skill regression covers its real command without model credentials; it does not replace this broader prompt contract.

### P2 Some shipped role instructions still describe removed tool procedures

[agents/appsec-stride-analyzer-v2.md](../../../agents/appsec-stride-analyzer-v2.md), lines 15–32, directs a Bash call to the missing `scripts/agent_progress.sh`. The active controller reads this role text. `_assessment_role_instructions` explicitly replaces legacy tool procedures with a tool-less structured exchange, so this is not evidence that the current host executes a missing script or grants Bash access. It is conflicting, unnecessary runtime prompt content and a risk for future consumers that reuse the role directly.

**Next action:** separate reusable analysis policy from Advisor tool procedures, bind current role instructions to the available host contract, and test both the real prompt and its execution boundary. Preserve analysis and evidence rules during that cleanup.

### P3 Coverage and installed documentation do not cover the new public surface completely

[pyproject.toml](../../../pyproject.toml) configures coverage for `scripts` only; a passing inherited threshold would omit `appsec_analyzer/cli.py`, API hosts, and the independent audit. `setup.py` includes selected user guides but omits their historical and root-document link targets. A guide that works in the checkout can therefore contain broken links inside the wheel.

**Next action:** include the public package in coverage without lowering its floor, and inventory installed documentation links alongside package assets. Define whether installed guides are self-contained or point to a versioned source documentation site. The new root requirements and contributor instructions are source-repository documentation, not an installed-product guarantee.

## Legacy and dead-code inventory

No runtime code was deleted in this review. The following classification distinguishes detached production resources from supported compatibility and maintainer tools.

| Area | Evidence and classification | Recommended disposition |
| --- | --- | --- |
| `runtime/appsec_status.py`, `runtime/session_banner.py`, `analyzers/security_steering.py` | Advisor status/session/coach entry points; excluded from wheel/sdist, with no Analyzer public caller. Retained tests and skills still refer to them. | Retire or archive with their Advisor-only tests and routing entries. |
| `runtime/version_status.py` | Imported by the excluded status tool; missing baseline imports; still packaged. | Remove from Analyzer packaging/current runtime after consumer classification. |
| `runtime/skill_policy_gate.py`, `runtime/check_skill_enabled.py`, `requirements/requirements_hook.py` | Detached plugin-hook or skill-toggle interfaces; no imported hook registration. Some helpers call one another and have tests, which does not establish an Analyzer product consumer. | Confirm Advisor ownership and retire together; retain any separately demonstrated engine consumer. |
| `renderers/render_threat_model_schema.py` | Only its dedicated test and inventory metadata reference it. Its docstring claims the old renderer consumes it, but that renderer no longer imports it. | Confirmed unused by the current runtime; remove the stale constants and their retired-format assertions in a cleanup change. |
| `renderers/render_threat_model.py` and marker template | Legacy include-marker renderer with dedicated tests; the production path uses `compose_threat_model.py`. No current controller call found. | Treat as a legacy standalone utility candidate, not as the production renderer. Decide whether to retain that utility explicitly. |
| Retained user skills besides the thin entry | Most still use `CLAUDE_PLUGIN_ROOT` or Advisor commands; only selected resources are packaged. | Inventory as historical/integration material, not advertised standalone commands. |
| `runtime/legacy_import.py`, `model/migrate_v3_to_v4.py`, older artifact schemas | Supported compatibility paths have callers and tests; old names/versions are intentional. | Keep while the declared compatible artifact versions require them. |
| `hook_payload.py`, logger and shared path/IO helpers | Hook-era names coexist with active imports and lifecycle consumers. | Do not remove based on naming or lack of a direct CLI. Trace specific functions before cleanup. |
| `figure1_harness.py`, `eval_analyst.py`, `ground_truth_recall.py`, mock server | Explicit developer/test utilities; few runtime imports are expected. | Keep if their documented development purpose remains supported; live evaluators need separate budget authorization. |

The initial token-reference scan also surfaced `persist_run_baseline.py`, `annotate_sequences.py`, `figure_deployment.py`, `render_progress.py`, `render_review_report.py`, `assessment_console.py`, `extract_report_section.py`, `live_run_holder.py`, `measure_run.py`, `model_lineup.py`, `run_summary.py`, `terminate_run.py`, and `qa_arch_coverage.py`. These are **candidates only**: maintainer commands, legacy consumers, subprocess use, and tests need a deliberate retention decision. Their filenames alone do not establish dead code.

## Documentation and requirement changes delivered

| Area | Correction |
| --- | --- |
| Product requirements | Replaced 73 mixed Advisor promises with 33 labeled user outcomes, retained representative IDs, recorded retirements and all mappings, and added the provider-free source-scan requirement. |
| Requirement bindings | Preserved existing resolvable evidence for consolidated requirements, recorded 20 dangling references removed from active bindings, and added current CLI/audit/state tests. Coverage remains explicitly partial. |
| `AGENTS.md` | No file existed. Added requirements-first maintenance, contract ownership, actual verification commands, legacy classification rules, and authorization boundaries. |
| README and current guides | Clarified `scan` versus `scan-sources`, model costs, Git URL retrieval, export availability/dependencies, audit limits, analyst budgets/answer deletion, and status/resume behavior. |
| Installed entry skill | Corrected the scanner-only example from `scan` to `scan-sources --json`; added a regression executing that documented command with provider credentials removed. |
| Security policy | Replaced Advisor version, output location, broad-tool, Anthropic-only, and unsupported response-time claims with current data flows and explicit qualification gaps; archived the old policy. |
| Contributor and script guides | Removed claims about absent plugin config, CI, CODEOWNERS, baseline package, and dependency manifest; explained working checks and failing inherited gates. |
| Examples and catalog guide | Removed the nonexistent sample PDF link, corrected blueprint-only audit claims, and documented local-catalog use and actual harvester configuration. |
| Navigation and history | Added a documentation index, repaired current links, marked inherited CI/cost/profile guidance, and preserved historical requirements and harvester instructions. |

The [migration proposal](../../../specs/changes/analyzer-user-requirements/proposal.md) records every former requirement. Interactive triage, baseline maintenance, separate scoring, and conversational assessment setup are not silently promised by the current standalone CLI. Requirements are normative acceptance criteria; unavailable independent export and incomplete audit guarantees remain explicit gaps.

The local OpenAI profile's model, supported reasoning settings, standard-price ceiling, and 272K long-context threshold were checked against the [official model documentation](https://developers.openai.com/api/docs/models/gpt-6.1-sol) and [pricing](https://developers.openai.com/api/docs/pricing) on 2026-10-17. This verifies the documented snapshot, not account access or live cost/quality qualification.

## Verification record

The final public offline target passed **68 tests**, including the new entry-skill scan example. The catalog validator passed with 33 requirements, and its dedicated suite passed **43 tests**. The corrected source-scan module separately passed **7 tests**. Catalog plus specification-guard checks produced **90 passes and one inherited failure**, the missing Claude registration file described above. The focused analyst/prompt/catalog run produced **92 passes, one skip, and one inherited failure**, the empty runtime-document invocation set.

Both inherited failures were reproduced against the unchanged starting revision in an isolated temporary source extraction. No failing test was removed, skipped, or weakened. The catalog count assertion changed from 73 to 33 because of the explicitly mapped consolidation; its structural and exact-reference checks remain intact.

Repository-wide Ruff lint over `appsec_analyzer`, `scripts`, and `tests` passed; changed Python files also pass formatting checks. All **33 current fenced public-command examples** parsed with the actual CLI parser, and the local-link check found **no unresolved current Markdown file targets** after excluding historical snapshots and intentional template links. This is syntax/link validation, not execution of paid commands. `git diff --check` passed. The temporary package-staging and audit-output reproductions confirmed the open findings without model calls.

Whole-suite collection failed as described above. The additional diagnostic execution with `--continue-on-collection-errors` was deliberately interrupted at approximately **20%** after confirming further inherited failures; its exit was 130 and it supplies no complete-suite pass count. Repairing the collection and ownership defects is required before that suite can serve as a release gate. Live model quality, actual host isolation, PDF/HTML external-tool execution, and external fixture oracles were not qualified by this review.

## Recommended cleanup order

1. Reconcile the test inventory and release workflow against actual engine and Advisor ownership, keeping current negative/boundary tests intact.
2. Fix resource staging and inventory both wheel and sdist, including installed documentation links and imports.
3. Add the independent audit's final secret gate and immutable provenance with negative tests.
4. Retire detached plugin helpers and clean role prompts without weakening active analysis/evidence contracts.
5. Qualify real providers and export tools only with separately authorized environments and budgets.
