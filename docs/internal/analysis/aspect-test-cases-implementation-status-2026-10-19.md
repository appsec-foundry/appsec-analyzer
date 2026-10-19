# Aspect test cases: implementation status

Status: working document for REQ-040, written 2026-10-19. It records what the implementation branch contains, what is still missing, and the decisions made on the way, so that later sessions can continue. The design and its open questions are in the [proposal](aspect-test-cases-proposal-2026-10-19.md). Nothing here is released, pushed, or measured with a live model.

## Where the work is

The implementation lives on the local branch `feat/aspect-test-cases`, derived from `main` at 356f0cfc. It has not been pushed or merged. Create a worktree to continue: `git worktree add <path> feat/aspect-test-cases`. Commit documentation and requirement changes on `main`, and the implementation on this one branch.

| Commit | Content |
| --- | --- |
| 6a6a5c5f | Figure 1 legend no longer claims STRIDE-per-element analysis. Every source-scanner rule gets a STRIDE category from its weakness class (`_CWE_TO_STRIDE` in `merge_threats.py`). |
| 0b2f9ad0 | Catalog `data/test-cases.yaml` (45 test cases, 14 aspects), schema, consistency tests. |
| 5afdf244 | Config scanner records `rules_evaluated` per check. `scripts/model/case_outcomes.py` derives outcomes of the nine rules test cases. Report appendix "Security Test Cases". |
| 01faebf6 | Finding details link test cases and rules. Completion summary row. SARIF uses the test case ID as `ruleId` for linked findings. |
| 7d949134 | Scan profile setting `test_cases` (boolean) reaches the controller. The controller adds `test_case_results` to the model. |
| 17f98015 | Object form of `test_cases` (`aspects`, `disable` with reasons). Organization profile `test_cases.required` refuses a conflicting disable before any model call. |
| 376cd28b | `case_candidates.py` (starting candidates, applicability) and `case_postchecks.py` (fixed post-checks). |
| 91dd81ca | `AssessmentBudget.hold` and `release` in `assessment_jobs.py`. |
| 22c65a4c | Roles `test_case_investigator` and `open_reviewer`, their policies and reply schemas, `case_analysis.py` validators, `component_outcome` in `case_outcomes.py`. |

## What works today

- With `test_cases: true` in a scan profile, a run links scanner findings to test cases, records an outcome for each of the nine rules test cases, and shows them in the YAML, the report appendix, the completion summary, and SARIF. This makes no additional model calls.
- Without the setting, output is unchanged.
- The model-backed building blocks exist and are tested offline, but nothing calls them yet.

## First visible run

The next step is a run whose result can be inspected, not the complete pilot. It needs three pieces on the same branch:

1. **Controller phase for one aspect, for example AuthZ.** New module `scripts/orchestrator/assessment_test_cases.py` with `run_pilot(...)`, called inside `_assessment_stride` after the STRIDE work is accepted and before `merge_assessment`. For each component it builds candidates with `case_candidates`, dispatches one `test_case_investigator` job, validates with `case_analysis.validate_investigation`, runs the post-checks, and turns the reply into rows with `case_outcomes.investigation_results`. A failed or unaffordable job becomes `replacement_result`. Producers are missing for the context artifacts `.dispatch-context/{component_id}/test-case-candidates.json` and `test-case-results.json`.
2. **Component rows in `test_case_results`.** `case_outcomes.build_block` reads the rows from a sidecar such as `.test-case-pilot.json`. The schema and the report appendix already accept the additive fields, but the appendix keys rows by test case ID only and needs a per-component view.
3. **Pilot findings visible.** List them separately in the YAML and the report, without merging them with the STRIDE findings.

Build and test these offline with a fake host. The run on Juice Shop causes real model cost and needs explicit authorization of its spending first. Compare the pilot and STRIDE results by hand for the first look.

## After the first run: decide with real results

| Item | Becomes necessary when |
| --- | --- |
| Open review role with the 20% reserve (`AssessmentBudget.hold` and `release` exist) | The first run shows what the investigator alone misses. |
| Batching for candidates beyond the cap of 40 per call | The run shows that the cap blocks `control` on large repositories. |
| Merge into `merge_assessment` (`pilot_documents`), union of `test_case_ids`, mapping of reply-local finding IDs | The pilot finds weaknesses STRIDE misses and is continued. |
| Removal rule: a confirmed post-check removes a scanner finding unless the evidence verifier marked it verified, otherwise the finding records `test_case_disagreement` | The merge exists. |
| Comparison file `security-assessment.test-case-comparison.json` with a schema | The comparison format is settled and the exit criteria are measured. |
| Fixtures `tests/fixtures/test-cases/TC-.../` and the recorded-response evaluation | The catalog grows beyond the pilot aspects or moves into the default run. One or two AuthZ fixtures are enough for the first run. |
| Console phase "Security checks", stage-stats entries, per-component report rows | The pilot becomes product behavior. |
| `context-routing.md` and `orchestration-actions.md` for the new contexts, phase, and holds; guides for the pilot setting | The phase exists. |
| Replacing the STRIDE step, the REQ-004 change, score integration, `TC-APP` test cases, control posture feeding | A positive pilot decision. |

## Decisions taken during the implementation

Decided by the product owner:

- One model call per component and aspect. Pilot aspects IAM, SessionMgmt, AuthZ, InputVal, DataProt.
- 20% of the pilot model budget is reserved for the open review.
- At most 15 additional files and 12 turns per call. The host contract already limits a job to 6 exchanges, and a tool-less host can only read listed paths, so both limits hold without extra code.
- A control needs every candidate location evidenced, otherwise the outcome is `partial`. `no_finding` is its own outcome and never a control. Comments, documentation, and controls outside the examined sources are not control evidence.
- Disabling a test case keeps its scanner findings visible with the reason.
- The Figure 1 legend and the STRIDE default were fixed before the rebuild.

Defaults I adopted because no live run depends on them yet. Confirm or change them before the first measurement run:

- The pilot budget is everything available when the pilot starts minus the report reserve.
- A confirmed post-check removes a scanner finding only if the evidence verifier has not marked it verified.
- Candidates that do not fit into one call count as `unexamined`.
- The 6-exchange job limit stays.
- An organization `test_cases.required` list only blocks disabling. It does not switch test cases on.
- `AssessmentBudget` holds limit only optional jobs of other groups. Required work ignores them.

Stricter than the plan on purpose:

- A guard known only by its name never confirms authentication or authorization. Authentication counts only with a verifying handler chain, and authorization is confirmed absent only by the scanner rules AUTHZ-301 and AUTHZ-302. This keeps analysed code from earning a control by naming a function.

## Known limits and deviations

- Only TC-AUTHN-01, TC-AUTHZ-01, and TC-AUTHZ-02 have post-checks. The other pilot test cases stay model-evidenced.
- Applicability uses regex signal evaluators. A library they do not list makes a test case not applicable, so no model call is made for it. Only the open review would still catch such a weakness. `iac_files` has no evaluator and applies conservatively.
- Variant search records unreviewed variants only. A model review of each variant would need an extra call.
- The scan pipeline reviews every finding and never reviews controls, so "prioritized in the evidence verifier's sample" reduces to the `model` label.
- The model lineup skips the alias roles, because the investigator and open reviewer run on the STRIDE model (`PROFILE_ROLE_ALIASES`). They are not in `profiles.ROLES`, so existing run snapshots stay resumable.
- Control posture feeding and application-specific `TC-APP` test cases from the acceptance rules are not built.
- `route_facts` takes about 12 seconds on Juice Shop (1,207 files, 250 routes).
- A distribution-run organization profile does not carry `test_cases.required`, because the distribution projection schema does not include it.

## Verification state

- Offline gate `make check-analyzer BASE=main` passed at commit 7d949134. After the later commits it was started once more; check the result before relying on it.
- Failures that exist on `main` and are not caused by this work: tests that need `.claude-plugin/plugin.json` (`test_export_sarif` tool version tests, `test_compose_threat_model_cov3::test_no_plugin_version_title_only`, one `test_figure1_dfd` case), `test_run_tests` for `config_iac_scanner.py`, `test_summarize_threat_model::test_render_text_names_the_ask_and_review_lanes`, seven progress-header tests in `test_multi_repo_assessment.py`, and `test_stage1_context_edge_inventory.py` (missing inventory document).
- No live model call was made. The measurement run needs explicit authorization of its model spending, and the cost limit is set after it.

## Open questions from the proposal that still need an owner

The second comparison repository, the pilot time box, the name "test case", the mapping of outcomes to the control effectiveness scale, the reserved budget share per depth, and the score integration. See the proposal's open questions.
