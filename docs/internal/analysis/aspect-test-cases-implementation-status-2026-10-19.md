# Aspect test cases: implementation status

Status: working document for REQ-040, written 2026-10-19. It records what the implementation branch contains, what is still missing, and the decisions made on the way, so that later sessions can continue. The design and its open questions are in the [proposal](aspect-test-cases-proposal-2026-10-19.md). Nothing here is released, pushed, or measured with a live model.

## Where the work is

The implementation lives on the branch `feat/aspect-test-cases`, derived from `main` at 356f0cfc. It is pushed up to 22c65a4c; 5e3f39bb is local only, and nothing is merged. Create a worktree to continue: `git worktree add <path> feat/aspect-test-cases`. Commit documentation and requirement changes on `main`, and the implementation on this one branch.

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
| 5e3f39bb | First visible run: controller phase for AuthZ (`assessment_test_cases.py`), component rows in `test_case_results`, `test_case_findings` in the model and the report section Test Case Findings (Pilot), per-component appendix rows, guides. |

## What works today

- With `test_cases: true` in a scan profile, a run links scanner findings to test cases, records an outcome for each of the nine rules test cases, and shows them in the YAML, the report appendix, the completion summary, and SARIF. This makes no additional model calls.
- With `test_cases: {aspects: [AuthZ]}`, the run also investigates the AuthZ test cases per component with the model, records one row per test case and component, and lists the investigation's findings apart from the threats. This is tested offline with a fake host only.
- Without the setting, output is unchanged.

## First visible run

Built in 5e3f39bb and tested offline. No live run has been made.

1. **Controller phase.** `scripts/orchestrator/assessment_test_cases.py` with `run_pilot(...)` runs inside `_assessment_stride` after the result line of the threat analysis and before `merge_assessment`, only when the profile's `test_cases` is an object with aspects. It investigates only `AuthZ` (`INVESTIGATED_ASPECTS`); other selected pilot aspects give a run warning. Per repository it reads `case_candidates.route_facts` once, from the scanner snapshot, the architecture's route inventory, and the scanner findings. Per component and aspect it records `disabled` and `not_applicable` rows without a model and sends one optional `test_case_investigator` job for the applicable test cases through `_assessment_components_concurrently`. The job reuses the STRIDE job's context envelope without `lens_ids` and adds `aspect` and `test_case_candidates`. Its preload follows the STRIDE pattern: the lines the context cites, then the candidates' anchors and resolved handler chains, then the direct helpers. `case_analysis.validate_investigation` and `investigation_normalizer` check and normalize the reply, and `case_outcomes.investigation_results` turns it into rows. A job replaced after a model failure or for budget gives `replacement_result` rows; the existing gap handling adds a warning for a failure and the budget-skip note for a budget skip. The STRIDE requests are only recorded for the pilot, and a test checks that they stay byte-identical.
2. **Sidecar and rows.** `_assessment_workspace` writes `.test-case-pilot.json` and `.dispatch-context/{component_id}/test-case-candidates.json` into the render workspace. `case_outcomes.build_block` appends the pilot rows after the unchanged rules rows. The appendix shows one row per component for model-investigated test cases, and the labels now read "Partial, not a control" and "No finding, no control".
3. **Pilot findings.** Each kept finding gets a run-wide `TCF-NNN` ID and appears in `test_case_findings`, declared in the v1 output schema and referenced from v2, never in `threats`. The rows' `finding_ids` name these IDs. The report section Test Case Findings (Pilot) appears only when the list is not empty and states that the findings are not yet merged with the findings register.

Decisions and limits of this step:

- Only `AuthZ` is investigated, as agreed for the first run.
- The object form of `test_cases` defaults `aspects` to all five pilot aspects (profile normalizer of 17f98015). Since 5e3f39bb, a profile that sets only `disable` therefore runs the AuthZ investigation and pays for it. Decide whether the object form should default to no aspects.
- A component that spans several repositories gets `undecidable` rows without a job, because candidate and route IDs are per repository.
- A reply that requests a source outside the admitted scope or breaks the exchange contract still stops the run, as for every optional job. Model failures, timeouts, settled host failures, and budget skips become `undecidable`.
- The evidence verifier does not review pilot findings. Each rests on the investigator's validated citations and its candidate's post-checks; the evidence basis is recorded per row, not per finding.
- The guides `docs/security-assessment.md` and `docs/profiles.md` on the branch describe the pilot and its cost. `context-routing.md` and `orchestration-actions.md` do not mention the phase yet.

### Running it on Juice Shop

The run causes model cost and needs explicit authorization of its spending first. Install Analyzer from the branch; the branch still names the command `scan`, because the rename to `assess` on `main` is not merged into it.

Scan profile `~/.config/appsec-analyzer/profiles/authz-pilot.yaml`:

```yaml
schema_version: 1
description: REQ-040 AuthZ pilot
model_profile: claude
assessment_depth: standard
budget: 25
max_parallel: 2
outputs: [markdown, yaml]
test_cases:
  aspects: [AuthZ]
```

```sh
appsec-analyzer scan --repo /home/mrohr/juice-shop --profile authz-pilot --output /home/mrohr/appsec-reports/juice-authz-pilot
```

The output directory must exist and lie outside the checkout.

An offline count with the components of the 2026-10-18 run gives four investigator jobs: Juice Shop Express Server with 32 TC-AUTHZ-01 and 12 TC-AUTHZ-02 candidates and none over the cap, Authentication & Session Surface with one candidate, and the Web3 surface and the Angular frontend without candidates. In the standard runs of 2026-10-16 and 2026-10-18, which cost USD 14.08 and 15.71 in total, a STRIDE job cost USD 0.26 to 0.31 on average with about 1.1 calls. If an investigator job costs one to two STRIDE jobs, the pilot adds about USD 1 to 3, and the run costs about USD 16 to 19. A budget of USD 25 leaves the pilot's optional jobs room; with less, they are skipped as undecidable before they could take the report reserve.

For the first look, compare the component rows and `test_case_findings` by hand with the STRIDE threats of the same report that carry CWE-639, CWE-285, CWE-862, or CWE-915.

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
| `context-routing.md` and `orchestration-actions.md` for the new contexts, phase, and holds; the guides already describe the setting | Before the branch is merged; the phase exists since 5e3f39bb. |
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

- Offline gate `make check-analyzer BASE=main` passed at commit 7d949134. At 5e3f39bb, `make check-analyzer BASE=356f0cfc` passed: the specs check, Ruff, 954 and 168 tests. The base is the merge base, because `main` has moved on and a comparison with it would count its newer commits as changes of the branch.
- At 5e3f39bb, `make test-controller` passed with the new pilot tests (8 tests), as did the test case, compose, schema, and direct `_assessment_stride` controller tests. `tests/test_report_anatomy.py` fails because `specs/changes/report-anatomy/report-anatomy.md` exists in no commit; this is not caused by the branch.
- Failures that exist on `main` and are not caused by this work: tests that need `.claude-plugin/plugin.json` (`test_export_sarif` tool version tests, `test_compose_threat_model_cov3::test_no_plugin_version_title_only`, one `test_figure1_dfd` case), `test_run_tests` for `config_iac_scanner.py`, `test_summarize_threat_model::test_render_text_names_the_ask_and_review_lanes`, seven progress-header tests in `test_multi_repo_assessment.py`, and `test_stage1_context_edge_inventory.py` (missing inventory document).
- No live model call was made. The measurement run needs explicit authorization of its model spending, and the cost limit is set after it.

## Open questions from the proposal that still need an owner

The second comparison repository, the pilot time box, the name "test case", the mapping of outcomes to the control effectiveness scale, the reserved budget share per depth, and the score integration. See the proposal's open questions.
