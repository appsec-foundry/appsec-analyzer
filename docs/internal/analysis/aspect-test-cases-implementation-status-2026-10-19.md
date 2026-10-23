# Aspect test cases: implementation status

Status: working document for REQ-040, written 2026-10-19. It records what the implementation branch contains, what is still missing, and the decisions made on the way, so that later sessions can continue. The design and its open questions are in the [proposal](aspect-test-cases-proposal-2026-10-19.md). Nothing here is released, pushed, or measured with a live model.

## Where the work is

The implementation lives on the branch `feat/aspect-test-cases`, derived from `main` at 356f0cfc. It is pushed up to 22c65a4c; later commits are local only, and nothing is merged. Create a worktree to continue: `git worktree add <path> feat/aspect-test-cases`. Commit documentation and requirement changes on `main`, and the implementation on this one branch.

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
| 90d27a7d | The object form of `test_cases` selects no aspect unless `aspects` names one, so only a named aspect starts the model pilot. |
| 80064794 | Changes after the first Juice Shop run: guard definitions in the preload, all state-changing routes for TC-AUTHZ-02 and -03, undecidable without an examined location, model-only controls named, catalog version 2. |
| 998b0b13 | Batching: a component and aspect with more than 40 candidates gets several investigator jobs, shared by location, and their replies are combined into one row per test case and component. |
| ec424ef9 | The pilot's console progress follows the provisional name: "Verifying AuthZ 1/7: component (part 1 of 4)", the result line "AuthZ verification: …", and the role label "verification" in status, correction, and warning lines. |
| e824f194, cfa30c2b, 676e68d7, 8f16254f | The commits of `fix/console-and-usage-limit` (3e4f6c9c, c45e1135, 1f42a5cd, 445d2079), applied to this branch: an immediate stop at a rejected usage window, the platform settings Preflight row, elapsed time on resume, and the Codex timeout test that counts a reaped descendant as ended. |
| cf0fbdc2 | Starting points after the second run: routes that finale-rest and epilogue resources generate, only in the pilot's facts; TC-AUTHZ-01 from every route that takes a request body; TC-AUTHZ-02 from authenticated reads without an object identifier. Catalog version 3. |

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
- Decided by the product owner on 2026-10-22: the object form of `test_cases` selects no aspect unless `aspects` names one (90d27a7d). Before, it defaulted to all five pilot aspects, so a profile that set only `disable` would have run the AuthZ investigation and paid for it.
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

### Result of the first run (2026-10-22)

The product owner ran the profile above at 90d27a7d on Juice Shop at 33518f5a0, standard depth, with `--ignore-legacy`, into `/home/mrohr/appsec-reports/juice-authz-pilot`. The run completed with 114 model calls for USD 14.84 and no run issues. The published model passed `validate_threat_model_output`, the four pilot findings appeared only in `test_case_findings`, and the report showed the section Test Case Findings (Pilot) and the per-component appendix rows.

Cost: the four investigator jobs took 8 calls and USD 1.58, between USD 0.11 and 0.65 per job and USD 0.40 on average. The STRIDE step took 27 jobs and USD 7.29, the evidence verifier 19 jobs and USD 2.45. Three of the four jobs needed one correction: two discovery escapes left unlisted, and a finding anchored in another component's file.

Outcomes: 45 component rows, of them 3 finding, 5 no finding, 1 undecidable, 36 not applicable, and no control. Every control claim a post-check could test was contradicted: two by the ownership check, one by an AUTHZ-301/302 scanner hit. Fourteen further control claims of TC-AUTHZ-01 lay outside routes, had no post-check, and the reason still read "control evidenced at 14". Seven of eight weakness claims at routes were confirmed by a post-check, so TC-AUTHZ-02 was deterministic. TC-AUTHZ-01 on the Express server reached the cap of 40 and left 9 candidates unexamined.

Comparison with the STRIDE step and the scanners of the same run:

| | Weakness |
| --- | --- |
| Both | Basket IDOR (TCF-001), unauthenticated metrics endpoint (TCF-002), application configuration without a role check (TCF-003) |
| Pilot only | Address update IDOR (TCF-004): `PUT /api/Addresss/:id` runs only `appendUserId()` and falls through to the generic finale REST handler, which updates any address by ID. Confirmed by reading the code. |
| STRIDE only | Product update without authorization (T-037), user list for any authenticated user (T-073), forged review author (T-040), client-side-only role checks (T-083) |
| Neither | Admin registration through mass assignment of `role` in `POST /api/Users` |

Causes found in the replies and the inventory:

- The preload carried no middleware definitions, so six `denyAll()` routes stayed undecidable with "implementation was not served".
- TC-AUTHZ-02 took only routes the inventory marks as suspects, and TC-AUTHZ-03 only scanner hits, which were none. `POST /api/Users` was rejected under TC-AUTHZ-02 as public registration, and no test case examined its body.
- `PUT /api/Products/:id` has no registration in `server.ts`; line 370 is commented out, and the finale REST generator creates the route from the data model. The route inventory does not list generated routes, so no test case received it as a candidate, and the model added none.
- TC-AUTHZ-03 without candidates recorded no finding, although nothing was examined and the model proposed undecidable.
- TC-AUTHZ-05 on the frontend stays undecidable, because the missing server check lies in another component.

Assessment: the mechanics hold and the control rule works as intended. The pilot found one true weakness that the STRIDE step missed, but missed four that it found. The causes are specific and fixable, not a failure of the approach.

### Changes after the first run

Decided by the product owner on 2026-10-22 and built in 80064794:

- The preload carries the definitions of the middlewares and guards the candidates' routes run, before the candidates, as for STRIDE.
- TC-AUTHZ-02 also starts from every state-changing route and TC-AUTHZ-03 from every route that accepts a body, whatever their guards (`route_inventory.state_changing`, `route_inventory.accepts_body`). The guidance of TC-AUTHZ-01 to -03 names routes that frameworks generate from data models. Catalog version 2.
- A test case without any examined location records undecidable instead of no finding.
- A reason names the controls that only model review supports. The appendix lists the components a test case does not apply to in one row.

An offline count with the components of this run gives the same four jobs. The Express server then has 31, 40, and 40 candidates, with 15 and 9 over the cap for TC-AUTHZ-02 and -03; `POST /api/Users` is a TC-AUTHZ-03 candidate. Generated routes still reach a job only when the model adds them, and the cap still leaves candidates unexamined, so batching and an inventory of generated REST routes are the next measures.

### Batching

Decided by the product owner on 2026-10-22 and built in 998b0b13:

- A component and aspect whose candidates exceed 40 (`case_candidates.MAX_CANDIDATES`) gets several investigator jobs. All candidates of one location go to the same job, so a route is read once for every test case that names it. A job takes whole locations up to 40 candidates; no candidate counts as unexamined any more.
- Only the first job adds model candidates. It answers every test case of the aspect and receives the locations of the other jobs as context data (`candidate_jobs.answered_elsewhere`); the controller rejects a model candidate in a later job or at such a location for correction. The first run supports this: the model added no candidate in the Express job (0 of 70 answers) and one in the whole run.
- `case_analysis.combine_investigations` combines the accepted replies before `case_outcomes.investigation_results`: test cases keep one entry, finding IDs become `part-<n>-<hash>` as in the STRIDE step, and the proposed outcome combines the jobs' proposals. Each test case still records one row per component.
- A failed or unaffordable job makes only its candidates undecidable, with the fixed replacement reason; the answers of the other jobs stand. A test case that no accepted job answered records the replacement result as before.
- Selectors stay `test-cases:{component}:{aspect}` for one job and gain `:{n}/{m}` for several, as the STRIDE and evidence jobs do, so resumed runs replay accepted jobs. STRIDE requests are unchanged.
- There is no limit on jobs per component beside the hard budget; jobs the budget does not reach make their candidates undecidable.
- Pooling the test cases of all investigated aspects into shared jobs per component, proposed to read code only once across aspects, waits until a second aspect is investigated. It changes the reply contract's `aspect` field and the decision "one model call per component and aspect".
- Prompt caching across jobs was considered and left out: in the first run the investigator calls wrote 518k input tokens to the cache and read 58k, and a shared prefix would need a packet format that the STRIDE step shares.

Data behind the choice: the Express server's 135 candidates lie on 65 locations, 55 of them named by more than one test case. Split test case by test case, four jobs would need 7,560 lines of preload with 31 to 37 windows each, at the limit of 36. Split by location, the same four jobs need 5,128 lines with 16 to 25 windows. Two jobs of 40 locations would need 3,840 lines, but the first would carry 85 answers and 32 windows.

### Second run on Juice Shop

Prepared on 2026-10-22 for 998b0b13 and run the same evening; the result follows below. The product owner starts it with `bash /tmp/authz-pilot/run.sh`, which runs the branch worktree with the profile above on Juice Shop at 33518f5a0 into `/home/mrohr/appsec-reports/juice-authz-pilot-2`. A new run replaces a completed run in its directory and reuses none of its jobs, so the second run uses its own directory and the first run's results stay in `juice-authz-pilot` for comparison.

An offline count with the first run's components gives seven investigator jobs: four for the Juice Shop Express Server with 40, 39, 40, and 16 candidates, one for Authentication & Session Surface with 17, one for Web3 / Wallet / NFT Surface with 6, and one for the Angular frontend, where only TC-AUTHZ-05 applies, without candidates. `POST /api/Users` is a TC-AUTHZ-02 and TC-AUTHZ-03 candidate in the third Express job. `PUT /api/Products/:id` is still no candidate.

Expected cost: in the first run, a call with no or one candidate cost USD 0.11 to 0.18, and the Express call with 70 answers cost USD 0.43 after a read exchange of USD 0.23. With a correction or read exchange in about every other job, the seven jobs should cost USD 1.70 to 3.40 instead of USD 1.58, and the whole run about USD 14.50 to 17.50 instead of USD 14.84. The STRIDE requests are unchanged, so the rest of the run should cost as before. The budget of USD 25 leaves room.

Measures against the first run:

| Question | Expected result |
| --- | --- |
| Admin registration through `role` in `POST /api/Users` | TC-AUTHZ-03 on the Express server records a weakness there with a finding. |
| The six `denyAll()` routes | None stays undecidable for unserved source; each is answered with the guard's definition cited. |
| Generated product route `PUT /api/Products/:id` | Probably still missed: it reaches a job only if the first Express job adds it, and the first run added no candidate there. A miss confirms the inventory of generated routes as the next step. |
| Unexamined candidates | No component row counts any. |
| Cost per job | Calls, USD, and corrections per investigator job, from the receipts in `.assessment-work/jobs` and the result events in `.assessment-work/host-events`, against the first run's USD 0.11 to 0.65. |
| First run's pilot findings | Basket IDOR, metrics endpoint, configuration without role check, and address update IDOR are found again. |

### Result of the second run (2026-10-22)

The product owner ran the profile at 998b0b13 on Juice Shop at 33518f5a0 into `/home/mrohr/appsec-reports/juice-authz-pilot-2`. At 20:25 the Claude subscription's five-hour usage window was exhausted during the fourth Express job; the host waited 15 and 60 seconds before the run stopped, and `--resume` after the reset at 21:10 replayed every accepted job without a model call. The run completed with 124 calls. The receipts add up to USD 16.36 against USD 14.84 in the first run; the run's own counter showed USD 20.56, because calls cancelled at the limit are charged their reservation. Fixes for the stop at the usage limit, the platform settings console line, and the elapsed time on resume are on the branch `fix/console-and-usage-limit` (3e4f6c9c, c45e1135, 1f42a5cd), derived from `main` at bfabee2e and not merged.

| Question | Result |
| --- | --- |
| Admin registration through `role` in `POST /api/Users` | Found: TC-AUTHZ-03 records a weakness there, TCF-009 "User registration accepts a client-supplied role (verify.ts:53)". The STRIDE step found it this time as well (T-036). |
| `denyAll()` routes | None undecidable: 19 candidates answered as control and 4 rejected, against 6 undecidable in the first run. |
| Generated product route `PUT /api/Products/:id` | Missed again; only the STRIDE step reports it (T-034). The model added no candidate except one on the frontend. |
| Unexamined candidates | None, against 9 in the first run. |
| Cost per job | Seven jobs, 13 calls, and USD 3.05, against four jobs, 8 calls, and USD 1.58. The Express jobs cost USD 0.34 to 0.59 each. The frontend and Authentication & Session jobs again needed one correction each, for the same reasons as in the first run. |
| First run's pilot findings | Three of four again: basket, metrics endpoint, and address update. The configuration without role check is missing. |

On the Express server all three seeded test cases record a finding: TC-AUTHZ-01 at 8 of 35 candidate locations, TC-AUTHZ-02 at 5 of 33, and TC-AUTHZ-03 at 4 of 24. Their controls, at 20, 10, and 7 locations, rest on model review only. The pilot reports 12 findings.

Comparison with the documented Juice Shop challenges that concern authorization (`data/static/challenges.yml`), both from this run:

| Challenge | Pilot | STRIDE step |
| --- | --- | --- |
| Admin Registration | TCF-009 | T-036 |
| View Basket | TCF-002 | T-003, T-004 |
| Exposed Metrics | TCF-008 | T-032, T-061 |
| Access Log | TCF-007 | T-027, T-028 |
| Forged Review | Partly: the author taken from the request body (TCF-006) | T-038, and editing any review as an instance of T-003 |
| Forged Feedback | TCF-010 | Missed |
| Manipulate Basket | TCF-003, `BasketId` from the client | Missed |
| Product Tampering | Missed | T-034 |
| GDPR Data Theft | Missed | T-063 |

Each finds seven of these challenges, together nine. Outside the list, only the STRIDE step reports the user list for any authenticated user (T-078), and only the pilot reports recycle-item and order-tracking IDOR; the latter may be intended, since the tracking ID is meant to be shared. The STRIDE step counts the payment card routes (`routes/payment.ts`) as instances of the IDOR finding T-001; the pilot answered them as controls, and the code scopes the query by the `UserId` that `appendUserId` sets from the token.

Causes of the pilot's misses:

- Product Tampering: the route is generated from the data model and has no inventory entry.
- Editing any review: `PATCH /rest/products/reviews` takes the object ID in the body, so TC-AUTHZ-01 did not select it, and TC-AUTHZ-03 answered it as a control because the update writes only `message`.
- User list: `GET /rest/user/authentication-details` has no path parameter and changes no state, so no test case selected it.
- GDPR Data Theft: business logic, which belongs to the open review.

Assessment by the implementing session, not yet a decision: for authorization the pilot matches the STRIDE step in hits on the reference list, with different misses, and is more traceable, with a verdict per route and counted coverage, and in the payment case more precise. Exit criterion 1 is not met, but the causes are specific. Combined, the two find nine of the challenges. The cost is the main risk: authorization alone costs about 40% of the STRIDE step, which covers all aspects, so five pilot aspects investigated separately would add about USD 10 to 15 per run. Recommended next: keep the STRIDE step, add the inventory of generated routes, let TC-AUTHZ-01 start from routes that take an object ID in the body, build the open review, and measure with a third run, since the first two runs already differ noticeably.

### Changes after the second run

Decided by the product owner on 2026-10-22 and built in cf0fbdc2:

- Routes that finale-rest and epilogue resources generate from data models become candidates, but only in the pilot's facts (`case_candidates.route_facts`). The route inventory, the STRIDE requests, the report, and the other commands stay unchanged, so the next run measures only the pilot. Adding them to the shared inventory was rejected for now: it would change default runs, `score`, `authnz-review`, and the STRIDE input, and the next run would mix two changes.
- A generated route anchors at its generator call and gets an ID after the inventory's highest. Its chain holds the call and the registrations of the same file that run for its path, such as an `app.use` mount or an `app.route` chain. An inventory row with the same file, method, and path keeps its anchor and gains the call in its chain. The context marks generated routes, and the routes of one call are one candidate each.
- Post-checks confirm a generated route's registration with their own reason and leave its guards and ownership not verifiable, because its handler is library code.
- TC-AUTHZ-01 also starts from every route that takes a request body, because the body can carry the object identifier, as in `PATCH /rest/products/reviews`. Chosen over a pattern for identifiers that the handler reads, which recognizes only Express code; both give nine jobs on Juice Shop.
- TC-AUTHZ-02 also starts from authenticated reads without an object identifier (`route_inventory.authenticated_read_without_id`), such as `GET /rest/user/authentication-details`. Chosen over unfiltered collection queries, which depend on ORM method names, and over every read without an identifier, which gives 43 candidates on Juice Shop.
- Detection of generated routes has fixed bounds on files, calls, loops, and spans, and accepts only plain absolute paths, because the parsed code is repository content.

The branch `fix/console-and-usage-limit` was merged into `main` (a9390915), and its commits were applied to this branch, so the next run stops at once at a rejected usage window.

An offline count with the second run's components gives nine investigator jobs instead of seven. The Express server gets six jobs with 39, 38, 39, 36, 59, and 24 candidates, 235 against 134; the 59 lie at the generator call, which as one location stays in one job. Authentication & Session Surface gets one job with 26 candidates, Web3 / Wallet / NFT Surface one with 9, and the Angular frontend one without candidates. 37 generated routes reach the Express server, among them `PUT /api/Products/:id` for TC-AUTHZ-01 to -03. `PATCH /rest/products/reviews` is a TC-AUTHZ-01 candidate, and `GET /rest/user/authentication-details` a TC-AUTHZ-02 candidate on Authentication & Session Surface. The pilot should cost about USD 3.80 to 4.50 instead of USD 3.05.

### Next run: AuthZ, InputVal, and DataProt together

Decided by the product owner on 2026-10-22: the third run waits until InputVal and DataProt have starting points of their own, and then tests AuthZ, InputVal, and DataProt in one run. DataProt is taken as a whole, with responses (TC-DATA-01), data at rest (TC-DATA-02), secrets (TC-DATA-03), and transport (TC-DATA-04), rather than only the output side; the last three need starting points from configuration and secret detection. A run costs about USD 16 to 18, of which the pilot is USD 3 to 4, so every run saved saves about USD 13. A resumed run cannot reuse an earlier run's STRIDE jobs, because a runtime change rejects `--resume`.

An offline count for the other pilot aspects with the second run's components and scanner findings shows why InputVal needs starting points first:

| Aspect | Jobs | Candidates |
| --- | --- | --- |
| InputVal | 6 | 5 on the Express server for 7 test cases, 1 on Authentication & Session Surface, none elsewhere; TC-INPUT-04 (output encoding) on the frontend has none |
| IAM | 8 | 139 on the Express server, because TC-AUTHN-01 starts from every route |
| SessionMgmt | 3 | none |
| DataProt | 9 | none |

InputVal and DataProt test cases start only from scanner hits, and the second run had six injection hits and none of the DataProt starting rules. The model added one candidate in each of the first two runs, so a test case without candidates would mostly record undecidable. The STRIDE step of the second run reported 5 cross-site scripting, 5 hard-coded credential, 2 SQL injection, 2 NoSQL injection, and 2 path traversal findings.

`bash /tmp/authz-pilot/run.sh` already writes into `/home/mrohr/appsec-reports/juice-authz-pilot-3`; the profile there still selects only `AuthZ`.

## After the first run: decide with real results

| Item | Becomes necessary when |
| --- | --- |
| Open review role with the 20% reserve (`AssessmentBudget.hold` and `release` exist) | Shown by the second run: GDPR Data Theft and other business logic reach no test case. |
| Shared jobs for the test cases of all investigated aspects of a component | A second aspect is investigated, planned with InputVal. Batching by location exists since 998b0b13. |
| Starting points for InputVal and DataProt beyond scanner hits, such as query, command, file, outbound request, and HTML output sinks, response serialization, stored sensitive fields, secrets, and transport settings | Shown by the offline count of 2026-10-22: InputVal has five candidates on the Express server and none for output encoding, DataProt none. Needed before the next run. |
| Route inventory entries for routes that frameworks generate from data models, such as finale REST resources | Shown by both runs. Built for the pilot's facts in cf0fbdc2; the shared inventory follows only when the pilot is continued. |
| TC-AUTHZ-01 candidates for routes that take an object ID in the body, and a starting point for sensitive listings without a path parameter | Shown by the second run. Built in cf0fbdc2. |
| Merge into `merge_assessment` (`pilot_documents`), union of `test_case_ids`, mapping of reply-local finding IDs | The pilot finds weaknesses STRIDE misses and is continued. |
| Removal rule: a confirmed post-check removes a scanner finding unless the evidence verifier marked it verified, otherwise the finding records `test_case_disagreement` | The merge exists. |
| Comparison file `security-assessment.test-case-comparison.json` with a schema | The comparison format is settled and the exit criteria are measured. |
| Fixtures `tests/fixtures/test-cases/TC-.../` and the recorded-response evaluation | The catalog grows beyond the pilot aspects or moves into the default run. One or two AuthZ fixtures are enough for the first run. |
| Console phase "Security checks", stage-stats entries, per-component report rows | The pilot becomes product behavior. |
| `context-routing.md` and `orchestration-actions.md` for the new contexts, phase, and holds; the guides already describe the setting | Before the branch is merged; the phase exists since 5e3f39bb. |
| Replacing the STRIDE step, the REQ-004 change, score integration, `TC-APP` test cases, control posture feeding | A positive pilot decision. |

## Decisions taken during the implementation

Decided by the product owner:

- One model call per component and aspect, and on 2026-10-22 several calls sharing the candidates by location when they exceed 40. Pilot aspects IAM, SessionMgmt, AuthZ, InputVal, DataProt.
- 20% of the pilot model budget is reserved for the open review.
- At most 15 additional files and 12 turns per call. The host contract already limits a job to 6 exchanges, and a tool-less host can only read listed paths, so both limits hold without extra code.
- A control needs every candidate location evidenced, otherwise the outcome is `partial`. `no_finding` is its own outcome and never a control. Comments, documentation, and controls outside the examined sources are not control evidence.
- Disabling a test case keeps its scanner findings visible with the reason.
- The Figure 1 legend and the STRIDE default were fixed before the rebuild.

Defaults I adopted because no live run depends on them yet. Confirm or change them before the first measurement run:

- The pilot budget is everything available when the pilot starts minus the report reserve.
- A confirmed post-check removes a scanner finding only if the evidence verifier has not marked it verified.
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
- `route_facts` takes about 12 seconds on Juice Shop (1,207 files, 250 routes), and 15 to 20 seconds with generated routes.
- Generated routes come only from finale-rest and epilogue, with literal endpoints or endpoints built in a `for (const {...} of list)` loop over an array literal of the same file. Other generators, such as Rails `resources`, Django REST Framework routers, or Spring Data REST, reach a job only when the model adds them. finale-rest is not installed in the Juice Shop checkout, so the routes per call follow the library's documented actions, with PUT for update unless `updateMethod` names another method, and were not compared with its code.
- The shared comment blanking (`shared/_source_lex.without_comments`) loses track after a regex literal that contains quotes. In Juice Shop's `server.ts` that happens at line 249, so later comments stay in the code that applicability signals and handler checks read. Generated routes skip registrations after `//` on the same line; the shared lexer is unchanged.
- A distribution-run organization profile does not carry `test_cases.required`, because the distribution projection schema does not include it.

## Verification state

- Offline gate `make check-analyzer BASE=main` passed at commit 7d949134. At 5e3f39bb, 90d27a7d, and 80064794, `make check-analyzer BASE=356f0cfc` passed: the specs check, Ruff, 954 and 168 tests. At 80064794, `make test-controller` passed as well (8 tests). At 998b0b13, `make check-analyzer BASE=356f0cfc` passed with 954 and 168 tests, and the tests of the changed modules passed with the pilot tests of `tests/test_controller_fixture.py`, including the new tests for shared jobs, a failed job, and a resumed run with shared jobs (156 tests). The three controller fixture tests that never start the pilot were not rerun. The base is the merge base, because `main` has moved on and a comparison with it would count its newer commits as changes of the branch.
- At ec424ef9, `make check-analyzer BASE=356f0cfc` passed the specs check, Ruff, and 168 tests; of 954 analyzer tests one failed, the Codex timeout test, whose race 8f16254f removes, and it passed three times alone. At cf0fbdc2, the gate passed with 954 and 168 tests, `make test-controller` with 12 tests, and the tests of the changed modules passed. The seven failing progress-header and budget tests of `test_multi_repo_assessment.py` fail at ec424ef9 as well, before the applied fixes.
- At 5e3f39bb, `make test-controller` passed with the new pilot tests (8 tests), as did the test case, compose, schema, and direct `_assessment_stride` controller tests. `tests/test_report_anatomy.py` fails because `specs/changes/report-anatomy/report-anatomy.md` exists in no commit; this is not caused by the branch.
- Failures that exist on `main` and are not caused by this work: tests that need `.claude-plugin/plugin.json` (`test_export_sarif` tool version tests, `test_compose_threat_model_cov3::test_no_plugin_version_title_only`, one `test_figure1_dfd` case), `test_run_tests` for `config_iac_scanner.py`, `test_summarize_threat_model::test_render_text_names_the_ask_and_review_lanes`, seven progress-header tests in `test_multi_repo_assessment.py`, and `test_stage1_context_edge_inventory.py` (missing inventory document).
- No live model call was made. The measurement run needs explicit authorization of its model spending, and the cost limit is set after it.

## Open questions from the proposal that still need an owner

The second comparison repository, the pilot time box, the mapping of outcomes to the control effectiveness scale, the reserved budget share per depth, and the score integration. See the proposal's open questions.

The name "test case" has a provisional answer. On 2026-10-22 the product owner chose, for now, "STRIDE-based" and "verification-based" for the two analysis methods, and "verification catalog" with "verification items" for the catalog and its entries, with IDs such as `VI-AUTHZ-01`. "Test case", "security check", and "control objective" were rejected: the first collides with software tests, the second with scanner checks, and the third describes implementation rather than verification. Results must keep saying "verified by model review only" where no post-check confirms a control. The REQ-040 wording and the rename wait until the pilot is continued, at the latest until the branch is merged.
