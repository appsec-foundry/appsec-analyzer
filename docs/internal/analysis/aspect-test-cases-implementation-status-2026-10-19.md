# Aspect test cases: implementation status

Status: working document for REQ-040, written 2026-10-19. It records what the implementation branch contains, what is still missing, and the decisions made on the way, so that later sessions can continue. The design and its open questions are in the [proposal](aspect-test-cases-proposal-2026-10-19.md). Nothing here is released, pushed, or measured with a live model.

## Target picture

Set by the product owner on 2026-10-22 and 2026-10-23 for the verification-based method; later sessions build toward it.

1. A clear catalog per aspect with two kinds of test cases: concrete ones, such as SQL injection, object ownership, or cross-site scripting, and one goal test case per aspect that asks for an attacker goal, such as changing data beyond one's rights, by any path.
2. Every test case names fixed scripts: when it applies, where it starts, and which post-checks test the model's claims. Fixtures with and without the weakness test each test case.
3. The model only judges. One job per component and aspect answers all of the aspect's test cases; the model may reject candidates with evidence and add its own.
4. It is efficient. A job runs only where a test case has a candidate or a goal test case applies, because each job costs its full context. The scripts before and after the model cost no tokens. Weaknesses the model finds at lines no pattern knows become new patterns, so the deterministic share grows.
5. Each aspect stays assignable to the verification-based or the STRIDE-based method on its own, so an aspect where the STRIDE step proves better can go back to it.

Starting points follow what made AuthZ work: the complete list of entry points and the code they run, not patterns of known weaknesses. A candidate is a route together with the code site its handler reaches; a site that no route reaches is a candidate of its own.

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
| b100c018 | InputVal, DataProt, and AI investigated: code sites in `data/code-sites.yaml`, routes with the sinks their handlers reach as candidates, the post-check `site-reached`, goal test cases, jobs only with a candidate or a goal. Catalog version 4. |
| 612811f1 | Changes after the third run: the reply contract admits `AI`, absent-at-sink controls located at the sink, every independent violation in one rejection, `starting_files` in the context, findings in shared files of no component, dropped findings instead of a replaced job, and no finding for an examined goal test case. |

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

### Changes for the third run

Decided by the product owner on 2026-10-23 and built in b100c018:

- InputVal, DataProt, and AI are investigated. AI joins the pilot aspects, which changes the decision of 2026-10-19; Juice Shop calls a language model in `routes/chat.ts` and documents four challenges about it. A scan profile accepts `AI` among its aspects.
- Code sites are defined in `data/code-sites.yaml` with lines each pattern must and must not mark, which a test checks, so that a starting point can be read without Python. A kind takes its pattern from the file, from an applicability signal, or from `analyzers/egress_clients.py` for outbound calls to a destination the request chooses. The kinds are `raw_query`, `nosql_query`, `command`, `html_output`, `parser`, `file_path`, `upload`, `transport`, `sensitive_field` (only in data model definitions), `outbound_request`, and `llm_call`.
- A test case names a kind as `code_sites.<kind>`. A route whose resolved handler reaches a site of that kind is the candidate and lists the sites as `sinks`, which the preload serves; a site that no route of the component reaches is a candidate of its own. TC-DATA-01 starts from read routes whose handlers read stored data (`route_inventory.reads_data`).
- Goal test cases TC-AUTHZ-06, TC-INPUT-07, TC-DATA-05, and TC-AI-05 are marked `goal: true`, have no starting points, and ride along in the first job of their aspect. Two alternatives were rejected: one broad injection question in place of the concrete SQL, NoSQL, and command test cases, because the product owner wants the concrete questions plus room beyond them; and goals the model derives for the application, which stay with the application-specific test cases of the proposal.
- Goal test cases name no CWE, so that none narrows the search; their findings name their own CWE as before. The concrete test cases keep theirs.
- The post-check `site-reached` confirms that the route's handler or the cited line holds a site of the kind the test case names. It confirms only the mechanism of a weakness, never contradicts, never decides a control, and runs also for candidates without a route. Its result "no fixed pattern marks the cited line" lists the weaknesses the patterns miss, the input for new patterns. TC-AUTHZ-06 runs the existing AuthZ checks, TC-DATA-01 and TC-DATA-05 `route-registered`.
- Jobs stay separate per aspect, rather than one job per component for all aspects, so that cost and results stay attributable per aspect, each aspect stays switchable, and AuthZ stays comparable with the second run. A job runs only when one of its test cases has a candidate or a goal test case applies; otherwise the aspect's test cases record undecidable with a fixed reason. A last job under a quarter of the candidate limit joins the job before it.
- The NoSQL pattern takes only queries on a collection and `$where`; half of the broader pattern's hits on Juice Shop were Sequelize calls.
- TC-DATA-03 has no starting points until the separate, Gitleaks-based `scan-secrets` command of REQ-042 exists, and the run profile disables it with that reason.
- Catalog version 4 with 49 test cases.

Token data from the second run: an investigator call read 55,000 to 99,000 input tokens, 73,000 on average, and wrote 300 to 12,000. Most of the input is the job's fixed context, so the number of jobs drives the cost more than the number of test cases or candidates.

An offline count with the second run's components gives 18 investigator jobs:

| Aspect | Jobs | Candidates |
| --- | --- | --- |
| AuthZ | 8 | as before; the frontend job without candidates no longer runs |
| InputVal | 5 | Express server 39 and 19, 41 of them routes with sinks; Angular frontend 30, among them 25 HTML sinks; Authentication & Session Surface 3; Web3 only the goal test case |
| DataProt | 4 | Express server 41; Sequelize data models 6 sensitive fields; Web3 only the goal test case; Authentication & Session Surface 2 |
| AI | 1 | Express server 4: `POST /rest/chat` reaching `streamText` and tool definitions |

Nine component and aspect pairs without a candidate run no job. Expected cost: the pilot about USD 7 to 10 against USD 3.05, the run about USD 20 to 23.50 by receipts. The product owner raised the profile's budget to USD 30, so that the pilot, which runs after the STRIDE step, keeps room.

### Third run on Juice Shop

Prepared on 2026-10-23 for b100c018. The product owner starts it with `bash /tmp/authz-pilot/run.sh`, which writes into `/home/mrohr/appsec-reports/juice-authz-pilot-3`. Its profile selects AuthZ, InputVal, DataProt, and AI, sets a budget of USD 30, and disables TC-DATA-03 with the reason above.

| Question | Expected result |
| --- | --- |
| Product Tampering, `PUT /api/Products/:id` | TC-AUTHZ-02 records a weakness at the generated route. |
| Editing any review, `PATCH /rest/products/reviews` | TC-AUTHZ-01 records a weakness there. |
| User list, `GET /rest/user/authentication-details` | TC-AUTHZ-02 on Authentication & Session Surface records a weakness. |
| Hits of the second run | The seven authorization challenges are found again. |
| Injection and parsing | Compared with the STRIDE step on the documented challenges of the categories Injection (14, three about the chatbot), XSS (9), XXE (2), and Insecure Deserialization (3) that a code review can find, such as Login Admin and Database Schema at `routes/login.ts` and `routes/search.ts`, the NoSQL challenges, SSTi, and the RCE challenges at `routes/b2bOrder.ts`. |
| Data protection | Compared on the Sensitive Data Exposure challenges that a code review can find, such as Password Hash Leak. |
| AI | Chatbot Prompt Injection, Greedy Chatbot Manipulation, System Prompt Extraction, and AI Debugging. |
| Goal test cases | How many findings they add that no concrete test case of their aspect records. |
| Pattern gaps | Weaknesses whose `site-reached` result says no fixed pattern marks them. |
| Cost per aspect | Jobs, calls, USD, and corrections per aspect against the estimate. |

### Result of the third run (2026-10-23)

The product owner ran the profile at b100c018 on Juice Shop at 33518f5a0 into `/home/mrohr/appsec-reports/juice-authz-pilot-3`. The run completed in 56 minutes with 141 calls for USD 22.23 and two run issues: the Express server's InputVal job 1/2 and its AI job were replaced after three rejected answers each.

| Question | Result |
| --- | --- |
| Product Tampering, `PUT /api/Products/:id` | Found: TCF-018 at the generated route, under TC-AUTHZ-02 and TC-AUTHZ-03. |
| Editing any review, `PATCH /rest/products/reviews` | Found: TCF-023 under TC-AUTHZ-01. |
| User list, `GET /rest/user/authentication-details` | Found: TCF-043 under TC-AUTHZ-02 on Authentication & Session Surface. |
| Hits of the second run | All seven again. With Product Tampering the pilot finds 8 of the 9 authorization challenges and misses only GDPR Data Theft. The STRIDE step of this run finds 6 and misses Admin Registration, Forged Feedback, and GDPR Data Theft. |
| Injection and parsing | Accepted: only the login SQL injection (TCF-044), which covers the four login challenges. The replaced InputVal job's answers held the search SQL injection, all three NoSQL challenges, SSTi, the b2bOrder RCE, XXE, and SSRF; the STRIDE step found all of them except NoSQL DoS and NoSQL Manipulation. Cross-site scripting: the pilot finds 7 of 9 (DOM, Bonus Payload, Reflected, HTTP-Header, API-only, Client-side and Server-side XSS Protection), the STRIDE step 4; both miss CSP Bypass and Video XSS. |
| Data protection | Pilot only: a second REST path to the password hash, because `saveLoginIp` returns the user record, and TOTP secrets stored in clear. STRIDE only: Email Leak (JSONP), Confidential Document and the two backups (FTP and null byte), and Exposed Credentials, the last with TC-DATA-03 disabled. Neither finds GDPR Data Theft, NFT Takeover, or `whoami?fields=password`. |
| AI | The AI job was replaced. Through AuthZ the pilot found the coupon tool without a server-side limit (TCF-012), which covers Chatbot Prompt Injection and Greedy Chatbot Manipulation. System Prompt Extraction was only in the rejected answer. Neither finds AI Debugging. |
| Goal test cases | No finding of their own. Seven answers said that nothing beyond the concrete test cases was found; the controller recorded each as undecidable. |
| Pattern gaps | One: passwords in the query string under TC-DATA-04. |
| Cost per aspect | AuthZ 9 jobs, 17 calls, USD 4.71, 4 corrections; InputVal 5 jobs, 9 calls, USD 2.65; DataProt 4 jobs, 4 calls, USD 0.62; AI 1 job, 3 calls, USD 0.73. The pilot cost USD 8.71 against USD 7 to 10 estimated. USD 2.26 went to the two replaced jobs and USD 1.25 to correction calls in accepted jobs. Without the pilot the run cost USD 13.52, as in the first two runs (USD 13.26 and 13.31). |

The comparison matched findings by file and title; the individual pilot findings were not checked against the code.

Root causes of the two replaced jobs, reproduced with the recorded answers and confirmed by an independent review:

- The reply contract did not admit the aspect `AI`, while the normalizer sets the aspect from the job, so every AI answer failed whatever the model wrote. The aspect list was kept by hand in five places, and no test sent an AI answer through the exchange.
- The investigator policy carried a shortened copy of the STRIDE trace rule without the sentence that `absent-at-sink` cites the sink, which the shared validator enforces. The model cited the truncation line before the sink.
- The review stopped at the first failing check. The first answer already broke three independent rules (unlisted further reads, a finding anchored in a file of no component, the trace rule), and the model learned of them one per correction; the third was the last.
- The context did not list the starting files that the policy names, so the model could not tell which of its reads were further reads. Unlisted further reads were rejected once in each of the first two runs and four times in this one.
- Shared helpers belong to no component, 12 of 14 files under `lib/` in Juice Shop. A finding could not anchor there, so an input-to-sink weakness whose sink lies in such a helper had no valid answer.

### Changes after the third run

Decided by the product owner on 2026-10-23 and built in 612811f1. The measures address the mechanisms above for any analyzed repository, not Juice Shop alone:

- The reply contract admits `AI`. A test checks that the reply contract, the profile code, and the profile schema name the same aspects, all from the catalog, and that a reply of every investigated aspect passes the normalizer, the contract, and the review. A controller test runs an AI job.
- The normalizer locates a control that is absent at the sink at the sink. Both pilot policies carry the STRIDE trace paragraph verbatim, and a test compares them.
- The review of an investigation reports every independent class of violation in one rejection, each within its share of the 2,000-character correction feedback, and names findings by index. The STRIDE step keeps its review.
- The context lists `starting_files`, the same set the review checks further reads against.
- A finding or model candidate may anchor in a shared file of no component that the job read, and still belongs to the component. Only the pilot allows it, so the STRIDE step stays comparable; extending the STRIDE step is open.
- A finding that still breaks an evidence, trace, or rating rule after the last correction is dropped with a warning, its weakness candidates record undecidable with a fixed reason, and the job's other answers stand. Only the pilot uses it.
- A goal test case records no finding when the model examined the component and proposes no finding. This changes the decision of 2026-10-22 for goal test cases only; a concrete test case without an examined location stays undecidable.
- A job artifact that breaks its output contract names the failing path in the error.

Considered and not built: classifying controller contract defects in the host, because a normalizer can turn a model error such as duplicate local IDs into an invalid artifact, and the aspect test already catches the drift before a run; and filling in unlisted further reads in the controller, because each needs a test case and a reason that only the model knows.

Raised by the product owner on 2026-10-23 and not built: the catalog has no OAuth or OIDC test case (state, PKCE, redirect URI, ID token validation, account linking by email), and IAM is not investigated. In the third run only the STRIDE step reported OAuth weaknesses.

### Fourth run on Juice Shop

Prepared on 2026-10-23 for 612811f1. The product owner starts it with `bash /tmp/authz-pilot/run.sh`, which now writes into `/home/mrohr/appsec-reports/juice-authz-pilot-4` with the same profile and budget.

| Question | Expected result |
| --- | --- |
| Replaced jobs | None; the Express server's InputVal and AI jobs are accepted. |
| Injection and parsing | InputVal test cases find the search SQL injection, the three NoSQL challenges, SSTi, the b2bOrder RCE, and XXE. |
| AI | AI test cases find Chatbot Prompt Injection, Greedy Chatbot Manipulation, and System Prompt Extraction. |
| Corrections | Correction calls cost less than the USD 1.25 of the third run, since one correction names every violation. |
| Dropped findings | Each dropped finding is named in a warning; none is expected. |
| Goal test cases | Answers without a finding record no finding instead of undecidable. |
| Cost | Pilot about USD 6 to 8, run about USD 19.50 to 21.50. |

### Result of the fourth run (2026-10-23)

The product owner ran the profile at 612811f1 on Juice Shop into `/home/mrohr/appsec-reports/juice-authz-pilot-4`, stopped it once at USD 7.00 and resumed it with `--resume`. The run completed in 48 minutes with 137 calls for USD 21.42 and no run issue.

| Question | Result |
| --- | --- |
| Replaced jobs | None. The Express server's InputVal job 1/2 (2 calls) and its AI job (1 call) were accepted, the two jobs that were replaced in the third run. |
| Product Tampering, editing any review, user list | Found: TCF-020 at `server.ts:501`, TCF-024 at `updateProductReviews.ts:18`, TCF-025 at `server.ts:363` and TCF-059. |
| Authorization challenges | The pilot finds 8 of the 9 and misses only GDPR Data Theft. The STRIDE step finds 7 and misses Forged Feedback and GDPR Data Theft; editing any review is an instance of its systemic ownership finding. |
| Injection and parsing | The pilot finds the search SQL injection (TCF-027), all three NoSQL challenges (TCF-028, TCF-029, TCF-030), SSTi (TCF-033), the b2bOrder RCE (TCF-034), and XXE (TCF-036), plus the login SQL injection and SSRF. The STRIDE step finds the search and login injection, the user profile injection (T-012), NoSQL DoS (T-028), the b2bOrder RCE (T-052), and SSRF; it has no finding for XXE or for the NoSQL queries in order tracking and review update. |
| Cross-site scripting | Both find the same 7 of 9: DOM, Bonus Payload, Reflected, HTTP-Header, API-only, Client-side and Server-side XSS Protection. The pilot reports them as seven findings (TCF-051 to TCF-057), the STRIDE step as instances of two systemic findings (T-001, T-003) and T-056. Neither reports Video XSS; both report the code evaluation in `userProfile.ts` for CSP Bypass, but as code injection. |
| Data protection | Both find the password hash path (pilot: `saveLoginIp` returns hash and TOTP secret, TCF-062; STRIDE: `whoami` field selection, T-069), the directory listing and null byte downloads, and passwords in the query string. Pilot only: TOTP secrets in clear (TCF-049). STRIDE only: Email Leak and Exposed Credentials, the latter with TC-DATA-03 disabled. Neither finds GDPR Data Theft or NFT Takeover. |
| AI | All three expected challenges: Chatbot Prompt Injection and Greedy Chatbot Manipulation through the coupon tool without a server-side limit (TCF-046), System Prompt Extraction through the discount policy in the system prompt (TCF-047). The STRIDE step finds them too (T-050, T-055, T-067). Neither finds AI Debugging. |
| Corrections | Four rejected answers in four accepted jobs, each with exactly one violation: three unlisted further reads, one finding anchored in a file the model had not read. The cost per call is not recorded; at the pilot's average of USD 0.24 per call the corrections cost about USD 1.00, against USD 1.25 in the third run. The rejection that names every violation at once was therefore not exercised. |
| Dropped findings | None; the pilot document records no dropped finding. |
| Goal test cases | Ten answers: two findings (TCF-006, memories list without authentication, and TCF-047, both also reported by another aspect or the STRIDE step), eight `no_finding`, none undecidable, against seven undecidable in the third run. |
| Pattern gaps | Three: TC-FILE-01 and TC-DATA-04 on the Express server (passwords in the query string, as in the third run), and TC-AI-05. |
| Cost per aspect | Pilot USD 7.59 for 19 jobs and 31 calls, against USD 6 to 8 estimated: AuthZ 9 jobs, 16 calls, USD 4.45; InputVal 5 jobs, 9 calls, USD 2.08; DataProt 4 jobs, 5 calls, USD 0.84; AI 1 job, 1 call, USD 0.22. The run cost USD 21.42 against USD 19.50 to 21.50, so USD 13.83 without the pilot. |

The comparison matched findings by file and title against all 83 STRIDE threats of `.threats-merged.json`, including the instances of systemic threats; the individual pilot findings were not checked against the code. The STRIDE counts of the third run came from the anchor location of each threat only, without instances, and may be too low: the fourth run's first count by that method gave the STRIDE step 6 authorization and 3 cross-site scripting challenges instead of 7 and 7.

Assessment by the implementing session, not yet a decision: the expectations of the fourth run are met except the correction cost, which could not be measured. The fixes of 612811f1 hold for the two replaced jobs. The pilot finds more than the STRIDE step on injection (XXE and two NoSQL challenges) and one more authorization challenge (Forged Feedback); on cross-site scripting both find the same. The STRIDE step finds Email Leak and Exposed Credentials, which the pilot does not, and both miss business logic. The AuthZ cost concentrates on the Express server (7 of 9 jobs, USD 3.81 of 4.45), the other two components cost USD 0.16 and 0.48 and produce findings as well, among them the user list. One cause stays open: three of four rejections are unlisted further reads, although the context lists the starting files; the same rejection occurred in every run.

### Analysis after the fourth run

Done by the implementing session on 2026-10-23 with the product owner, from the fourth run's `security-assessment.yaml` and `.threats-merged.json`.

- The challenge counts understate what verification adds for authorization. About ten of its AuthZ findings have no counterpart among the 83 survey threats or their instances. Five were checked in the Juice Shop code and hold: any user reads any user record (`GET /api/Users/:id`, TCF-018), deletes any feedback (`/api/Feedbacks/:id`, TCF-021), creates products (`POST /api/Products`, TCF-016), reads and deletes other users' basket items (`/api/BasketItems/:id`, TCF-019; the survey reports only `PUT`), and reads recycle items without login (`GET /api/Recycles/:id`, TCF-007). The other five were not checked; order tracking may be intended.
- The survey names a few examples and one systemic finding for authorization; verification walks route by route and finds the gaps the survey does not enumerate. For cross-site scripting both found the same seven challenges.
- The methods did not know of each other. Verification starts from the route inventory and scanner hits, not from survey findings, and no step linked their results. Of 62 verification findings, 23 had a survey threat with the same CWE at the same line, 24 within three lines.
- Verification cost USD 7.59 for four of fourteen aspects, as much as the survey for all of them. The survey still found weaknesses outside the catalog in every run, such as JWT handling in the chatbot, OAuth without `state`, password reset throttling, CI/CD supply chain, and Email Leak.

Decided by the product owner on 2026-10-23:

- The methods are called Survey and Verify. Verification does not replace the survey: it covers only catalog aspects, costs far more per aspect, and missed survey findings in every run. Taking single aspects out of the survey waits until verification loses nothing over several runs and two repositories, and until it is measured whether the survey gets cheaper without them.
- The requirements name both methods, and "test case" becomes "verification item" there (`15ab1c78`, proposal `specs/changes/survey-and-verify/proposal.md`). Code, catalog IDs, the `test_cases` key, and saved results keep the old names until a later change.
- The verified aspects per depth are a setting, not a requirement. Shipped defaults: quick runs the survey only, standard verifies AuthZ, thorough verifies AuthZ, InputVal, DataProt, and AI. AuthZ alone at standard depth, because verification found 8 of 9 authorization challenges against 6 to 7 for the survey in the third and fourth runs, has deterministic post-checks, and found the weaknesses above; InputVal is the next candidate, measured in one run only, and standard depth with both would exceed the USD 20 standard limit already on Juice Shop. A scan profile changes the aspects per depth; an organization profile makes aspects mandatory.
- Findings of both methods at the same location and CWE are shown once and name both. A control that verification evidenced at a survey finding's location marks it contradicted and never removes it. Survey findings are not sent to verification as candidates: an independent second finding is stronger evidence than a model asked to confirm a presented claim, and it would add calls.
- The run states before the first verification job, not before the first model call, whether the budget covers the jobs, because their number depends on the components the architecture analysis finds; aspects the budget cuts short are marked incomplete.
- The console names the survey's progress lines "Survey" and counts the verification jobs in the progress share and remaining time.

### Survey and verify by depth (built 2026-10-23)

Built on the branch after merging `main` into it:

- `data/verification-depths.yaml` holds the shipped defaults. `profiles.resolve_scan` resolves `test_cases` for the run's depth: no setting takes the default, `depths` overrides single depths, `aspects` covers the others, and `false` at a depth runs the survey only. `profiles show` names the default's origin. The organization profile's `test_cases.required_aspects` joins the selected aspects in the controller.
- `run_pilot` states the job count, estimated cost, and remaining budget before the first job, using the survey's job reserve until a verification job is accepted (`AssessmentBudget.job_usd`), and records `incomplete_aspects` when the budget replaced a job.
- `case_outcomes.combine_methods` runs after the model is built: a verification finding with the same CWE within three lines of a survey threat's evidence or instance (since changed to the same line and CWE family, see "Linking survey and verification findings") gets `survey_finding_ids`, the threat `verification`, and a survey threat at a location where an item with its CWE evidenced a control `verification_contradicted`. Component results carry `control_locations` for that.
- The report's finding cards say "Found by: survey and verification" or "Contradicted by verification", the section Verification Findings lists only findings the survey did not report, and the appendix is called Verification Items and names incomplete aspects. The completion summary row is called Verification. The run header shows `Methods: Survey · Verify AuthZ`.
- The console labels the survey's component lines "Survey:" and its bars "Survey jobs", and grows the threat analysis share by each planned verification job.

Limits of this step:

- Verification findings that the survey did not report still stay apart from the findings register and its totals, priorities, and mitigations. The full merge into `merge_assessment` is not built.
- The defaults reach runs with a profile snapshot, which every `appsec-analyzer assess` run has. The internal controller without a run profile keeps verification off unless asked for it.
- A run saved at standard or thorough depth before the defaults existed cannot resume and needs a new run; quick depth resumes.
- `IAM` and `SessionMgmt` are accepted but not investigated, so the thorough default lists the four investigated aspects.
- A job replaced by a model failure, not the budget, makes its candidates undecidable but does not mark the aspect incomplete.
- The budget statement estimates verification jobs from the survey's reserve per job, which is 1.5 times its average cost; the fourth run's verification jobs cost USD 0.40 each against USD 0.28 per survey job.

### Depth settings (built 2026-10-23)

Decided by the product owner on 2026-10-23, after asking which other settings could join the verified aspects in one configuration (proposal `specs/changes/assessment-depth-settings/proposal.md`, REQ-018):

- One shipped file, `data/assessment-depths.yaml`, states what each depth does: `verify`, `abuse_cases`, `derived_abuse_cases`, `architect_review`, `actor_discovery`, and `budget` of a run started through the Claude Code assessment dialogue. It replaces `data/verification-depths.yaml` and reproduces the earlier behavior of every depth.
- An organization profile sets its own defaults under `depths`; a team's scan profile changes single values for single depths under `depths` and wins over the organization; command-line flags win over both. The scan profile's verified aspects moved from `test_cases.depths` to `depths.<depth>.verify`.
- The scan profile lists abuse cases to always check (`check_abuse_cases`) or never check (`skip_abuse_cases`); which cases fit an application stays out of the shipped file. A case the organization switched off cannot be checked.
- Binding organization values exist only for what was binding before: required verification items and aspects, and switched-off abuse cases. Binding values for the other settings were left out until someone needs one.
- `max_parallel` stays a scan profile setting without a per-depth default, because it depends on the provider and the machine. Model selection per role stays in the model profiles; technical limits are not settings.
- The trust boundary crossings examined in detail (2, 4, and 6 per depth) were dropped from the requirement: only the plugin-era dispatch reads that limit, and the `assess` controller examines every crossing.
- The requirement text was rewritten for users who do not know the product: each term is explained where it appears.

Built on `feat/assessment-depth-settings`: `appsec_analyzer/depth_settings.py` layers the files, `resolve_config.resolve_depth_settings` applies them after the organization profile and decides the architect review and the abuse case stage, the matcher and the deriver take their counts from `.skill-config.json`, actor discovery reads its switch there, and the dialogue entry takes its budget from the same layers. The controller refuses, before the first model call, a checked case that the organization switched off or a shipped `AC-T`/`AC-B` ID that does not exist.

Limits: organization distributions (REQ-039) do not carry `depths` yet, like `test_cases.required`; a checked organization or repository case that is not active is skipped with a warning only when the cases are matched; `derived_abuse_cases` is at most 6, the deriver's proposal limit; other depth-dependent behavior, such as the thorough-only database privilege check and the plugin-era STRIDE turn budgets, phase time budgets, and evidence verifier limit, is unchanged and not a setting.

### Cost of authorization verification (analysed 2026-10-23)

The product owner asked whether authorization verification runs only where it is needed, since it cost USD 4.45 in the fourth run. Analysed by the implementing session from the fourth run's job receipts, host events, and candidate files, without model calls.

- Components: 3 of 9 components got AuthZ jobs; the others have no routes and record not applicable or undecidable without a call. All three produced findings. The Express server cost USD 3.81 in 7 jobs and 13 calls.
- Candidates: the model rejected 144 of 294 candidate answers as not applicable. Narrowing the starting points would still lose findings: 31 of 37 weakness answers came from the route facts that start every state-changing route, body route, or authenticated read without identifier, not from scanner hits, among them admin registration through `role` in `POST /api/Users`, `/encryptionkeys` and `/support/logs` without login, and the user list. Skipping routes by their authentication, identifier, or guard signal would presume the answer the verification exists to give.
- Cost driver: each call sends 56,000 to 110,000 input tokens and returns 1,000 to 17,000. Of the USD 4.45, 9 answer calls cost USD 2.67, 4 calls that read further code before answering USD 0.87, and 3 correction calls USD 0.92. The 16 calls wrote 1.25 million tokens to the prompt cache and read 0.16 million from it.
- Corrections: across the four runs, nine verification and open review replies were rejected only because `discovery_escapes` left out a file the job had served; two of the three AuthZ corrections of the fourth run were of this kind.
- Repeated paths: 19 candidate answers share method and path with another candidate of the same test case, such as four registrations of `POST /api/Users`. They are separate registrations with their own middleware, which the model answers differently (`POST /rest/user/data-export` at `server.ts:620` a control, at `server.ts:621` undecidable) and the post-checks evaluate per registration.

Decided by the product owner on 2026-10-23: build the correction fix and merge repeated paths. Built in ed6bae78: an unlisted further read no longer rejects a verification or open review reply, because the job receipt records every served range; a listed file the job did not serve, more than 15 further files, and findings in unread files are still rejected. Merging repeated paths was not built: it would mix answers about different code into one candidate and need per-registration post-checks to change, for at most one job less on Juice Shop. Expected saving: about USD 0.70 of authorization verification per run on Juice Shop, and the same rejection in the other aspects.

Open: two of the four further-read calls fetched guard code from `lib/insecurity.ts`, although the preload is meant to carry the guards the candidates' routes run. Prompt caching across the jobs of one component, set aside in the batching decision, remains the largest lever and would apply to the survey as well.

A later run on 2026-10-23 showed the same: 6 of 16 authorization calls only asked for two to four further slices, mostly `lib/insecurity.ts` and `models/*.ts`, at USD 1.34 together. Two producer gaps caused it. `middleware_definitions` took a registration's last argument for its handler, so a guard-only registration such as `app.get('/api/Users', isAuthorized())` named no guard; 96 of 131 Juice Shop routes with middleware had none. Generated REST routes recorded neither the guards of the registrations that run for them nor the data model the generator serves. Built in 2e56eb65: a last argument that hands the request on counts as middleware, generated routes list their guards and data model, and the verification preload serves guards, then data models, then the candidates' windows, inside the job's allowed sources. Not measured in a run yet; the open points are in [Verification cost: open points](verification-cost-open-points-2026-10-23.md). Survey requests change with the added middleware spans, so earlier accepted survey jobs are not reused.

### Linking survey and verification findings (analysed 2026-10-23)

The product owner asked whether authorization verification works together with the survey or runs independently of it. Analysed by replaying `combine_methods` offline on the saved models and pilot sidecars of runs 2 to 4, without model calls.

- During the analysis the methods stay independent, as decided. They meet only in `combine_methods` after the model is built, which the controller calls whenever verification is selected.
- The rule "same CWE within three lines" linked 38 pairs over the three runs, 4 of them wrongly, all on neighbouring lines of a route table: `POST /api/Products` with the commented-out guard of `PUT /api/Products/:id` (runs 2 to 4, `server.ts:369` and `370`), and deleting any feedback with the user list (run 3, `server.ts:361` and `363`). A wrong link hides a finding that only verification reported, because the section Verification Findings lists only unlinked findings. No link between 1 and 3 lines apart was correct.
- The exact CWE missed findings that are the same weakness on the same line: in run 4 `TCF-059` (CWE-862) and `T-075` (CWE-639) at `routes/authenticatedUsers.ts:12` with nearly the same title, and `TCF-032` (CWE-94) and `T-012` (CWE-95); in run 3 three more such pairs. The report showed each twice.
- The survey's own merge already counts the same file, line, and CWE family as one finding (`merge_threats._evidence_identity_key`). That rule, applied to both methods, links all 5 missed pairs and none of the 4 wrong ones. CWE families across a range of three lines would have added two more wrong links in run 3.
- It does not link the same weakness labelled with CWEs of different families (`TCF-006`/`T-031`, CWE-862 and CWE-359; `TCF-008`/`T-033`, CWE-862 and CWE-552; `TCF-013`/`T-042`, CWE-639 and CWE-290) or anchored on different lines (`TCF-020` at the finale resource, `server.ts:501`, and `T-039` at the commented-out guard, `server.ts:370`). Same line alone is no criterion: `TCF-012` (order tracking without ownership) and an instance of the NoSQL injection `T-028` share `routes/trackOrder.ts:18`.
- The contradiction rule had the same three-line range. No saved run has `control_locations`, so it could only be checked in unit tests.

Decided by the product owner on 2026-10-23: one finding needs the same file, line, and CWE family; a contradiction needs the same line and keeps a CWE of the verification item, because an ownership check does not show that a role check exists. Proposal `specs/changes/survey-verify-linking/proposal.md`. Linking by route and handler for the remaining pairs is not built.

### Authentication verification (built 2026-10-24)

Asked by the product owner on 2026-10-24: the aspect `IAM` is renamed `AuthN`, because its items TC-AUTHN-01 to 05 cover authentication only, and it gets starting points so that it can be verified. The control domain IAM of the report's security architecture section is a separate list and keeps its name. The aspect was never released, so profiles get no alias for the old name.

- `AuthN` is an investigated aspect. No depth verifies it by default; a scan profile selects it, as `test_cases.aspects` or `depths.<depth>.verify`.
- TC-AUTHN-01 keeps every route as a candidate, as decided for AuthZ, and adds WebSocket, GraphQL, and message handlers (`code_sites.channel`). TC-AUTHN-02 and 03 start from token checks (`code_sites.token_handling`), TC-AUTHN-04 from password hashing, password fields in data models, and account routes, TC-AUTHN-05 from account routes. An account route is one whose path names login, registration, recovery, password, a second factor, or authentication (`route_inventory.credential_flow`).
- A code site kind with `anchor: site` stays one candidate where routes reach it and lists them in `reached_by`, as a scanner hit does. Token checks, password hashing, and channels use it: a token check in a shared guard would otherwise make every route behind the guard a candidate for the same question.
- The applicability signal `password_handling` also counts a hash call with a password argument, so a data model that hashes passwords with its own helper is examined. Before, TC-AUTHN-04 was not applicable there.
- Catalog version 5.

Offline count with the components, route inventory, and scanner findings of `juice-verify-cost-2`, without model calls: 9 AuthN jobs, against 8 before the change and 9 for AuthZ by the same count, which matches the fourth run. TC-AUTHN-01 drives the cost with 147 candidates on the Express server, 5 of its jobs. At USD 0.40 to 0.50 per verification job, AuthN would add about USD 3.60 to 4.50 per Juice Shop run. Not measured in a run.

Open: the existing kind `sensitive_field` uses `^\s*` in a multiline pattern, which backtracks quadratically over a run of blank lines in a file that defines data models: 8,000 blank lines take about 5 seconds. The new kind `password_field` uses `^[ \t]*` and stays linear; a test checks the four new kinds on hostile input. SessionMgmt still has no starting points, and the catalog has no OAuth or OIDC item.

Changed after the third measuring run, decided by the product owner on 2026-10-24: TC-AUTHN-01 moved to the aspect `AuthNRoutes`, `AuthN` gained items for SSO and OAuth sign-in and for insecure methods (TC-AUTHN-06, 07, catalog version 6), standard depth verifies `AuthN` with AuthZ, InputVal, DataProt and AI, and thorough depth adds `AuthNRoutes`. The reasons and figures are in point 10 of [the open points](verification-cost-open-points-2026-10-23.md).

## After the first run: decide with real results

| Item | Becomes necessary when |
| --- | --- |
| Open review role with the 20% reserve (`AssessmentBudget.hold` and `release` exist) | Shown by the second run: GDPR Data Theft and other business logic reach no test case. |
| Shared jobs for the test cases of all investigated aspects of a component | A second aspect is investigated, planned with InputVal. Batching by location exists since 998b0b13. |
| Starting points for InputVal and DataProt beyond scanner hits, such as query, command, file, outbound request, and HTML output sinks, response serialization, stored sensitive fields, secrets, and transport settings | Built in b100c018, except secrets, which wait for REQ-042. |
| Fixtures `tests/fixtures/test-cases/TC-.../` with and without the weakness for the pilot aspects | After the third run, to measure exit criterion 2 offline. |
| Code sites in helper modules that a handler calls, and more REST resource generators | Pattern gaps or misses of the third run show it. |
| Route inventory entries for routes that frameworks generate from data models, such as finale REST resources | Shown by both runs. Built for the pilot's facts in cf0fbdc2; the shared inventory follows only when the pilot is continued. |
| TC-AUTHZ-01 candidates for routes that take an object ID in the body, and a starting point for sensitive listings without a path parameter | Shown by the second run. Built in cf0fbdc2. |
| Merge into `merge_assessment` (`pilot_documents`), union of `test_case_ids`, mapping of reply-local finding IDs | Partly built after the fourth run: findings at the same location and CWE are linked and shown once, and verified controls contradict survey findings. Verification-only findings joining the register, its totals, and mitigations is open. |
| Removal rule: a confirmed post-check removes a scanner finding unless the evidence verifier marked it verified, otherwise the finding records `test_case_disagreement` | The merge exists. |
| Comparison file `security-assessment.test-case-comparison.json` with a schema | The comparison format is settled and the exit criteria are measured. |
| Fixtures `tests/fixtures/test-cases/TC-.../` and the recorded-response evaluation | The catalog grows beyond the pilot aspects or moves into the default run. One or two AuthZ fixtures are enough for the first run. |
| Console phase "Security checks", stage-stats entries, per-component report rows | Decided after the fourth run: no own phase; survey and verification share Threat analysis, and the progress counts verification jobs. Stage-stats entries are open. |
| `context-routing.md` and `orchestration-actions.md` for the new contexts, phase, and holds; the guides already describe the setting | Written before the merge, after the fourth run. |
| Replacing the STRIDE step, the REQ-004 change, score integration, `TC-APP` test cases, control posture feeding | A positive pilot decision. |

## Integration option: methods by assessment depth

Raised by the product owner on 2026-10-23 and taken as the direction for a later integration; the aspects per depth are decided after the fourth run and a run on a second repository.

The idea is to choose the methods by assessment depth: the cheaper method alone at quick depth, both combined at standard depth. The cost data of the three runs reverse the first guess about which method is cheaper. At standard depth the STRIDE step covers every aspect of every component for about USD 7, with evidence verification about USD 10, while the pilot's four aspects are estimated at USD 6 to 8 after 612811f1, and AuthZ alone cost USD 4.71 in the third run. The pilot's cost follows its number of jobs, because every call carries about 90,000 tokens of context, so all 14 catalog aspects would cost far more than the STRIDE step. The rules test cases cost nothing.

| Depth | Methods | Added cost |
| --- | --- | --- |
| quick | STRIDE step and rules test cases | none |
| standard | STRIDE step, plus test cases for the aspects where the pilot measurably finds more; after three runs AuthZ and the cross-site scripting part of InputVal | about USD 3 to 5 |
| thorough | STRIDE step, test cases for every pilot aspect, and the open review | about USD 8 to 10 |

Conditions:

- Combining both needs the merge step, which is not built; until then the same weakness appears in the threats and in the test case findings.
- The interactive launch caps standard depth at USD 20. The third run cost USD 22.23 with four pilot aspects, so standard depth can take only selected aspects.
- The target picture keeps every aspect assignable to one method. The depth would decide which aspects get both. Whether the STRIDE step becomes cheaper when it leaves an aspect to the test cases is not measured; its cost follows the fixed context per component more than the number of aspects.
- The data come from one intentionally vulnerable repository, three runs, and standard depth only. Quick depth has no measured cost in this pilot.
- The change alters REQ-040 and the behavior of the depths, so it needs its own requirement proposal and the product owner's approval.

Decided by the product owner on 2026-10-23: what each depth runs is configuration, not code. The table above is the shipped default. A configuration states per depth which aspects get the verification-based method beside the STRIDE step, and whether the open review runs, in the way the model profiles already state per depth which model each role uses (`depths` in `data/model-profiles/*.yaml`). An operator's scan profile can override the default, and an organization profile can require aspects, as `test_cases.required` does today. The exact place and schema are part of the requirement proposal.

Superseded after the fourth run: the shipped defaults are quick with the survey only, standard with AuthZ verification, and thorough with all four investigated aspects; see [Analysis after the fourth run](#analysis-after-the-fourth-run).

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

- For the depth settings, only the tests of the changed modules ran: `tests/test_depth_settings.py`, `tests/test_profiles.py`, `tests/test_resolve_org_profile.py`, `tests/test_resolve_config.py`, `tests/test_assessment_posture.py`, `tests/test_derive_abuse_cases.py`, `tests/test_match_abuse_cases.py`, `tests/test_org_profile_schema.py`, and the dialogue budget tests of `tests/test_public_assessment_operations.py` and `tests/test_single_repo_controller.py`. `test_the_deprecated_org_guardrail_key_still_resolves` fails as on `main`, because no plugin version file exists.
- For the survey and verify step after merging `main` (82e9de5e), only the tests of the changed modules ran, as the product owner asked: `tests/test_controller_fixture.py` (14 tests), the profile, case outcome, budget statement, and summary tests (238), the organization profile tests (155), the public CLI and state tests after the merge (356), and the console and header tests of `tests/test_multi_repo_assessment.py` whose texts changed (24); `scripts/check_specs.py` and Ruff on the changed files passed. `test_render_text_names_the_ask_and_review_lanes` fails as on `main`. The rest of `tests/test_multi_repo_assessment.py` and the offline gate `make check-analyzer` were not run.
- The merge left two copies of one console test and an older branch test of the Preflight row that `main` replaced with its Preflight block (07317bde); the copy and the older test were removed.

- Offline gate `make check-analyzer BASE=main` passed at commit 7d949134. At 5e3f39bb, 90d27a7d, and 80064794, `make check-analyzer BASE=356f0cfc` passed: the specs check, Ruff, 954 and 168 tests. At 80064794, `make test-controller` passed as well (8 tests). At 998b0b13, `make check-analyzer BASE=356f0cfc` passed with 954 and 168 tests, and the tests of the changed modules passed with the pilot tests of `tests/test_controller_fixture.py`, including the new tests for shared jobs, a failed job, and a resumed run with shared jobs (156 tests). The three controller fixture tests that never start the pilot were not rerun. The base is the merge base, because `main` has moved on and a comparison with it would count its newer commits as changes of the branch.
- At ec424ef9, `make check-analyzer BASE=356f0cfc` passed the specs check, Ruff, and 168 tests; of 954 analyzer tests one failed, the Codex timeout test, whose race 8f16254f removes, and it passed three times alone. At cf0fbdc2, the gate passed with 954 and 168 tests, `make test-controller` with 12 tests, and the tests of the changed modules passed. The seven failing progress-header and budget tests of `test_multi_repo_assessment.py` fail at ec424ef9 as well, before the applied fixes.
- At b100c018, `make check-analyzer BASE=356f0cfc` passed the specs check, Ruff, and 954 and 168 tests. `make test-controller` passed 12 of 13 tests; the thirteenth expected the AuthZ test cases without TC-AUTHZ-06, and after that expectation was added it passed alone. The tests of the changed modules passed: candidates, post-checks, outcomes, case analysis, catalog, and profiles. The bound of the NoSQL pattern changed after the gate, and its example test and the catalog tests passed again.
- At 612811f1, the tests of the changed modules and their direct consumers passed: case analysis, outcomes, candidates, post-checks, catalog, host, jobs, budget holds, multi-repository analysis, intermediate validation, and profiles (907 tests), and `make test-controller` (14 tests, including a new one with an AI job). The controller tests ran before two rejection texts and one comment were reworded; the case analysis and multi-repository analysis tests ran after (233 tests). `make check-analyzer` and `tests/test_multi_repo_assessment.py` were not run, because the change touches no public command, packaging, or requirement.
- At 5e3f39bb, `make test-controller` passed with the new pilot tests (8 tests), as did the test case, compose, schema, and direct `_assessment_stride` controller tests. `tests/test_report_anatomy.py` fails because `specs/changes/report-anatomy/report-anatomy.md` exists in no commit; this is not caused by the branch.
- Failures that exist on `main` and are not caused by this work: tests that need `.claude-plugin/plugin.json` (`test_export_sarif` tool version tests, `test_compose_threat_model_cov3::test_no_plugin_version_title_only`, one `test_figure1_dfd` case), `test_run_tests` for `config_iac_scanner.py`, `test_summarize_threat_model::test_render_text_names_the_ask_and_review_lanes`, seven progress-header tests in `test_multi_repo_assessment.py`, and `test_stage1_context_edge_inventory.py` (missing inventory document).
- No live model call was made. The measurement run needs explicit authorization of its model spending, and the cost limit is set after it.

## Open questions from the proposal that still need an owner

The second comparison repository, the pilot time box, the mapping of outcomes to the control effectiveness scale, the reserved budget share per depth, and the score integration. See the proposal's open questions.

The name "test case" has a provisional answer. On 2026-10-22 the product owner chose, for now, "STRIDE-based" and "verification-based" for the two analysis methods, and "verification catalog" with "verification items" for the catalog and its entries, with IDs such as `VI-AUTHZ-01`. "Test case", "security check", and "control objective" were rejected: the first collides with software tests, the second with scanner checks, and the third describes implementation rather than verification. Results must keep saying "verified by model review only" where no post-check confirms a control. The REQ-040 wording and the rename wait until the pilot is continued, at the latest until the branch is merged.

The name "STRIDE-based" stays for now but should be improved, as decided by the product owner on 2026-10-23: it suggests threat modeling per data flow element, while the step is an open, evidence-based code review per component that uses the six STRIDE categories as a checklist and as the label of its findings. Names considered and not taken: "exploration", too weak and generic; "LLM exploration", because the verification-based method is model-backed as well and the product documents say "model", never "LLM"; "sweep", for the breadth the step shows across aspects; "open review", because the planned open review role uses it; "discovery", "audit", and "review", already taken by discovery phases, `audit-requirements`, and `review`.

Decided by the product owner on 2026-10-23: the console and requirement texts say "Survey" for the first method and "Verify" for the second, both short enough for the progress grid. "STRIDE-based" remains a valid description of the survey (it uses the six STRIDE categories as its checklist and as the label of its findings). The requirements use both names since the approved proposal of `15ab1c78`, and the console, report, and guides since the implementation that followed; code names, catalog IDs, and the `test_cases` key keep the old wording for now.
