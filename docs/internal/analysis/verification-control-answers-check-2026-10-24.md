# Additional AuthZ control answers on the Express server (first measuring run against pilot run 4)

Status: analysis record, written 2026-10-24 offline without model calls. Since then the wrong answer's cause is addressed by TC-AUTHZ-01's guidance (3515cf86), and the lost wallet controls by `reached_by` with the routes' guard registrations (3515cf86, d376462a); see points 8 and 9 of [the open points](verification-cost-open-points-2026-10-23.md). The deterministic support in fix 2 below was not built.

Data: component `component-191fd03d5dfa5985`, the 7 AuthZ verification jobs of each run (the same job IDs `test-cases:component-191fd03d5dfa5985:AuthZ:N/7`) of `juice-authz-pilot-4` and the first measuring run `juice-verify-cost-1`, both on Juice Shop at 33518f5a0.

## Candidate statuses

| Status | Run 4 | First measuring run |
|---|---|---|
| control | 85 | 96 |
| weakness | 33 | 39 |
| rejected | 110 | 113 |
| undecidable | 20 | 6 |
| neither | 11 | 5 |

The net 11 additional controls are 18 new control answers and 7 that are no longer controls. Candidate IDs are the same in both runs.

## The 18 new control answers

Where they came from:

- 10 were `rejected` in run 4 with the same reasoning ("denyAll blocks the route", "only message is set"). Only the label changed.
- 8 were `undecidable` (6) or `neither` (2) in run 4 because the guard body had not been served. Since the preload fix, the guard definitions arrive with the first packet (jobs 2, 3, 4, 5 and 7 got `lib/insecurity.ts` 52–92 and 144/154–197).

Verdict: **17 correct, 1 wrong, 0 doubtful.**

| # | Test case | Route (anchor) | Before | Verdict | Reason |
|---|---|---|---|---|---|
| 1 | 01 | POST /api/Quantitys (server.ts:430) | rejected outside-objective | correct | `app.post('/api/Quantitys', security.denyAll())`; denyAll = `expressJwt({secret: ''+Math.random()})` (insecurity.ts:53) rejects every token; registered before the generated resources (server.ts:501), so it runs first. |
| 2 | 01 | POST /api/SecurityQuestions (392) | rejected outside-objective | correct | Same denyAll. |
| 3 | 01 | DELETE /api/Recycles/:id (390) | neither | correct | Same denyAll; Recycles are user-owned, nobody can delete. |
| 4 | 01 | PUT /api/Recycles/:id (389) | neither | correct | Same. |
| 5 | 01 | DELETE /api/Products/:id (371) | rejected outside-objective | correct | Same. |
| 6 | 01 | POST /rest/user/data-export (621) | undecidable missing-source | **wrong** | See below. |
| 7 | 02 | DELETE /api/Products/:id (371) | undecidable | correct | denyAll. |
| 8 | 02 | GET /rest/order-history/orders (624) | undecidable | correct | `isAccounting()` (insecurity.ts:157–163) checks the token's role `accounting` on the server, else 403. That `verify()` does not pin the JWT algorithm is a token-forgery weakness, not a missing role check. |
| 9 | 02 | PUT /api/Recycles/:id (389) | undecidable | correct | denyAll. |
| 10 | 02 | DELETE /api/Recycles/:id (390) | undecidable | correct | denyAll. |
| 11 | 03 | POST /api/Quantitys (430) | rejected unreachable | correct | denyAll. |
| 12 | 03 | PUT /api/Cards/:id (440) | rejected not-a-weakness | correct | denyAll. |
| 13 | 03 | PUT /api/Recycles/:id (389) | undecidable | correct | denyAll. |
| 14 | 03 | POST /api/Hints (376) | rejected not-a-weakness | correct | denyAll. |
| 15 | 03 | POST /api/SecurityQuestions (392) | rejected unreachable | correct | denyAll. |
| 16 | 03 | POST /api/Challenges (373) | rejected not-a-weakness | correct | denyAll. |
| 17 | 03 | PATCH /rest/products/reviews (634) | rejected not-a-weakness | correct | `$set: { message: req.body.message }` (updateProductReviews.ts:19): the body cannot set the author or other fields. The missing owner check on the same route is reported separately as a TC-AUTHZ-01 finding (TCF-025, updateProductReviews.ts:18). |
| 18 | 03 | PUT /api/Feedbacks/:id (433) | rejected not-a-weakness | correct | denyAll. |

All 15 denyAll answers have the right method and path, and the middleware runs before the generated handlers. Several cite only the registration line (for example server.ts:389) and not the guard body, although the job was served insecurity.ts:53. The controller does not require the enforcing line in a control's evidence.

Not checked: express-jwt 0.1.3 and jsonwebtoken 0.4.0 are very old versions, and `node_modules` was not installed, so whether they accept unsigned (`alg: none`) tokens is open. If they do, denyAll and isAuthorized could be bypassed. That would be a dependency weakness outside what the verification question covers.

Status choice: for routes denied to everyone, both `control` and `rejected` with `unreachable` or `outside-objective` (for objects that are not user-owned, such as Products or SecurityQuestions under TC-AUTHZ-01) are defensible under the policy. 10 of the 18 changed only this label, so control counts are not comparable between runs.

### The wrong answer: POST /rest/user/data-export (server.ts:621), TC-AUTHZ-01

- Claim: "appendUserId overwrites body UserId from the token before the export reads it". Evidence: insecurity.ts:178 and dataExport.ts:26.
- True for the memories query: `MemoryModel.findAll({ where: { UserId: req.body.UserId } })` (dataExport.ts:26), with `appendUserId()` on the route (server.ts:621, insecurity.ts:178).
- But the same handler also returns orders by a vowel-masked e-mail: `ordersCollection.find({ email: updatedEmail })` with `updatedEmail = email.replace(/[aeiou]/gi, '*')` (dataExport.ts:22, 33). Several accounts share one masked e-mail, so a caller can export another user's orders. Object access is not bound to the caller.
- Job 7 was served dataExport.ts 5–55, which includes line 33. This is a judgement error, not missing source.
- Earlier runs: the survey reported it in run 2 (T-063, dataExport.ts:33); no verification run did. In the first measuring run neither method reported line 33.
- Consequence: the report listed the route as a confirmed control location of TC-AUTHZ-01. The test case's outcome stayed `finding` because of other weaknesses.

## The 7 answers that are no longer controls

| Candidate | Run 4 | First measuring run | Assessment |
|---|---|---|---|
| TC-AUTHZ-01 routes/order.ts:148, 150, 157 (code sites, no route) | control (the wallet uses `req.body.UserId`, overwritten by `app.use('/rest/basket', isAuthorized(), appendUserId())`, server.ts:356) | undecidable missing-source | Run 4 was right: the checkout route `/rest/basket/:id/checkout` (server.ts:604) falls under that prefix middleware. Job 1 read server.ts 354–370 in run 4 but not in the measuring run. The preload served guards only for route candidates, not for code-site candidates without a route. A loss of a correct control, not a wrong answer. |
| TC-AUTHZ-01 POST /rest/user/data-export (620) | control | undecidable | The control in run 4 was wrong for the same reason as #6 above; undecidable is better. |
| TC-AUTHZ-02 GET /rest/order-history (623) | control | rejected not-a-weakness | Both acceptable for the role question. The same masked-e-mail lookup (orderHistory.ts:16–17) has no TC-AUTHZ-01 candidate. |
| TC-AUTHZ-02 GET /profile (666) | control | rejected not-a-weakness | Both acceptable. |
| TC-AUTHZ-03 routes/dataErasure.ts:74 | control | rejected outside-objective | Both acceptable. |

## Proposed generic fixes for the wrong answer

Cause: the model took the one query bound to a token-derived ID as the control for the whole handler. The handler runs a second lookup of user data on a derived, non-unique attribute of the caller. Neither the policy nor the validator asked a control answer to account for every lookup of user-owned data in the handler.

1. **A rule in the instructions (small, any repository).** A control at an object-access location must cover every lookup of user-owned data that the handler makes on that request; binding one query does not protect another. A lookup by a transformed or non-unique attribute of the caller, such as a masked, truncated or case-folded e-mail or a display name, does not bind the object to the caller. Built as TC-AUTHZ-01 guidance (3515cf86); the second measuring run reported the data export as a finding.
2. **Deterministic support (larger, not built).** Give TC-AUTHZ-01 a `code_sites.*` fact for data lookups in the handler chain. The code-site mechanism in `scripts/model/case_candidates.py` already attaches sites to the route candidate whose chain reaches them as `sinks`, so the data-export candidate would list dataExport.ts:26, 33 and 40, and the instructions already say that sinks are where the mechanism lies. `validate_investigation` could then reject a `control` that neither cites nor addresses each sink, with a correction reason. Offline test: a fixture handler with two queries, one by `req.body.UserId` (overwritten by the guard) and one by `email.replace(...)`; the candidate carries both sinks, and a reply claiming a control while citing only the first gets a correction or ends as `partial`.

## Side observations outside this check

- The scanner finding T-006 (CWE-639, "Broken authorization — routes/dataExport.ts:26") and the verification control on the same line are not marked as a contradiction, because `combine_methods` checks only threats with `source == "stride"`. Here the control is right for line 26, so the scanner finding is a false positive for that line.
- Code-site candidates without a route (TC-AUTHZ-01 at routes/order.ts) got no guard preload. A generic fix serves the guards, including `app.use` prefix guards, of the routes whose chain reaches the site; built as `reached_by` (3515cf86) and its guard registrations (d376462a).
