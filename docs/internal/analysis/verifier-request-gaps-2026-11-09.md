# Findings the Verifier cannot test: open points in the assessment

Status 2026-11-09. Basis: `/home/mrohr/assessments/juice-shop-std/security-assessment.yaml` (Juice Shop 33518f5a, generated 2026-11-08 10:36 UTC, before e954cedc) and an AppSec Verifier run on its findings rated high or above, in which 13 findings were not testable. Analyzer code compared: `main` at 60276cd7.

## Summary

Two of the 13 findings fail because the assessment names no request for them (T-011, T-034). The others need operator input by design, need proof methods the Verifier lacks, or are blocked on purpose. T-037 was a parsing error in the Verifier and is fixed there. e954cedc addresses the request gap in part; its effect needs a fresh run.

| Finding | Verifier need | Cause | Belongs to |
| --- | --- | --- | --- |
| T-011 | request information | the scenario names no request ("req.body.UserId and the like"), and no instance carries `route_ids` | Analyzer |
| T-034 | request information | the scenario names `routes/profileImageUrlUpload.ts:24` where the request `POST /profile/image/url` belongs; the instance's `route_ids: [R-008]` do not resolve, because the attack surface published no IDs | Analyzer (e954cedc publishes the IDs; the Verifier reads them since this analysis) |
| T-005 | injection contract | the operator declares the tested input in `injection_inputs` | operator, by design |
| T-030 | injection contract | the input is a path segment (`/rest/track-order/:id`), which the Verifier cannot test | Verifier |
| T-031 | injection contract | as T-005; in addition no request is named | operator, Analyzer |
| T-025, T-026, T-032 | marker file | the operator places a marker file on the target | operator, by design |
| T-037 | access request | the scenario names "GET and DELETE /api/BasketItems/:id", and the Verifier read only the DELETE | Verifier, fixed |
| T-038, T-039, T-041 | access request | the findings name only writes; the Verifier's proofs need a read of the resource or a write that creates one | Verifier, see point 4 |
| T-012 | write-injection proof | the proof would repeat the login POST | by design |

## Open points for the Analyzer

1. **Findings name no request.** `attack_steps` are filled for 2 of 90 findings and `verification_context` for 1 of 90 (T-001). The Verifier reads a request from `METHOD /path` in the scenario, the attack steps and the instance scenarios, and from `verification_context.variants[].request`. T-034's scenario names a file and line where the request belongs, and T-011's names none. e954cedc asks for `verification_context` on every finding that a request reaches (REQ-049). To check after the next Juice Shop run: do T-011 and T-034, or the findings that replace them, carry a variant request?

2. **Route references do not resolve yet.** In the old assessment 18 instances of 15 findings carry `route_ids`, T-034 among them; T-011 and T-031 carry none or empty lists. The attack surface published no IDs before e954cedc, so none of them resolved. The IDs are numbered per run and cannot be checked against the golden fixture: R-065 sits on T-005's instance in `routes/search.ts` in the assessment but is `GET /rest/admin/application-configuration` in the golden. The golden has 109 attack-surface entries with `route_ids` and no finding with any. To check after the next run: how many findings that a request reaches carry `route_ids` that resolve, and whether they name the right route (T-034: `POST /profile/image/url`).

3. **One handler for two registrations.** The attack surface merges both registrations of `POST /rest/user/data-export` (`server.ts:620` with `verifyImageCaptcha`, `server.ts:621` with `dataExport`) and keeps the notes of the first. A finding in `routes/dataExport.ts` (T-087) cannot be matched through the handler. Since e954cedc the entry lists the `route_ids` of both registrations, so a finding with resolving `route_ids` would still reach it.

4. **Access-control findings that name only writes.** T-038 (`PUT /rest/basket/:id/coupon/:coupon`), T-039 (three POSTs without authentication) and T-041 (`POST /api/Products`) name only the vulnerable write. The Verifier proves access control by comparing reads, or with a record it creates and reads back; it never changes a record it did not create. The read request of the same resource (for T-038 `GET /rest/basket/:id`) would let it plan such a proof. Undecided whether the assessment should name it, for example as a variant prerequisite, or whether the Verifier looks it up in the attack surface, as it already does for the POST that creates a record. The Verifier-side lookup needs no Analyzer change.

5. **Injection inputs only in prose.** T-005's scenario names `GET /rest/products/search?q=`. The operator still declares the tested input in the Verifier's scope file, which is a safety rule there, but a structured input in `verification_context` would let the Verifier propose that line. Point 1 covers this once the variants carry their inputs.

## Changes on the Verifier side

- Fixed: several methods before one path ("GET and DELETE /x") each name a request. T-037 now gets GET and DELETE, plus the creating `POST /api/BasketItems` as preparation, and is no longer blocked. Whether it confirms is open: a basket item has no text field that keeps the Verifier's marker, as T-027 showed.
- Fixed: the hint for missing request information no longer offers a scope entry for SSRF and similar classes, and says that `--source` helps only when the finding's file declares its route.
- Done: the Verifier reads the `route_ids` of findings and instances and resolves them in `attack_surface[].route_ids`, and it reads `registered:` as well as `handler:` in the attack-surface notes, so that a finding at a registration line keeps its route when the handler is imported. Assessments whose attack surface lists no IDs, such as the one above, give the same requests as before; the effect shows only with an assessment from e954cedc or later.
- Deferred: linking a finding to the routes whose registration calls a function from its file, read with `--source`. On the old assessment it linked 11 of the 14 findings without a request, but among the findings rated high or above it made only T-034 testable. Resolving route references from the assessment makes it unnecessary if point 2 holds.

## Next check

Run the current Analyzer on Juice Shop, then `appsec-verifier preflight --offline` with the same selection, and compare its `Not testable` list with the 13 findings above.
