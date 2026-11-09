# Assessment handoff to the Verifier: analysis and implementation plan

Status 2026-11-09: the new assessment confirms two losses of known route information in Analyzer. Preserve finding-level route references and publish referenced generated routes first, verify those repairs offline, then address remaining runtime-context gaps. The changes are planned, not implemented. The [new-assessment review](#new-assessment-review) and [implementation plan](#implementation-plan) below supersede the initial hypotheses where they differ.

## Initial assessment

Status 2026-11-09. Basis: `/home/mrohr/assessments/juice-shop-std/security-assessment.yaml` (Juice Shop 33518f5a, generated 2026-11-08 10:36 UTC, before e954cedc) and an AppSec Verifier run on its findings rated high or above, in which 13 findings were not testable. Analyzer code compared: `main` at 60276cd7.

### Initial summary

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

### Initial open points for the Analyzer

1. **Findings name no request.** `attack_steps` are filled for 2 of 90 findings and `verification_context` for 1 of 90 (T-001). The Verifier reads a request from `METHOD /path` in the scenario, the attack steps and the instance scenarios, and from `verification_context.variants[].request`. T-034's scenario names a file and line where the request belongs, and T-011's names none. e954cedc asks for `verification_context` on every finding that a request reaches (REQ-049). To check after the next Juice Shop run: do T-011 and T-034, or the findings that replace them, carry a variant request?

2. **Route references do not resolve yet.** In the old assessment 18 instances of 15 findings carry `route_ids`, T-034 among them; T-011 and T-031 carry none or empty lists. The attack surface published no IDs before e954cedc, so none of them resolved. The IDs are numbered per run and cannot be checked against the golden fixture: R-065 sits on T-005's instance in `routes/search.ts` in the assessment but is `GET /rest/admin/application-configuration` in the golden. The golden has 109 attack-surface entries with `route_ids` and no finding with any. To check after the next run: how many findings that a request reaches carry `route_ids` that resolve, and whether they name the right route (T-034: `POST /profile/image/url`).

3. **One handler for two registrations.** The attack surface merges both registrations of `POST /rest/user/data-export` (`server.ts:620` with `verifyImageCaptcha`, `server.ts:621` with `dataExport`) and keeps the notes of the first. A finding in `routes/dataExport.ts` (T-087) cannot be matched through the handler. Since e954cedc the entry lists the `route_ids` of both registrations, so a finding with resolving `route_ids` would still reach it.

4. **Access-control findings that name only writes.** T-038 (`PUT /rest/basket/:id/coupon/:coupon`), T-039 (three POSTs without authentication) and T-041 (`POST /api/Products`) name only the vulnerable write. The Verifier proves access control by comparing reads, or with a record it creates and reads back; it never changes a record it did not create. The read request of the same resource (for T-038 `GET /rest/basket/:id`) would let it plan such a proof. Undecided whether the assessment should name it, for example as a variant prerequisite, or whether the Verifier looks it up in the attack surface, as it already does for the POST that creates a record. The Verifier-side lookup needs no Analyzer change.

5. **Injection inputs only in prose.** T-005's scenario names `GET /rest/products/search?q=`. The operator still declares the tested input in the Verifier's scope file, which is a safety rule there, but a structured input in `verification_context` would let the Verifier propose that line. Point 1 covers this once the variants carry their inputs.

### Verifier changes recorded in the initial review

- Fixed: several methods before one path ("GET and DELETE /x") each name a request. T-037 now gets GET and DELETE, plus the creating `POST /api/BasketItems` as preparation, and is no longer blocked. Whether it confirms is open: a basket item has no text field that keeps the Verifier's marker, as T-027 showed.
- Fixed: the hint for missing request information no longer offers a scope entry for SSRF and similar classes, and says that `--source` helps only when the finding's file declares its route.
- Done: the Verifier reads the `route_ids` of findings and instances and resolves them in `attack_surface[].route_ids`, and it reads `registered:` as well as `handler:` in the attack-surface notes, so that a finding at a registration line keeps its route when the handler is imported. Assessments whose attack surface lists no IDs, such as the one above, give the same requests as before; the effect shows only with an assessment from e954cedc or later.
- Deferred: linking a finding to the routes whose registration calls a function from its file, read with `--source`. On the old assessment it linked 11 of the 14 findings without a request, but among the findings rated high or above it made only T-034 testable. Resolving route references from the assessment makes it unnecessary if point 2 holds.

## New-assessment review

The follow-up uses `/home/mrohr/assessments/juice-shop-std2/security-assessment.yaml`, generated 2026-11-09 at 06:00:37 UTC. Both assessments examine Juice Shop commit `33518f5a0911e25d9df747b1e70fb7af279a755c`. Analyzer code inspected: `11fcb79b`, including `e954cedc`; Verifier code inspected: `1ebe5b7`, including route-reference support from `d378b12`.

The old YAML SHA-256 is `435999d26f744c089bdd411bb1f3ea83f68d52db0faede53ed39468377c6b1e9`; the new YAML SHA-256 is `782075988e82549ede7da18b5bb32e1996bb12b15a97e082bcb5fe63bff78dfc`. These local directories are review evidence, not packaged fixtures. Finding IDs change between assessments; comparisons use the weakness and source location, not matching IDs alone.

Both files were loaded with the current Verifier and their runtime contexts validated. The review inspected saved analysis responses and route inventories and evaluated the Verifier's planning predicates. It did not execute `verify`, contact Juice Shop, call a model, or run a complete `preflight` command. No runtime exploitability is established.

| Measure | Old assessment | New assessment |
| --- | ---: | ---: |
| Findings | 90 | 112 |
| Findings with `verification_context` | 1 | 48 |
| Runtime variants | 1 | 68 |
| Attack-surface entries with `route_ids` | 0 of 113 | 113 of 113 |
| Findings with route references on the finding or its instances | 15 | 17 |
| High or Critical findings | 37 | 44 |
| High or Critical findings in a supported Verifier proof class | 19 | 23 |

Every published route reference in the new assessment resolves, and published entry points match the same run's route inventory. This does not establish completeness: references removed before publication and routes missing from the exported inventory cannot appear as dangling references.

### Finding-level route references are removed

The final loop in `merge_assessment` in [merge_threats.py](../../../scripts/model/merge_threats.py) removes `route_ids` from every finding after joining verification results. References on retained instances can survive, but a standalone finding may have no instances to carry them. In [test_multi_repo_builder.py](../../../tests/test_multi_repo_builder.py), `test_verification_findings_about_different_routes_on_one_line_stay_apart` explicitly expects the top-level references to disappear.

New T-036, about key and log file serving, comes from verification finding TCF-051. The saved `.test-case-pilot.json` gives it `R-004` and `R-005`. Both routes appear in the published attack surface, but T-036 carries neither reference and the Verifier finds no request. Restoring only those two known references to an in-memory copy makes the Verifier resolve `ALL /encryptionkeys/:file` and `ALL /support/logs/:file`. This establishes a lookup repair, not a working proof of the finding's claim.

### Generated CRUD routes are not published

`_generated_routes` in [case_candidates.py](../../../scripts/model/case_candidates.py) identifies routes registered by a resource generator and assigns IDs after the inventory's highest ID. Verification candidates can therefore know routes that the report's `.route-inventory.json` does not contain.

New T-050 comes from TCF-026, whose candidate identifies `R-130` as `PUT /api/Products/:id`, registered by the generator at `server.ts:501`. The report inventory ends at `R-120` and the published attack surface contains no `R-130`. Retaining the finding's reference alone would not repair this case: `keep_published_route_refs` in [build_threat_model_yaml.py](../../../scripts/model/build_threat_model_yaml.py) would still remove an unresolved reference.

Saved verification findings also reference unpublished generated routes `R-126`, `R-132`, `R-133`, `R-134`, and `R-152`. Preserve the identity and evidenced method/path of referenced routes across analysis and publication, including repository ownership, rather than assigning unrelated IDs during rendering.

### Runtime context improves but remains incomplete

Six new High or Critical findings in supported Verifier classes have no request its endpoint reader can resolve: T-001, T-034, T-035, T-036, T-037, and T-050. A missing request can be hidden by an earlier blocker, such as the marker-file requirement for T-036 or the operator-resource requirement for T-037. The same was true of old T-025, T-026, T-031, and T-032; the initial two-request-blocker count did not cover every missing request.

T-001 is a grouped scanner finding about caller-supplied owner IDs. T-034 and T-035 describe stored XSS in the administration page. T-036 and T-050 are verification findings; T-037 is a survey finding about key serving. Saved analysis responses for T-034, T-035, T-036, T-037, and T-050 already lack `verification_context`. No later context loss is demonstrated for those findings; the survey salvage fallback is not their established cause.

Several earlier request gaps are addressed. Old SSRF T-034 corresponds to new T-040, which names `POST /profile/image/url`, JSON input `imageUrl`, a listener prerequisite, and an expected callback. Old product-search SQL injection T-005 corresponds to new T-007, which provides the request, input `q`, query construction, processing, and comparison observations. Old data-export T-087 corresponds to new T-105, which names export and order-history requests with prerequisites and unknowns. Old template-injection T-031 corresponds to new T-032, which names `GET /profile` but explicitly records that the username write route and its validation were not served.

The existing [REQ-049 acceptance contract](../contracts/requirement-acceptance.md#req-049-prepare-targeted-runtime-checks) permits optional context and forbids invented runtime facts. Absence alone must not invalidate every finding. Obtain source-supported information where available and identify unresolved information explicitly.

### Verifier limits remain separate

The route-reference and method-list readers are implemented. Operator identities, injection contracts, marker files, and execution permission remain separate from assessment data. New T-031 supplies path inputs for NoSQL injection, but the Verifier's injection experiment contract accepts query, JSON, and form inputs, not path inputs. New T-027 describes a multipart ZIP upload; ordinary form submission and a read-marker proof do not establish support for that upload and write-traversal proof. The login SQL-injection proof remains blocked because it would repeat POSTs.

The initial proposal to add a GET for write-access findings is insufficient by itself. The proof needs a test resource, relevant identities, and observations establishing the claimed state change. The Verifier's `expand_variants` creates separate plans, and the controller selects each variant's request rather than treating all variants as one workflow. A setup or readback request in another variant therefore does not define a shared create/change/read sequence. Freely worded prerequisites also do not automatically become executable requests.

Under assumed availability of two normal identities, one privileged identity, a browser, a callback, and write permission, but without operator resource or injection contracts, the 23 supported High or Critical findings expand to 36 plans. Seventeen have no initial blocker; nineteen are blocked: four for missing requests, four for access-proof preparation, five for injection contracts, two for repeated writes, three for marker files, and one for an operator resource. These are conditional planning results, not configured accounts, granted permissions, or proof that the unblocked plans will succeed.

Some variants describe the same request and input with different wording. For example, T-007 has two product-search SQL variants that become separate plans. A later deduplication review should distinguish repeated descriptions from different hypotheses; matching method and path alone is insufficient to merge them safely.

## Implementation plan

Repair the two losses of already known information first. Verify the repair offline using existing fields before considering a larger YAML change. This plan records the intended work; it does not implement it or authorize another model-backed assessment.

1. **Preserve known route references.** Retain finding-level references through merging and final assembly. Preserve distinct route scopes when findings are joined, instance references, and the check that published references resolve. Update the test that currently requires top-level references to be stripped while retaining its assertion that findings about different routes stay separate.
2. **Publish referenced generated routes.** Carry already evidenced resource-generator routes into the attack surface with consistent IDs and repository provenance. Reuse established route data and deduplication rules. Consult [ARCHITECTURE.md](../../../ARCHITECTURE.md) before changing module ownership or dependencies. Do not infer a new route solely from a finding's prose or guess authentication properties.
3. **Verify both repairs offline.** Use the saved new assessment intermediates as local reproduction evidence without overwriting the original deliverables. Add small repository fixtures so regression tests do not depend on `/home/mrohr/assessments`. Cover a standalone finding retaining references, generated-route publication, multiple registrations, distinct route scopes, and explicit handling of unknown or mismatched references. Confirm T-036 and T-050 resolve to the correct requests through the current Verifier reader. Run affected producer and consumer tests, relevant schema and golden checks, and the required standalone offline gate for the eventual behavior change. Select tests through requirement bindings and reviewed routes; no whole-suite or live run is needed by default.
4. **Address remaining context omissions.** Re-evaluate missing requests after the route fixes. Trace scanner, survey, and verification paths separately. Within existing authorized analysis calls and correction handling, obtain supported inputs, prerequisites, and observations where available; make unresolved information explicit. Preserve valid findings and compatibility with older assessments lacking context. Additional model calls or a changed required outcome need a separate requirement and authorization decision.
5. **Handle Verifier proof extensions separately.** Prioritize path-input injection, multipart uploads with a suitable traversal proof, and multi-request state-change proofs by the findings that need testing. Define each proof and its limits before asking Analyzer for additional fields. Review duplicate runtime variants after the information-loss fixes, preserving distinct evidence and hypotheses.

## Verification status

The initial offline review established schema-readable input, resolvable published references, the two information-loss paths, and conditional planning blockers. It included the in-memory T-036 reference restoration and inspection of T-050's generated-route candidate. No source or saved assessment was changed during that review.

## Local implementation, 2026-11-09

The implementation is on `fix/verifier-assessment-handoff`, based on `acf11118`, in the separate worktree `/tmp/appsec-analyzer-verifier-handoff`. It fixes existing REQ-014 and REQ-049 behavior without changing the public schema, adding model calls, or running another assessment.

| Plan item | Implemented behavior and limits |
| --- | --- |
| 1. Route references | Merging retains top-level references, including standalone verification findings. Existing publication still removes references whose routes are absent. Different route scopes remain distinct. |
| 2. Generated routes | Static route IDs are unique across repositories. Generated IDs follow all static IDs. Reporting consumes these analyzed inventories instead of rescanning; source locations are qualified, and duplicate endpoint rows retain every registration's source. Generated-route authentication and authorization remain unknown. |
| 3. Offline verification | Synthetic single- and multi-repository fixtures exercise extraction, generated-route planning, publication, schema validation and reference resolution. Negative cases reject duplicate or malformed IDs and sources outside admitted repositories. Saved Juice Shop evidence also passes the current Verifier reader in a route-only replay described below. |
| 4. Missing context | Existing survey, investigation and open-review instructions now require a final check of request, input, controls and write/read links. Their normalizers preserve supplied context and mark omitted context with empty variants and an explicit unresolved reason. The final survey fallback records removed invalid context as a gap. This does not establish that future model responses will supply every missing fact. Scanner-only findings retain their existing evidence and links; no runtime request is inferred from a scanner rule. |
| 5. Verifier extensions | No new proof classes were implemented. The follow-up scope below separates reader repair from new target-contact and proof behavior. Near-duplicate variants retain distinct hypotheses and evidence; existing exact-payload deduplication remains in effect. |

The route-only replay reads the saved report inventory, verification findings and candidate sidecars, carries 26 candidate-backed generated routes through `publication_inventories` and `build_attack_surface`, and restores the saved verification references on an in-memory copy. The copied YAML passes Analyzer schema validation and the Verifier's `read_assessment`. No restored reference is removed as unresolved. The original YAML retains SHA-256 `782075988e82549ede7da18b5bb32e1996bb12b15a97e082bcb5fe63bff78dfc`.

| Finding | Before | After, using the current Verifier reader |
| --- | --- | --- |
| T-036 | No endpoint | `ALL /encryptionkeys/:file`, `ALL /support/logs/:file` |
| T-050 | No endpoint | `PUT /api/Products/:id`, plus three unrelated SecurityQuestions hints from the same registration line |

The temporary replay script is `/tmp/appsec-verifier-handoff-replay.py`; its copied YAML and JSON result are under `/tmp/appsec-verifier-handoff-replay/`. This is a replay of the route handoff, not a complete pipeline rerun: the original combined-source directory no longer exists. No target or model was contacted, and no exploitability claim follows.

The extra T-050 hints come from `appsec_verifier/endpoints.py::finding_endpoints`: after resolving explicit route IDs, it also matches every entry sharing a handler or registration location, then caps the result at four. Resource generators register several resources at one location. The reader should use this location heuristic only where explicit request or route evidence does not already resolve the finding; preparation routes should remain a separate, resource-specific decision. Add a regression with two generated resources at one line before changing this behavior. Analyzer must retain the true registration instead of hiding evidence to influence the heuristic.

### Implementation checks

| Check | Result |
| --- | --- |
| Context, merge, investigation and planning tests | 408 passed |
| Route publication and attack-surface tests | 18 passed |
| Export consumers and additional invalid-route cases | 56 passed |
| Selected single- and multi-repository report runs and source-boundary cases | 5 passed |
| Generated-route controller regression | 1 passed; the existing fake architecture first needed its browser user and interaction restored to satisfy the current flow contract. The same fixture failure was reproduced on unchanged main. |
| `make check-analyzer BASE=acf11118` | Initial invocation: specification and lint checks passed; 1,105 public contract cases passed and seven failed because the sandbox's `/tmp/.git` placeholder made temporary outputs appear inside a checkout. All seven then passed outside the sandbox, with the last four repeated without concurrent sandbox processes. The remaining gate command was run separately: 168 passed, including prompt, documentation and distribution checks. The original Make invocation exited nonzero; it was not rerun wholesale. |
| Final specification, Ruff lint/format, diff and documentation-link checks | Passed |
| Golden replay | `test_replay_zero_drift_all_stages` skipped because the ignored `_last-run` fixture is absent. No golden success is claimed. |

No whole-suite target, full controller suite, live assessment, target pentest or model-backed qualification ran. The improved instructions remain unqualified on a new live assessment. The existing source and runtime-context validation still rejects unserved, stale or malformed evidence; no check was weakened to obtain these results.

### Verifier follow-up scope

The Verifier's [AGENTS.md](/home/mrohr/appsec-verifier/AGENTS.md) requires agreed requirement wording before a new probe class, changed target contact or new proof behavior. The following are drafts for that separate decision; this implementation neither approves them nor changes Verifier code.

- **Verify injection through path inputs.** Operators can test an evidenced path parameter using repeated baseline and matched control observations. Encode only the selected parameter, retain the rest of the route, enforce destination and path scope after substitution, and require a response-field contrast rather than reflected input or timing alone.
- **Verify uploaded archive traversal.** Operators can test an evidenced multipart archive upload using only a designated test location and marker. Require explicit write authorization, bounded file content and archive entries, evidence linking the upload to the marker outside the intended extraction directory, and a defined cleanup procedure. A successful upload or a read-only traversal marker is insufficient proof.
- **Verify state changes across requests.** Operators can test an evidenced create/change/read sequence on their own test resources with named identities. Require a baseline, ownership and identity contrast, readback that establishes the claimed state change, explicit write authorization and cleanup. Requests in separate runtime variants do not implicitly share state or become one workflow.

These extensions would send additional or different requests to the target, can modify test data, and may increase model and request costs. The simpler current option is to retain explicit blockers and perform those checks manually under the operator's authorization. They need proof contracts and negative tests in Verifier before any additional Analyzer fields are proposed.
