# Aspect test cases for full assessments

Status: draft proposal, not implemented. Nothing in this document describes current behavior unless it says so.

## Problem

The full assessment describes its model analysis as STRIDE per component. In practice it is an evidence-based security code review whose findings receive a STRIDE category afterwards.

Two saved Juice Shop assessments show this. On 2026-10-18, 72 of 87 findings came from the STRIDE model step; all 72 carried a CWE and a `file:line` location, and 4 were marked as architectural violations. On 2026-10-16, the figures were 58 of 75, 58 of 58, and 4. The remaining findings came from deterministic scanners.

The model step finds real weaknesses that no scanner rule can express, for example a wallet top-up that trusts a client-supplied amount or a password change without the current password. Three properties are missing, however:

1. Coverage is not visible. A report cannot say which questions were asked about authentication and which were answered.
2. The model step has no deterministic follow-up. A model claim is not re-checked by code, and a confirmed weakness is not searched for in sibling locations.
3. The STRIDE label is partly cosmetic. For 71 of the 95 source-scanner rules, `merge_threats._AUTHZ_TO_STRIDE` has no entry, so their findings default to Tampering.

## Proposal

Replace open STRIDE prompting with named test cases grouped by security aspect. A test case is an assignment with an objective: deterministic pre-checks supply starting points, the model investigates within the objective with room for its own judgment and search, and deterministic post-checks test the model's claims. STRIDE remains a tag on each test case and a grouping view in the report.

The aspect vocabulary starts from the `domain` field of `data/architecture-coverage-rules.yaml` and is adjusted where the catalog review below found gaps. The catalog covers all existing rules from the start; model-backed test cases are introduced aspect by aspect, as described under Rollout.

Three elements keep the assessment open to weaknesses nobody anticipated: the model's freedom inside each test case, an open review per component with its own budget share, and application-specific test cases the model derives from business invariants. The existing abuse cases remain for attack chains across aspects.

## Test case definition

A catalog test case is a plugin-owned, versioned YAML entry. Repository content cannot define, select, or disable catalog test cases.

```yaml
id: TC-AUTHZ-01
title: Object access checks the owner
aspect: AuthZ
stride: [Elevation of Privilege]
cwe: CWE-639
mode: seeded
objective: >
  Determine whether every access to user-owned objects in this component is
  bound to the authenticated caller or tenant.
applies_when:
  - route_inventory: component has routes with an object identifier parameter
starting_points:
  rules: [AUTHZ-001, AUTHZ-002, AUTHZ-301]
  facts: [route_inventory.missing_authz_suspect, route_inventory.authn_signal]
guidance: >
  Start with the candidates. Also check other entry points of the component that
  reach the same data, such as WebSocket handlers, GraphQL resolvers, jobs, or
  exports. Consider compensating controls such as ORM scopes, policies, row-level
  security, or a gateway. Reject candidates that are public by design, with evidence.
scope: component
evidence:
  finding: request input, data access, and the location where the ownership check is missing
  control: location of the ownership comparison
post:
  - route-registered
  - handler-chain-lacks-guard: ownership
  - variant-search: same data-access pattern in other handlers of the component
references: [OWASP API1:2023, OWASP ASVS authorization]
fixtures: tests/fixtures/test-cases/TC-AUTHZ-01/
```

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier. Never renamed or reused. |
| `aspect`, `stride`, `cwe` | Classification. `stride` drives only the report view and the Threat Dragon export. |
| `mode` | `rules`: outcome from the rules, no model call by default. `seeded`: rules seed a model investigation. `model`: little or no rule support. |
| `objective` | The question the test case must answer for the component. |
| `applies_when` | Deterministic applicability from existing signals. A test case that does not apply makes no model call. |
| `starting_points` | Scanner rules and facts that seed the investigation. They are not a limit. |
| `guidance` | What to consider: variants, other entry points, compensating controls, and rules carried over from the current STRIDE policy. |
| `scope` | The area the model may search beyond the starting points, bounded as described under Execution. |
| `evidence` | The locations required for a finding and for a confirmed control. |
| `post` | Fixed deterministic checks run on the model's claims. |
| `fixtures` | Code with and without the weakness, used to test the test case itself. |

The rules of the current STRIDE policy move into the `guidance` of the matching test cases instead of being lost: trace persisted input to its sink, give input, sink, and connection for injection CWEs, and cite the consumer that trusts an identity when claiming spoofing.

## Execution

1. Deterministic scanners and inventories run once per assessment, as today.
2. For each applicable test case, code builds the starting candidates from the pre-check results. A test case whose `applies_when` fails records `not_applicable` and makes no model call.
3. The model works on the objective. It may reject starting candidates with evidence, add candidates of its own, and follow data flows beyond them within `scope`. Each candidate records `origin: pre-check` or `origin: model`. Additional searches are bounded and recorded in the same way as today's `discovery_escapes[]`, with a reason and the searched paths.
4. Weaknesses the model notices while working on a test case are assigned to the matching test case or reported as outside the test catalog.
5. Post-checks run on every finding and control claim. A variant search adds sibling locations as instances; it never creates a finding without model review of each instance.

A test case in `rules` mode skips steps 3 and 4. Its outcome follows from its rules: a violated rule is a finding, and a rule whose expected pattern is present is deterministic control evidence. A model context review runs only where the operator enables it, for example to judge whether a flagged Dockerfile builds a production image; it can add context but cannot remove the finding.

Post-checks are fixed functions with typed parameters. The model supplies values such as a route ID, file, line, or symbol; code validates them against the admitted source scope. The model never writes regular expressions, queries, or scripts that the assessment executes. Existing code that can serve the first post-checks: `route_inventory.py`, `handler_resolver.py`, `flow_route_auth.py`, and `authz_confirm.py`.

Each post-check returns one of three results:

| Result | Effect |
| --- | --- |
| `confirmed` | The claim stands with deterministic confirmation. |
| `contradicted` | The claim becomes `undecidable` and the report gives the reason. |
| `not_verifiable` | The script cannot judge the claim, for example a route the inventory does not know. The claim keeps its outcome and is labelled as evidenced by model review only. |

Without the third result, post-checks would downgrade exactly the candidates the model found on its own. Frequent `not_verifiable` results also show where a scanner or inventory needs to improve.

## Outcomes

| Outcome | Meaning |
| --- | --- |
| `finding` | Evidence shows the weakness and no post-check contradicts it. |
| `control` | Evidence shows the protecting control at a cited location and no post-check contradicts it. |
| `undecidable` | The source or a post-check could not settle the question. The reason is reported. |
| `not_applicable` | `applies_when` failed. |
| `disabled` | An operator disabled the test case. |

An unchecked, undecidable, or disabled test case is never reported as a control. A control that no post-check confirms is labelled model-evidenced and is prioritized in the evidence verifier's sample.

Removing a deterministic finding requires more than a model answer. If a scanner rule reports a location and the model answers `control` for it, the finding is removed only when a post-check confirms the control. A `not_verifiable` result is not enough; the finding stays and records that the model disagreed.

## Open review and application-specific test cases

After the test cases, an open review runs per component. It receives the test case results and the confirmed business context, including the use case and declared harm, and looks for evidence-supported weaknesses that no test case covers: business rules, state transitions, workflows, race conditions, quantity and price manipulation, and misuse of features. The same evidence rules apply. The report lists these findings as outside the test catalog.

A share of the model budget is reserved for the open review. Otherwise the test cases could consume the budget and the open review, which finds most business-logic weaknesses, would be cut first.

The model can also derive application-specific test cases. It identifies business invariants from the context and the code, for example "a balance increases only through a confirmed payment" or "an order belongs to exactly one customer", and writes a test case for each. These test cases receive run-specific IDs such as `TC-APP-003`, use the same outcomes and evidence rules, and run only fixed post-checks. They cannot disable, replace, or change catalog test cases. The existing `appsec-abuse-case-deriver`, which proposes up to three application-specific abuse cases at thorough depth, is the starting point.

Weaknesses that the open review finds repeatedly become candidates for new catalog test cases. During the pilot, the number of open-review findings in the pilot aspects measures how complete the catalog is.

## Merging findings

Today, `scripts/model/merge_threats.py` collects STRIDE results and scanner findings into one list, removes exact duplicates by CWE, STRIDE category, component, file, line, and title keywords, joins findings at the same line and CWE family, and folds systemic findings through `data/consolidation-groups.yaml`. Remaining candidates are grouped by CWE and STRIDE category, with a secondary endpoint grouping, and the `appsec-threat-merger` model step decides whether to merge them.

The STRIDE category in these keys has caused duplicates. The code records two Juice Shop cases: the same remote code execution at `routes/b2bOrder.ts:23` shipped as two Critical findings because two component analyzers chose Tampering and Elevation of Privilege, and a mass-assignment and an admin-role finding on the same `POST /api/Users` stayed apart because their CWE and STRIDE pairs differed. The same-line key and the endpoint grouping were added to repair these cases.

With test cases, STRIDE leaves all merge keys. The rules become:

| Case | Rule |
| --- | --- |
| One test case hits the same object several times | One finding with `instances[]`. The test case states what makes two hits the same defect: the control scope, the data object, or the sink. `consolidation-groups.yaml` gains a `test_case_id` predicate; no second consolidation mechanism is needed. |
| A scanner rule is a starting point of a test case | The rule hit becomes evidence on the test case result instead of a separate finding. |
| Two test cases hit the same location | One finding listing both test case IDs when one fix resolves both; otherwise separate findings. The same-line key stays as a safety net across all sources. |
| A weakness in one aspect enables one in another | No merge. The findings stay separate and are linked through the existing `compound_chain_ids`. |
| An open-review finding matches a test case finding | One finding; the test case ID takes precedence and `merged_from` keeps the open review as a source. |
| Ambiguous candidates | The model merge step remains, but candidates are grouped by test case or CWE family and endpoint, not by STRIDE category. |

A finding from another source stays when the matching test case is disabled; it then carries no test case ID.

During the pilot, the report shows the merged result and `merged_from` keeps every source. A separate comparison file records which findings in the pilot aspects the STRIDE step and the test cases each found, which is the input for the first exit criterion below.

A finding linked to two test cases counts once in the severity totals and once per test case in the test case table. The report states this next to the table so that the differing sums do not look like an error.

## Disabling test cases

Operators can disable individual test cases and individual scanner rules. Every disable needs a reason.

```yaml
# Operator-owned scan profile
test_cases:
  disable:
    - id: TC-AUTHN-05
      reason: Password recovery is handled by the external identity provider (ADR-012).
```

An organization profile can list test cases as required. A scan profile cannot disable a required test case; the run refuses before any model call and names the conflict. This follows the existing rule for actors, where an organization-level disable cannot be re-enabled by a lower layer.

Disabling reduces coverage; it does not hide results. Under REQ-018, configuration must not suppress evidence-supported findings. A finding that another test case, the open review, an abuse case, or a scanner rule produced therefore stays in the report even if it matches a disabled test case. The report lists every disabled test case with its reason and the profile that disabled it.

Repository files cannot disable test cases, because analyzed code could otherwise hide its own weaknesses.

## Report and exports

Each finding names the test cases and scanner rules behind it, for example `Test cases: TC-AUTHZ-01 · Rules: AUTHZ-002, AUTHZ-301`, or is marked as found outside the test catalog. Each ID links to an anchor in a new report appendix. Findings and controls that only model review supports carry that label.

The appendix lists every test case of the catalog version used and every application-specific test case of the run: title, objective, evidence rule, outcome per component, and disable reason where applicable. The report stays self-contained, so the links also work in PDF and HTML exports outside the repository.

`threat-model.yaml` gains `test_case_ids`, `rule_ids`, and the candidate origin per finding and a `test_case_results` list. SARIF uses the test case ID as `ruleId` and carries the definition in `rules[]`.

## Pipeline integration and user-facing output

STRIDE currently names the analysis stage throughout the live progress, the completion summary, the report, and the exports. Once test cases drive the analysis, these surfaces must describe aspects and test case results instead. STRIDE stays only where it classifies a finding or where an export format requires it.

| Surface | Current output | Proposed output | Producer |
| --- | --- | --- | --- |
| Live progress | Stage `STRIDE`, `Analyzing all STRIDE categories`, `3/6 STRIDE jobs` | Stage `Security checks`, per component `Authorization: 5/7 test cases · 2 findings · 1 undecidable`, then `Open review` | `appsec_analyzer/assessment/console.py`, `scripts/renderers/render_progress.py` |
| Progress events | `STRIDE_PROGRESS`, `STRIDE_STALE`, `STRIDE_COMPONENT_TIMEOUT` | New test case and open-review events; the STRIDE events remain only for aspects still analyzed by the STRIDE step | `scripts/runtime/write_stride_progress.py`, `scripts/orchestrator/stride_dispatch_waves.py` |
| Run header and model lineup | Role `STRIDE`, option `--stride-model` | Role `Security checks`; the option keeps working as an alias during the transition | `scripts/runtime/model_lineup.py`, `appsec_analyzer/cli.py` |
| Completion summary | `N STRIDE-analyzed`, phase `STRIDE Enumeration` | `Test cases: 38 run · 9 findings · 21 controls · 5 undecidable · 3 not applicable · 2 disabled`, one line per aspect, plus open-review findings | `scripts/renderers/render_completion_summary.py` |
| Report scope text | `analysed with full STRIDE`, `Max 2 threats per STRIDE category` | `checked with N applicable test cases and an open review`; depth selects test cases instead of capping findings per category | `scripts/renderers/pregenerate_fragments.py`, `scripts/renderers/compose_threat_model.py` |
| Per-component coverage | `STRIDE Coverage: Spoofing: … · Tampering: …` | Aspect coverage matrix: components by aspects, each cell with outcome counts and a link to the appendix | `data/sections-contract.yaml`, `scripts/renderers/compose_threat_model.py` |
| Finding details | `STRIDE: Elevation of Privilege` in the references | `Test cases` and `Rules` with links, or `outside the test catalog`; STRIDE as a classification tag next to CWE | `scripts/renderers/compose_threat_model.py`, `scripts/renderers/walkthrough_renderer.py` |
| Top threats table | STRIDE letter column with legend | Aspect column; STRIDE letter moves into the description tag | `templates/fragments/top-threats.md.j2` |
| Figure 1 | Per-element STRIDE strip labelled `STRIDE-per-element: filled = threats found in that class` | Per-component outcome badge (findings, controls, undecidable); the per-element claim is removed because no per-element analysis takes place | `scripts/renderers/figure1_dfd.py` |
| SARIF | Rule name `<stride>/<title>`, STRIDE tag | `ruleId` is the test case ID; tags carry aspect and STRIDE | `scripts/exporters/export_sarif.py` |
| Threat Dragon | Diagram type and threat type STRIDE | Unchanged; Threat Dragon expects STRIDE types, so every test case keeps a STRIDE tag | `scripts/exporters/export_threat_dragon.py` |
| `threat-model.yaml` | Required `stride` per threat | `stride` stays required; `aspect`, `test_case_ids`, `rule_ids`, and candidate origin are added | `schemas/threat-model.output.schema.yaml` |

Internal names such as `stride_outputs.py`, `appsec-stride-analyzer-v2`, and `APPSEC_STRIDE_MAX_ATTEMPTS` are not visible to users. They are renamed only when the STRIDE step itself is retired, so the pilot does not mix a rename with a behavior change.

The current Figure 1 legend already claims STRIDE-per-element analysis, which the assessment does not perform. That label is misleading today, independently of this proposal.

During the pilot, the new output is opt-in through a scan profile setting. A default run keeps today's output, so no report mixes two presentations without explanation. A pilot run shows the aspect matrix for the `rules` test cases and the pilot aspects and labels the remaining aspects as `model review (STRIDE)`. The setting is removed when all aspects have test cases or the pilot ends.

## Testing the test cases

Every catalog test case needs fixtures with and without the weakness, as the deterministic rules already have. An offline replay checks the deterministic parts. A recorded-response eval measures per test case how often it finds the seeded weakness, how often it reports one that is not there, and how often findings rest on model-added candidates rather than starting points.

## Existing rule inventory

The catalog does not start from nothing. The assessment already ships 167 deterministic rules, 14 abuse cases, and model checklists:

| Source | Rules | Content |
| --- | --- | --- |
| `data/config-iac-checks.yaml` | 57 | Dockerfile, GitHub workflows, Compose, Dependabot, Renovate, npm, Kubernetes, Helm, Terraform, and 16 coding-agent configuration checks |
| `data/source-auth-checks.yaml` | 57 | 21 authentication and authorization rules, 29 injection rules in four weakness groups across seven languages, 7 mobile rules |
| `data/crypto-checks.yaml` | 25 | Weak hashes, non-cryptographic randomness, bcrypt cost, ECB mode, and hand-rolled XOR, mostly per language |
| Other source rules | 10 | `AUTHN-001`, `AUTHN-002`, `AUTHZ-202`, `AUTHZ-301`, `AUTHZ-302`, `INJ-NODE-006` to `-008`, and the `INJ-LLM` and `AUTHZ-LLM` rules defined in code |
| `data/architecture-coverage-rules.yaml` | 15 | 6 hard rules and 9 hypotheses with a `domain` field |
| `data/abuse-cases/` | 14 | 7 technical attack chains and 7 business abuse cases |
| Model lenses | about 100 rows | OWASP LLM Top 10, OWASP ASI Top 10, SPA, supply chain, MCP, and RAG checklists |

## Catalog review

Converting this inventory one-to-one into test cases would produce a catalog nobody can read and a model call for every rule. The review applies seven decisions.

1. A test case is a security question, not a detector. Language variants and duplicate detectors become starting points of one test case. SQL injection has nine rules (`INJ-001`, six language variants, and two mobile SQLite rules); they all seed one test case.
2. Not every test case needs a model. Each test case declares a mode. `rules` test cases take their outcome from their rules and make no model call by default; a rule whose expected pattern is present yields deterministic control evidence, the strongest kind. `seeded` test cases use rules as starting points and let the model judge reachability, data flow, and compensating controls. `model` test cases have little or no rule support and rely on the model within their objective.
3. Vague questions are not test cases. "Input validation is broken" (`ARCH-INPUT-001`) yields generic findings; it remains a starting point for specific test cases.
4. Each question has one owner. Secrets, transport encryption, password storage, and file paths were spread across several aspects in the first draft; each now belongs to one test case, and other test cases reference it in their guidance.
5. Business abuse cases stay as they are. The seven `AC-B` cases already ask business-level questions such as approval bypass, exceeded limits, and withdrawn rights. The catalog adds only one business-logic test case for server-side business values, so the two do not duplicate each other. Technical abuse cases link test cases into attack chains, for example `AC-T-002` across object ownership and mass assignment.
6. The aspect list needs four additions and one removal. Crypto, Availability, BusinessLogic, and DevTooling have no aspect today, although Denial of Service findings occur and 16 rules check coding-agent configuration. RealTime is an entry point, not an aspect; WebSocket concerns belong in the guidance of the authentication, authorization, and input test cases.
7. Duplicate detectors are resolved as shared starting points. `IAC-011` and `ARCH-SUPPLY-001` both detect unpinned actions, `AUTHZ-005` and `ARCH-JWT-001` both detect missing JWT algorithm pinning, and `AUTHZ-008` and `ARCH-AUTHN-001` both detect unauthenticated routes. Under one test case they produce one result.

Two existing rules are questionable as findings. `IAC-003` reports a missing container health check as Denial of Service; that is operational hardening rather than a weakness an attacker can use, so the catalog does not map it to a test case. The Dependabot and Renovate rules report a missing practice rather than a vulnerability; they stay as a `rules` test case, but their severity should be reviewed against the separate supply-chain practice findings.

The largest gaps without any deterministic rule are cross-site scripting, the most frequent Juice Shop finding class, file uploads and archive extraction, deserialization, excessive data in responses, and rate limiting. These test cases start in `model` mode and are the first candidates for new rules.

## Catalog structure

The catalog has 45 test cases in 14 aspects: 9 in `rules` mode, 23 in `seeded` mode, and 13 in `model` mode. Each entry carries its CWE and STRIDE tags in the YAML definition.

| Aspect | ID | Question | Mode | Starting points today |
| --- | --- | --- | --- | --- |
| IAM | TC-AUTHN-01 | Sensitive routes, operations, and channels require authentication | seeded | route inventory, AUTHZ-008, ARCH-AUTHN-001, ARCH-MGMT-001 |
| IAM | TC-AUTHN-02 | Tokens are verified with a pinned algorithm and a server-held key | seeded | AUTHZ-005, -006, -007, -103, -201, -GO-001, -CS-001, -PHP-001, -RB-001, ARCH-JWT-001 |
| IAM | TC-AUTHN-03 | Token expiry, issuer, and audience are validated | seeded | AUTHZ-009, -104, -CS-003 |
| IAM | TC-AUTHN-04 | Passwords are strong and stored with an adaptive hash | seeded | AUTHN-002, CRYPTO-001 family, CRYPTO-003 |
| IAM | TC-AUTHN-05 | Recovery, re-authentication, and login responses resist takeover and enumeration | model | AUTHN-001 |
| SessionMgmt | TC-SESSION-01 | Session tokens are protected in storage, transport, lifetime, and logout | model | ARCH-COOKIE-001 |
| AuthZ | TC-AUTHZ-01 | Object access checks the owner | seeded | AUTHZ-001, -002, -301, route inventory, ARCH-BOLA-001 |
| AuthZ | TC-AUTHZ-02 | Privileged operations check the role or permission | seeded | route inventory, AUTHZ-302, ARCH-AUTHZ-001 |
| AuthZ | TC-AUTHZ-03 | Request bodies cannot set privileged fields | seeded | AUTHZ-003, -004, -101, -102, -202, -PHP-002, -RB-002 |
| AuthZ | TC-AUTHZ-04 | Tenant data stays isolated | model | capability signals (tenant identifier) |
| AuthZ | TC-AUTHZ-05 | Authorization the client interface implies is enforced on the server | model | none |
| InputVal | TC-INPUT-01 | Database queries are parameterized | seeded | INJ-001, six language variants, MOBILE-AND-001, MOBILE-DART-001, ARCH-SQLI-001 |
| InputVal | TC-INPUT-02 | NoSQL predicates are not built from input | seeded | INJ-NODE-006 |
| InputVal | TC-INPUT-03 | Input cannot reach OS commands, code evaluation, or template compilation | seeded | INJ-002, six language variants, INJ-NODE-007, INJ-NODE-008 |
| InputVal | TC-INPUT-04 | Output is encoded for its context, including DOM sinks | model | ARCH-XSS-001, ARCH-XSS-002 |
| InputVal | TC-INPUT-05 | Outbound requests cannot be steered to unintended destinations | seeded | INJ-003, six language variants |
| InputVal | TC-INPUT-06 | Parsers reject external entities and unsafe deserialization | seeded | INJ-005 |
| InputVal | TC-FILE-01 | File paths stay within intended directories and files are served only as intended | seeded | INJ-004, six language variants |
| InputVal | TC-FILE-02 | Uploads and archives are type-checked, size-limited, and extracted safely | model | none |
| DataProt | TC-DATA-01 | Responses contain only intended fields | model | none |
| DataProt | TC-DATA-02 | Sensitive data is protected at rest | seeded | IAC-092, MOBILE-AND-002, MOBILE-DART-002, MOBILE-IOS-001, MOBILE-RN-001 |
| DataProt | TC-DATA-03 | Secrets are not embedded in code, client bundles, or deployment files | seeded | ARCH-SECRET-001, IAC-023, IAC-083, IAC-093 |
| DataProt | TC-DATA-04 | Data in transit is encrypted and kept out of URLs | seeded | ARCH-TLS-001, IAC-084, IAC-086, IAC-094 |
| Crypto | TC-CRYPTO-01 | Cryptographic primitives are current and not hand-rolled | seeded | CRYPTO-001 family, CRYPTO-004, CRYPTO-JAVA-003, CRYPTO-HOMEGROWN-XOR |
| Crypto | TC-CRYPTO-02 | Secrets and tokens use cryptographic randomness and are not derived from public data | seeded | CRYPTO-002 family |
| FrontendSec | TC-FRONT-01 | Browser protections are configured: CSP, framing, CORS, subresource integrity, message origins | model | ARCH-CORS-001 |
| FrontendSec | TC-MOBILE-01 | Mobile WebViews and inter-process interfaces do not expose privileged functions | seeded | MOBILE-AND-003 |
| Audit | TC-AUDIT-01 | Security-relevant actions are logged, and logs and errors do not leak data | model | IAC-014 |
| Availability | TC-AVAIL-01 | Expensive and authentication endpoints are rate-limited and input-driven work is bounded | model | none |
| BusinessLogic | TC-LOGIC-01 | Business values and workflow order are decided on the server | model | none; business abuse cases AC-B-001 to -007 |
| AI | TC-AI-01 | Untrusted content cannot steer the model into privileged actions | model | AC-T-007, LLM lens |
| AI | TC-AI-02 | Model output is validated before it reaches interpreters, browsers, or structured sinks | seeded | INJ-LLM-001, -002, -003 |
| AI | TC-AI-03 | Model-selected tools, objects, and destinations are authorized and restricted | seeded | AUTHZ-LLM-001, INJ-LLM-004, MCP lens |
| AI | TC-AI-04 | Retrieval and memory respect the caller's access | model | RAG lens |
| Infra | TC-INFRA-01 | Containers and pods run with least privilege | rules | IAC-002, -004, -020, -021, -022, -080, -081, -082, -085 |
| Infra | TC-INFRA-02 | Data and admin services are not publicly exposed | rules | IAC-024, -090, -091, -095, -096 |
| Infra | TC-INFRA-03 | Service identities and cloud permissions follow least privilege | seeded | IAC-097, ARCH-DBSEP-001 |
| SupplyChain | TC-SUPPLY-01 | Build inputs are pinned and locked | rules | IAC-001, IAC-011, IAC-050, ARCH-SUPPLY-001 |
| SupplyChain | TC-SUPPLY-02 | Dependencies are updated automatically | rules | IAC-030 to -035 |
| SupplyChain | TC-SUPPLY-03 | Install and build scripts cannot run untrusted code | rules | IAC-005, IAC-051 |
| SupplyChain | TC-SUPPLY-04 | Released artifacts are signed and described by an SBOM | rules | IAC-040, IAC-041 |
| SupplyChain | TC-CI-01 | Workflows run with least-privilege tokens | rules | IAC-010, IAC-015 |
| SupplyChain | TC-CI-02 | Untrusted event data and forks cannot execute in privileged workflows | seeded | IAC-012, IAC-013 |
| DevTooling | TC-DEVAGENT-01 | Coding agents run sandboxed and with approvals | rules | IAC-060, -061, -063, -064, -066, -067, -068, -071 |
| DevTooling | TC-DEVAGENT-02 | Agent tools, MCP servers, hooks, and permission rules are not auto-trusted or over-broad | rules | IAC-062, -065, -069, -070, -072, -073, -074, -075 |

Every existing rule appears as a starting point except `IAC-003`, for the reason given in the review. The 13 `model` test cases are reported as such; the SPA and other lens patterns are model guidance, not executed rules, so they do not count as starting points.

## Rollout

1. Catalog and rule-backed results. Define all 45 test cases, map every rule as a starting point, and run the 9 `rules` test cases. This phase adds no model calls, gives every scanner finding a test case and a consistent STRIDE tag, and removes the Tampering default for unmapped source rules.
2. Model pilot. Run the `seeded` and `model` test cases for the pilot aspects beside the STRIDE step, with the open review and the exit criteria below. The pilot aspects are a product decision; the recommendation is IAM, SessionMgmt, AuthZ, InputVal, and DataProt, which together cover the most frequent finding classes and contain both strong and weak rule support.
3. Remaining aspects. Crypto, FrontendSec, Audit, Availability, BusinessLogic, AI, and the seeded supply-chain and infrastructure test cases follow once the pilot decision is positive.

`authnz-review` already runs `route_inventory.py`, `source_auth_scanner.py`, and `authz_confirm.py` before its agent. The authentication and authorization part of the pilot can start from that pipeline, split the agent's open steps into test cases, and add the post-checks.

## Compatibility and cost

During the pilot, the STRIDE step keeps running for all aspects, and its findings in the pilot aspects are compared with the test case results instead of being removed.

REQ-004 currently requires all six STRIDE categories for every component. Its acceptance text gains a pilot exception. The report schema and saved assessments gain new optional fields; older assessments remain readable without test case results.

Model calls grow with the number of applicable test cases and candidates, and the open review adds a reserved share. The total cost is unknown until measured. For reference, the Juice Shop thorough assessment on 2026-10-17 cost USD 28.01 and standard USD 15.85, mostly for STRIDE.

## Risks

| Risk | Rating | Reason | Mitigation |
| --- | --- | --- | --- |
| Fewer weaknesses found | High | Open STRIDE prompting finds logic flaws such as a client-supplied wallet amount. Narrow test cases would see only what their starting points show. | Starting points are not limits; the model may add candidates and search within each objective. The open review has its own budget share. Application-specific test cases cover business invariants. The STRIDE step keeps running during the pilot and results are compared per finding. |
| False assurance from `control` outcomes | High | This risk is new. Today the report says nothing where nothing was found; with test cases it states that a control exists. A wrong model answer then claims protection that is absent, which is worse than silence. | A control needs a cited location and no contradicting post-check. Controls without deterministic confirmation are labelled model-evidenced and sampled first by the evidence verifier. A deterministic finding is removed only with a confirmed control. The wording is "control evidenced at X", never "secure". Fixtures with a seeded weakness must never yield `control`. |
| Cost and run time | Medium | More but smaller model calls, plus the open review. The hard budget limits spending and never rises automatically, so the practical effect is more `undecidable` results when the budget runs out. | Candidates are batched per component. The pilot measures cost per test case and for the open review. |
| Pilot never finishes | Medium | Two analysis paths remain in parallel, with double maintenance and inconsistent reports. | The pilot is time-boxed, opt-in, and ends with an explicit decision. |
| Catalog maintenance | Medium | The catalog starts with 45 test cases over 167 rules and will grow through the open review. Without fixtures the catalog decays. | Fixtures are mandatory per catalog test case, as for scanner rules. Recurring open-review findings feed the catalog. |
| Repository content in prompts | Low to medium | Candidate lists carry route paths and symbol names from the analyzed code, and application-specific test cases are written by the model from that code. Both are additional paths for untrusted text into model instructions. | Candidates are passed as data, not inside the instruction text. Application-specific test cases cannot disable or change catalog test cases and run only fixed post-checks. Post-check parameters are validated. The existing REQ-031 boundary applies. |
| Misuse of disabling | Low | Only operators can disable, with a reason, visibly in the report. Organizations can require test cases; repositories cannot disable any. | As described above. |
| Incompatible output | Low | Version 0.1.0a0 has no release, the pilot is opt-in, and the Threat Dragon export is unchanged. | Changelog entry. |
| Data sent to models | Low | Providers and destinations stay the same; some excerpts may be sent more than once. | None beyond existing controls. |

The current state also carries a risk. The report promises a method that does not take place, the Figure 1 legend claims per-element STRIDE analysis, and nobody can verify which coverage a run achieved. A reader who relies on that overestimates the analysis in the same way as with a wrong `control` outcome.

## Pilot exit criteria

The thresholds are set by the product owner before the pilot starts.

1. No loss: every finding in the pilot aspects that the STRIDE step reports on Juice Shop and the second repository is also found by a test case or the open review, or is shown to be a false positive.
2. No false controls: no test case reports `control` on a fixture with a seeded weakness.
3. Cost: the additional cost compared with the current assessment stays below the agreed limit.

## Draft requirement

Proposed entry in `requirements.md`:

- **REQ-039:** **Trace findings to named checks.** The assessment checks security aspects through named test cases and also looks for weaknesses outside them, such as insecure business logic. The live progress, the completion summary, and the report show for each test case whether it found a weakness, confirmed a protecting control, could not decide, did not apply, or was disabled. Each finding links the test cases and scanner rules behind it, or is marked as found outside the test catalog. Teams can disable individual test cases with a recorded reason; a disabled test case never counts as a confirmed control.

Proposed acceptance section:

Define each catalog test case in plugin-owned, versioned YAML with a stable ID, aspect, STRIDE tag, CWE, mode, objective, deterministic applicability, starting points from scanner rules and facts, guidance, required evidence, deterministic post-checks, and fixtures. Repository content cannot define, select, or disable catalog test cases.

Map every shipped scanner rule to a test case as a starting point, or record why a rule has none. A test case in rules mode takes its outcome from its rules and makes no model call unless the operator enables a context review, which cannot remove a finding.

Pre-checks provide starting points, not limits. Within the test case's objective and a bounded search, the model may reject candidates with evidence, add its own, and follow data flows beyond them; each candidate records whether it came from a pre-check or the model. Weaknesses found while working on a test case belong to the matching test case or are reported as outside the test catalog.

Record exactly one outcome per applicable test case and component: finding, control, undecidable, not applicable, or disabled. An unchecked, undecidable, or disabled test case is never reported as a control.

Post-checks are fixed functions with validated parameters and return confirmed, contradicted, or not verifiable. Model output never supplies executable patterns, queries, or code. A contradicted claim becomes undecidable with the reason. A claim that no post-check can verify keeps its outcome and is labelled as evidenced by model review only.

A control requires a cited location and no contradicting post-check. A control that no post-check confirms is labelled model-evidenced and is prioritized for evidence verification. A finding from a deterministic rule is removed only when a post-check confirms the control; otherwise it remains and records the disagreement.

Run an open review per component after the test cases. It receives their results and the confirmed business context and reports evidence-supported weaknesses that no test case covers, under the same evidence rules. Reserve a share of the model budget for the open review so that test cases cannot consume it. The model may derive application-specific test cases from business invariants it identifies; they receive run-specific IDs, use the same outcomes and evidence rules, run only fixed post-checks, and cannot disable, replace, or change catalog test cases.

Show test case progress in the live progress and outcome counts in the completion summary. In the report, link each finding to its test cases and rules, or mark it as found outside the test catalog, through a self-contained appendix that lists every test case, its outcome per component, and every disable reason. Retain test case and rule IDs in YAML and SARIF.

Operator-owned scan profiles can disable a test case only with a reason. Organization profiles can mark test cases as required; a conflicting disable refuses the run before any model call. Disabling never suppresses a finding that another source supports.

During the pilot, test cases are selected through a scan profile setting that names the model-backed pilot aspects; default runs keep the current output.

Proposed changes to existing acceptance sections:

| Requirement | Change |
| --- | --- |
| REQ-004 | Add: "When the test case pilot is selected, the pilot aspects are examined through REQ-039 test cases and the open review instead of STRIDE prompting; all other concerns keep the six STRIDE categories." |
| REQ-018 | Add a reference to the REQ-039 rules for disabling and requiring test cases. |

REQ-003, REQ-008, REQ-013, REQ-014, and REQ-016 are covered through REQ-039 without changing their text.

## Open questions

### Decisions before any implementation

1. Approve, change, or reject REQ-039 and its acceptance text as drafted above. Under `AGENTS.md`, no requirement is added and no code is written before this approval, and implementation needs a separate explicit request.
2. Is the catalog structure of 45 test cases in 14 aspects acceptable as the starting point, including the four new aspects and the removal of RealTime?
3. Which aspects form the model pilot in rollout phase 2? The recommendation is IAM, SessionMgmt, AuthZ, InputVal, and DataProt; smaller alternatives are IAM and AuthZ alone, or IAM, AuthZ, and InputVal.
4. Should rollout phase 1, which adds no model calls, start before the pilot decision?
5. What are the thresholds for the exit criteria, in particular the accepted additional cost, and how long is the pilot time box?
6. Which second, not intentionally vulnerable repository serves as the pilot comparison target?

### Design questions

7. Should a command-line option disable test cases for one run, or should disabling require a profile so the reason is always recorded?
8. Should a disabled scanner rule also remove its starting-point input from test cases, or only its standalone findings?
9. How large is the reserved budget share for the open review, and does it differ by assessment depth?
10. Is the model context review for `rules` test cases off by default, and which severities or rules may enable it?
11. How should test case results feed the security score, if at all?
12. Should Figure 1 keep a STRIDE view at all, or show only test case outcomes per component?
13. Should the aspect changes also apply to the `domain` field of `data/architecture-coverage-rules.yaml` and its schema, or does the catalog keep its own aspect list?
14. Should the report and product keep the name "threat model" once STRIDE no longer drives the analysis, or describe the result as an evidence-based security assessment?
15. Should the requirements audit and the test catalog share one execution engine while keeping separate catalogs, one compliance-oriented and one attack-oriented?
16. How long does `--stride-model` remain as an alias after the role is renamed?

### Findings to follow up independently of this proposal

17. The Figure 1 legend `STRIDE-per-element: filled = threats found in that class` claims an analysis that does not take place. Should it be corrected now, before the pilot?
18. For 71 of the 95 source-scanner rules, `merge_threats._AUTHZ_TO_STRIDE` has no entry, so the same weakness receives different STRIDE categories by language; for example, JWT parsing without signature verification is Spoofing in Node and Tampering in Java and Go. Rollout phase 1 removes this default. Should the mapping be fixed earlier?
19. Neither saved Juice Shop assessment contains a threat with source `architecture-coverage` or `threat-hypothesis`, although 15 architecture rules exist. Where do their results go: discarded, merged, or recorded elsewhere such as `weaknesses`?
20. Should `IAC-003` (missing container health check) stop producing a Denial of Service finding and become a hardening note?
21. Should the Dependabot and Renovate rules keep their current severity, or move to the separate supply-chain practice findings?
