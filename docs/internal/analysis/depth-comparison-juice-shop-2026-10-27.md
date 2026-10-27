# Juice Shop depth comparison: quick, standard, and thorough

On 2026-10-26 and 2026-10-27, one run per assessment depth assessed the same Juice Shop commit with the current Analyzer and the `claude` profile. `quick` cost USD 8.17 and took 22 minutes, `standard` USD 14.71 and 41 minutes, and `thorough` USD 39.74 and 1 hour 36 minutes across several attempts. Thorough reported the widest coverage and the most verified results; survey and verification on Opus account for 78% of its cost. Part of its additional register entries describe the same problem twice, and severities and abuse-case verdicts varied between runs in ways that depth does not explain. One run per depth on one application cannot separate the effect of depth from variation between runs.

## Evidence and scope

The local evidence is in `/home/mrohr/quick`, `/home/mrohr/standard`, and `/home/mrohr/thorough`, copied from the runs' output directories under `/tmp`. All three assessed Juice Shop commit `33518f5a0911e25d9df747b1e70fb7af279a755c` on `master` (about 820 source files, nine components) and report engine version `0.6.0b6` with analysis version 5. The directories are local evidence, not durable repository fixtures; this record keeps the measurements and finding IDs needed to trace its conclusions.

For each run, `security-assessment.yaml` supplies the finding register, mitigations, abuse cases, and the resolved model per role. `.assessment-state.json` supplies cost accounting and limits, `.assessment-work/jobs/*.receipt.json` the role, calls, and cost of each accepted job, `.assessment-work/summary.txt` the run summary, and `.assessment-work/render/.skill-config.json` the resolved depth settings. Phase durations of the finalization come from the console output the user captured; they are not saved in the output directories. Finding IDs below are register IDs of the respective run; the same ID denotes different findings in different runs.

| Run | Report completed (UTC) | Host-event attempt | Hard budget | Run status |
| --- | --- | --- | --- | --- |
| quick | 2026-10-26 06:15 | `attempt-cvk5bj71` | USD 30 | 1 warning |
| standard | 2026-10-26 20:10 | `attempt-mgze17p8` | USD 30 | 1 warning |
| thorough | 2026-10-27 06:06 | `attempt-bdtl3vi0` (last attempt only) | USD 44 | clean |

Three limits apply to the comparison:

- The warning of the quick and standard runs says that Analyzer code or analysis resources changed during the run. Each may combine results of two Analyzer versions.
- The thorough run was continued with `--resume`. 168 of its 226 model calls and USD 36.88 of its cost come from earlier attempts. Its summary itemizes only the 58 calls of the last attempt by model, and its total time covers all attempts. The last attempt ran architect review, abuse cases, threat merging, post-survey synthesis, and report rendering; survey and verification ran earlier.
- No run reported skipped model work, apart from four abuse cases that standard left unchecked at its depth limit.

The resolved settings differed as follows:

| Setting | quick | standard | thorough |
| --- | --- | --- | --- |
| Survey model | Sonnet | Sonnet | Opus |
| Other roles on Opus | none | none | verification, merge, triage, post-survey synthesis |
| Verified aspects | none | AuthN, AuthZ, InputVal, AI | AuthN, AuthNRoutes, AuthZ, InputVal, DataProt, AI |
| Survey findings per threat category and component | 1 | not capped | not capped |
| Evidence-verifier finding limit | 20 | 30 | 100 |
| Abuse cases | skipped | up to 3 business rules | up to 8 business rules and 3 derived |
| Architect review | no | no | yes |
| Actor discovery | no | yes | yes |
| Diagrams and QA depth | minimal, core | standard, full | extended, extended |

Verification (`test_case_investigator`) follows the survey model, as mapped in `appsec_analyzer/model_roles.py`. All other roles used Sonnet, and the recon scanner used Haiku.

## Cost and time

Costs are the controller's recorded amounts, not a reconciled provider invoice. The receipt sums agree with `.assessment-state.json` to the cent.

| Measurement | quick | standard | thorough |
| --- | ---: | ---: | ---: |
| Recorded cost | USD 8.17 | USD 14.71 | USD 39.74 |
| Model calls | 84 | 147 | 226, of which 168 reused |
| Accepted jobs | 62 | 105 | 138 |
| Tokens | 4.3 million | 6.8 million | 1.1 million in the last 58 calls; reused calls not itemized |
| Time in the run summary | 22 minutes | 41 minutes | 1 hour 36 minutes in total, 22 minutes after resuming |
| `analysis_duration_seconds` in the YAML | 1,164 | 2,133 | 988 (last attempt) |
| Finalization phase | 3 min 09 s, USD 0.58, 206,000 tokens | 7 min 07 s, USD 0.68, 266,000 tokens | not captured |

The thorough receipts add up to 227 calls, one more than the 226 in its summary and state; the USD amounts agree.

Cost by model, from the run summaries:

| Model | quick | standard | thorough |
| --- | --- | --- | --- |
| Sonnet | 80 calls, USD 8.15, 4.0 million tokens | 145 calls, USD 14.70, 6.7 million tokens | 56 calls, USD 2.30, 1.0 million tokens (last attempt) |
| Haiku | 4 calls, USD 0.02, 258,000 tokens | 2 calls, USD 0.01, 113,000 tokens | none in the last attempt |
| Opus | none | none | 2 calls, USD 0.55, 107,000 tokens (last attempt) |
| Not itemized | none | none | 168 reused calls, USD 36.88 |

Cost by role, as jobs / calls / USD from the job receipts:

| Role | quick | standard | thorough |
| --- | ---: | ---: | ---: |
| Survey | 22 / 26 / 3.94 | 22 / 26 / 4.19 | 22 / 38 / 12.05 |
| Verification | not run | 19 / 28 / 4.80 | 31 / 56 / 18.92 |
| Evidence verifier | 16 / 24 / 1.71 | 26 / 33 / 2.36 | 27 / 43 / 2.90 |
| Trust-boundary analyst | 7 / 9 / 0.93 | 7 / 10 / 0.93 | 7 / 9 / 0.94 |
| Architect review | not run | not run | 11 / 17 / 0.89 |
| Abuse-case verifier | not run | 10 / 22 / 0.52 | 17 / 37 / 0.85 |
| Abuse-case deriver | not run | not run | 1 / 1 / 0.02 |
| Control analyst | 9 / 12 / 0.46 | 9 / 13 / 0.49 | 9 / 10 / 0.45 |
| Finding combiner | 1 / 1 / 0.06 | 3 / 3 / 0.18 | 4 / 4 / 0.73 |
| Threat merger | 2 / 2 / 0.13 | 3 / 3 / 0.16 | 3 / 3 / 0.49 |
| Post-survey synthesis | 1 / 1 / 0.10 | 1 / 1 / 0.16 | 1 / 1 / 0.50 |
| Architecture analyst | 1 / 3 / 0.36 | 1 / 2 / 0.27 | 1 / 2 / 0.35 |
| Actor discovery | not run | 1 / 2 / 0.10 | 1 / 1 / 0.08 |
| Security-architecture renderer | 1 / 1 / 0.35 | 1 / 1 / 0.38 | 1 / 1 / 0.40 |
| Management-summary renderer | 1 / 1 / 0.12 | 1 / 1 / 0.14 | 1 / 1 / 0.14 |
| Recon scanner | 1 / 4 / 0.02 | 1 / 2 / 0.01 | 1 / 3 / 0.01 |
| Total | 62 / 84 / 8.17 | 105 / 147 / 14.71 | 138 / 227 / 39.74 |

Survey and verification together cost USD 3.94 (48%) in quick, USD 8.99 (61%) in standard, and USD 30.97 (78%) in thorough. All three runs split the survey into the same 22 jobs. On Opus, a survey call cost about USD 0.32 instead of USD 0.15 to 0.16 on Sonnet, and a verification job USD 0.61 instead of USD 0.25. Thorough also ran 31 instead of 19 verification jobs; it verifies two more aspects.

## Findings

| Measurement | quick | standard | thorough |
| --- | ---: | ---: | ---: |
| Finding-register entries | 51 | 104 | 147 |
| Critical / High / Medium | 5 / 19 / 27 | 3 / 32 / 69 | 5 / 45 / 97 |
| Locations (instances) | 104 | 199 | 269 |
| Management-summary findings (Critical / High / Medium) | 31 (4 / 12 / 15) | 56 (2 / 15 / 39) | 91 (4 / 26 / 61) |
| Entries classified as `confirmed-exploitable` | 26 | 50 | 80 |
| Entries classified as `insecure-practice` | 25 | 54 | 67 |
| Distinct CWEs | 34 | 48 | 61 |
| Files with at least one finding | 48 | 73 | 77 |
| Mitigations (P1 / P2 / P3) | 57 (4 / 16 / 37) | 125 (3 / 32 / 90) | 164 (5 / 45 / 113, and 1 P4) |
| Verification results | not run | 31 findings, 3 controls, 14 undecidable | 49 findings, 6 controls, 1 partial, 28 undecidable |
| Abuse cases | skipped | 6 confirmed, 1 partially blocked, 3 unresolved, 4 not checked (limit) | 8 confirmed, 1 partially blocked, 5 unresolved |
| Cost per register entry | USD 0.16 | USD 0.14 | USD 0.27 |
| Cost per Critical or High entry | USD 0.34 | USD 0.42 | USD 0.79 |

Moving from quick to standard added 53 register entries for USD 6.54, about USD 0.12 each. Moving from standard to thorough added 43 entries for USD 25.03, about USD 0.58 each. Of these, 28 are Medium, 13 High, and 2 Critical, so each additional Critical or High entry cost about USD 1.67.

The management-summary totals fold `insecure-practice` entries into weakness classes. They are not counts of unique vulnerabilities. The classifications are assessment outputs, not independent exploit validation, and there is no labeled reference set, so precision and recall cannot be calculated from these counts.

Register entries by component. Each run named the components differently; the table uses one name per component:

| Component | quick | standard | thorough |
| --- | ---: | ---: | ---: |
| Express API server | 31 | 70 | 94 |
| Authentication and session surface | 7 | 13 | 21 |
| Angular client | 5 | 11 | 15 |
| CI/CD pipeline | 6 | 7 | 6 |
| Sequelize data access | 2 | 1 | 4 |
| Real-time WebSocket channel | 0 | 1 | 4 |
| Web3, wallet, and NFT surface | 0 | 1 | 3 |
| SQLite and MarsDB stores | 0 | 0 | 0 |

Register entries by STRIDE category:

| Category | quick | standard | thorough |
| --- | ---: | ---: | ---: |
| Spoofing | 8 | 13 | 22 |
| Tampering | 18 | 33 | 37 |
| Repudiation | 0 | 0 | 1 |
| Information disclosure | 11 | 19 | 42 |
| Denial of service | 0 | 4 | 5 |
| Elevation of privilege | 14 | 35 | 40 |

Origin and evidence of the register entries:

| Measurement | quick | standard | thorough |
| --- | ---: | ---: | ---: |
| Found by the survey only | 28 | 29 | 33 |
| Found by verification only | 0 | 37 | 60 |
| Found by scanners only | 14 | 7 | 6 |
| Found by several of these | 9 | 31 | 45 |
| No finder recorded | 0 | 0 | 3 |
| Evidence check `verified` / `ambiguous` | 40 / 11 | 83 / 21 | 129 / 18 |
| Evidence basis `llm-verified` / `pointer-resolved` / `ambiguous` | 40 / 0 / 11 | 72 / 11 / 21 | 104 / 25 / 18 |
| Source survey / source scan / config scan / configuration defect | 32 / 12 / 5 / 2 | 85 / 11 / 6 / 2 | 127 / 14 / 4 / 2 |

Register entries by attack vector:

| Vector | quick | standard | thorough |
| --- | ---: | ---: | ---: |
| Anonymous internet user | 30 | 71 | 101 |
| Authenticated internet user | 11 | 16 | 20 |
| Requires a victim's action | 2 | 8 | 12 |
| Build time | 6 | 7 | 6 |
| Repository read access | 2 | 2 | 8 |

Weaknesses, controls, and architecture model:

| Measurement | quick | standard | thorough |
| --- | --- | --- | --- |
| Weakness-register entries (Critical / High / Medium / Low) | 28 (3 / 3 / 20 / 2) | 34 (1 / 9 / 24 / 0) | 42 (3 / 6 / 32 / 1) |
| Weakness kind implementation / design | 22 / 6 | 27 / 7 | 36 / 6 |
| Security controls (Adequate / Partial / Weak / Missing / Unsafe) | 37 (2 / 12 / 13 / 6 / 4) | 36 (3 / 12 / 12 / 5 / 4) | 34 (4 / 11 / 10 / 6 / 3) |
| Components / actors | 9 / 3 | 9 / 3 | 9 / 3 |
| Data flows / external entities / assets | 18 / 4 / 6 | 17 / 6 / 4 | 19 / 5 / 4 |
| Trust boundaries | 11 | 10 | 13 |
| Attack-surface entries (deterministic) | 109 | 109 | 109 |

### Critical register entries

| Run | ID | Finding | Evidence | Finder, evidence check |
| --- | --- | --- | --- | --- |
| quick | T-003 | SQL injection in product search | `routes/search.ts:23` | survey and scanners, verified |
| quick | T-008 | Broken authorization | `routes/memory.ts:15` | scanners, ambiguous |
| quick | T-009 | Insecure direct object reference | `routes/order.ts:148` | scanners, verified |
| quick | T-010 | SQL injection in login query | `routes/login.ts:34` | survey and scanners, verified |
| quick | T-011 | Code injection through the stored user name | `routes/userProfile.ts:61` | survey and scanners, verified |
| standard | T-004 | SQL injection in login query | `routes/login.ts:34` | survey, scanners, and verification, verified |
| standard | T-005 | SQL injection in product search | `routes/search.ts:23` | survey, scanners, and verification, verified |
| standard | T-011 | Checkout trusts a client-supplied user ID for wallet changes | `routes/order.ts:150` | survey and scanners, ambiguous |
| thorough | T-001 | Attacker-controlled owner ID in resource queries | `routes/dataExport.ts:26` | scanners, verified |
| thorough | T-003 | SQL injection in product search | `routes/search.ts:23` | survey, scanners, and verification, verified |
| thorough | T-008 | SQL injection in login query | `routes/login.ts:34` | survey, scanners, and verification, verified |
| thorough | T-009 | Server-side eval of the stored user name | `routes/userProfile.ts:61` | survey, scanners, and verification, verified |
| thorough | T-010 | Stored user name compiled as Pug template | `routes/userProfile.ts:87` | scanners and verification, verified |

## Coverage by depth

Register entries were matched across runs by CWE and an overlapping evidence file. Of the quick entries, 43 of 51 have a counterpart in standard and 42 of 51 in thorough. Of the standard entries, 84 of 104 have a counterpart in thorough, while 63 of the 147 thorough entries have none in standard. Most unmatched entries describe a known topic under another CWE. The only Critical or High quick entry without a counterpart is T-008 at `routes/memory.ts`, whose evidence check is `ambiguous`. The only High standard entry without a thorough counterpart is T-035 (unsalted MD5), which thorough reports under the same topic at other locations (T-043, T-048).

The table checks known Juice Shop weaknesses by evidence file and keywords in title and scenario, then by reading the matched titles. Keyword matching can miss entries described in other words.

| Known weakness | quick | standard | thorough |
| --- | --- | --- | --- |
| SQL injection in login and product search | T-010, T-003 | T-004, T-005 | T-008, T-003 |
| Code execution through the stored user name on the profile page | T-011 | T-027, T-031 | T-009, T-010 |
| XXE in complaint upload | T-027 | T-034 | T-041 |
| Zip slip in complaint upload | T-021 | T-026 | T-029 |
| SSRF through the profile image URL | T-028 | T-036 | T-044 |
| Hard-coded JWT signing key | T-018 | T-023 | T-018, T-019 |
| Unsalted MD5 password hashes | T-052, T-054 | T-035, T-037 | T-043, T-048 |
| Role mass assignment at registration | T-036 | T-044, T-045 | T-056 |
| Layout path traversal in data erasure | T-020 | T-025 | T-028, T-037 |
| Code execution in B2B orders | not found | T-038 | T-049 |
| Two-factor authentication weaknesses | not found | T-112 | T-047 |
| CAPTCHA answer disclosed to the client | not found | T-075 | T-064, T-094, T-107 |
| Unauthenticated metrics endpoint | not found | T-076, T-109 | T-097, T-134 |
| Feedback created with another user's ID | not found | not found | T-082 |
| Unsigned coupon codes | not found | not found | T-030 |
| Open redirect | not found | not found | T-058 |
| Missing WebSocket handshake authentication | not found | not found | T-060 |
| Orders selected by masked e-mail in data export | not found | not found | T-106, T-137, T-138 |

No run reported a YAML bomb in the complaint upload (thorough T-131 mentions YAML parsing only as part of an unauthenticated upload), XSS through video subtitles, or stack traces and API documentation exposed to anonymous callers. Findings in the language-model chat (`routes/chat.ts`) grew from 3 in quick to 5 in standard and 8 in thorough.

## Abuse cases

Quick skips abuse cases. Standard and thorough considered the same 14 cases:

| Case | Standard | Thorough |
| --- | --- | --- |
| AC-T-001 Account takeover through XSS and token theft | inconclusive, High | fully viable, High |
| AC-T-002 Bulk data exfiltration through broken object authorization | partially blocked, High | partially blocked, High |
| AC-T-003 Privilege escalation through JWT algorithm confusion | inconclusive, High | inconclusive, High |
| AC-T-004 Privilege escalation through mass assignment at registration | fully viable, Critical | fully viable, Critical |
| AC-T-005 Authentication bypass through exposed secret material | fully viable, Critical | inconclusive, High |
| AC-T-006 Remote code execution through server-side injection | fully viable, Critical | inconclusive, High |
| AC-T-007 Privileged action through prompt injection into a tool-calling model | fully viable, Medium | fully viable, Medium |
| AC-B-001 User reads or changes another user's data | not checked (limit) | fully viable, Critical |
| AC-B-002 User gains more rights than intended | not checked (limit) | fully viable, High |
| AC-B-003 User takes over another account | not checked (limit) | fully viable, High |
| AC-B-004 User bypasses a required approval | inconclusive | inconclusive |
| AC-B-005 User exceeds a limit or one-time entitlement | fully viable, Medium | fully viable, Medium |
| AC-B-006 User keeps using a withdrawn right | not checked (limit) | inconclusive |
| AC-B-007 User misuses a privileged function | fully viable, High | fully viable, High |

Thorough confirmed three business cases that standard did not check because of its limit, and lost two technical cases that standard had confirmed.

## Quality problems

**Duplicate entries grow with depth.** The register contains groups of entries whose first evidence points to the same file and line: none in quick, 7 groups with 18 entries in standard, and 20 groups with 49 entries in thorough. Not every group is a duplicate. For example, `server.ts:501` registers several routes with different weaknesses. In thorough, at least the following describe the same problem more than once, usually once from the survey and once from verification under another CWE:

- T-129 and T-145: identical title, `server.ts:278`, CWE-306 and CWE-862.
- T-038, T-039, and T-096: the memories endpoint at `routes/memory.ts:24`, CWE-213, CWE-359, and CWE-200.
- T-106, T-137, and T-138: orders selected by masked e-mail at `routes/dataExport.ts:33`.
- T-028 and T-037: `routes/dataErasure.ts:104`, CWE-22 and CWE-73.
- T-064 and T-094: CAPTCHA answer at `routes/captcha.ts:31`, CWE-804 and CWE-200.
- T-088 and T-149: review author taken from the request at `routes/createProductReviews.ts:26`.
- T-127 and T-144 (Deluxe upgrade without payment), T-097 and T-134 (metrics endpoint), T-111 and T-152 (authentication details endpoint), and T-018 and T-019 (hard-coded RSA key) describe the same exposure at neighboring lines.

In standard, T-090 and T-103 (`routes/deluxe.ts:43`) and T-044 and T-045 (role at registration) are comparable pairs. Part of the increase from 104 to 147 entries is therefore duplication, not additional weaknesses.

**Severity of the same problem varies between runs.** The memories endpoint is Critical in quick (T-008), Medium in standard (T-091), and High in thorough (T-038, T-039). The code execution through the stored user name is Critical in quick and thorough, but High in standard. The Critical counts of 5, 3, and 5 follow these differences more than depth.

**Critical ratings without confirmed exploitability.** Each run has one Critical entry classified as `insecure-practice` rather than `confirmed-exploitable`: quick T-008 (scanner only, evidence `ambiguous`), standard T-011 (evidence `ambiguous`), and thorough T-001 (scanner only, evidence verified).

**Abuse-case verdicts differ between runs with the same verifier model.** Both runs used Sonnet for abuse-case verification. AC-T-005 and AC-T-006 are fully viable and Critical in standard but inconclusive in thorough; AC-T-001 changes the other way.

**Run-specific component names.** All runs found the same nine components but named them differently, for example "Juice Shop Express HTTP API", "Juice Shop Express server", and "Juice Shop Express API". This makes comparisons across runs harder.

**Summary display.** The thorough summary reports 164 mitigations but lists only P1, P2, and P3, which add up to 163; the one P4 mitigation is not shown. The console output the user captured for the quick run names the report file `security-assessment-juice-shop-standard-v0.6.0b6`, while the saved `summary.txt` of that run names `security-assessment-juice-shop-quick-v0.6.0b6`. This difference was not reproduced.

## Comparison with the 2026-10-17 measurement

The [earlier standard and thorough comparison](stride-model-cost-comparison-2026-10-17.md) used the inherited Advisor engine with a USD 30 budget. Its thorough run skipped verification and all abuse-case checks and produced no more verified results than standard. In this measurement, thorough had a USD 44 budget, skipped no work, and produced more verification results (49 instead of 31 findings) and more confirmed abuse cases (8 instead of 6) than standard. It used about USD 40, which is twice the default `--budget` of USD 20 for `assess`.

## Conclusions and candidate fixes

Standard has the lowest cost per register entry and found every weakness of the coverage table that quick found, plus code execution in B2B orders. Quick found the most severe known weaknesses of this application but missed B2B code execution and runs no verification. Thorough adds coverage at a much higher marginal cost, and its counts overstate the number of additional weaknesses.

These single runs do not establish repeatable differences. Repeat runs per depth with identical budget and Analyzer version are needed to separate depth from variation, and counts should be compared after merging duplicates.

The following generic changes would address the observed problems for any repository. They are candidates, not implemented or measured fixes:

- Merge entries at the same file and line across CWEs when their mechanism traces describe the same source and sink. The existing guard that requires mechanism evidence for broad CWE matches must remain.
- Rate an `insecure-practice` entry with `ambiguous` evidence below Critical, or mark such Critical entries separately in the summary.
- Show P4 mitigations in the run summary line, or state that the line lists only P1 to P3.
- Keep component names stable across runs of the same source.

Verification on Opus is the largest single cost of thorough (USD 18.92). Running thorough verification on Sonnet would be a candidate cost reduction; its effect on verification results is unmeasured.
