# Why verification missed survey findings (pilot runs 3 and 4)

Status: analysis record, written 2026-10-24 offline without model calls, against main at 3fa2d25f. The fixes 1 and 2 below were built and merged into main (3515cf86) and measured in the second measuring run; see point 9 of [the open points](verification-cost-open-points-2026-10-23.md). The column "On main" describes main at 3fa2d25f.

Data: the pilot runs `juice-authz-pilot-3` (started 2026-10-23 08:14, code b100c018) and `juice-authz-pilot-4` (10:46, code 612811f1), both verifying AuthZ, InputVal, DataProt and AI with the pilot scan profile, on Juice Shop at 33518f5a0. The catalog (`data/test-cases.yaml`) and the code sites (`data/code-sites.yaml`) were unchanged on main since 612811f1.

A "miss" is a survey finding with a CWE of the aspect's catalog that no verification finding matches by file, line and CWE family (`case_outcomes._identity`). AI rows are limited to findings that concern the language model feature.

Classes: A no candidate reached the location; B no fitting catalog item; C candidate present but answered wrongly (C-job: the job returned no acceptable result and was replaced); D item disabled or not applicable; E survey finding doubtful; F verification reported the same weakness at another anchor, file, component or CWE family, so only the link is missing.

## One row per miss

| Run | Survey | CWE | Location (component) | Item | Verification candidate | Item result in that component | Class | Survey finding real? | On main |
|---|---|---|---|---|---|---|---|---|---|
| 3 | T-005 | 89 | routes/search.ts:23 (Express) | TC-INPUT-01 | yes: INJ-001 at the line, route /rest/products/search with sinks :23, :47 | undecidable, all 2 unexamined: InputVal job 1/2 replaced | C-job | yes | fixed by 612811f1; run 4 linked |
| 3 | T-031 | 918 | routes/profileImageUrlUpload.ts:24 (Express) | TC-INPUT-05 | yes: route /profile/image/url, sink :24 | undecidable, job replaced | C-job | yes | fixed; run 4 linked |
| 3 | T-053 | 943 | routes/trackOrder.ts:18 (Express) | TC-INPUT-02 | yes: INJ-NODE-006 at the line | undecidable, job replaced | C-job | yes | fixed; run 4 linked |
| 3 | T-055 | 79 | models/feedback.ts:44 (Sequelize data access) | TC-INPUT-04 | no: the item applies only with frontend code; not applicable in this component | not_applicable | F | yes (weak sanitizer, stored XSS) | unchanged; verification reports the sinks about.component.ts:119 and administration.component.ts:91 in the Angular frontend |
| 3 | T-056 | 79 | models/product.ts:45 (Sequelize) | TC-INPUT-04 | as above | not_applicable | F | yes | unchanged; sink search-result.component.ts:110 reported by verification |
| 3 | T-063 | 79 | routes/saveLoginIp.ts:22 (Authentication surface) | TC-INPUT-04 | not applicable in this component | not_applicable | F | yes | unchanged; sink last-login-ip.component.ts:39 reported by verification |
| 3 | T-069 | 611 | routes/fileUpload.ts:76 (Express) | TC-INPUT-06 | yes: route /file-upload | undecidable, job replaced | C-job | yes | fixed; run 4 linked |
| 3 | T-004 | 922 | Services/request.interceptor.ts:16 (Angular) | TC-DATA-02 | no: starting points are sensitive model fields and IaC/mobile rules; no site kind for browser storage | undecidable: no DataProt item has a starting candidate in the component, no job ran | A | yes (token in localStorage, readable by any XSS) | unchanged |
| 3 | T-044 | 798 | login/login.component.ts:62 (Angular) | TC-DATA-03 | none | disabled by the pilot profile | D (A when enabled) | yes (test credentials in the client bundle) | unchanged |
| 3 | T-065 | 200 | server.ts:283 (Express) | TC-DATA-01 / TC-AUTHZ-02 | verification AuthZ TCF-007 CWE-862 at server.ts:283 | – | F (same line, other CWE family) | yes | unchanged; the line is a route table line, so linking across families stays unsafe |
| 3 | T-071 | 598 | Services/user.service.ts:54 (Angular) | TC-DATA-04 | no frontend candidate | no job in Angular | F | yes | unchanged; verification reports the server side routes/changePassword.ts:14 (TCF-030) |
| 3 | T-054 | 1427 | routes/chat.ts:206 (Express) | TC-AI-01 | yes: route /rest/chat with chat.ts sinks | undecidable, AI job replaced | C-job | yes | fixed; run 4 AI job accepted |
| 3 | T-078 | 20 | routes/chat.ts:179 (Express) | TC-AI-03 | yes, job replaced | undecidable | F | yes | verification AuthZ TCF-012 reports the coupon limit at chat.ts:184 |
| 4 | T-039 | 862 | server.ts:370 (Express) | TC-AUTHZ-02 | generated PUT /api/Products/:id at server.ts:501 | finding | F | yes, but the survey anchors on a commented-out line (`// app.put(...)`) | unchanged; verification TCF-020 at server.ts:501 |
| 4 | T-056 | 79 | models/product.ts:45 (Sequelize) | TC-INPUT-04 | not applicable | not_applicable | F | yes | sink search-result.component.ts:110 reported |
| 4 | T-063 | 79 | data-export/data-export.component.ts:71 (Angular) | TC-INPUT-04 | yes: document.write site | candidate status "neither": "document.write of the caller's own export data; attacker control not shown" | E | doubtful: the export holds only the caller's own data, at most self-XSS | – |
| 4 | T-004 | 922 | Services/request.interceptor.ts:16 (Angular) | TC-DATA-02 | no | no job in Angular | A | yes | unchanged |
| 4 | T-023 | 798 | lib/insecurity.ts:21 (Authentication surface) | TC-DATA-03 | none | disabled by the pilot profile | D | yes (embedded RSA private key) | enabled, the ARCH-SECRET-001 evidence names this line and would probably seed a candidate (not checked) |
| 4 | T-049 | 798 | routes/login.ts:60 (Authentication surface) | TC-DATA-03 | none | disabled | D (A when enabled) | partly: challenge-detection code that holds default account passwords | – |
| 4 | T-065 | 200 | routes/appConfiguration.ts:15 (Express) | TC-DATA-01 | no: DATA-01 selected only GET routes whose handler calls a database API (`reads_data`); this handler returns the configuration | partial; goal TC-DATA-05 no_finding | A (goal: C) | yes, low (the configuration is meant for the frontend, but returned whole) | unchanged |
| 4 | T-066 | 200 | routes/captcha.ts:31 (Express) | TC-DATA-01 | no: the handler uses `build()`/`save()`, not in the database pattern | as above | A (goal: C) | yes (captcha answer in the response) | unchanged |
| 4 | T-067 | 200 | routes/chat.ts:105 (Express) | TC-DATA-01 / TC-AI-05 | verification AI TCF-047 at chat.ts:200 | – | F | yes | – |
| 4 | T-072 | 598 | Services/user.service.ts:54 (Angular) | TC-DATA-04 | no frontend candidate | no job in Angular | F | yes | server side changePassword.ts:14 reported (TCF-045) |
| 4 | T-073 | 598 | Services/user.service.ts:54 (Angular) | TC-DATA-04 | as T-072 | as T-072 | F | yes; duplicate of T-072 (same line and CWE) | – |
| 4 | T-074 | 200 | lib/startup/registerWebsocketEvents.ts:30 (WebSocket channel) | TC-DATA-05 | none: the component has no routes, so DATA-01 and DATA-05 do not apply and DATA-02/04 have no starting point | not_applicable / no job | D | partly: solved-challenge notifications to every client, by design of the challenge mode | – |
| 4 | T-050 | 20 | routes/chat.ts:184 (Express) | TC-AI-03 | verification AI TCF-046 CWE-1427 at the same line | finding | F (same line, other CWE family) | yes | – |
| 4 | T-055 | 1427 | routes/chat.ts:191 (Express) | TC-AI-01 | verification AI TCF-046 at chat.ts:184, same attack chain | finding | F | yes | – |

## Counts

27 misses (run 3: 13, run 4: 14).

| Class | Count | Rows |
|---|---|---|
| F same weakness, other anchor | 13 | run 3: T-055, T-056, T-063, T-065, T-071, T-078; run 4: T-039, T-056, T-067, T-072, T-073, T-050, T-055 |
| C-job job replaced | 5 | run 3: T-005, T-031, T-053, T-069, T-054 (all fixed since 612811f1) |
| A no candidate | 4 | T-004 (both runs), T-065 and T-066 (run 4) |
| D disabled or not applicable | 4 | T-044, T-023, T-049 (TC-DATA-03 disabled by the pilot profile), T-074 (component without routes) |
| E survey doubtful | 1 | T-063 run 4 |
| B, C (other) | 0 | |

Real verification gaps at 3fa2d25f: 4 (A), plus 3 that the profile's TC-DATA-03 switch hides, plus 1 in a component without routes. In run 4 DataProt, the earlier count of "9 of 10 missed" shrinks to 3 gaps (T-004, T-065, T-066), 2 disabled by the profile, 1 without routes, and 3 linking differences.

## Generic fixes, ranked

1. **A code site kind for credentials kept in client-side storage (TC-DATA-02).** TC-DATA-02 started only from sensitive model fields and IaC/mobile rules, so a browser frontend never got a DataProt candidate, and with DATA-01 and DATA-05 inapplicable without routes, no DataProt job ran for it at all. A kind `client_storage` for writes to `localStorage`/`sessionStorage` or script-set cookies whose key names a credential (token, auth, jwt, session, password, secret, key, credential), named like the existing `sensitive_field` kind, gives Juice Shop 9 sites in the Angular frontend and one job. Built (3515cf86); the second measuring run found the token in `localStorage` with it.

2. **Widen `reads_data` for TC-DATA-01 to handlers that return stored or configured data.** It required a database read call in the handler, so responses built from configuration, generated values or ORM `build()/save()/create()` were never candidates. Adding ORM persistence calls and configuration reads (`config.get/util`, `process.env`, and equivalents for Python and Java) selects 9 more GET handlers on Juice Shop (/rest/captcha, /rest/image-captcha, /rest/admin/application-configuration, /rest/admin/application-version, /rest/country-mapping, /rest/web3/nftMintListen, /promotion, /metrics twice), so Express DATA-01 needs a second job. Built (3515cf86); the second measuring run found the image captcha's answer, and the text captcha became a candidate.

3. **Leave TC-DATA-03 to the profile until scan-secrets exists (REQ-042).** The three secret misses come from the pilot profile's disable entry, not from the product. Enabled, the ARCH-SECRET-001 evidence names lib/insecurity.ts:21 (probably a candidate); credentials in a client bundle and in challenge code have no starting point, which is the scope of REQ-042. No code change.

4. **No change to linking (13 F cases).** Verification already reports these weaknesses at the sink, on the server side, or on the same line under another CWE family. The published survey findings carry no instances or traces for them, so a deterministic link would have to guess across files; two are same-line, different-family cases on route table and handler lines, where the 2026-10-23 replay showed wrong links. A "related findings" mark across files would be new report output and needs an approved requirement and evidence that the links are right. In the first measuring run the AuthZ case (T-040) linked because its instances include server.ts:501.

5. **Low gain, not recommended now:** a `realtime_events` applicability signal so DATA-01 and DATA-05 also run for components that only emit socket events (1 case, partly by design); a route fact for GET routes on credential operations for TC-DATA-04 (verification already adds that server-side finding itself).

## Option (b): a targeted follow-up check of survey findings verification did not find

Over runs 3 and 4 it would cover 27 findings, but 13 are F (verification already reported the same weakness, so the follow-up mostly confirms a duplicate) and 5 were job failures that no longer occur. 9 remain (A 4, D 4, E 1); after fixes 1 and 2 about 5, of which 3 are hidden only by the profile switch. That is about 2 to 3 findings per thorough run and none at standard depth with AuthZ only (first measuring run: 0). Fixing the starting points keeps both methods independent and covers the same gaps for every repository, so (b) was not built.

## Side observations outside this analysis

- The survey anchored T-039 on a commented-out route line (server.ts:370), and the finding passed the evidence review.
- The survey kept T-072 and T-073 as two findings with the same line and CWE.
- The AI catalog's CWEs (79, 639, 200, 20, 918, 94) overlap other aspects, so CWE-based counts overstate AI misses; the real AI survey findings of run 4 are all F.
