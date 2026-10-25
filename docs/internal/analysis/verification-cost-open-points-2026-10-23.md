# Verification cost: open points

Status: working document, written 2026-10-23 after merges 34da4812 and 72c57eb4. The first lets the authorization verification preload the guards of guard-only registrations and the data models of generated REST routes (2e56eb65). The second shows verification progress as one step per component (09f256e0). The points below are left open. The figures come from the receipts and host events of one interrupted Juice Shop run at standard depth, without new model calls. Points 2 and 3 were updated on 2026-10-24 with an offline rebuild of the verification context, an offline check of the CLI, a live check of a few cents, and the host events of the fourth pilot run. Points 1, 3 and 8 were updated the same day with offline checks of the measuring run's answers and an offline rebuild of its survey requests. Point 9 and the order were added the same day after the second measuring run; everything built for it is merged into main. Point 10 was added the same day after the third measuring run. Point 11 was added on 2026-10-25 after the fourth measuring run, from its receipts, model and merge artifacts, without new model calls. Point 12 was added the same day after the fifth measuring run.

## Baseline

Authorization verification ran 9 jobs with 16 calls for USD 4.28: 7 jobs for the Express server, one each for the Web3 surface and the authentication surface. 6 of the 16 calls only asked for 2 to 4 further source slices, at USD 1.34 together. Each call sent 65,000 to 100,000 input tokens, of which about 11,000 came from the prompt cache, and returned 1,000 to 20,000 tokens.

## 1. Measure the fixes in one run

One Juice Shop run at standard depth with AuthZ only, a fresh output directory and a budget of USD 25 measures the preload fix, the progress per component, the path cut of point 2 and the caching of point 3 together. It should show:

- how many authorization verification calls run, and how many of them only ask for further source (before: 16 and 6);
- what verification costs (before USD 4.28; expected about USD 2 to 2.5);
- what the survey costs, which the path cut and the own cache markers change as well (fourth run: 28 calls, USD 7.10);
- in the host events, cache reads in every AuthZ verification call after the first: the instructions and preamble, about 13,000 tokens, plus a component's shared context in its later jobs, and a job's context and preload in its later calls; in no call of any role a cache write of its varying rest;
- no more rejections that name a test case of another job than before, since all jobs of a component now get the catalog text of all its test cases;
- no fewer weakness answers and no more undecidable candidates than before (42 weakness answers on the Express server);
- one console row per verified component instead of one per job.

The changes alter the survey and verification requests, so the run reuses no earlier accepted job of either. It is prepared as `bash /tmp/verify-cost-run/run.sh` with the profile beside it and writes into `/home/mrohr/appsec-reports/juice-verify-cost-1`.

### Result

The product owner ran it on 2026-10-24 at 288794a7. After its last model call the run stopped at publication: since 1c4d57f4 every run with a verified control broke the output schema, because the combined model qualifies each control location with its repository and hash (fixed in eac6f491, merged in e22b8796). A new start with the fix took all 122 accepted jobs from the cache without a model call and completed without a run issue. The whole run cost USD 12.96; the fourth run with four verified aspects cost USD 21.42 for 137 calls.

| From the host events | Fourth run | This run |
|---|---|---|
| Verification calls, USD | 16, 4.45 | 16, 2.57 |
| Calls that only asked for further source | 4 (baseline run: 6) | 5 |
| Survey calls, USD | 28, 7.10 | 26, 5.27 |
| Evidence review calls, USD | 27, 2.62 | 30, 2.02 |

- Verification wrote 404,156 tokens into the cache, read 831,241 and sent 58,827 as plain input: USD 1.21 of input, against the estimate of USD 1.17. Its 135,475 output tokens cost USD 1.35 and are now more than half of its cost.
- The later Express jobs read 34,932 tokens in their first call, the shared start; a job's later calls read 60,836 to 173,878. The Web3 job started together with the first Express job and read nothing.
- The whole run still wrote 2.9 million tokens into the cache and read 1.7 million; the survey wrote 1.46 million of them, since its jobs of a component differ in their instructions (order step 4).
- Both corrections concerned a finding outside the component; none named another job's test case.
- Of 294 candidates, 226 got the same answer as in the fourth run; between the third and the fourth run it was 237 of 293. On the Express server weakness answers rose from 33 to 39, controls from 85 to 96, and undecidable answers fell from 20 to 6, mostly generated routes whose data model is now preloaded.
- Verification found 18 findings the survey did not (fourth run 17, third 16). One authorization finding of runs 2 to 4 is missing: order tracking without an owner check (`routes/trackOrder.ts:18`), rejected as outside the objective; the survey did not report it either. Security answers with a caller-chosen UserId (`server.ts:501`) are there as TCF-024; an earlier version of this list named them as missing. Rejections as outside the objective fell from 46 to 38.
- The survey reported 106 findings against 113; 77 percent of the fourth run's were found again, against 80 percent between the third and the fourth run. Critical and High stayed at 3 and 23 against 3 and 22.
- Checked offline against the code: the 11 additional control answers on the Express server are 18 new and 7 lost ones. 10 of the new ones were rejections with the same reasoning in the fourth run, mostly routes behind `denyAll`, so control counts are not comparable between runs; 8 became decidable because the guard bodies are now preloaded. 17 of the 18 are correct. The answers one by one are in [the control answers check](verification-control-answers-check-2026-10-24.md).
- One new control is wrong: `POST /rest/user/data-export` under TC-AUTHZ-01. The guard binds the memories query (`routes/dataExport.ts:26`), but the same handler looks up orders by a vowel-masked e-mail that several accounts share (`routes/dataExport.ts:33`). That line was in the served source, so it is a judgement error. Of the lost controls, three wallet sites in `routes/order.ts` were correct in the fourth run and are undecidable now: a scanner hit inside a handler got no guards of the route that reaches it, and job 1 did not read the prefix guard at `server.ts:356` this time.

## 2. The component context dominates each call

Of each call's 65,000 to 100,000 input tokens, the served source took 26 to 70 KB, roughly 10,000 to 23,000 tokens, and the system prompt about 11,000. The rest, roughly 45,000 to 60,000 tokens, is the component context that the survey job of the same component also receives, together with the candidate list. It is the same for every part of a component and for both calls of a job. These shares are estimates from served byte counts, not measured token counts.

The plan was to rebuild the Express server's verification context offline, list its parts by size, and check which parts an aspect's answers relied on. The hope was that cutting the context per aspect could roughly halve verification cost. The measurement below replaces the estimates above; the hope does not hold.

### Measured parts

Measured offline on 2026-10-24 with the code of main and Juice Shop at 33518f5a0, standard depth. The analyzer's `assess` entry ran on a copy of the fourth pilot run's output directory, so its accepted recon, architecture, boundary and control jobs came from the cache; its host refused every model call, and none was attempted. A replacement for the STRIDE stage built each component's context envelope as `_assessment_stride` does and ran `run_pilot` with a job runner that recorded each verification request instead of executing it. Rebuilt packets against the fourth run's first calls give 2.2 to 2.5 bytes per token; the token figures use 2.3.

Express server, AuthZ part 2 of 7:

| Part of the call | Bytes | About tokens | Same in every part |
|---|---|---|---|
| Output tool schema | 13,163 | 5,700 | yes |
| Role instructions with the part's test cases | 15,554 | 6,800 | no |
| Path lists of `component` and `incident_components` | 38,840 | 16,900 | yes |
| `readable_sources` (352 paths) | 18,892 | 8,200 | yes |
| `incident_flows` (8 flows) | 15,249 | 6,600 | yes |
| `existing_controls` (8 controls) | 7,217 | 3,100 | yes |
| `threat_categories` (19 categories) | 6,061 | 2,600 | yes |
| `adjacent_boundaries` and the rest of the envelope | 6,179 | 2,700 | yes |
| Candidates, `candidate_jobs` and `starting_files` | 11,075 | 4,800 | no |
| Preloaded source (26 to 36 windows per part) | 48,765 to 72,408 | 21,000 to 31,500 | no |

- The shared envelope is 92,438 bytes, about 40,000 tokens, of an Express call's 80,000 to 97,000. The earlier estimate of 45,000 to 60,000 counted the candidate list in.
- 42 percent of the envelope are path lists. Each path of the component and of its neighbours is listed with its repository ID, and every one of them also appears in `readable_sources`; the component itself appears twice, as `component` and in `incident_components`. The Web3 surface (30,839 of 65,244 bytes) and the authentication surface (31,337 of 68,762) show the same; the Angular frontend's envelope holds 68,439 such bytes of 122,914.
- The evidence anchors of controls, flows and boundaries carry 82 sha256 values, 6,232 bytes. `model_components` already drops path hashes because acceptance checks citations against served slices, never against these rows; whether that holds for these anchors too is not checked.
- Part 1 also carries `candidate_jobs.answered_elsewhere`: 218 locations that other parts answer, 33,857 bytes with an anchor and a route each. Grouped by file as line lists without the routes, they take 1,344 bytes.

### What AuthZ used

From the fourth run's 9 accepted AuthZ answers with 29 findings:

- Evidence cites files of the verified component (310 citations) or files of no component (28), never a file of a neighbour.
- No answer names a flow ID, a boundary name or a control name. 19 findings describe `controls_in_place` in their own words.
- All 29 findings use TH-06. The investigation policy gives the same category without the taxonomy, through its STRIDE fallback E→TH-06.

Unused in the answers does not mean unused by the model. The neighbours, flows and boundaries also back the ownership and trace rules of `validate_stride`, which every repository needs, so they stay. What AuthZ can do without is only the taxonomy and the controls of other domains, at most about 5,700 tokens or 6 percent of a call; an aspect cut needs a rule per aspect in plugin data and saves little.

### Generic cuts

These hold for any repository and drop no information:

- List each readable path once, in `readable_sources` grouped by owning component, and drop the path lists from `component` and `incident_components`. This removes about 38,000 bytes, 16,500 tokens, from each Express call, and the same share from every survey call, which carries the same envelope.
- Write `answered_elsewhere` per file as line lists, if the check of answered locations compares anchors only: about 14,000 tokens less in each call of a first part.
- Drop the evidence hashes from the envelope if the validators do not need them: 6,232 bytes.

Without caching, the path cut alone would have saved about USD 1.30 in the fourth run's 31 verification calls and about USD 1.57 in its 28 survey calls at the write price (upper bounds from the envelopes' component lists). It applies to every host, not only the Claude CLI. With the caching of point 3 the shared envelope is written once per component and read otherwise, so the cut then saves only on those first writes and on reads.

The path cut is merged in fbe81ab4 (77a3c9a8). Rebuilt offline the same way, it shrinks the Express server's envelope from 92,179 to 53,402 bytes and the Angular frontend's from 122,914 to 57,372. The 19 verification packets of the fourth run's profile shrink by 18 percent in total, 11 to 24 percent each. The readable sources and their owners stay the same. Since the preload fills the room left in a packet, 4 of the 7 Express parts now preload 1 to 5 more windows, 6,000 to 14,000 bytes.

The largest blocks per part are then the preloaded source (21,000 to 31,500 tokens, different in each part) and the output. In the fourth run's 16 AuthZ calls, output cost USD 1.32 of USD 4.45 and cache writes USD 3.11.

## 3. Prompt caching with the Claude CLI host

Each call is a separate `claude -p` with one user message. Shared component context, candidates and source slices sit in the same block (`_prompt` in `scripts/runtime/assessment_host.py`), so only the system prompt is read from the cache. Find out whether the CLI accepts several separately cacheable content blocks, for example through stream-json input, or whether only an API host can mark the shared context as a cache breakpoint. This lever would apply to the survey as well, and it was already named the largest one in the [implementation status](aspect-test-cases-implementation-status-2026-10-19.md#cost-of-authorization-verification-analysed-2026-10-23).

The cache matches only a byte-identical start of the request, in the order tools, system prompt, messages, and only at a position where an earlier request set a cache marker. A request carries at most four markers, and a marker with a longer TTL must come before one with a shorter TTL. An entry becomes readable only once the response of the request that wrote it starts streaming, so parallel requests over the same start all write and none reads.

### How the CLI places its markers

Checked on 2026-10-24 without model calls. CLI 2.1.310, started with the transport's flags (`ClaudeCliTransport.argv` in `scripts/runtime/analyst_host.py`), sent its requests to a local stand-in for the Messages API (`ANTHROPIC_BASE_URL` on 127.0.0.1, a dummy key, an empty configuration directory). The stand-in recorded each request body and answered with a fixed reply.

- The tools come first: a deferred placeholder and `StructuredOutput`, which carries the `--json-schema` schema. Neither has a marker.
- The system prompt has three blocks: an unmarked billing line, a marked identity line, and the marked `--system-prompt` text.
- With text input the prompt is one unmarked user string. The CLI appends a system-role environment block after it (working directory, model, budget, date) and marks that block. This marker covers the whole packet, so every call writes its packet into the cache, and later calls read only the system prompt entry.
- With `--input-format stream-json` a user message can carry several text blocks, and the CLI forwards a `cache_control` set on one of them unchanged. One own marker makes four, the API maximum. The CLI also forwards a second own marker, which makes five; the API rejects more than four (not tried live).
- `--input-format stream-json` requires `--output-format stream-json`. Several user messages on stdin run as separate turns, each answered, so a shared start cannot be sent as a message of its own.
- `FORCE_PROMPT_CACHING_5M=1`, which the transport sets for every assessment exchange (`short_cache=True` in `scripts/orchestrator/orchestration_controller.py`), keeps the CLI's markers at five minutes, and an own marker without `ttl` also lasts five minutes. With `ENABLE_PROMPT_CACHING_1H=1` the CLI's markers get `ttl: 1h` while the own marker stays at five minutes, so the one-hour environment marker after it would break the TTL order. An own marker must then carry the CLI's TTL.
- `DISABLE_PROMPT_CACHING=1` (or `DISABLE_PROMPT_CACHING_SONNET=1`) removes the CLI's three markers and keeps the caller's. The caller then decides every cache position, and nothing after its last marker is written into the cache. The CLI computes `total_cost_usd` from the usage fields either way: with a fixed stand-in usage, both settings reported the same cost.
- The CLI prices cache reads for `claude-sonnet-5-5` at USD 0.10 per million tokens, not USD 0.20 as this document assumed before. Recomputing investigator call 0059 of the fourth pilot run (79,805 written, 11,478 read, 2 input and 1,274 output tokens) gives exactly its USD 0.2134043.

### What the three obstacles mean now

- The response schema changes only from a job's fourth call. With `MAX_EXCHANGES` 6 and `MAX_CORRECTIONS` 2, `completion_required` first holds when three calls are left. The earlier statement that a job's second call differs at the start was wrong. In the fourth pilot run no investigator job made more than three calls: 10 jobs made one, 6 made two, 3 made three.
- The role instructions still carry the catalog text of the part's own test cases (`catalog_instructions(share)` in `scripts/orchestrator/assessment_test_cases.py`), so the parts of one component share nothing worth caching. Within a job the instructions do not change, and a later call repeats the earlier call's context and preloaded source slices in the same order before its new slices.
- A marker after the shared context is possible with stream-json input, as its own marked block.

### Options

1. **One own marker, CLI caching kept.** Send the packet as stream-json in two blocks inside the untrusted data envelope: first the trusted preamble with the shared component context, marked, then the part's candidates, source slices and counters. A job's later calls then read the shared context. The other parts of a component read it as well once all parts get the same instructions, for example the catalog text of every test case the component's aspect verifies with the part's own test cases named in its context, and once the first part starts alone and the others follow when its first response streams. The CLI's environment marker still writes each call's whole packet at the premium of 25 percent.
2. **CLI caching off, own markers only.** As option 1, plus `DISABLE_PROMPT_CACHING=1` for these calls and own markers after the trusted preamble, which takes over the system prompt entry, after the shared context, and after the preloaded source. A job's second call then also reads its preloaded source, and nothing after the last marker pays the write premium. The same change fits every role that uses `run_exchange`, so it also removes the side finding below.

Both options keep repository text in the untrusted user message (REQ-031); only the split into blocks and the markers change. Each call keeps its own receipt, so cost per job and per aspect stays as it is. Same instructions for all parts need a check that a part answers only its own test cases. Both options rely on CLI behavior that is observed, not documented: the Claude Code documentation does not describe the stream-json input format, nor that an own `cache_control` is forwarded. A CLI update could drop the marker without an error; the cache read counts in the host events would show it.

### Estimated effect

Prices as the CLI computes them for `claude-sonnet-5-5`: input USD 2.00, five-minute write USD 2.50, read USD 0.10 per million tokens. A token read instead of written saves USD 2.40 per million.

- Shared component context read instead of written: about USD 0.10 per call that repeats it, at the Express server's measured 40,000 tokens (point 2). With the same instructions for all parts, every call except the first of each component repeats the context: 13 of the baseline's 16 calls, about USD 1.2, or about USD 0.7 for the about 10 calls expected after the preload fix. Without that change only a job's later calls repeat it: 7 of the baseline's 16 calls, fewer after the preload fix.
- Option 2 adds the job's preloaded source on its second call, 10,000 to 23,000 tokens or USD 0.02 to 0.06 per second call, and removes the premium on each call's unique rest.
- Side finding, measured over the fourth pilot run's 112 recorded calls: they wrote 5,625,396 tokens into the cache and read 819,989, for USD 18.72. The write premium was USD 2.81, 15 percent. Switching the CLI's caching off without own markers would save only about USD 1.25, because the system prompt reads would then cost the full input price. With option 2's marker after the trusted preamble the system prompt is still read, so most of the USD 2.81 is saved.

### Live check

The stand-in cannot show whether the API accepts the four markers with the subscription's login, or whether a second call reads the marked block. The product owner ran a script on 2026-10-24 that made four sequential calls with the transport's flags on synthetic text only: a marked shared block and a varying block, twice with the CLI's caching on and twice with it off. It cost USD 0.067, and all four calls succeeded.

| Call | Input | Written | Read | USD |
|---|---|---|---|---|
| Caching on, part 1 | 2 | 11,248 | 0 | 0.0286 |
| Caching on, part 2 | 2 | 1,770 | 9,478 | 0.0059 |
| Caching off, part 1 | 1,771 | 9,478 | 0 | 0.0278 |
| Caching off, part 2 | 1,772 | 0 | 9,478 | 0.0050 |

The second call of each pair read the 9,478 tokens up to the own marker (tools, system prompt, shared block), so the marker works across separate `claude -p` processes. With the CLI's caching on, each call also wrote its varying rest at the write price; with it off, the rest was billed as plain input and nothing after the own marker was written. The shared block came out at about 9,000 tokens instead of the planned 5,000, which does not change the result.

### Built

Option 2 is merged in d9ee6490. a26ac7b5 gives every exchange prompt its blocks and sends them from the assessment's CLI host as stream-json with own markers and `DISABLE_PROMPT_CACHING=1`, for every role. c7384e4d gives all verification jobs of a component and aspect the catalog text of all their test cases, marks the component's context and the aspect as shared, runs the first job of every component and aspect before all later ones, and starts a later job once its first has ended.

Rebuilt offline the same way as in point 2, all 9 AuthZ jobs of the fourth run's three components get the same 17,001 bytes of instructions, and the 7 Express jobs share a block of 53,720 bytes after the 704-byte preamble. For the fourth run's call pattern of 16 AuthZ calls, the estimated input cost falls from about USD 2.49 after the path cut to about USD 1.17. The estimate assumes 2.3 bytes per token, 8,000 tokens of further reads per later call and no additional corrections; the output, USD 1.32 in that run, stays.

The survey jobs of a component then still differed in their instructions ("This is job 2 of 5"). On the branch `feat/verify-quality-survey-cache` they get the same instructions: the job count and the duty of job 1 to report what only the supplied controls, flows or boundaries show moved into a `survey_jobs` context key after the shared component context, and the jobs mark that context as shared. The jobs of a component run one after another, at most 2 minutes 22 seconds apart in the fourth run, so the five-minute cache entry holds without waiting.

Rebuilt offline from the measuring run, with each survey job answered by the artifact the run accepted for it, the 22 survey jobs keep their batches and preload. The later jobs of the Express server (4 of 5) and of the Angular frontend (9 of 10) share their instructions and a component context of 50,802 and 57,766 bytes. With one call per job and 2.3 bytes per token, the survey's cache writes fall from 1,446,000 tokens (measured: 1.46 million) to 923,000 and its cache reads rise from 66,000 to 592,000; its input cost falls from about USD 3.62 to USD 2.37. The change leaves the verification requests as they were; the rebuild reused them.

## 4. Larger verification jobs

A job takes at most 40 candidates (`MAX_CANDIDATES` in `scripts/model/case_candidates.py`). 80 would cut the Express server's 7 jobs to about 4, but each candidate would get about half as much preloaded source, which can raise further reads or undecidable answers. Decide only with a comparison run.

## 5. Limits of the preload fix

- Route chains such as `app.route(path).get(guard)` still resolve no guard definition.
- A middleware passed through a wrapper, such as `asyncHandler(check())`, yields only the wrapper's first body as its span.
- A data model defined as a class or behind an export alias is served from its module's first line, at most `MAX_MODEL_LINES` (120) lines; a longer model file may be cut off.
- Only `finale-rest` and `epilogue` resource generators get data models.

## 6. The route inventory is built twice

The architecture phase builds the route inventory once per repository (`_assessment_inventories` in `scripts/orchestrator/orchestration_controller.py`), and the consolidation runs `analyzers/route_inventory.py` again before the coverage checks. Building it once and reusing it would save a deterministic pass, so run time, not model cost.

## 7. Recommendations from another session, assessed

Another session recommended splitting verification by size instead of by aspect: one call per component with every applicable test case of every aspect, split only above 40 candidates. Its three options and their assessment:

- **One call per component with all test cases.** At standard depth only AuthZ is verified, so the 9 Juice Shop jobs already were one call per component, split at 40 candidates; the Express server's roughly 250 candidates still need about 7 parts. Pooling saves only where a component gets several aspects, which is thorough depth, and there mostly for small components. It must keep each aspect assignable to verification or the survey on its own, with results and cost per aspect: results stay per test case, but a pooled call needs a rule that splits its cost, for example by candidate share. Whether a longer list of questions lowers thoroughness per question needs a thorough run.
- **Test cases and open search in one call.** Within verification this exists in part: the goal item, such as TC-AUTHZ-06, rides along in the first job of each component. The `open_reviewer` contract in `scripts/contexts/case_analysis.py` exists, but the controller does not dispatch it. Merging verification into the survey call would contradict the decisions that verification never replaces the survey and that both methods find independently.
- **Several calls with prompt caching.** This matches point 3, with two corrections: moving the catalog text out of the instructions is not enough, since a marker must follow the shared context (the response schema stays the same up to a job's third call, see point 3); and the source is not shared between parts, only the component context.

## 8. Survey findings that verification missed

The product owner asked whether verification should build on the survey's findings to raise quality. Feeding survey findings to verification was not built: the model tends to confirm what it is shown, and "found by both" would no longer be independent evidence (REQ-040 reports it per finding). Instead, an offline analysis on 2026-10-24 asked why verification missed survey findings, to fix the causes in verification itself; each miss is listed in [the gap analysis](verification-gaps-pilot-runs-3-4-2026-10-24.md).

In the measuring run verification found all 4 survey findings with an authorization CWE itself, and no survey finding is contradicted by a verified control in any run. In pilot runs 3 and 4, which also verified InputVal, DataProt and AI, 27 survey findings of a verified aspect had no verification finding on the same line with the same CWE family:

- 13 are the same weakness that verification reported elsewhere: at the sink in the frontend while the survey cites the server-side source, on the server side while the survey cites the client, or on the same line under another CWE family.
- 5 were jobs that returned no acceptable result in run 3; fixed since 612811f1.
- 4 had no starting place: a token in `localStorage` (Angular frontend, both runs), and the captcha answer and the application configuration in GET responses (run 4).
- 4 were out of scope: three embedded secrets whose item TC-DATA-03 the pilot profile disabled, and one in a component without routes.
- 1 survey finding is doubtful: the data export writes only the caller's own data.

A targeted follow-up check of such survey findings would cover about 2 to 3 per thorough run after the fixes below, and none at standard depth with AuthZ only, so it was not built.

Built with offline tests and merged into main (3515cf86):

- TC-DATA-02 also starts from browser code that keeps a credential in script-readable storage: `localStorage` or `sessionStorage` writes, script-set cookies and `document.cookie` with a credential-like key (code site kind `client_storage`). Juice Shop's Angular frontend gets one DataProt job with 9 such places; before, it got none.
- TC-DATA-01 also starts from GET routes whose handlers create or save a record or read configuration. On Juice Shop the Express server's DataProt candidates grow from 41 to 50, which needs a second job.
- A scanner hit inside a handler lists the routes whose resolved handler reaches it (`reached_by`, at most 3), so the job knows which registration and guards decide it; their guards and registrations are preloaded only into room the candidates leave. All 20 such TC-AUTHZ-01 candidates on the Express server get their route. Job 1 there fills its 36 preload windows with candidates, so the prefix guard at `server.ts:356` still has to be read; point 9 shows that the job did not read it, and why `reached_by` now names it.
- TC-AUTHZ-01's guidance says that a control must bind every lookup of user-owned data the handler makes, and that a lookup by a transformed or non-unique attribute of the caller, such as a masked e-mail, does not bind it. This changes the verification instructions, so no earlier verification job is reused.

Two survey defects showed up and are not fixed: the fourth run anchored a finding on a commented-out route line (`server.ts:370`, `// app.put(...)`) and it passed the evidence review, and it kept two findings with the same line and CWE (T-072, T-073).

## 9. Second measuring run

Juice Shop at standard depth with AuthZ and DataProt verified, started from a copy of the first measuring run, so recon, architecture, controls and boundaries came from its accepted jobs (output `juice-verify-cost-2`, code c7d5470f). The run took 47 minutes of working time; a 29-minute pause while the laptop slept is not counted.

| Accepted jobs, USD | First run (AuthZ) | Second run (AuthZ, DataProt) |
| --- | --- | --- |
| Survey jobs | 5.26 | 4.41 |
| Evidence review | 2.01 | 2.07 |
| Verify AuthZ | 2.57 | 2.33 |
| Verify DataProt | – | 1.03 |
| All jobs | 12.96 | 12.87 |

The survey's cache reads rose from 66,000 to 1.0 million tokens and its writes fell from 1.46 to 1.03 million, so the shared survey instructions save about USD 0.85; the offline rebuild predicted fewer reads because it counted one call per job, while correction calls read the cache too. The savings pay for most of DataProt. The closing line's USD 12.87 and 128 calls include USD 1.83 and 24 calls for the 17 reused jobs; the real calls cost USD 11.03.

| Juice Shop at standard depth, USD | Pilot 2 (AuthZ) | Pilot 3 (AuthZ, DataProt, InputVal) | First measuring run (AuthZ) | Second measuring run (AuthZ, DataProt) |
| --- | --- | --- | --- | --- |
| Survey jobs | 7.49 | 7.14 | 5.26 | 4.41 |
| Verification | 3.05 | 6.45 | 2.57 | 3.36 |
| Evidence review | 2.27 | 2.67 | 2.01 | 2.07 |
| Other jobs | 3.55 | 3.71 | 3.12 | 3.03 |
| Accepted jobs | 16.36 | 19.97 | 12.96 | 12.87 |
| Closing line | 20.56 | 22.23 | 12.96 | 12.87 |

Most of the drop since the pilot runs came before the second run. The own cache markers of point 3 cut the survey by about USD 2 for every role that uses them, the smaller verification context and fewer corrections cut verification, and the jobs that failed or were repeated in the pilot runs, about USD 4 above the accepted jobs in pilot 2, no longer occur since 612811f1. The shared survey instructions add the USD 0.85 above.

What the fixes of point 8 did:

- The Angular frontend's new DataProt job found the session token in `localStorage` (`login.component.ts:101`, CWE-922).
- The data export is now a finding instead of a wrong control, and `orderHistory.ts:17` with the same masked-email lookup is new.
- The image captcha's answer was found. The text captcha was a candidate now, but the job dismissed it as "returned by design to this challenge app".
- The application configuration was found as an AuthZ finding (`server.ts:607`), not as DataProt.
- Verification reported 35 AuthZ findings, 28 of them not in the survey. The 3 AuthZ survey findings verification did not link it reported elsewhere: the registration role on neighbouring lines, the image captcha under another CWE family, the configuration under AuthZ. Of the DataProt survey findings, whoami (`currentUser.ts:30`) had no candidate because its handler reads no stored data, and the challenge flags sent to every WebSocket lie outside the catalog.

Defects found, each fixed on main with tests:

- A false finding: the checkout's wallet debit at `order.ts:150` was reported as trusting a client-supplied UserId, because job 1 never saw the prefix guard with `appendUserId` at `server.ts:356`. `reached_by` now lists where the route and its guards are registered (d376462a).
- The verification policy now states that an application's purpose never makes a weakness acceptable, and when `public-by-design` applies (ed4cff29).
- A wrong contradiction: a control for one generated REST route at `server.ts:501`, the generator call that registers 37 routes, contradicted the survey's finding about another. A line that registers several routes is no longer a control location (3785a26e).
- Two jobs reported the data export at `dataExport.ts:33` twice; combined jobs now report a weakness at one line and CWE family once (0199b02f).
- Every Juice Shop run reported the session token in browser storage twice, once from the survey and once from abuse case AC-T-001, because promoted abuse-case findings came after the merge. They now go through the merge's grouping and review against the findings already there (c8b9afb2); offline, exactly this pair is the one group the merger is asked about in both measuring runs.
- The closing line names what reused jobs cost (4ba33332), and the summary says how many undecidable items had no location to examine (5cf5bd45): 21 of the run's 22.

The live progress now says what each step produced, each number once: the survey its findings and cost, verification each aspect's findings and cost, the merge its survey and scanner inputs, the consolidation per aspect what only one method found and how many findings the report keeps, and a line for abuse-case findings that were merged or added.

## 10. Third measuring run

Juice Shop at standard depth with AuthN, AuthZ, DataProt, InputVal and AI verified, started from a copy of the first measuring run like point 9 (output `juice-verify-cost-3`, code ba28e3bd). The run took 55 minutes of working time and recorded no run issue.

| Accepted jobs, USD | Second run (AuthZ, DataProt) | Third run (AuthN, AuthZ, DataProt, InputVal, AI) |
| --- | --- | --- |
| Survey jobs | 4.41 | 4.24 |
| Evidence review | 2.07 | 2.00 |
| Verify AuthZ | 2.33 | 2.30 |
| Verify DataProt | 1.03 | 1.02 |
| Verify AuthN | – | 2.09 |
| Verify InputVal | – | 1.30 |
| Verify AI | – | 0.19 |
| Other jobs, reused ones included | 3.03 | 3.09 |
| All jobs | 12.87 | 16.24 |

The real calls cost USD 14.40 for 125 calls; the closing line's USD 16.24 and 149 calls include USD 1.83 and 24 calls for the 17 reused jobs. Verification ran 30 jobs with 43 calls: AuthZ 9 jobs and 14 calls, AuthN 9 and 13, DataProt 6 and 8, InputVal 5 and 7, AI 1 and 1. The offline estimate before the run was USD 1.90 for AuthN, 1.10 for InputVal, 0.20 for AI and USD 14 to 15 for the real calls.

What the fixes of point 9 did:

- The wallet sites `routes/order.ts:148`, 150 and 157 are controls again; the answer at line 148 cites the prefix guard at `server.ts:356`, and the false wallet finding is gone.
- The text captcha's answer (`routes/captcha.ts:31`) is a DataProt finding.
- The session token in browser storage is one finding: the survey's at `login.component.ts:101`, linked with the DataProt finding there. Abuse case AC-T-001 binds its step at `basket.service.ts:64` to it; the merge of abuse-case findings made one call for USD 0.01.
- No survey finding is contradicted, so neither is the one at `server.ts:501`.
- `dataExport.ts:33` is one finding, although jobs 1 and 7 of the Express server both reported it.

One defect is new, caused by the fold of 0199b02f. Job 6 of the Express server reported three findings at `server.ts:501`, the generator call that registers 37 routes: the product update (PUT, R-263), the hint update (PUT, R-286) and security answers with a caller-chosen UserId (POST, R-256). The fold's identity is file, line and CWE family, and CWE-862 and CWE-915 share the family `authz`, so the report kept only the product update. The security answers finding, TCF-024 in the first measuring run, is missing, and the hint update survives only inside AuthN's finding at `server.ts:503`.

Fixed in `_fold_duplicate_findings` with a test: findings whose candidates name different routes stay apart, and a candidate without a route, such as the code site at `dataExport.ts:33`, still folds. Recombining this run's accepted replies with the fix gives the three findings at `server.ts:501` back and still one at `dataExport.ts:33`; the findings of the other aspects do not change.

### Benefit per aspect

"Only Verify" and "only survey" are the consolidation lines. "New" counts verification findings with no other finding at the same line: no survey or scanner finding and none of another aspect.

| Aspect | Findings | Only Verify | Only survey | New | USD |
| --- | --- | --- | --- | --- | --- |
| AuthZ | 33 | 27 | 3 | 16, 4 of them High | 2.30 |
| InputVal | 25 | 8 | 5 | 6, 2 of them High | 1.30 |
| DataProt | 10 | 6 | 3 | 4, 1 of them High | 1.02 |
| AuthN | 18 | 14 | 2 | 5, none High | 2.09 |
| AI | 2 | 2 | 10 | 1, Low | 0.19 |

- AuthZ's new findings are mostly routes of the route table without an owner or role check and request bodies that set the owner. The four High ones are the basket item's BasketId from the body, the product update, the address update by ID and the user list.
- InputVal links 17 of its 25 findings to the survey, so most of its value is independent confirmation. New are XXE in the XML upload (`lib/xml.ts:35`) and the browsable key directory (`server.ts:277`), both High, the log directory, a null-byte bypass of the FTP allow-list and two Low ones.
- DataProt adds TOTP secrets stored in plaintext (High), both captcha answers, and the password hash and TOTP secret in the login IP response.
- AuthN's 13 other findings lie on lines where another method already reports a finding, mostly of the same weakness: AuthZ (`server.ts:278`, `server.ts:676`, `routes/memory.ts:24`), the scanners (the unpinned token algorithm, routes without authentication middleware), DataProt (the embedded private key) or the survey. The report lists most of these weaknesses twice. Its 5 new findings are two missing password strength rules, two routes without authentication that AuthZ reports on neighbouring lines, and unauthenticated socket.io connections (Low).
- AI's "only survey" count is overstated, because the AI catalog's CWEs overlap other aspects (point 8).

The product owner decided on 2026-10-24 that `standard` verifies AuthZ, InputVal, DataProt and AI, and that `thorough` adds AuthN, which no depth verified before. On Juice Shop this raises standard's verification from USD 2.30 to USD 4.81; AI gets jobs only for components with a language model signal. The cheaper variant, AuthZ and DataProt, would have cost USD 1.02 more. The figures come from one run of a deliberately vulnerable application.

AuthN has two parts of very different value. TC-AUTHN-01, sensitive routes require authentication, had 169 of AuthN's 229 candidates and about USD 1.5 of its USD 2.09, estimated by each job's share of candidates. Its 9 findings are all CWE-306; 7 are routes that AuthZ, the scanners or the survey already report, and the 2 new ones, socket.io connections and the web3 routes, are Low. TC-AUTHN-02 to 05, tokens, passwords and recovery, had 60 candidates for about USD 0.6. Their 9 findings include all 6 High ones of AuthN, which the survey or the scanners found too (MD5 twice, the unpinned token algorithm, the embedded key, a password change without the current password, a reset by security answer), and 3 new Medium ones (password strength twice, token expiry not checked). The deterministic route checks settle too little to make TC-AUTHN-01 cheap: on the Express server they confirmed 30 of its 71 controls and 9 of its 14 weaknesses without the model.

The product owner considers parts of authentication, such as a correct SSO or OAuth integration, central enough for standard depth. That speaks for splitting AuthN: the token, password and recovery items at standard depth, the route item at thorough depth. The catalog has no item for an OAuth or OIDC flow itself, such as state, PKCE, redirect URIs or ID token checks; the survey's finding of an implicit OAuth flow without state or PKCE (`login.component.ts:148`) had no verification item to match.

Built, as the product owner decided: TC-AUTHN-01 keeps its ID and moves to the aspect `AuthNRoutes`, which only `thorough` verifies; `AuthN` keeps TC-AUTHN-02 to 05 and gains TC-AUTHN-06 for SSO and OAuth sign-in and TC-AUTHN-07 for insecure methods (credentials and tokens in URLs, Basic authentication, the implicit and password grants, passwords a client encodes itself); `standard` verifies `AuthN`. The new items start from code sites alone, since no scanner rule covers them, and apply only where the code signs in through OAuth, OpenID Connect or SAML or passes credentials that way. A site after a URL's `://` now counts, which the comment guard of the code sites dropped before. The catalog is version 6, so no earlier verification job is reused. Counted offline on Juice Shop with the third run's components and candidates, without model calls: `AuthN` needs 4 jobs instead of 9, with TC-AUTHN-06 at the three places of the Angular frontend's hand-built implicit flow and TC-AUTHN-07 at those and at the password built from the e-mail address (`oauth.component.ts:30`, 46); `AuthNRoutes` needs 6. The cost of `AuthN` at standard depth is therefore expected at about USD 0.6 to 0.9; a run has not measured it.

Not fixed:

- Verification findings of different aspects at one line stay separate findings, for example the embedded private key at `lib/insecurity.ts:21` from AuthN and DataProt beside the scanner's finding, or `routes/memory.ts:24` from AuthN, AuthZ, DataProt and the survey. The fold works only within one component and aspect.
- Verification findings are linked only with survey findings. At the same line and CWE as a scanner finding both stay in the report: T-013 and the unpinned token algorithm, T-027 and the Pug template, T-020 and the layout path, T-031 and the embedded key.

Still open from earlier points, each to be solved for any repository:

- AI is selected only by the `llm_features` signal, which detects SDK imports in JavaScript and Python. An architecture that names a language model service should select it too.
- Handlers that return the caller's data without reading stored data, such as whoami (`currentUser.ts`, point 9), have no starting point.
- TC-AUTHZ-01 has no deterministic support that makes every data lookup of a handler a sink (fix 2 in [the control answers check](verification-control-answers-check-2026-10-24.md)).
- The two survey defects of point 8: a finding on a commented-out line passed the evidence review, and two findings with the same line and CWE stayed apart.

### Business abuse cases and verification

Asked by the product owner on 2026-10-25 whether abuse cases do the same as verification. The boundary, as the README now states it: verification checks a general security property at every place of a component where it matters; an abuse case starts from a goal and asks whether it can be reached in this application from start to end. Technical abuse cases link existing findings into an attack path and rate it, so they run after the findings exist; in the third run 12 of the 16 steps of all ten checked abuse cases were bound to findings already there, for USD 0.47. Business abuse cases state what users of this application must not be able to do. Rules a team supplies are what verification cannot know, and they stay as they are.

The overlap lies in three built-in business cases that ask a verification question: AC-B-001 (other users' data) and AC-B-002 (more rights than intended) under AuthZ, AC-B-003 (account takeover) under AuthN. Standard depth checks three optional business cases, chosen by the most related findings, so in the first three measuring runs AC-B-001 and AC-B-003 took places while AC-B-002, AC-B-006 and AC-B-007 never ran. Decided: a built-in case names the aspects that ask its question (`verified_by`), and when the run verifies one of them, it comes after the other optional cases; its omission names the aspect. Requested, team-supplied and model-derived cases keep their own limits and order. Not built: merging business cases into verification, and answering a business case from verification results.

Abuse cases still bind only to survey and scanner findings, because verification findings are not in the findings register yet; in the third run AC-T-003 (JWT algorithm confusion) stayed inconclusive although AuthN had found the unpinned algorithm (TCF-077). The planned combined register (be4dbc35) would let the chains use them.

## 11. Fourth measuring run

Juice Shop at standard depth with the shipped default aspects AuthN, AuthZ, InputVal, DataProt and AI and a budget of USD 25, started from a copy of the third measuring run (output `juice-verify-cost-4`). The completing attempt ran on 34ab1527. Its verification jobs came from an earlier attempt on b41a37be; no change between the two alters a model request. The run recorded no run issue. It cost USD 15.91 for 149 calls: 125 calls for USD 14.72 were reused from earlier attempts and the third run, and the last attempt made 24 calls for USD 1.19, for abuse cases and the report. The attempts are listed in [the run's handoff](verification-run-4-handoff-2026-10-25.md).

### Aborted attempts

Three attempts stopped before the fourth completed:

- The first started 25 seconds after a restart, and systemd then emptied `/tmp` together with the host directory. It stopped after four minutes without a new model call. The run script now sets `TMPDIR` outside `/tmp`; the analyzer is unchanged.
- The second stopped after verification with "Selected source state changed", because another agent wrote into the Juice Shop checkout during the run. Every receipt is bound to the fingerprint of the whole source, although the analysis reads only the snapshot taken at the start. A requirement that lets such a run finish on its snapshot and name the changed files is drafted; its wording awaits approval.
- The third stopped after the merge with "Merged finding anchor is outside its component ownership". Verification accepted the XXE finding TCF-045 at `lib/xml.ts:35`, a file of no component, and the merge's ownership check rejected it. Fixed at both checks in 34ab1527.

### Cost

| Accepted jobs, USD | Third run | Fourth run |
| --- | --- | --- |
| Survey jobs | 4.24 | 4.24, reused |
| Evidence review | 2.00 | 2.00, reused |
| Verify AuthZ | 2.30 | 2.54 |
| Verify InputVal | 1.30 | 1.37 |
| Verify DataProt | 1.02 | 1.10 |
| Verify AuthN | 2.09, with TC-AUTHN-01 | 0.99 |
| Verify AI | 0.19 | 0.19 |
| Finding combination | – | 0.30 |
| Other jobs, reused ones included | 3.09 | 3.19 |
| All jobs | 16.24 | 15.91 |

- Catalog version 6 changed every verification request, so no verification job was reused from the third run. Verification ran 25 jobs with 38 calls, against 30 and 43: AuthN 4 jobs and 6 calls instead of 9 and 13, AuthZ 9 and 15, DataProt 6 and 9, InputVal 5 and 7, AI 1 and 1.
- AuthN without TC-AUTHN-01 cost USD 0.99, slightly above the offline estimate of USD 0.6 to 0.9. AuthZ, InputVal and DataProt cost 5 to 11 percent more than in the third run; AuthZ made one call more.
- Verification at standard depth now costs USD 6.18 on Juice Shop, against USD 6.90 for the five aspects of the third run.
- The new finding_combiner role made 4 calls for USD 0.30 and wrote 44 combined texts; about two thirds of its cost is output.

### Results

- TC-AUTHN-06 reported the hand-built implicit flow at `login.component.ts:148`, and the register made it one finding with the survey's (CWE-352, High). TC-AUTHN-07 reported the password built from the e-mail address (`oauth.component.ts:30`, used for the login at line 46) and the token in the userinfo URL (`user.service.ts:68`). Both joined survey findings, the second also a DataProt finding. All three confirm survey findings; none is new.
- At `server.ts:501` the product update (T-057) and the hint update (T-072) stay separate findings, so the fix of fa4e2924 holds. The security answers with a caller-chosen UserId (R-256) are missing again, for another reason: the Express job answered "undecidable, missing-source" because the `SecurityAnswer` data model was not served. The job's served ranges list six data models of generated routes but not `models/securityAnswer.ts`, and the job made one call without asking for it. The third run's job did not get that file either and answered with a weakness.
- AC-B-001, AC-B-002 and AC-B-003 were not performed, each naming the verified aspect that asks its question. AC-B-004, AC-B-005 and AC-B-007 ran, and AC-B-006 exceeded the limit. This is the order 6a02d919 set.
- AC-T-003 (JWT algorithm confusion) stays inconclusive, for another reason than assumed. Its first step, the unpinned algorithm, was already confirmed in the third run through the scanner finding at `routes/verify.ts:120`, which now also carries AuthN's finding. The open second step asks whether a forged role claim is accepted without reading the role from the database, and no method reports a finding about it.
- The merge made 154 findings from 110 survey findings, 101 scanner hits and 91 verification findings. 121 are in the report, 10 were refuted and 23 fell below the severity floor. 43 of the 121 name more than one method. TCF-045 is T-038, a High finding of the Express server.
- The pairs that point 10 left apart are one finding each now: the embedded private key at `lib/insecurity.ts:21` (AuthN and DataProt with the survey), the unpinned token algorithm (survey, scanners and AuthN), the Pug template, the layout path and `routes/memory.ts:24`.
- Of 44 combined texts, 43 were applied. The 44th belonged to a Low finding that the severity floor removed afterwards, because the combination runs before the floor.

Defects and inconsistencies found:

- A combined text can state a wrong number of places. T-058 holds 14 distinct places and says "Two route registrations in server.ts are weak", T-053 holds 8 and says "Two routes", and T-003 holds 5 in five components and says "Three frontend components". `_part` in `scripts/model/merge_threats.py` gives the combiner only each part's primary location, so the model counts parts instead of places. 10 of the 43 combined findings hold more than two places.
- A verification finding joins a scanner finding at any of the scanner finding's locations, so one finding can hold different weaknesses. T-001 combines the scanner's trusted owner field at `routes/dataExport.ts:26` with verification's basket item update at `routes/basketItems.ts:68`, and T-058 the registration without authentication at `server.ts:598` with the feedback UserId at `server.ts:402`. This follows the rule of f08b618e, but the combined text then describes two weaknesses.
- The consolidation's "121 of 154 findings in the report" and the closing summary's "Findings 55" are two counts. The closing row counts the Management Summary's risk distribution: it leaves out the 69 findings that fold into a weakness as insecure practice and adds the 3 design-risk weaknesses, 52 plus 3. The third run counted the same way, 79 findings and 39 in the row. Unlike the overview that `summarize_threat_model.py` renders, the closing row does not name the register count.
- Since f08b618e a verification finding without a partner and without a confirming post-check is labelled insecure practice, so it folds as well. 26 of the 41 findings only verification reported are outside the 55, among them the Critical registration with a client-chosen role (T-013, the report's scenario 3.3) and 7 High ones. The row says "Critical 3" while the register holds 5 Critical findings.
- The closing line's "≥ 639k tokens" counts only the last attempt's 24 calls, while its cost covers all 149.
- The `Verify start` line estimated about USD 0.58 instead of about USD 6, because `has_accepted` in `scripts/runtime/assessment_jobs.py` counts a receipt whose request changed, here after the catalog change.

### Benefit per aspect

"Only Verify" and "only survey" are the consolidation lines, from the third attempt's console and an offline replay of the same jobs. "New" counts register findings that only verification reported and that share no line with a survey or scanner finding or a finding of another aspect.

| Aspect | Findings | Only Verify | Only survey | New | USD |
| --- | --- | --- | --- | --- | --- |
| AuthZ | 34 | 28 | 4 | 14, 1 of them High | 2.54 |
| InputVal | 27 | 6 | 4 | 5, 4 of them High | 1.37 |
| DataProt | 14 | 6 | 3 | 3, 1 of them High | 1.10 |
| AuthN | 14 | 4 | 3 | 3, none High | 0.99 |
| AI | 2 | 1 | 9 | none | 0.19 |

- AuthN's new findings are the missing password strength rule on change and on reset, which the third run found too, and account enumeration through the security question lookup (`routes/securityQuestion.ts:21`). Its other 11 findings include all 8 High ones, each also reported by the survey or the scanners: MD5 twice, the unpinned algorithm, the embedded key, the password change without the current password, the reset by security answer, the implicit flow and the password built from the e-mail address. The token check without expiry, issuer or audience (`lib/insecurity.ts:55`) is reported only by verification, on a line where the algorithm finding also lies.
- At standard depth AuthN therefore mostly confirms other methods, for half the third run's cost. Per new finding AuthN costs about USD 0.33, AuthZ USD 0.18, InputVal USD 0.27 and DataProt USD 0.37.
- AuthZ's new High finding is the product update at `server.ts:501`. Of the third run's four new High ones, the basket item's BasketId and the address update are Medium this time, and the user list joined a survey finding (T-055).
- InputVal's new findings are the XXE, the browsable ftp folder and key directory and the null-byte bypass, all High, and the fetched profile image written to a public folder.
- DataProt's new findings are the TOTP secrets stored in plaintext (High), the application configuration served to anonymous callers and the full user record in the login IP response.

The figures come from one run of a deliberately vulnerable application.

### Open from this run

Each to be solved for any repository:

- Give the combiner each part's locations or their number, and let the policy forbid counts the context does not give. Fixed in 22f10c00: each request carries `location_count`, and the policy allows a number of places only from it.
- Find out why the Express job's preload served six data models but not `models/securityAnswer.ts`, and why the job answered undecidable instead of reading the file. Cause: data models get a quarter of the free preload windows, six in that job, and `evidence_preload` kept files in path order, so the job got the first six of eleven models alphabetically. Fixed: the models most candidates need come first, and each generated candidate names where its data model is defined when the job may read that file. Rebuilt offline, the job now gets `models/securityAnswer.ts`, and its 59 generated candidates name their models, among them the five still left out; the verification requests grow by 0.5 percent.
- Decide whether verification findings without a confirming post-check count in the closing summary's Findings row, and let the row name the register count when the two differ.
- Let the closing line's token count cover the same calls as its cost. Receipts of reused calls record no tokens, so the line now names the calls its tokens cover, such as "639k tokens in 24 of them", instead of "≥ 639k tokens".
- Deferred: let the `Verify start` estimate leave out receipts whose request changed. The estimate is made before the requests are built; telling a changed request apart needs a hash of the role instructions in every receipt or building all requests first. It matters only when the catalog or a policy changes between an interrupted run and its continuation.
- Let a run finish on its snapshot when the source changes, once the drafted requirement is approved.

## 12. Fifth measuring run

Juice Shop at standard depth with the shipped default aspects and a budget of USD 25, started from a copy of the fourth measuring run (output `juice-verify-cost-5`, code d1429c36, the fixes of point 11). Recon, architecture, controls, boundaries, the survey and the evidence review came from the fourth run's accepted jobs; every verification job ran again, since the preload fix changes its instructions and candidates. The run completed without an abort or a run issue. It cost USD 15.59 for 147 calls; 83 calls for USD 8.24 were reused, and the 64 new calls cost about USD 7.35.

| Accepted jobs, USD | Fourth run | Fifth run |
| --- | --- | --- |
| Verify AuthZ | 2.54 | 2.49 |
| Verify InputVal | 1.37 | 1.33 |
| Verify DataProt | 1.10 | 1.10 |
| Verify AuthN | 0.99 | 0.81 |
| Verify AI | 0.19 | 0.18 |
| Finding combination | 0.30 | 0.25 |
| All jobs | 15.91 | 15.59 |

The fixes of point 11:

- No combined text states a wrong number of places. Of the 10 combined findings with more than two places, T-004 says "6 locations" for its 6 places, T-081 says that it "holds a further place", and the others name no number.
- The Express AuthZ job that lacked `models/securityAnswer.ts` got it, among the six data models its candidates need most. POST /api/SecurityAnswers is a finding again (T-115, CWE-639, a caller-chosen UserId), and the three findings at `server.ts:501` stay apart (T-056, T-072, T-115).
- The closing line reads "≈ USD 15.59 · 147 model calls · 3.2M tokens in 64 of them".

A defect the run showed: a verification job anchored a finding in a file of another component three times, as in the second and third runs. The decisive line lay there: the embedded key in `lib/insecurity.ts` from the data layer, the address update registered in `server.ts` from the authentication surface, and the role field in `models/user.ts` from the Express server. Acceptance rejects such anchors because the owning component's jobs report them, but the correction said "move or remove it" or "anchor it in one of them". Over the second, third and fifth runs, 4 of 9 corrections removed the finding and 5 moved it to a line of the job's own files that does not show the weakness. In this run that made T-058, the address update at `lib/insecurity.ts:178`, which repeats T-051 at `server.ts:426`, and moved the role field to `server.ts:422`, where several findings already report it. The diagnostic log read the apostrophe of "component's" as the start of a quoted value, so these rejections were unreadable there. Fixed in 80ca6d1d: the investigation policy says to leave such a weakness out, both corrections allow a new anchor only at a line that itself shows the weakness, and an apostrophe inside a word no longer opens a quote in the log. The next run measures it.

The run also reports 113 findings in the register and 52 in the closing Findings row (Critical 3, High 18, Medium 31), 43 verification findings and 4 controls, and 5 confirmed and 5 unresolved abuse cases. Since f4692241 the closing summary names the register by severity beside that row when the two differ; the counting is unchanged.

### Benefit per aspect

"New" counts register findings that only verification reported and that share no line with a survey or scanner finding or with a finding of another aspect; "confirmed" means a post-check confirmed it.

| Aspect | Findings | Also survey or scanner | New | New Critical or High | New confirmed | USD |
| --- | --- | --- | --- | --- | --- | --- |
| AuthZ | 27 | 9 | 13 | 6 | 0 | 2.49 |
| InputVal | 18 | 14 | 4 | 3 | 4 | 1.33 |
| DataProt | 14 | 8 | 5 | 1 | 5 | 1.10 |
| AuthN | 12 | 8 | 4 | 1 | 0 | 0.81 |
| AI | 1 | 0 | 0 | 0 | – | 0.18 |

- The third and fourth runs had 32 and 25 new findings with 7 and 6 High ones, so the benefit is stable while severities vary between runs.
- InputVal and DataProt add serious findings the survey missed, each confirmed by a post-check: XXE, directory listings with keys, the null-byte bypass of the FTP allow-list, TOTP secrets in plaintext and the captcha answers in responses.
- AuthZ names single routes without an owner or role check, such as `GET /api/Users/:id`, `PUT /api/Products` and `POST /api/SecurityAnswers`, where the survey and the scanners report at most a systemic finding. Two of its 13 new findings are artifacts: T-058, the moved duplicate fixed in 80ca6d1d, and T-014, the role field anchored at `routes/verify.ts:53`, which repeats T-057.
- No new AuthZ or AuthN finding has a post-check, so all of them stay unscored and outside the headline count, the Critical T-014 included. The value of the route-level findings shows only in the register.
- AuthN mostly confirms: of its 4 new findings one is High, a Google profile accepted without checking the token audience. It stays at standard depth by the product owner's decision for SSO and OAuth.
- About 40 findings were reported by two or more methods independently, which makes them more reliable without lengthening the list.

The figures come from one deliberately vulnerable application. Whether the benefit holds on an ordinary application is open.

## Order

1. Find out whether the CLI can cache behind the shared context (point 3). Done: it can, with an own marker in stream-json input.
2. Rebuild the Express server's verification context offline and size its parts (point 2). Done: the generic path cut is worth more than a cut per aspect.
3. Measure everything built so far in one run (point 1). Done: verification cost USD 2.57 instead of USD 4.45, with answers within the usual run-to-run spread.
4. Give the survey jobs of a component the same instructions, so they share their context too (point 3). Done: about USD 0.85 less in the second measuring run.
5. Measure step 4 and the verification fixes of point 8 in a second run (point 9). Done: AuthZ and DataProt cost about what AuthZ alone cost before; the fixes found the missing places, and five defects it showed are fixed.
6. Measure the fixes of point 9 in a third run with all five aspects (point 10). Done: all fixes work; the new fold merged findings of different routes at one line, which is fixed.
7. Decide the default aspects of `standard` from the cost and benefit per aspect (point 10). Done: standard verifies AuthZ, InputVal, DataProt and AI; thorough adds AuthN.
8. Split AuthN so that its token, password and recovery items, and new items for SSO and OAuth integration and for insecure authentication methods, can run at standard depth while the route item stays at thorough depth (point 10). Done: `AuthN` at standard, `AuthNRoutes` at thorough; at standard depth `AuthN` cost USD 0.99 in the fourth run (point 11).
9. Measure the AuthN split, the combined register and the later place of business cases in a fourth run (point 11). Done: AuthN mostly confirms other methods for USD 0.99, the register combines 43 findings, and the business cases run as decided; combined texts with wrong counts and a data model missing from the preload are new defects.
10. Fix the counts in combined texts, find out why the `SecurityAnswer` data model was not preloaded, and correct the closing line's token count and the `Verify start` estimate (point 11). Done except the estimate, which is deferred.
11. Measure the fixes of step 10 in a fifth run (point 12). Done: all three work; anchors in another component's file still made duplicates, fixed in 80ca6d1d.
12. Decide whether verification findings without a confirming post-check count in the closing summary's Findings row (point 11). Decided: the counting stays, since it treats every method alike, and the row names the register by severity beside it (f4692241).
13. Give AuthZ verification findings deterministic post-checks, such as a route without any guard or an owner field taken from the request body, so that route-level findings are confirmed and scored (point 12). The route inventory already knows each route's guards.
14. Measure verification on a second application that is not deliberately vulnerable, together with step 13 and 80ca6d1d (point 12).
15. Solve the open points of point 10 for any repository when one of them matters: AI selection from the architecture, a starting point for handlers like whoami, TC-AUTHZ-01's lookups as sinks, and the two survey defects.
16. Build pooling by size into the next batching step and measure it in a thorough run (point 7).
