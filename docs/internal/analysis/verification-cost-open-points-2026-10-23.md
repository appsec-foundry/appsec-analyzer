# Verification cost: open points

Status: working document, written 2026-10-23 after merges 34da4812 and 72c57eb4. The first lets the authorization verification preload the guards of guard-only registrations and the data models of generated REST routes (2e56eb65). The second shows verification progress as one step per component (09f256e0). The points below are left open. The figures come from the receipts and host events of one interrupted Juice Shop run at standard depth, without new model calls.

## Baseline

Authorization verification ran 9 jobs with 16 calls for USD 4.28: 7 jobs for the Express server, one each for the Web3 surface and the authentication surface. 6 of the 16 calls only asked for 2 to 4 further source slices, at USD 1.34 together. Each call sent 65,000 to 100,000 input tokens, of which about 11,000 came from the prompt cache, and returned 1,000 to 20,000 tokens.

## 1. Measure the two fixes in one run

One Juice Shop run at standard depth, with a fresh output directory and a budget of about USD 25, should show:

- how many authorization verification calls run, and how many of them only ask for further source (before: 16 and 6);
- what verification costs (before USD 4.28; expected about USD 3);
- no fewer weakness answers and no more undecidable candidates than before (42 weakness answers on the Express server);
- one console row per verified component instead of one per job.

The added middleware spans change the survey requests, so the run cannot reuse earlier accepted survey jobs.

## 2. The component context dominates each call

Of each call's 65,000 to 100,000 input tokens, the served source took 26 to 70 KB, roughly 10,000 to 23,000 tokens, and the system prompt about 11,000. The rest, roughly 45,000 to 60,000 tokens, is the component context that the survey job of the same component also receives, together with the candidate list. It is the same for every part of a component and for both calls of a job. These shares are estimates from served byte counts, not measured token counts.

Next step: rebuild the Express server's verification context offline and list its parts by size. Then check which parts an aspect's answers relied on. If AuthZ needs only the authentication and authorization controls, roles and trust boundaries, cutting the context per aspect could roughly halve verification cost. The cut must hold for any repository and must not move repository text into the instructions (REQ-031).

## 3. Prompt caching with the Claude CLI host

Each call is a separate `claude -p` with one user message. Shared component context, candidates and source slices sit in the same block (`_prompt` in `scripts/runtime/assessment_host.py`), so only the system prompt is read from the cache. Find out whether the CLI accepts several separately cacheable content blocks, for example through stream-json input, or whether only an API host can mark the shared context as a cache breakpoint. This lever would apply to the survey as well, and it was already named the largest one in the [implementation status](aspect-test-cases-implementation-status-2026-10-19.md#cost-of-authorization-verification-analysed-2026-10-23).

The cache matches only a byte-identical start of the request, in the order tools, system prompt, messages, and only at a position where an earlier request set a cache marker. Three things differ today before the shared context ends:

- The response schema is the host's output tool, the first part of the request. It changes when a job must complete (`completion_required`), so the second call of a job differs from its first at the very start.
- The role instructions carry the catalog text of the job's own test cases (`catalog_instructions(share)`), so the first part of a component, which also lists the goal item, differs from the later parts.
- The CLI sets its marker at the end of the one message, after the candidates and source slices that vary per part. No marker follows the shared context.

The first two can be fixed in the controller. The third depends on the host. Only the component context is shared between parts: each part preloads the source of its own candidates.

Estimated effect for `claude-sonnet-5-5` (input USD 2.00, 5-minute cache write USD 2.50, cache read USD 0.20 per million tokens): reading 45,000 to 60,000 tokens of shared context instead of writing them saves about USD 0.10 to 0.13 per repeated call, roughly USD 1 for the about 10 calls a Juice Shop authorization verification needs after the preload fix. The receipts' costs match the 5-minute write price: 100,206 written tokens and 368 output tokens cost USD 0.254.

Side finding: every call writes its whole packet into the cache at the write premium of 25 percent, but almost nothing is read back. If caching cannot be made to hit, not writing these calls would save about 20 percent of their input cost, in the whole run and not only in verification. Whether the CLI allows that is not checked.

Next step: read how `claude -p` places cache markers and whether stream-json input can carry separately marked blocks, without model calls. Then, with the product owner's approval, test two calls that share a prefix of about 5,000 tokens, which costs a few cents.

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
- **Several calls with prompt caching.** This matches point 3, with two corrections: moving the catalog text out of the instructions is not enough, since the response schema must stay the same and a marker must follow the shared context; and the source is not shared between parts, only the component context.

## Order

1. Find out whether the CLI can cache behind the shared context (point 3), first from documentation, then with a test of a few cents.
2. Rebuild the Express server's verification context offline and size its parts (point 2).
3. Build pooling by size into the next batching step and measure it in a thorough run (point 7).
4. Measure everything built so far in one run (point 1).
