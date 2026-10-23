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

## 4. Larger verification jobs

A job takes at most 40 candidates (`MAX_CANDIDATES` in `scripts/model/case_candidates.py`). 80 would cut the Express server's 7 jobs to about 4, but each candidate would get about half as much preloaded source, which can raise further reads or undecidable answers. Decide only with a comparison run.

## 5. Limits of the preload fix

- Route chains such as `app.route(path).get(guard)` still resolve no guard definition.
- A middleware passed through a wrapper, such as `asyncHandler(check())`, yields only the wrapper's first body as its span.
- A data model defined as a class or behind an export alias is served from its module's first line, at most `MAX_MODEL_LINES` (120) lines; a longer model file may be cut off.
- Only `finale-rest` and `epilogue` resource generators get data models.

## 6. The route inventory is built twice

The architecture phase builds the route inventory once per repository (`_assessment_inventories` in `scripts/orchestrator/orchestration_controller.py`), and the consolidation runs `analyzers/route_inventory.py` again before the coverage checks. Building it once and reusing it would save a deterministic pass, so run time, not model cost.
