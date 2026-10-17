---
reason: Operators want the option to fund remaining reviews when a local interactive scan reaches its budget, while CI must never wait for input or authorize extra spending implicitly.
affected_ids: [REQ-016, REQ-019, REQ-022, REQ-023, REQ-034]
compatibility: Full assessments gain --non-interactive. Eligible terminals may ask for a higher total USD limit; unattended modes retain the existing limit and fallback behavior. Owned state gains optional budget_authorizations; compatible resume with the original configuration restores only previously approved increases. Existing states remain valid. Older readers that reject the added field cannot resume newly authorized states.
verification: Offline tests cover public flag forwarding, terminal and CI eligibility, positive and malformed numeric input, decline and cancellation, serialized admission with running calls, settled budget failures, approval persistence before dispatch, failed persistence, invalid authorization history, and compatible resume. No paid calls are needed.
---

# Interactive budget approval

This extends the REQ-022 and REQ-023 acceptance contract. The input is a new total USD maximum, not an incremental amount. Approval is explicit and belongs to this run. Empty input, EOF, three invalid attempts, or cancellation never raises the limit. After declining, the process stops asking. At most 16 increases can be recorded for one run.

The question requires input and diagnostic terminals, a normal local controller console, and absence of recognized CI markers. `--non-interactive`, `--quiet`, and JSON controller output disable it. Agent-driven invocations use `--non-interactive` so the terminal's presence cannot substitute for operator authorization.

The shared admission lock prevents other workers from starting calls during the question; existing calls settle before it appears. Recording the approved limit precedes spending. Each increase is linked to the preceding maximum in owned state, while the identity retains its initial configured limit. Compatible resume with the original command restores the validated last approval; a new run gets no inherited spending permission. Time spent answering counts against the existing deadline. More money cannot override call limits, source restrictions, cancellation, or unknown accounting.

Verification passed a combined 299-test offline run covering budgets, owned state, discovery, review, public CLI, and logging. Additional terminal, public lifecycle, and specification checks passed 182 tests; after the final admission-timeout regression was added, all 127 budget and discovery tests passed. Ruff, formatting, local documentation links, and the specification gate against `688edc82` pass. These runs overlap and are not a full-suite qualification. No paid model calls were made.
