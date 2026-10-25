---
reason: A finding that only verification reported reaches the evidence review only as part of a combined finding, so unless a post-check confirms it, it stays unscored and outside the headline count, while survey and scanner findings all pass that review. The AuthZ and AuthN post-checks rarely confirm a weakness, because a guard's code cannot tell an authentication from a guard that denies everything. In the fifth measuring run on Juice Shop (2026-10-25), 21 of 33 findings that only verification reported stayed unscored, among them all 13 new AuthZ findings, 6 of them Critical or High.
affected_ids: [REQ-040]
compatibility: The REQ-040 outcome changes once implemented; it is not built yet. Findings that only verification reported and that no post-check confirms go to the evidence review after verification, which adds model calls to `assess`; the deterministic commands are unchanged. A confirmed finding is scored and counted, so headline counts of new assessments are higher than those of earlier runs with verification. A rejected finding stays in the register, marked as contradicted and unscored, unlike a rejected survey finding, which leaves the report. Saved assessments keep their results; the change applies when an assessment runs again.
verification: For this catalog change, make check-specs against the base commit. The implementation needs tests that a verification-only finding without a confirming post-check, also one outside the verification catalog, reaches the evidence review and is scored when the review confirms it; that a rejected one stays in the register as contradicted and unscored; that an open verdict or a budget shortfall leaves it labelled as evidenced by model review only and records a gap; that a finding confirmed by a post-check or reviewed as part of a combined finding is not reviewed again; and that a run without such findings makes no review call.
---

# Evidence review for findings only verification reported

Changes REQ-040 so that a weakness that only verification found passes the same evidence review as a survey finding, unless a post-check already confirms it. REQ-004 already treats scanner rule hits this way. The earlier change that put [verification findings into the register](../verification-findings-in-register/proposal.md) left such findings unscored; this change gives them a way to be scored.

## Decisions

The product owner chose this option on 2026-10-25 over a narrow deterministic rule and approved the requirement wording and its acceptance points the same day.

- The narrow rule would have confirmed a route that a REST resource generator registers with no guard at all and no hook before the write. In the fifth measuring run it would have confirmed 3 of the 13 new AuthZ findings (T-056, T-072, T-115). The code recognizes only finale-rest and epilogue as such generators, so on other applications it would confirm almost nothing.
- A finding the review rejects stays in the register, marked as contradicted and unscored, instead of leaving the report as a rejected survey finding does. This follows the existing REQ-040 rule for a survey finding that verification contradicts. Removing it would be more uniform and shorten the report, but a reviewer that sees only bounded source windows could drop a weakness that verification followed across several files.

## Risks raised

- **Model cost:** about 4 more calls for the 21 findings in 3 components of the fifth measuring run, roughly USD 0.30 to 0.50 per run. The estimate comes from the evidence review's cost in the measuring runs, about USD 2.00 for 30 calls, and is not measured. It grows with the number of findings only verification reports.
- **Data sent to models:** the same source windows of the same repository go to the same model as today. No new host and no other credentials.
- **Changed saved results:** up to 21 findings of the fifth measuring run would have become scorable, so headline counts are not directly comparable with earlier runs.
- **Duplicates:** a finding that repeats another one at a different line, such as T-014 repeating T-057, can be confirmed and counted twice. The review does not resolve that.
- **Model reviews model:** the reviewer reads at most 8 source windows per call and can reject a weakness that verification followed across several files. Text in the analyzed repository can influence its verdict. Because a rejection does not remove the finding, a manipulated verdict can at most leave it unscored, as it is today.
