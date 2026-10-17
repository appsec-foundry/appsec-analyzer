---
reason: A thorough assessment could skip Architect Review and every abuse-case verification for budget reasons while normal console phase completions showed only processed candidate counts.
affected_ids: [REQ-003, REQ-011, REQ-016, REQ-023]
compatibility: Normal progress gains immediate coverage-gap warnings and explicit review totals. Quiet mode, budgets, optional-job fallback policy, artifact schemas, publication gates, and exit codes are unchanged.
verification: Offline job, review, and console tests cover immediate budget gaps, accepted work without gaps, checked versus partial or missing case results, missing architect proposals, terminal and redirected output, safe diagnostic text, and the existing tight-budget assessment integration.
---

# Visible review coverage

Optional job replacements notify the controller when the gap occurs. Normal progress prints the role, an eligible abuse-case ID, and a fixed explanation of a budget skip or unavailable model result. Raw host errors and repository text cannot enter this new diagnostic path. Forked component jobs inherit the callback, and accepted jobs emit no gap.

Architect Review reports reviewed, unreviewed, and unresolved findings. Abuse-case verification reports checked, partial, and unchecked candidates from the validated export. A reasoned inconclusive case can be checked; an absent candidate result cannot. Phase completion repeats these counts instead of presenting the candidate count as completed verification. Supplemental architect review remains in the abuse-case phase.

This change implements the existing coverage and progress requirements. It does not reserve additional review budget, make optional work required, raise spending limits, or classify report publication as full verification.

Targeted job, review, console, and progress-feed tests pass. The existing tight-budget integration test still fails because it expects Management Summary not to run; the unchanged `688edc82` checkout fails at the identical assertion. Its new immediate-gap assertion passes before that pre-existing failure. The failure is retained, with no weakened expectation or skipped test.
