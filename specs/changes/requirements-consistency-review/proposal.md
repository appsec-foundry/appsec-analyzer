---
reason: A consistency and clarity review of requirements.md and the acceptance contract found diverging status terms, an unclear rule on business context lowering impact, a conflict between stating every open decision and showing at most three, and contract rules filed under unrelated requirements. The user decided each open point.
affected_ids: [REQ-004, REQ-009, REQ-011, REQ-012, REQ-013, REQ-016, REQ-018, REQ-019, REQ-023, REQ-028, REQ-029, REQ-030, REQ-036]
compatibility: No command, artifact, schema, or exit code changes. REQ-009 now explicitly allows an explicit, sourced absence of business harm to lower business impact without changing priority tiers, relaxing caps, or hiding findings. The other edits move or reword existing rules without relaxing them.
verification: Run the specification gate against the previous commit. The REQ-009 lowering rule describes intended behavior; whether the scoring code applies it has not been verified.
---

# Requirements consistency review

REQ-009 previously forbade business context to raise likelihood but left open whether it may lower impact. An explicit, sourced absence of business harm may now lower business impact. Priority tiers, caps, technical findings, and independent obligations stay unchanged.

REQ-012 requires every unresolved decision to be stated. REQ-013 previously limited the report to three. The report now highlights up to three and lists the rest with the supporting detail.

The user catalog now uses the contract status names. REQ-011 lists confirmed, unproven, mitigated, unresolved, inapplicable, and unchecked abuse cases. REQ-029 lists pass, partial, fail, unverifiable, and not applicable. The REQ-030 contract now refers to unverifiable requirements instead of controls.

Contract rules moved to the requirement they serve. Organization distributions moved from REQ-019 to REQ-018. Provider rate-limit handling moved from REQ-016 to REQ-023. The REQ-028 job-cancellation rule was removed because REQ-024 already defines cancellation. The REQ-004 product statement duplicated the catalog introduction and was removed. REQ-016 and REQ-023 now start with their general rule. The REQ-036 text was split into paragraphs without wording changes. Bindings for the moved rules moved with them.

Preflight checks stay in REQ-016 because they cover Git access as well as providers and serve early failure explanation.
