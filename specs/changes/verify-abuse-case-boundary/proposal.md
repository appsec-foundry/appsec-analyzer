---
reason: The product owner asked whether abuse cases do the same as verification. Three built-in business abuse cases ask what authorization and authentication verification already ask, and the catalog's business logic item names all built-in business cases as its starting points, so without a stated boundary new verification items and abuse cases can keep asking the same questions twice.
affected_ids: [REQ-040, REQ-011]
compatibility: No behavior changes. The REQ-040 and REQ-011 outcomes are unchanged; their acceptance rules now state which questions belong to verification and which to abuse cases, and REQ-011 records the order of built-in business cases that 6a02d919 built, where a case whose question a verified aspect asks comes after the others. Requested, team-supplied, and model-derived abuse cases keep their limits and order. Saved assessments keep their results.
verification: tests/test_match_abuse_cases.py checks that an optional built-in case whose verified_by names a verified aspect gives its place and names the aspect in its omission, that the order is unchanged when that aspect is not verified, that a requested case keeps its place, that the verified aspects come from the run configuration, and that the built-in cases name AuthZ for AC-B-001 and AC-B-002 and AuthN for AC-B-003. make check-specs checks the changed acceptance sections and this proposal.
---

# Boundary between verification and abuse cases

Adds one sentence to the REQ-040 acceptance rules and two to REQ-011. The analysis behind it is in point 10 of [the open points](../../../docs/internal/analysis/verification-cost-open-points-2026-10-23.md#business-abuse-cases-and-verification); the README's section on abuse cases says the same for users.

## Decisions

Approved by the product owner on 2026-10-25:

- A verification item asks whether one security property holds within a component, at every place where it matters. The aspects' goal items, which ask for an attacker goal by any path in one component, stay verification items.
- An abuse case asks whether a goal can be reached in the application from start to end. A technical case rates a path through several weaknesses from the findings; a business case checks a rule of the application's flow, such as an approval, a limit, or a withdrawn right.
- A built-in business case whose question a verified aspect already asks comes after the other built-in cases (AC-B-001 and AC-B-002 under AuthZ, AC-B-003 under AuthN). It stays in the library, so a run that does not verify the aspect still checks it.
- Not decided: merging business cases into verification, and answering a business case from verification results. Both were weighed and left out, because abuse cases cost about 3 percent of a standard run and team-supplied rules are what verification cannot know.

## Risks raised

- **Business logic item:** TC-LOGIC-01 asks whether prices, quantities, balances, and the order of workflow steps are decided on the server. Under the new rule the workflow order is a business rule, which overlaps AC-B-004 and AC-B-005. BusinessLogic is not investigated today, so nothing changes now; before it is, the item must keep only the part that can be checked place by place, such as client-supplied prices, quantities, and balances.
- **Fallback cases:** by the rule, AC-B-001 to AC-B-003 are verification questions. They stay as built-in cases for runs whose profile deselects AuthZ or AuthN.
- **Evidence base:** the order of business cases rests on three measuring runs on one intentionally vulnerable repository, in which AC-B-002, AC-B-006, and AC-B-007 never ran at standard depth.
