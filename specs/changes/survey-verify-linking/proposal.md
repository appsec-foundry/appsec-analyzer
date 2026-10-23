---
reason: Replaying the link between survey and verification findings on three saved Juice Shop runs showed that the rule "same CWE within three lines" joined findings about different routes on neighbouring lines of a route table, which hid findings that only verification reported, and kept apart findings about the same weakness on the same line whose CWEs differ within one weakness family, which the report then showed twice.
affected_ids: [REQ-040]
compatibility: The REQ-040 outcome is unchanged; its acceptance rule for one combined finding now requires the same code line and a CWE of the same weakness family instead of the same CWE within three lines. Findings on neighbouring lines that were shown once are now shown separately, and findings of one family on the same line that were shown twice are now shown once. A survey finding is marked contradicted only by a control evidenced on the same line. Saved assessments keep their results; the change applies when a model is built again.
verification: Unit tests in tests/test_case_outcomes.py link the same line with an identical CWE and with a CWE of the same family, and keep apart a neighbouring line, another family on the same line, an unclassified CWE that differs, findings without a CWE, and scanner findings. The contradiction test marks only a control on the same line and with a CWE of the verification item. The new tests fail against the previous rule. An offline replay on the saved runs 2 to 4 confirmed 5 added correct links and 4 removed wrong ones.
---

# Linking survey and verification findings

Changes how REQ-040 recognises that the survey and verification found the same weakness. The [implementation status](../../../docs/internal/analysis/aspect-test-cases-implementation-status-2026-10-19.md#linking-survey-and-verification-findings-analysed-2026-10-23) records the replay and its results.

## Decisions

The product owner chose this rule on 2026-10-23 among three options: the same line and CWE family, the CWE family on the same line next to the earlier three-line rule, and no change.

- One finding needs the same file, the same line, and a CWE of the same family. The families are those the survey uses to merge its own findings, so both methods count duplicates the same way. A CWE outside every family must match exactly.
- Neighbouring lines stay apart. No link between one and three lines apart was correct in the replay, and a wrong link hides a finding that only verification reported, which weighs more than a weakness shown twice.
- A contradiction needs the same line and keeps a CWE of the verification item, not of its family, because an ownership check does not show that a role check exists.

## Risks raised

- **Remaining duplicates:** the same weakness still appears twice when the methods label it with CWEs of different families or anchor it on different lines. Linking by route and handler would cover these cases and is not part of this change.
- **Anchor differences:** a weakness that the two methods anchor one or two lines apart was linked before and now appears twice. The replay found no such case.
- **Evidence base:** three runs on one intentionally vulnerable repository; the contradiction rule was checked in unit tests only, because no saved run records control locations.
