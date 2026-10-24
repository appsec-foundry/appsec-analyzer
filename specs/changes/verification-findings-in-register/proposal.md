---
reason: Verification findings stayed in a list apart from the findings register, its totals, priorities, and mitigations, and were only linked to survey findings at the same location. A weakness that several methods found named the methods but kept only the text of one of them, and a verification finding at the location of a scanner finding was shown twice. The Juice Shop run of 2026-10-24 reported 88 verification findings, 57 of them outside the register, 10 of those on the line of a scanner finding in it.
affected_ids: [REQ-040]
compatibility: The REQ-040 outcome changes. Verification findings receive finding IDs, priorities, and mitigations and count in the register's totals, so totals and priorities of new assessments are higher than those of earlier runs with verification. A verification finding that no evidence review covers and no post-check confirms is now left unscored. A combined finding names each method and its description and remediation cover all parts; producing that text is a new model call in the consolidation. The report section that listed verification findings apart appears only for saved models that still contain such a list. Saved assessments keep their results; the change applies when an assessment runs again.
verification: Unit tests of the merge combine a verification finding with a survey finding and with a scanner finding on the same line and CWE family, also when their threat categories differ, and keep apart neighbouring lines, other families, different routes on one line, and refuted findings. They check that a combined finding keeps every location, item, and rule, takes the severity of its most severe part and the review verdict of its reviewed part, and that a model-only verification finding is unscored. Tests of the rewrite job check that a reply dropping a location, changing the severity, or failing falls back to the most severe part's text with the remediation steps of all parts. Renderer and console tests check the method names and counts.
---

# Verification findings in the findings register

Changes REQ-040 so that verification findings join the findings register and a weakness that several methods found is one finding whose text covers all of them. The earlier [linking of survey and verification findings](../survey-verify-linking/proposal.md) defined when two findings are the same weakness; this change keeps that rule and applies it to scanner findings as well.

## Decisions

The product owner approved the requirement wording and its acceptance points on 2026-10-24 and chose the full merge with a model-written combined text, built in two steps: first the deterministic merge that is the fallback, then the model rewrite. The product owner also accepted that a verification finding evidenced by model review only is left unscored.

The implementing session derived the following rules from the approved wording and the Juice Shop run:

- Verification findings run through the same register steps as survey findings: IDs, the severity floor, priorities, mitigations, and abuse case matching.
- A verification finding becomes part of a survey or scanner finding on the same line with a CWE of the same family, whatever their threat categories. The survey merge keeps different categories apart, but four of 32 linked pairs in the Juice Shop run differed only in their category; the approved REQ-040 rule names the line and the CWE family only.
- Verification findings whose candidates name different routes on one line stay apart, as within verification itself. A refuted survey or scanner finding never absorbs a verification finding.
- The more severe part stays as the finding; on equal severity the reviewed part stays. The finding takes the evidence review verdict of its reviewed part, because that review examined the same weakness at the same location.
- A verification finding without a reviewed partner takes its verdict from the post-checks: a confirmed post-check counts as a resolved pointer and keeps the score, otherwise the finding is ambiguous and left unscored.
- Verification findings without a partner are not offered to the merge reviewer and are not folded into systemic findings, because a wrong merge hides a finding that only verification reported.
- The combined text is written by a model from the finding texts and their locations only; no source files are sent. The code keeps locations, severity, IDs, and methods, and checks that the text cites every part's location.

## Risks raised

- **Model cost:** the rewrite is a new model call in the consolidation, batched per component. The Juice Shop run had about 50 findings with more than one method. Its cost is not measured yet.
- **Data sent to models:** only finding texts and locations that the run produced; no new source files and no new host.
- **Changed saved results:** totals and priorities change, so new reports are not directly comparable with earlier ones; in the Juice Shop run up to 47 findings would have joined the register before the severity floor.
- **Fewer scores:** verification findings without a reviewed partner or a confirming post-check are unscored. The alternative of scoring them would count weaker evidence fully.
- **Changed meaning:** a model can soften a statement while combining texts. The code owns every fact field and the fallback applies when a location is missing.
