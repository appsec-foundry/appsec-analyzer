---
reason: Hits of application-wide architecture rules no longer reach the assessment. The earlier pipeline turned high-confidence architecture anti-patterns and confirmed architecture hypotheses into findings; that step was dropped when the stage slices were replaced, and the current controller runs the architecture coverage only after the merge. No requirement stated that rule hits join the assessment, so the gap went unnoticed.
affected_ids: [REQ-004]
compatibility: Not implemented yet; current runs are unchanged. Once implemented, a reassessment can show new findings from architecture rules without any code change, each additional rule hit joins the evidence review of its component and can add review calls within the existing limits, and the runtime fingerprint change invalidates earlier resume identities. Saved assessments stay readable.
verification: make check-specs BASE=HEAD. tests/test_assessment_scanner_findings.py::test_an_absence_is_reviewed_by_reading_its_file_and_merged guards that a confirmed configuration rule hit is reviewed and merged. The implementation must add intended and negative cases for architecture rules. A confirmed anti-pattern becomes a finding that names its rule, a rejected one does not, and a run without rule hits makes no extra review call.
---

# Architecture rule hits as findings

Extends REQ-004 so that deterministic rule hits, including application-wide architecture rules, become findings after the same evidence review as survey findings. Not implemented yet.

## Decisions

The product owner approved the wording on 2026-10-23.

- Rule hits pass the evidence review before they become findings. The earlier pipeline merged architecture hits without review; the only hit observed while preparing this change, a permissive CORS anti-pattern in the `appsec-advisor` repository, matched the rule's own description text in a data file.
- The simpler variant, listing rule hits only as unreviewed notes without a model call, was not chosen: such hits would not count as findings and would carry no rating.

## Risks raised

- **Model cost:** additional rule hits join the evidence review of their component, which reviews findings in batches, and can add review calls. Juice Shop produced no architecture hit at standard or thorough depth; `appsec-advisor` produced one at thorough depth.
- **Data sent to models:** nothing new. The review receives the same masked source windows as other scanner findings.
- **Saved results:** a reassessment can report findings as new although the code did not change.
- **Run time:** the architecture coverage has to run before the threat analysis; reusing that result in the consolidation avoids a second run.

## Related requirements

These requirements keep their wording. The implementation has to satisfy them, or they need their own decision.

- **REQ-040:** a finding names the verification items and scanner rules behind it. The verification links findings to rules through source and configuration check IDs only, so a finding from an architecture rule would not be linked. Separately, the architecture rules are listed as starting points of verification items, but their hits never reach the verification, because the coverage runs after it.
- **REQ-006:** the architecture coverage records a status per control (partial, weak, missing, anti-pattern). The earlier pipeline used it for the security controls and checked its visibility with `scripts/validators/qa_arch_coverage.py`. The current controller merges these statuses but no step reads them, and the completeness gate is not called. The cause is the same: the coverage runs after the Controls phase.
- **REQ-008 and REQ-009:** the earlier design left architecture findings unscored and capped them below Critical. The implementation has to decide whether a finding confirmed by the evidence review keeps these limits.
- **REQ-001:** `scan-sources` does not run the architecture coverage, so its output will not show these hits. This change does not alter that.
