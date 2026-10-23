---
reason: Hits of application-wide architecture rules no longer reach the assessment. The earlier pipeline turned high-confidence architecture anti-patterns and confirmed architecture hypotheses into findings; that step was dropped when the stage slices were replaced, and the current controller runs the architecture coverage only after the merge. No requirement stated that rule hits join the assessment, so the gap went unnoticed.
affected_ids: [REQ-004]
compatibility: A reassessment can show new findings from architecture rules without any code change. Each additional rule hit joins the evidence review of its component and can add review calls within the existing limits. The runtime fingerprint change invalidates earlier resume identities. Saved assessments stay readable.
verification: make check-specs BASE=HEAD. tests/test_assessment_scanner_findings.py guards the intended and negative cases. test_an_architecture_hit_is_reviewed_with_its_component_and_kept_only_when_confirmed runs the controller stages with a confirming and a refuting review, test_a_full_assessment_publishes_a_confirmed_architecture_finding_without_a_score publishes a valid model with the confirmed finding, test_only_anchored_high_confidence_architecture_hits_become_findings keeps low-confidence, unconfirmed and unanchored hits out, test_architecture_anchors_and_findings_use_the_assessment_depth checks the depth, and test_repositories_without_scanner_findings_yield_empty_owners checks that a repository without hits adds no finding to review.
---

# Architecture rule hits as findings

Extends REQ-004 so that deterministic rule hits, including application-wide architecture rules, become findings after the same evidence review as survey findings. The scanner stage of the threat analysis now runs the architecture coverage on every repository snapshot and passes high-confidence anti-patterns and confirmed hypotheses with a source line to the evidence review. Component finalization runs it at the assessment's depth, so every file such a hit cites has an owning component.

## Decisions

The product owner approved the wording on 2026-10-23.

- Rule hits pass the evidence review before they become findings. The earlier pipeline merged architecture hits without review; the only hit observed while preparing this change, a permissive CORS anti-pattern in the `appsec-advisor` repository, matched the rule's own description text in a data file.
- The simpler variant, listing rule hits only as unreviewed notes without a model call, was not chosen: such hits would not count as findings and would carry no rating.
- Architecture findings keep their earlier limits after a confirming review: no CVSS score and no Critical rating. The merge validators already enforce both for the `architecture-coverage` and `threat-hypothesis` sources.
- The architecture coverage runs three times per repository and run: at component finalization, in the scanner stage, and in the consolidation. One run took about 6 seconds on Juice Shop. Rerunning it on the same frozen snapshot replaces a stored result that a resumed run would have to keep consistent.

## Risks raised

- **Model cost:** additional rule hits join the evidence review of their component, which reviews findings in batches, and can add review calls. Juice Shop produced no architecture hit at standard or thorough depth; `appsec-advisor` produced one at thorough depth.
- **Data sent to models:** nothing new. The review receives the same masked source windows as other scanner findings.
- **Saved results:** a reassessment can report findings as new although the code did not change.
- **Run time:** the architecture coverage has to run before the threat analysis, which adds two runs per repository.

## Related requirements

These requirements keep their wording. The open points and their options are in [architecture coverage: open points](../../../docs/internal/analysis/architecture-coverage-open-points-2026-10-23.md).

- **REQ-040:** a finding names the verification items and scanner rules behind it. The report now links an architecture finding to its rule and to the verification items that list the rule. Verification starting points are unchanged: architecture hits add no candidate, so verification job counts and costs stay as they were. Whether architecture hits should become starting points is a separate decision.
- **REQ-006:** the architecture coverage records a status per control (partial, weak, missing, anti-pattern). The earlier pipeline used it for the security controls and checked its visibility with `scripts/validators/qa_arch_coverage.py`. The current controller merges these statuses but no step reads them, and the completeness gate is not called. This change leaves that open. Adding a control row for every status the model did not cover failed review for three reasons. Rule control names such as `Schema / Allowlist Input Validation` do not match the model's control names reliably. On Juice Shop all three statuses were `partial` with low confidence and no evidence. And the controls sidecar schema documents that the model's rating wins on conflict.
- **REQ-008 and REQ-009:** see the decision on scoring limits above.
- **REQ-001:** `scan-sources` does not run the architecture coverage, so its output will not show these hits. This change does not alter that.
