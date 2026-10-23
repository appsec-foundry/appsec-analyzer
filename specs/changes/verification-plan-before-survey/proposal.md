---
reason: The verification jobs are now decided before the survey, so the live progress weighs them from the start and its share no longer drops when the survey ends. The acceptance rule asked for the budget statement as soon as the job count is known, which now would be before the survey, when the cost per job has not been measured yet.
affected_ids: [REQ-040]
compatibility: The REQ-040 outcome is unchanged. The run names the planned verification jobs before the survey and still states their estimated cost and whether the remaining budget covers them right before the first verification job. Saved assessments are not affected.
verification: tests/test_controller_fixture.py::test_shared_candidates_are_answered_once_and_combined_into_one_row_per_test_case checks that the plan comes before the first survey job and the budget statement before the first verification job; tests/test_verification_budget.py checks the budget statement; tests/test_multi_repo_assessment.py::test_verification_is_a_second_threat_analysis_step_whose_share_never_falls checks that the share never falls.
---

# Verification plan before the survey

Changes when REQ-040 names the verification jobs and when it states the budget for them. Implemented in 02a5f025.

## Decisions

The product owner approved the wording on 2026-10-23.

- The planned jobs are named before the survey starts. They depend only on the verification catalog, the architecture and the scanner findings, not on survey results.
- The budget statement stays right before the first verification job. Before the survey no survey job has been measured, so an estimate then would use a full call allowance per job and overstate the cost.

## Risks raised

- **Two statements instead of one:** the job count appears before the survey and again with the budget statement. A reader sees the count twice.
