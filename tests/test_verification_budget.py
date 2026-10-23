"""The verification budget statement before the first verification job (REQ-040)."""

from __future__ import annotations

import pytest
from orchestrator import assessment_test_cases


class _Budget:
    def __init__(self, per_job, available, subscription=False):
        self.per_job, self.available, self.subscription = per_job, available, subscription
        self.roles = []

    def job_usd(self, role, fallback_role):
        self.roles.append((role, fallback_role))
        return self.per_job

    def available_usd(self):
        return self.available


class _Jobs:
    def __init__(self, budget):
        self.budget, self.notes = budget, []


def test_a_covered_verification_says_so_and_leaves_no_note():
    jobs = _Jobs(_Budget(0.4, 10.0))
    text = assessment_test_cases._budget_statement(jobs, 19, ["AuthZ", "InputVal"])
    assert text == "Verify: 19 jobs for AuthZ, InputVal, about USD 7.60; the remaining USD 10.00 covers them"
    # Before the first verification job, a survey job's reserve stands in for one.
    assert jobs.budget.roles == [("test_case_investigator", "stride_analyzer")] and not jobs.notes


def test_an_uncovered_verification_warns_and_records_a_note():
    jobs = _Jobs(_Budget(0.5, 1.0))
    text = assessment_test_cases._budget_statement(jobs, 4, ["AuthZ"])
    assert text.endswith("may not cover them, and an aspect that cannot finish is marked incomplete")
    assert jobs.notes == [
        "verification needs about USD 2.00 for 4 jobs, but USD 1.00 remained; "
        "aspects whose jobs the budget stops are marked incomplete"
    ]


@pytest.mark.parametrize("count", [1, 3])
def test_a_subscription_run_names_its_limits_instead_of_dollars(count):
    jobs = _Jobs(_Budget(0.0, 0.0, subscription=True))
    text = assessment_test_cases._budget_statement(jobs, count, ["AI"])
    assert text.endswith("; the run's call and time limits apply") and "USD" not in text and not jobs.notes
