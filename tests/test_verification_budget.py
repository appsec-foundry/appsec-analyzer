"""The verification budget statement before the first verification job (REQ-040)."""

from __future__ import annotations

import pytest
from orchestrator import assessment_test_cases


class _Budget:
    def __init__(self, per_job, available, subscription=False):
        self.per_job, self.available, self.subscription = per_job, available, subscription
        self.roles = []
        self.charged = []

    def job_usd(self, role, fallback_role):
        self.roles.append((role, fallback_role))
        return self.per_job

    def available_usd(self):
        return self.available

    def charged_of(self, *groups):
        self.charged.append(groups)
        return self.per_job * len(groups)


class _Jobs:
    def __init__(self, budget):
        self.budget, self.notes = budget, []


def test_a_covered_verification_says_so_and_leaves_no_note():
    jobs = _Jobs(_Budget(0.4, 10.0))
    text = assessment_test_cases._budget_statement(jobs, 19, ["AuthZ", "InputVal"], 3)
    # The console shows the components and weighs the jobs the line ends with.
    assert text == "Verify start · 3 components · AuthZ, InputVal · ≈ USD 7.60, USD 10.00 of the budget left · 19 jobs"
    # Before the first verification job, a survey job's reserve stands in for one.
    assert jobs.budget.roles == [("test_case_investigator", "stride_analyzer")] and not jobs.notes


def test_an_uncovered_verification_warns_and_records_a_note():
    jobs = _Jobs(_Budget(0.5, 1.0))
    text = assessment_test_cases._budget_statement(jobs, 4, ["AuthZ"], 1)
    assert text == (
        "Verify start · 1 component · AuthZ · ≈ USD 2.00, but only USD 1.00 of the budget left; "
        "an aspect that cannot finish is marked incomplete · 4 jobs"
    )
    assert jobs.notes == [
        "verification needs about USD 2.00 for 4 jobs, but USD 1.00 remained; "
        "aspects whose jobs the budget stops are marked incomplete"
    ]


@pytest.mark.parametrize("count", [1, 3])
def test_a_subscription_run_names_its_limits_instead_of_dollars(count):
    jobs = _Jobs(_Budget(0.0, 0.0, subscription=True))
    text = assessment_test_cases._budget_statement(jobs, count, ["AI"], 1)
    assert text.endswith(f" · the run's call and time limits apply · {count} job{'s' if count > 1 else ''}")
    assert "USD" not in text and not jobs.notes


def test_an_aspect_without_a_job_costs_nothing_and_keeps_its_item_results(monkeypatch):
    # A component where no item applies plans no verification job; the step still ends with its results.
    component = {
        "id": "C-1",
        "name": "web",
        "repository_ids": ["r1"],
        "paths": [{"repository_id": "r1", "path": "index.php"}],
    }
    architecture = {"components": {"components": [component]}}
    monkeypatch.setattr(assessment_test_cases, "_repository_findings", lambda scope, scanned: {"r1": []})
    monkeypatch.setattr(assessment_test_cases, "_repository_facts", lambda *args: {"r1": {}})
    monkeypatch.setattr(
        assessment_test_cases.case_candidates, "applies", lambda case, facts, cid: (False, "no route in scope")
    )
    said = []
    planned = assessment_test_cases.plan_pilot(
        None, architecture, {}, {"aspects": ["AuthZ"], "disable": []}, progress=said.append
    )
    assert not planned["work"]
    jobs = _Jobs(_Budget(0.4, 10.0))
    pilot = assessment_test_cases.run_pilot(
        None,
        jobs,
        architecture,
        planned,
        {},
        requirement_ids=frozenset(),
        instructions=None,
        concurrently=None,
        label=lambda row: row["name"],
        progress=said.append,
    )
    assert pilot["results"] and {row["outcome"] for row in pilot["results"]} == {"not_applicable"}
    assert jobs.budget.charged == [()]
    assert said[-2] == "Verify done · no aspect verified"
    assert said[-1].startswith("AuthZ · 0 findings · ≈ USD 0.00 · ")
