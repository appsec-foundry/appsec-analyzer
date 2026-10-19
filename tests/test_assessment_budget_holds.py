"""A budget hold keeps a share of the money or calls left for one group's optional work."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime.analyst_host import HostReply
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import RECEIPT_SCHEMA, REPORT_JOB, AssessmentBudget

from tests.test_assessment_jobs import setup

ACCEPTED = {"action": "complete", "reads": [], "artifact": {"result": "accepted"}}
OPTIONAL = dict(on_failure=lambda reason: {"result": "not reviewed"})


def _views(budget, group, optional=True):
    with budget.job(group, "test_case_investigator", optional):
        return budget.available_usd(), budget.call_limit()


def test_other_optional_groups_see_the_available_budget_minus_the_hold():
    budget = AssessmentBudget(10.0, 1.0, 100, 7200)
    budget.plan_completion()
    budget.spent_usd = 2.0
    # USD 8 left minus the USD 1 report reserve; 100 calls minus 2 for the report.
    assert _views(budget, "tc:a") == (7.0, 98)
    budget.hold("open:a", 3.0, 20)
    assert _views(budget, "tc:a") == (4.0, 78)
    assert _views(budget, "open:a") == (7.0, 98)
    budget.hold("open:b", 1.0, 5)
    assert _views(budget, "tc:a") == (3.0, 73)
    assert _views(budget, "open:a") == (6.0, 93)
    assert _views(budget, "open:b") == (4.0, 78)


def test_required_work_and_calls_outside_a_job_ignore_holds():
    budget = AssessmentBudget(10.0, 1.0, 100, 7200)
    budget.plan_completion()
    budget.spent_usd = 2.0
    budget.hold("open:a", 6.0, 90)
    assert _views(budget, "stride:b", optional=False) == (7.0, 98)
    assert (budget.available_usd(), budget.call_limit()) == (7.0, 98)


def test_a_hold_applies_without_a_completion_reserve():
    budget = AssessmentBudget(10.0, 1.0, 100, 7200)
    budget.spent_usd = 2.0
    budget.hold("open:a", 3.0, 20)
    assert _views(budget, "tc:a") == (5.0, 80)
    assert _views(budget, "open:a") == (8.0, 100)


def test_release_restores_the_budget_of_other_groups():
    budget = AssessmentBudget(10.0, 1.0, 100, 7200)
    budget.plan_completion()
    budget.spent_usd = 2.0
    budget.hold("open:a", 3.0, 20)
    budget.hold("open:a", 5.0, 10)  # a second hold replaces the first
    assert _views(budget, "tc:a") == (2.0, 88)
    budget.release("open:a")
    budget.release("open:unknown")
    assert budget.holds == {} and _views(budget, "tc:a") == (7.0, 98)


def test_a_hold_keeps_the_report_reserve_for_the_held_group(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.spent_usd = 0.94
    jobs.budget.hold("open", 0.5, 0)
    assert jobs.execute(**kwargs, budget_group="open", **OPTIONAL) == {"result": "not reviewed"}
    assert host.calls == 0 and jobs.gaps[0]["budget"]
    assert jobs.execute(**{**kwargs, "role": "secarch_renderer", "selector": REPORT_JOB}) == {"result": "accepted"}
    assert host.calls == 1


def test_other_groups_get_a_budget_gap_while_the_held_group_runs(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path, replies=[ACCEPTED, ACCEPTED])
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.spent_usd = 0.5
    jobs.budget.hold("open", 0.42, 0)
    # USD 0.45 left after the report reserve; the hold leaves USD 0.03 for others.
    assert jobs.execute(**kwargs, budget_group="tc", **OPTIONAL) == {"result": "not reviewed"}
    assert host.calls == 0 and [gap["selector"] for gap in jobs.gaps] == ["one"] and jobs.gaps[0]["budget"]
    assert jobs.execute(**{**kwargs, "selector": "two"}, budget_group="open", **OPTIONAL) == {"result": "accepted"}
    assert host.calls == 1 and len(jobs.gaps) == 1
    jobs.budget.release("open")
    assert jobs.execute(**kwargs, budget_group="tc", **OPTIONAL) == {"result": "accepted"}
    assert host.calls == 2


@pytest.mark.parametrize("group", ["open", "tc"])
def test_no_budget_prompt_while_a_hold_is_active(tmp_path, group):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.spent_usd = 0.94
    asked = []
    jobs.budget.on_budget_increase = asked.append
    jobs.budget.hold("open", 0.01, 0)
    assert jobs.execute(**kwargs, budget_group=group, **OPTIONAL) == {"result": "not reviewed"}
    assert asked == [] and host.calls == 0 and jobs.gaps[0]["budget"]
    # The same shortfall asks once no hold is active.
    jobs.budget.release("open")
    assert jobs.execute(**kwargs, budget_group=group, **OPTIONAL) == {"result": "not reviewed"}
    assert len(asked) == 1 and host.calls == 0


def test_an_oversized_hold_gives_the_held_group_a_gap_instead_of_stopping_the_run(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path, replies=[ACCEPTED, ACCEPTED])
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.spent_usd = 0.5
    asked = []
    jobs.budget.on_budget_increase = asked.append
    jobs.budget.hold("open", 5.0, 50)
    assert jobs.execute(**kwargs, budget_group="tc", **OPTIONAL) == {"result": "not reviewed"}
    # The held group spends what is actually left, then records a gap.
    assert jobs.execute(**{**kwargs, "selector": "two"}, budget_group="open", **OPTIONAL) == {"result": "accepted"}
    jobs.budget.spent_usd = 0.94
    assert jobs.execute(**{**kwargs, "selector": "three"}, budget_group="open", **OPTIONAL) == {
        "result": "not reviewed"
    }
    assert [gap["selector"] for gap in jobs.gaps] == ["one", "three"] and all(gap["budget"] for gap in jobs.gaps)
    assert asked == [] and host.calls == 1
    assert jobs.execute(**{**kwargs, "role": "secarch_renderer", "selector": REPORT_JOB}) == {"result": "accepted"}
    assert host.calls == 2


def test_a_subscription_run_holds_calls(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path, replies=[ACCEPTED, ACCEPTED])
    jobs.budget = budget = AssessmentBudget(None, None, 10, 3600, spent_usd=None, subscription=True)
    host.invoke = lambda *args: HostReply(ACCEPTED, None)
    budget.plan_completion()
    budget.hold("open", None, 6)
    assert _views(budget, "tc") == (0.0, 2)
    assert _views(budget, "open") == (0.0, 8)
    assert _views(budget, "stride:b", optional=False) == (0.0, 8)
    budget.calls = 2
    assert jobs.execute(**kwargs, budget_group="tc", **OPTIONAL) == {"result": "not reviewed"}
    assert jobs.gaps[0]["budget"] and budget.calls == 2
    assert jobs.execute(**{**kwargs, "selector": "two"}, budget_group="open", **OPTIONAL) == {"result": "accepted"}
    assert budget.calls == 3 and budget.spent_usd is None


@pytest.mark.parametrize(
    "subscription, group, usd, calls",
    [
        (False, "", 1.0, 0),
        (False, None, 1.0, 0),
        (False, "open", None, 0),
        (False, "open", -0.01, 0),
        (False, "open", float("nan"), 0),
        (False, "open", float("inf"), 0),
        (False, "open", True, 0),
        (False, "open", "1", 0),
        (False, "open", 1.0, -1),
        (False, "open", 1.0, 1.5),
        (False, "open", 1.0, True),
        (True, "open", 1.0, 2),
        (True, "open", 0.0, 2),
        (True, "open", None, None),
    ],
)
def test_an_invalid_hold_is_refused(subscription, group, usd, calls):
    if subscription:
        budget = AssessmentBudget(None, None, 10, 60, spent_usd=None, subscription=True)
    else:
        budget = AssessmentBudget(1.0, 0.05, 10, 60)
    with pytest.raises(ExchangeError, match="Invalid budget hold"):
        budget.hold(group, usd, calls)
    assert budget.holds == {}


def test_a_held_job_writes_only_the_receipt_contract(tmp_path):
    """The state side is covered in test_assessment_state.py."""
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.hold("open", 0.5, 3)
    assert jobs.execute(**kwargs, budget_group="open", **OPTIONAL) == {"result": "accepted"}
    receipt = json.loads(next(jobs.directory.glob("*.receipt.json")).read_text())
    assert set(receipt) == set(json.loads(RECEIPT_SCHEMA.read_text())["required"])
    assert "hold" not in json.dumps(receipt)
