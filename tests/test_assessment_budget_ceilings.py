"""Near the limit, calls of a measured role hold what that role costs, so the run stays parallel."""

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime.analyst_host import HostReply, TransportError
from runtime.assessment_jobs import AssessmentBudget
from runtime.multi_repo_discovery import MAX_PAID_RETRIES, BudgetExhausted

ROLE = "test_case_investigator"
STOPPED = "error_max_budget_usd"


def _budget(spent, largest=0.6):
    """A USD 20 run with a USD 2 call ceiling and the role's largest accepted job at `largest`."""
    budget = AssessmentBudget(20.0, 2.0, 100, 7200)
    budget.plan_completion()
    if largest:
        budget.accepted("tc:done", ROLE, largest, 1)
    budget.spent_usd = spent
    return budget


def _admitted(budget, role=ROLE, calls=4):
    """The ceilings of the calls that start while all of them keep running."""
    release = threading.Event()
    ceilings = []

    class Running:
        def __init__(self, ceiling):
            ceilings.append(ceiling)

        def invoke(self, *args):
            release.wait(10)
            return HostReply({}, 0.1)

    def call(index):
        with budget.job(f"tc:{index}", role, True):
            budget.invoke(Running, "", "", {}, 30, lambda: False)

    threads = [threading.Thread(target=call, args=(index,)) for index in range(calls)]
    for thread in threads:
        thread.start()
    time.sleep(0.3)
    started, held = list(ceilings), budget.spent_usd
    release.set()
    for thread in threads:
        thread.join(10)
    assert len(ceilings) == calls and not budget.failed
    return started, held


def _stopped_at(budget, usd_of_call, optional=True):
    """Run one call whose hosts stop at their ceiling while `usd_of_call` says so; returns the ceilings it got."""
    ceilings = []

    class Host:
        def __init__(self, ceiling):
            ceilings.append(ceiling)

        def invoke(self, *args):
            if usd_of_call(len(ceilings)):
                raise TransportError("stopped at its ceiling", reason=STOPPED, usd=ceilings[-1])
            return HostReply({}, 0.1)

    with budget.job("tc:a", ROLE, optional):
        try:
            budget.invoke(Host, "", "", {}, 30, lambda: False)
        finally:
            budget.last_ceilings = ceilings
    return ceilings


def test_near_the_limit_a_measured_role_keeps_all_workers_busy():
    started, held = _admitted(_budget(13.5))
    # USD 2 per call would have let two of them start.
    assert started == [0.9] * 4 and held == pytest.approx(13.5 + 4 * 0.9)


def test_while_the_money_covers_every_worker_each_call_keeps_the_full_ceiling():
    assert _admitted(_budget(5.0))[0] == [2.0] * 4


def test_a_role_without_a_measurement_keeps_the_full_ceiling_and_waits():
    assert _admitted(_budget(13.5, largest=0))[0] == [2.0] * 2


def test_a_measured_ceiling_has_a_floor_and_never_exceeds_the_full_one():
    assert _admitted(_budget(13.5, largest=0.1), calls=1)[0] == [0.5]
    assert _admitted(_budget(13.5, largest=1.9), calls=1)[0] == [2.0]


def test_a_measured_ceiling_keeps_an_api_hosts_worst_case_call():
    budget = _budget(13.5)
    budget.call_floor_usd = 1.5
    assert set(_admitted(budget)[0]) == {1.5}


def test_measured_ceilings_never_reach_into_the_report_reserve():
    started, held = _admitted(_budget(15.9))
    assert started == [0.9, 0.9] and held <= 20.0 - 2.0


def test_a_call_stopped_at_its_measured_ceiling_is_repeated_once_with_the_full_one():
    budget = _budget(13.5)
    notices = []
    budget.on_retry = notices.append
    assert _stopped_at(budget, lambda ceilings: ceilings == 1) == [0.9, 2.0]
    assert [(row["reason"], row["usd"], row["paid"]) for row in budget.retries] == [("measured_ceiling", 0.9, True)]
    assert budget.spent_usd == pytest.approx(13.5 + 0.9 + 0.1) and not budget.failed
    assert len(notices) == 1 and "ceiling" in notices[0]


def test_a_call_stopped_again_ends_the_budget_as_before():
    budget = _budget(16.5)
    with pytest.raises(BudgetExhausted):
        _stopped_at(budget, lambda ceilings: True, optional=False)
    assert budget.last_ceilings == [0.9, 0.6] and len(budget.retries) == 1


def test_an_optional_call_is_not_repeated_on_money_its_role_no_longer_fits():
    budget = _budget(16.5)
    with pytest.raises(BudgetExhausted):
        _stopped_at(budget, lambda ceilings: True)
    assert budget.last_ceilings == [0.9]


def test_the_repeat_counts_against_the_paid_retries():
    budget = _budget(13.5)
    budget.retries = [{"reason": "timeout", "usd": 0.1, "paid": True}] * MAX_PAID_RETRIES
    with pytest.raises(BudgetExhausted):
        _stopped_at(budget, lambda ceilings: True)
    assert budget.last_ceilings == [0.9]


def test_a_ceiling_the_budget_cut_ends_the_budget_without_a_repeat():
    budget = _budget(17.6)
    with pytest.raises(BudgetExhausted):
        _stopped_at(budget, lambda ceilings: True, optional=False)
    assert budget.last_ceilings == [0.4] and budget.retries == []


@pytest.mark.parametrize(
    "surveyed, reserve",
    [
        ([], 2.0),
        ([0.1], 0.5),
        ([0.2, 0.559, 0.3], 1.118),
        ([1.5], 2.0),
    ],
)
def test_the_report_reserve_follows_the_largest_survey_job(surveyed, reserve):
    budget = _budget(0.0, largest=0)
    for index, usd in enumerate(surveyed):
        budget.accepted(f"stride:{index}", "stride_analyzer", usd, 1)
    assert budget._reserve()[0] == pytest.approx(reserve)


def test_a_measured_report_reserve_lets_the_last_optional_steps_run_near_the_limit():
    """Run 1667 stood at USD 17.82, needed USD 1.47 more, and a flat USD 2 reserve asked for more money."""
    budget = _budget(17.82, largest=0)
    budget.accepted("stride:a", "stride_analyzer", 0.559, 1)
    budget.accepted("verify:a", ROLE, 0.253, 1)
    with budget.job("actors", "actor_discoverer", True):
        assert budget.available_usd() == pytest.approx(20.0 - 17.82 - 1.118)
