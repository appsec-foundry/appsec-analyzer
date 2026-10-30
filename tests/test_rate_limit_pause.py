"""Shared model admission cooldowns, without provider calls or real sleeps."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from runtime.analyst_host import HostCancelled, HostReply, TransportError
from runtime.assessment_jobs import AssessmentBudget
from runtime.multi_repo_discovery import DiscoveryBudget


def invoke(budget, host, stop=lambda: False):
    return budget.invoke(lambda ceiling: host, "s", "p", {}, 600, stop)


class Limited:
    def __init__(self, failures=1, reset=None, usd=0.0, usage_window=False):
        self.failures, self.reset, self.usd, self.usage_window = failures, reset, usd, usage_window
        self.calls = 0

    def invoke(self, *args):
        self.calls += 1
        if self.calls <= self.failures:
            raise TransportError(
                "rate_limit",
                reason="rate_limit",
                usd=self.usd,
                retry_after_s=self.reset,
                usage_window=self.usage_window,
            )
        return HostReply({}, 0.01)


@pytest.fixture
def clock(monkeypatch):
    from runtime import multi_repo_discovery

    now = [1000.0]
    monkeypatch.setattr(multi_repo_discovery.time, "monotonic", lambda: now[0])
    return now


def test_shared_backoff_then_success_resets_failure_streak(clock, monkeypatch):
    budget = DiscoveryBudget(1, 0.05, 20, 600)
    host = Limited(3)
    waits = []

    def wait(seconds):
        waits.append((host.calls, seconds))
        clock[0] += seconds

    monkeypatch.setattr(budget._lock, "wait", wait)
    invoke(budget, host)
    assert [sum(s for calls, s in waits if calls == n) for n in (1, 2, 3)] == [15, 60, 180]
    assert host.calls == 4 and budget.calls == 4
    assert budget.spent_usd == pytest.approx(0.01)
    assert budget._rate_failures == 0


@pytest.mark.parametrize("reset", [90, 3600])
def test_provider_reset_is_respected_or_stops_without_retry(clock, monkeypatch, reset):
    budget = DiscoveryBudget(1, 0.05, 20, 600)
    host = Limited(reset=reset)
    waited = []

    def wait(seconds):
        waited.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(budget._lock, "wait", wait)
    if reset <= 180:
        invoke(budget, host)
        assert sum(waited) == reset and host.calls == 2
    else:
        with pytest.raises(TransportError, match="--resume"):
            invoke(budget, host)
        assert not waited and host.calls == 1
        with pytest.raises(TransportError, match="--resume"):
            invoke(budget, Limited(0))
        assert budget.calls == 1


@pytest.mark.parametrize("usage_window", [False, True])
def test_a_usage_window_stop_is_reported_for_the_failed_and_for_later_calls(clock, usage_window):
    budget = DiscoveryBudget(1, 0.05, 20, 600)
    with pytest.raises(TransportError) as first:
        invoke(budget, Limited(reset=3600, usage_window=usage_window))
    with pytest.raises(TransportError) as later:
        invoke(budget, Limited(0))
    assert first.value.usage_window is usage_window and later.value.usage_window is usage_window


def test_cooldown_does_not_extend_run_deadline(clock):
    budget = DiscoveryBudget(1, 0.05, 20, 10)
    host = Limited()
    with pytest.raises(TransportError, match="--resume"):
        invoke(budget, host)
    assert budget.deadline == 1010 and host.calls == 1


def test_other_worker_waits_before_host_creation_and_cancel_remains_available(monkeypatch):
    budget = DiscoveryBudget(1, 0.05, 20, 600)
    limited = threading.Event()
    waiting = threading.Event()
    cancel = threading.Event()
    host = Limited(10)
    original_wait = budget._lock.wait
    budget.on_retry = lambda message: limited.set()

    def wait(seconds):
        if threading.current_thread().name.endswith("_1"):
            waiting.set()
        return original_wait(seconds)

    monkeypatch.setattr(budget._lock, "wait", wait)
    other = Limited(0)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(invoke, budget, host, cancel.is_set)
        try:
            assert limited.wait(2)
            second = pool.submit(invoke, budget, other, cancel.is_set)
            assert waiting.wait(2)
            assert other.calls == 0 and budget.calls == 1
        finally:
            cancel.set()
            with budget._lock:
                budget._lock.notify_all()
        for future in (first, second):
            with pytest.raises(HostCancelled):
                future.result(timeout=2)


def test_paid_rate_limit_keeps_one_retry_limit(clock, monkeypatch):
    budget = DiscoveryBudget(1, 0.05, 20, 600)
    host = Limited(10, usd=0.02)
    monkeypatch.setattr(budget._lock, "wait", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(TransportError):
        invoke(budget, host)
    assert host.calls == 2 and budget.spent_usd == pytest.approx(0.04)


def test_subscription_rate_limits_report_no_cost_and_use_the_free_retry_schedule(clock, monkeypatch):
    budget = AssessmentBudget(None, None, 20, 600, spent_usd=None, subscription=True)
    host = Limited(3, usd=None)
    plain_invoke = host.invoke
    host.invoke = lambda *args: HostReply({}, None) if host.calls >= host.failures else plain_invoke(*args)
    monkeypatch.setattr(budget._lock, "wait", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    invoke(budget, host)
    assert {row["paid"] for row in budget.retries} == {False}
