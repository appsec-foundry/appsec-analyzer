"""Resume rechecks scoped contracts and never grants authority from a receipt."""

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime.analyst_host import HostCancelled, HostReply
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
from runtime.multi_repo_scope import AssessmentScope, RepositoryView

RID = "repo-0123456789abcdef"
SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["result"],
    "properties": {"result": {"type": "string"}},
}


class Host:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = 0

    def invoke(self, *args):
        self.calls += 1
        return HostReply(next(self.replies), 0.01)


def setup(tmp_path, *, replies=None, validate=None, should_stop=lambda: False):
    scope = AssessmentScope(
        (
            RepositoryView(RID, tmp_path / "source", "a" * 40, "b" * 64, {"app.py": b"print('test')\n"}),
            RepositoryView("repo-abcdef0123456789", tmp_path / "peer", "c" * 40, "d" * 64, {"peer.py": b"pass\n"}),
        ),
        tmp_path / "out",
    )
    host = Host(replies or [{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}])
    budget = AssessmentBudget(1.0, 0.05, 10, 60)
    checkpoints = []
    jobs = AssessmentJobs(
        scope,
        tmp_path / "out/jobs",
        budget,
        lambda role, ceiling: host,
        should_stop,
        lambda: checkpoints.append((budget.calls, budget.failed)),
    )
    kwargs = dict(
        role="architecture_analyst",
        selector="one",
        instructions="trusted",
        context={},
        schema=SCHEMA,
        allowed_sources=frozenset({(RID, "app.py")}),
        validate=validate or (lambda artifact, ranges: None),
    )
    return jobs, host, kwargs, checkpoints


def test_accepted_job_is_revalidated_and_reused_without_dispatch(tmp_path):
    seen = []
    jobs, host, kwargs, checkpoints = setup(tmp_path, validate=lambda a, r: seen.append(a["result"]))
    first = jobs.execute(**kwargs)
    first["result"] = "modified by caller"
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    # Reviewed inside the exchange, accepted before the receipt, revalidated on reuse.
    assert host.calls == 1 and seen == ["accepted", "accepted", "accepted"]
    assert checkpoints == [(1, True), (1, False)]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in jobs.directory.iterdir())


@pytest.mark.parametrize(
    "field,value", [("instructions", "different"), ("context", {"changed": True}), ("allowed_sources", frozenset())]
)
def test_changed_request_cannot_reuse_completed_job(tmp_path, field, value):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    kwargs[field] = value
    with pytest.raises(ExchangeError, match="stale"):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_changed_artifact_fails_without_another_call(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    artifact = next(path for path in jobs.directory.iterdir() if not path.name.endswith(".receipt.json"))
    artifact.write_text(json.dumps({"result": "changed"}))
    with pytest.raises(ExchangeError, match="changed"):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_receipt_cannot_replace_artifact_with_an_external_link(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    artifact = next(path for path in jobs.directory.iterdir() if not path.name.endswith(".receipt.json"))
    outside = tmp_path / "external.json"
    outside.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(outside)
    with pytest.raises(ExchangeError, match="regular"):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_rejected_semantics_never_get_a_completion_receipt(tmp_path):
    def reject(artifact, ranges):
        raise ExchangeError("semantics rejected")

    reply = {"action": "complete", "reads": [], "artifact": {"result": "accepted"}}
    jobs, host, kwargs, _ = setup(tmp_path, replies=[reply] * 6, validate=reject)
    with pytest.raises(ExchangeError, match="semantics"):
        jobs.execute(**kwargs)
    assert list(jobs.directory.iterdir()) == []
    # The first result and at most two corrections; no receipt for any of them.
    assert host.calls == 3


def test_a_rejected_result_is_corrected_with_the_controller_reason(tmp_path):
    prompts = []

    def accept_only_corrected(artifact, ranges):
        if artifact["result"] != "corrected":
            raise ExchangeError("result must name the corrected state")

    replies = [
        {"action": "complete", "reads": [], "artifact": {"result": "first"}},
        {"action": "complete", "reads": [], "artifact": {"result": "corrected"}},
    ]
    jobs, host, kwargs, _ = setup(tmp_path, replies=replies, validate=accept_only_corrected)
    original = host.invoke

    def record(*args):
        prompts.append(args[1])
        return original(*args)

    host.invoke = record
    assert jobs.execute(**kwargs) == {"result": "corrected"}
    assert host.calls == 2
    assert "rejected_result" not in prompts[0]
    assert "result must name the corrected state" in prompts[1]


@pytest.mark.parametrize("reason", ["result must name the corrected state", "threats/0: missing evidence"])
def test_a_rejection_reaches_the_transport_whose_answer_it_rejects(tmp_path, reason):
    """The job's host wrapper forwards the correction notice, so the call's own log can record it."""
    notices = []

    def reject_first(artifact, ranges):
        if artifact["result"] != "corrected":
            raise ExchangeError(reason)

    replies = [
        {"action": "complete", "reads": [], "artifact": {"result": "first"}},
        {"action": "complete", "reads": [], "artifact": {"result": "corrected"}},
    ]
    jobs, host, kwargs, _ = setup(tmp_path, replies=replies, validate=reject_first)
    host.on_correction = notices.append
    assert jobs.execute(**kwargs) == {"result": "corrected"}
    assert notices == [reason]


def test_an_accepted_first_answer_sends_no_correction_notice(tmp_path):
    notices = []
    jobs, host, kwargs, _ = setup(tmp_path)
    host.on_correction = notices.append
    jobs.execute(**kwargs)
    assert notices == []


def test_cli_transport_records_a_rejection_in_its_event_stream(tmp_path):
    from runtime.analyst_host import ClaudeCliTransport

    events = tmp_path / "events" / "0001-stride_analyzer.jsonl"
    transport = ClaudeCliTransport(tmp_path / "work", events_path=events)
    # Before the call has written its stream there is nothing to annotate.
    transport.on_correction("ignored")
    assert not events.exists()
    events.parent.mkdir()
    events.write_text('0.5\t{"type": "result"}\n')
    transport.on_correction("STRIDE investigation is incomplete: " + "x" * 3000)
    stamp, record = events.read_text().splitlines()[-1].split("\t", 1)
    assert stamp == "-" and json.loads(record)["type"] == "controller_rejection"
    assert (
        json.loads(record)["reason"].startswith("STRIDE investigation is incomplete")
        and json.loads(record)["reason"] == "STRIDE investigation is incomplete: " + "x" * 3000
    )
    # An unrecorded call keeps no file.
    ClaudeCliTransport(tmp_path / "work2").on_correction("ignored")


def test_cancellation_stops_even_a_cached_job(tmp_path):
    cancelled = [False]
    jobs, host, kwargs, _ = setup(tmp_path, should_stop=lambda: cancelled[0])
    jobs.execute(**kwargs)
    cancelled[0] = True
    with pytest.raises(HostCancelled, match="cancelled"):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_controller_retrieval_is_receipted_and_rechecked(tmp_path):
    replies = [
        {
            "action": "read",
            "artifact": None,
            "reads": [{"repository_id": RID, "path": "app.py", "start_line": 1, "end_line": 1}],
        },
        {"action": "complete", "reads": [], "artifact": {"result": "accepted"}},
    ]
    seen = []
    jobs, host, kwargs, _ = setup(tmp_path, replies=replies, validate=lambda a, ranges: seen.append(ranges))
    jobs.execute(**kwargs)
    jobs.execute(**kwargs)
    assert len(seen[0]) == 1 and seen[0] == seen[1] and host.calls == 2


@pytest.mark.parametrize("seconds", [0, 43201, True])
def test_assessment_duration_remains_bounded(seconds):
    with pytest.raises(ExchangeError):
        AssessmentBudget(1, 0.1, 10, seconds)


def test_time_asleep_counts_against_the_deadline(monkeypatch):
    from runtime.multi_repo_discovery import BudgetExhausted

    budget = AssessmentBudget(1.0, 0.05, 10, 3600)
    assert budget.remaining_seconds() > 3500
    # Suspend: wall time moves on, the monotonic clock does not.
    woke = time.time() + 2 * 3600
    monkeypatch.setattr(time, "time", lambda: woke)
    with pytest.raises(BudgetExhausted):
        budget.remaining_seconds()


def test_aggregate_deadline_and_unknown_cost_close_dispatch(tmp_path):
    from runtime.multi_repo_discovery import BudgetExhausted

    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.deadline = 0
    with pytest.raises(BudgetExhausted):
        jobs.execute(**kwargs)
    assert host.calls == 0
    jobs.budget.deadline = time.monotonic() + 60
    jobs.budget.failed = True
    with pytest.raises(ExchangeError):
        jobs.budget.invoke(lambda ceiling: host, "", "", {}, 1, lambda: False)
    assert host.calls == 0


def test_each_host_call_gets_at_most_the_per_call_time_limit(tmp_path):
    from runtime.multi_repo_discovery import MAX_CALL_SECONDS

    granted = []

    class Timed(Host):
        def invoke(self, system, prompt, schema, timeout_s, should_stop):
            granted.append(timeout_s)
            return super().invoke(system, prompt, schema, timeout_s, should_stop)

    jobs, host, kwargs, _ = setup(tmp_path)
    timed = Timed([{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}])
    jobs.host_factory = lambda role, ceiling: timed
    jobs.budget.deadline += 10 * MAX_CALL_SECONDS
    jobs.execute(**kwargs)
    assert granted and all(value <= MAX_CALL_SECONDS for value in granted)


def _inherit(tmp_path, jobs, kwargs, **change):
    """A fresh session whose cache holds the jobs an unfinished earlier run accepted."""
    cache = jobs.directory.with_name("cache")
    jobs.directory.rename(cache)
    budget = AssessmentBudget(1.0, 0.05, 10, 60)
    host = Host([{"action": "complete", "reads": [], "artifact": {"result": "redone"}}])
    fresh = AssessmentJobs(
        jobs.scope, jobs.directory, budget, lambda role, ceiling: host, lambda: False, lambda: None, cache=cache
    )
    return fresh, host, {**kwargs, **change}


def test_a_fresh_run_reuses_an_earlier_run_s_accepted_job_and_counts_its_cost(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    fresh, fresh_host, request = _inherit(tmp_path, jobs, kwargs)
    assert fresh.execute(**request) == {"result": "accepted"}
    assert fresh_host.calls == 0
    assert (fresh.budget.calls, fresh.budget.spent_usd) == (1, pytest.approx(0.01))
    # The closing line names what reused jobs charged; a job of this run's own is not counted again.
    assert (fresh.budget.reused_calls, fresh.budget.reused_usd) == (1, pytest.approx(0.01))
    assert jobs.budget.reused_calls == 0
    # The adopted, charged job joins this run's receipts and leaves the cache.
    assert len(list(fresh.directory.glob("*.receipt.json"))) == 1
    assert not list(fresh.cache.iterdir())


def test_a_job_taken_over_tells_the_console_and_a_job_that_ran_does_not(tmp_path):
    """The console says in each phase that a job came from the earlier run, once the first one does."""
    jobs, host, kwargs, _ = setup(tmp_path)
    told = []
    jobs.on_reused = lambda: told.append("own run")
    jobs.execute(**kwargs)
    assert told == []
    fresh, _, request = _inherit(tmp_path, jobs, kwargs)
    fresh.on_reused = lambda: told.append("earlier run")
    # A forked component view keeps the callback.
    assert fresh.view().execute(**request) == {"result": "accepted"}
    assert told == ["earlier run"]


@pytest.mark.parametrize("change", [{"instructions": "changed task"}, {"validate": "reject"}])
def test_an_inherited_job_that_no_longer_fits_is_redone_not_fatal(tmp_path, change):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    if change.get("validate") == "reject":

        def stricter(artifact, ranges):
            if artifact["result"] == "accepted":
                raise ValueError("rule added since the earlier run")

        change = {"validate": stricter}
    fresh, fresh_host, request = _inherit(tmp_path, jobs, kwargs, **change)
    assert fresh.execute(**request) == {"result": "redone"}
    assert fresh_host.calls == 1


def test_an_inherited_job_whose_artifact_changed_still_fails(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    artifact = next(path for path in jobs.directory.iterdir() if not path.name.endswith(".receipt.json"))
    artifact.write_text(json.dumps({"result": "changed"}))
    fresh, fresh_host, request = _inherit(tmp_path, jobs, kwargs)
    with pytest.raises(ExchangeError, match="changed"):
        fresh.execute(**request)
    assert fresh_host.calls == 0


class Hanging(Host):
    """Times out for the first `hangs` calls, as a stalled host call does."""

    def __init__(self, hangs, error=None):
        super().__init__([{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}])
        self.hangs, self.error = hangs, error

    def invoke(self, *args):
        self.calls += 1
        if self.calls <= self.hangs:
            from runtime.analyst_host import HostTimeout

            raise (self.error or HostTimeout("host call exceeded its time limit"))
        return HostReply(next(self.replies), 0.01)


def _hanging(tmp_path, host):
    jobs, _, kwargs, _ = setup(tmp_path)
    jobs.host_factory = lambda role, ceiling: host
    return jobs, kwargs


def test_a_hung_call_is_retried_once_with_its_reservation_kept(tmp_path):
    host = Hanging(1)
    jobs, kwargs = _hanging(tmp_path, host)
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert host.calls == 2 and jobs.budget.calls == 2
    # The hung call keeps its full reservation; accounting stays available.
    assert jobs.budget.spent_usd == pytest.approx(0.05 + 0.01) and not jobs.budget.failed


def test_a_second_hang_fails_and_names_its_job(tmp_path):
    from runtime.analyst_host import HostTimeout

    host = Hanging(2)
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(HostTimeout, match="^one: host call exceeded its time limit"):
        jobs.execute(**kwargs)
    assert host.calls == 2


def test_a_cancelled_call_is_never_retried(tmp_path):
    host = Hanging(1, error=HostCancelled("job cancelled"))
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(HostCancelled, match="job cancelled"):
        jobs.execute(**kwargs)
    assert host.calls == 1


class Refused(Host):
    """Fails the first `failures` calls with a settled host error, as an overloaded API does."""

    def __init__(self, failures, reason, usd=0.0):
        super().__init__([{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}])
        self.failures, self.reason, self.usd = failures, reason, usd

    def invoke(self, *args):
        from runtime.analyst_host import TransportError

        self.calls += 1
        if self.calls <= self.failures:
            raise TransportError(f"host call failed: {self.reason}", reason=self.reason, usd=self.usd)
        return HostReply(next(self.replies), 0.01)


@pytest.fixture
def no_retry_wait(monkeypatch):
    from runtime import multi_repo_discovery

    monkeypatch.setattr(multi_repo_discovery, "TRANSIENT_RETRY_DELAYS", (0, 0, 0))


@pytest.mark.parametrize("reason", ["rate_limit", "server_error", "api_error", "no_structured_output"])
def test_a_transient_settled_failure_is_retried_until_the_call_succeeds(tmp_path, no_retry_wait, reason):
    host = Refused(2, reason)
    jobs, kwargs = _hanging(tmp_path, host)
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert host.calls == 3 and jobs.budget.calls == 3
    # Refused calls settle at their reported cost; accounting stays available.
    assert jobs.budget.spent_usd == pytest.approx(0.01) and not jobs.budget.failed


@pytest.mark.parametrize(
    "reason", ["stream_disconnected", "connection_failed", "connection_timeout", "dns_unavailable"]
)
def test_a_dropped_connection_without_a_cost_report_is_repeated_once(tmp_path, no_retry_wait, reason):
    # Codex subscriptions and API hosts report no cost for a failed call, so it counts as paid.
    host = Refused(1, reason, usd=None)
    jobs, kwargs = _hanging(tmp_path, host)
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert host.calls == 2 and [row["reason"] for row in jobs.budget.retries] == [reason]


def test_a_connection_that_stays_down_stops_after_one_repeat(tmp_path, no_retry_wait):
    from runtime.analyst_host import TransportError

    host = Refused(10, "stream_disconnected", usd=None)
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(TransportError, match="stream_disconnected.*--resume") as caught:
        jobs.execute(**kwargs)
    assert caught.value.reason == "stream_disconnected" and host.calls == 2


@pytest.mark.parametrize("reason", ["authentication_failed", "quota_exhausted", "tls_error", "transport"])
def test_an_account_configuration_or_unknown_failure_is_not_repeated(tmp_path, no_retry_wait, reason):
    from runtime.analyst_host import TransportError

    host = Refused(1, reason, usd=None)
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(TransportError):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_every_host_failure_code_has_exactly_one_retry_class():
    """A failure code nobody classified must not silently become a run-ending error."""
    import ast
    from pathlib import Path

    from runtime import multi_repo_discovery as policy
    from runtime.assessment_diagnostics import FAILURE_CODES

    classes = (policy.TRANSIENT_FAILURES, policy.NETWORK_FAILURES, policy.FATAL_FAILURES)
    assert not any(a & b for i, a in enumerate(classes) for b in classes[i + 1 :])
    produced = set(FAILURE_CODES)
    root = Path(__file__).resolve().parents[1]
    for source in (root / "appsec_analyzer").rglob("*.py"):
        for node in ast.walk(ast.parse(source.read_text())):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name == "ApiTransportError" and node.args and isinstance(node.args[0], ast.Constant):
                produced.add(node.args[0].value)
            if name in ("TransportError", "ApiTransportError"):
                produced |= {
                    kw.value.value for kw in node.keywords if kw.arg == "reason" and isinstance(kw.value, ast.Constant)
                }
    assert produced - set().union(*classes) == set()


@pytest.mark.parametrize("optional", [False, True])
def test_a_transient_failure_that_persists_still_stops_a_required_job(tmp_path, no_retry_wait, optional):
    from runtime.analyst_host import TransportError

    host = Refused(10, "rate_limit")
    jobs, kwargs = _hanging(tmp_path, host)
    if optional:
        kwargs["on_failure"] = lambda reason: pytest.fail("Rate limits cannot become optional coverage gaps")
    with pytest.raises(TransportError, match="rate_limit.*--resume"):
        jobs.execute(**kwargs)
    assert host.calls == 4 and not jobs.budget.failed


@pytest.mark.parametrize(
    "reason,usd",
    [("authentication_failed", 0.0), ("billing_error", 0.0), ("invalid_request", 0.0), ("error_max_budget_usd", 0.05)],
)
def test_a_failure_a_repeat_cannot_clear_is_not_retried(tmp_path, no_retry_wait, reason, usd):
    from runtime.analyst_host import TransportError

    host = Refused(1, reason, usd)
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(TransportError, match=reason):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_a_failure_without_a_cost_report_is_charged_its_reservation_and_stays_resumable(tmp_path, no_retry_wait):
    from runtime.analyst_host import TransportError

    host = Refused(1, "no_result", usd=None)
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(TransportError, match="--resume"):
        jobs.execute(**kwargs)
    assert host.calls == 1 and not jobs.budget.failed
    assert jobs.budget.spent_usd == pytest.approx(jobs.budget.call_usd)


def test_a_repeated_call_records_the_reservation_its_failure_was_charged(tmp_path, no_retry_wait):
    host = Refused(1, "server_error", usd=None)
    jobs, kwargs = _hanging(tmp_path, host)
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    # The retry warning sums these rows, so they carry what the budget charged.
    assert jobs.budget.retries == [{"reason": "server_error", "usd": pytest.approx(0.05), "paid": True}]
    assert jobs.budget.spent_usd == pytest.approx(0.05 + 0.01)
    # The job's group is charged for both calls, the failed one included.
    assert jobs.budget.charged_of(kwargs["selector"]) == pytest.approx(0.06)
    assert jobs.budget.charged_of("another-job") == 0.0


def test_an_api_call_above_a_reduced_ceiling_ends_the_budget_without_a_charge(tmp_path):
    """An API host sends nothing whose worst case exceeds what is left; that is a budget end, not a failure."""
    from runtime.analyst_host import TransportError
    from runtime.multi_repo_discovery import BudgetExhausted

    host = Refused(2, "budget_exhausted")
    jobs, kwargs = _hanging(tmp_path, host)
    jobs.budget.call_usd = 0.5
    jobs.budget.spent_usd = 0.8
    with pytest.raises(BudgetExhausted, match="less than its worst-case cost"):
        jobs.execute(**kwargs)
    assert host.calls == 1 and jobs.budget.spent_usd == pytest.approx(0.8) and not jobs.budget.failed
    # At the full ceiling the request itself exceeds a call; more budget would not help.
    jobs.budget.spent_usd = 0.0
    with pytest.raises(TransportError, match="budget_exhausted") as caught:
        jobs.execute(**kwargs)
    assert not isinstance(caught.value, BudgetExhausted) and jobs.budget.spent_usd == 0.0


def test_a_paid_failure_is_repeated_once_and_reported(tmp_path, no_retry_wait):
    from runtime.analyst_host import TransportError

    notices = []
    host = Refused(1, "no_structured_output", usd=0.04)
    jobs, kwargs = _hanging(tmp_path, host)
    jobs.budget.on_retry = notices.append
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert host.calls == 2 and jobs.budget.spent_usd == pytest.approx(0.05)
    assert jobs.budget.retries == [{"reason": "no_structured_output", "usd": 0.04, "paid": True}]
    assert len(notices) == 1 and "no_structured_output" in notices[0]
    # A second paid failure of the same call is not paid for again.
    host = Refused(2, "no_structured_output", usd=0.04)
    jobs, kwargs = _hanging(tmp_path / "again", host)
    with pytest.raises(TransportError, match="no_structured_output"):
        jobs.execute(**kwargs)
    assert host.calls == 2


def test_paid_retries_stop_once_the_run_has_spent_its_allowance(tmp_path, no_retry_wait):
    from runtime import multi_repo_discovery
    from runtime.analyst_host import TransportError

    jobs, kwargs = _hanging(tmp_path, Refused(0, "no_structured_output"))
    for number in range(multi_repo_discovery.MAX_PAID_RETRIES):
        host = Refused(1, "no_structured_output", usd=0.01)
        jobs.host_factory = lambda role, ceiling, host=host: host
        assert jobs.execute(**{**kwargs, "selector": f"job-{number}"}) == {"result": "accepted"}
    host = Refused(1, "no_structured_output", usd=0.01)
    jobs.host_factory = lambda role, ceiling: host
    with pytest.raises(TransportError):
        jobs.execute(**{**kwargs, "selector": "one-too-many"})
    assert host.calls == 1
    # Free refusals stay retried after the paid allowance is spent.
    host = Refused(2, "rate_limit")
    jobs.host_factory = lambda role, ceiling: host
    assert jobs.execute(**{**kwargs, "selector": "free"}) == {"result": "accepted"}


def test_the_run_warning_counts_retries_and_their_paid_cost():
    from orchestrator.orchestration_controller import _assessment_retry_warning

    assert _assessment_retry_warning([]) is None
    rows = [
        {"reason": "rate_limit", "usd": 0.0, "paid": False},
        {"reason": "rate_limit", "usd": 0.0, "paid": False},
        {"reason": "no_structured_output", "usd": 0.04, "paid": True},
    ]
    text = _assessment_retry_warning(rows)
    assert text.startswith("3 model call(s) were repeated")
    assert "no_structured_output ×1, rate_limit ×2" in text and "USD 0.04" in text
    assert "USD" not in _assessment_retry_warning(rows[:1])


def test_a_nearly_spent_budget_stops_with_its_reason_before_another_call(tmp_path):
    jobs, kwargs = _hanging(tmp_path, Host([{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}]))
    jobs.budget.spent_usd = 0.97
    with pytest.raises(ExchangeError, match="budget exhausted: USD 0.03 is left"):
        jobs.execute(**kwargs)
    assert jobs.budget.calls == 0


@pytest.mark.parametrize("selector", ["review:orders", "verify:billing"])
@pytest.mark.parametrize("component_view", [False, True])
def test_optional_work_preserves_the_report_budget(tmp_path, selector, component_view):
    """A review cannot consume the last report allowance, regardless of its name."""
    from runtime.assessment_jobs import REPORT_JOB

    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.spent_usd = 0.94
    reported = []
    jobs.on_gap = reported.append
    if component_view:
        jobs = jobs.view()
    result = jobs.execute(**{**kwargs, "selector": selector}, on_failure=lambda reason: {"result": "not reviewed"})
    assert result == {"result": "not reviewed"} and host.calls == 0
    assert jobs.gaps[0]["budget"] and not list(jobs.directory.glob("*.receipt.json"))
    assert reported == jobs.gaps
    assert jobs.execute(**{**kwargs, "role": "secarch_renderer", "selector": REPORT_JOB}) == {"result": "accepted"}
    assert host.calls == 1 and jobs.budget.spent_usd == pytest.approx(0.95)
    assert REPORT_JOB not in jobs.budget.required
    assert len(reported) == 1  # the accepted report is not a coverage gap


@pytest.mark.parametrize("floor, reviewed", [(0.0, True), (0.05, False)])
def test_the_report_reserve_keeps_an_api_hosts_worst_case_call(tmp_path, floor, reviewed):
    """An API host sends no call below its worst case, so optional work also leaves that much for the report."""
    from runtime.assessment_jobs import REPORT_JOB

    jobs, _, kwargs, _ = setup(
        tmp_path, replies=[{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}] * 2
    )
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.call_floor_usd = floor
    jobs.budget.spent_usd = 0.88
    result = jobs.execute(
        **{**kwargs, "selector": "review:orders"}, on_failure=lambda reason: {"result": "not reviewed"}
    )
    assert result == ({"result": "accepted"} if reviewed else {"result": "not reviewed"})
    assert jobs.execute(**{**kwargs, "role": "secarch_renderer", "selector": REPORT_JOB}) == {"result": "accepted"}


def test_optional_work_still_runs_with_sufficient_completion_budget(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"}) == {"result": "accepted"}
    assert host.calls == 1 and jobs.gaps == []


@pytest.mark.parametrize("remaining, expected_calls", [(1.75, 1), (0.05, 1), (0.049, 0), (0.0, 0)])
def test_finishing_summary_uses_only_the_actual_remaining_budget(tmp_path, remaining, expected_calls):
    from runtime.assessment_jobs import REPORT_JOB, SUMMARY_JOB

    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget = AssessmentBudget(30.0, 2.0, 100, 7200)
    jobs.budget.plan_completion()
    jobs.budget.accepted(REPORT_JOB, "secarch_renderer", 0.25)
    jobs.budget.spent_usd = 30.0 - remaining
    ceilings = []

    def factory(role, ceiling):
        ceilings.append(ceiling)
        return host

    jobs.host_factory = factory
    result = jobs.execute(
        **{**kwargs, "role": "ms_renderer", "selector": SUMMARY_JOB},
        on_failure=lambda reason: {"result": "fallback"},
    )
    assert host.calls == expected_calls
    assert result == {"result": "accepted" if expected_calls else "fallback"}
    assert all(0.05 <= ceiling <= remaining for ceiling in ceilings)
    assert jobs.budget.spent_usd <= 30.0


@pytest.mark.parametrize("limit", ["pending_report", "time", "calls", "other_role"])
def test_finishing_summary_still_obeys_completion_and_execution_limits(tmp_path, limit):
    from runtime.assessment_jobs import FINALIZATION_SECONDS, REPORT_JOB, SUMMARY_JOB

    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget = AssessmentBudget(30.0, 2.0, 100, 7200)
    jobs.budget.plan_completion()
    jobs.budget.spent_usd = 28.25
    if limit != "pending_report":
        jobs.budget.accepted(REPORT_JOB, "secarch_renderer", 0.25)
    if limit == "time":
        jobs.budget.deadline = time.monotonic() + FINALIZATION_SECONDS
    elif limit == "calls":
        jobs.budget.calls = jobs.budget.max_calls
    elif limit == "other_role":
        # Enough for the summary, less than 1.5 x the report's cost for a cold role.
        jobs.budget.spent_usd = 29.70
    role = "other" if limit == "other_role" else "ms_renderer"
    assert jobs.execute(
        **{**kwargs, "role": role, "selector": SUMMARY_JOB},
        on_failure=lambda reason: {"result": "fallback"},
    ) == {"result": "fallback"}
    assert host.calls == 0 and jobs.gaps[0]["budget"]


def test_finishing_summary_corrections_stop_at_the_remaining_budget(tmp_path):
    from runtime.assessment_jobs import REPORT_JOB, SUMMARY_JOB

    def reject(artifact, ranges):
        raise ExchangeError("correct the result")

    jobs, host, kwargs, _ = setup(tmp_path, validate=reject)
    jobs.budget = AssessmentBudget(30.0, 2.0, 100, 7200)
    jobs.budget.plan_completion()
    jobs.budget.accepted(REPORT_JOB, "secarch_renderer", 0.25)
    jobs.budget.spent_usd = 29.95
    assert jobs.execute(
        **{**kwargs, "role": "ms_renderer", "selector": SUMMARY_JOB},
        on_failure=lambda reason: {"result": "fallback"},
    ) == {"result": "fallback"}
    assert host.calls == 1 and jobs.budget.spent_usd == pytest.approx(29.96)
    assert jobs.gaps[0]["budget"] and not list(jobs.directory.glob("*.receipt.json"))


def test_optional_work_protects_pending_analysis_and_uses_measured_job_cost(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.plan_required("stride:remaining", "stride_analyzer", 4)
    jobs.budget.spent_usd = 0.73
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"}) == {"result": "not reviewed"}
    assert host.calls == 0
    # A validated batch updates both outstanding work and the role estimate.
    jobs.budget.accepted("stride:remaining", "stride_analyzer", 0.01, 1)
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"}) == {"result": "accepted"}
    assert host.calls == 1


def test_one_expensive_batch_does_not_reserve_its_cost_for_every_pending_batch(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget = AssessmentBudget(10.0, 2.0, 100, 7200)
    jobs.budget.plan_completion()
    jobs.budget.plan_required("stride:remaining", "stride_analyzer", 10)
    for usd in (0.6, 0.2, 0.2, 0.2):
        jobs.budget.accepted("stride:done", "stride_analyzer", usd, 1)
    jobs.budget.accepted("review:done", "architecture_analyst", 0.1, 1)
    jobs.budget.spent_usd = 3.0
    # 10 pending batches at 1.5 x the USD 0.30 average plus the USD 2 report
    # leave USD 0.50; doubling the USD 0.60 outlier would reserve USD 14.
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"}) == {"result": "accepted"}
    assert host.calls == 1 and jobs.gaps == []
    jobs.budget.spent_usd = 3.45
    assert jobs.execute(**{**kwargs, "selector": "two"}, on_failure=lambda reason: {"result": "not reviewed"}) == {
        "result": "not reviewed"
    }
    assert host.calls == 1 and jobs.gaps[0]["budget"]


def test_a_cold_optional_role_needs_the_run_average_above_the_full_report_reserve(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget = AssessmentBudget(20.0, 2.0, 100, 7200)
    jobs.budget.plan_completion()
    optional = dict(on_failure=lambda reason: {"result": "not reviewed"})
    # Without any accepted job, an optional job still needs a full call allowance.
    jobs.budget.spent_usd = 17.29
    assert jobs.execute(**{**kwargs, "role": "threat_merger"}, **optional) == {"result": "not reviewed"}
    for usd in (0.2, 0.3):
        jobs.budget.accepted("stride:done", "stride_analyzer", usd, 1)
    # The report keeps its full USD 2 reserve; the USD 0.30 above it is less
    # than 1.5 x the USD 0.25 that accepted jobs cost on average.
    jobs.budget.spent_usd = 17.70
    assert jobs.execute(**{**kwargs, "role": "threat_merger", "selector": "two"}, **optional) == {
        "result": "not reviewed"
    }
    assert host.calls == 0 and len(jobs.gaps) == 2
    jobs.budget.spent_usd = 17.29
    assert jobs.execute(**{**kwargs, "role": "threat_merger", "selector": "three"}, **optional) == {
        "result": "accepted"
    }
    assert host.calls == 1 and len(jobs.gaps) == 2


def test_optional_work_waits_for_pending_analysis_before_asking_for_more_budget(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget = AssessmentBudget(1.0, 0.05, 100, 7200)
    jobs.budget.plan_completion()
    jobs.budget.plan_required("stride:remaining", "stride_analyzer", 4)
    jobs.budget.spent_usd = 0.73
    asked = []
    jobs.budget.on_budget_increase = asked.append
    optional = dict(on_failure=lambda reason: {"result": "not reviewed"})
    # The controller retries this budget gap once the analysis reserve is released.
    assert jobs.execute(**kwargs, **optional) == {"result": "not reviewed"}
    assert asked == [] and jobs.gaps[0]["budget"] and host.calls == 0
    # Required analysis that cannot fit still asks.
    jobs.budget.spent_usd = 0.99
    with pytest.raises(ExchangeError, match="budget"):
        jobs.execute(**{**kwargs, "role": "stride_analyzer", "selector": "stride:remaining"})
    assert len(asked) == 1 and host.calls == 0
    # Once only the report reserve remains, an optional shortfall asks too.
    jobs.budget.plan_required("stride:remaining", "stride_analyzer", 0)
    jobs.budget.spent_usd = 0.94
    assert jobs.execute(**{**kwargs, "selector": "two"}, **optional) == {"result": "not reviewed"}
    assert len(asked) == 2 and host.calls == 0


@pytest.mark.parametrize(
    "max_parallel, pending, skipped", [(1, 4, True), (2, 4, True), (4, 4, False), (2, 3, True), (16, 17, True)]
)
def test_optional_work_keeps_time_for_pending_analysis_with_configured_workers(
    tmp_path, max_parallel, pending, skipped
):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget = AssessmentBudget(1.0, 0.05, 100, 3600, max_parallel=max_parallel)
    jobs.budget.deadline = time.monotonic() + 2400
    jobs.budget.plan_completion()
    jobs.budget.plan_required("stride:remaining", "stride_analyzer", pending)
    result = jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"})
    assert result == {"result": "not reviewed" if skipped else "accepted"}
    assert host.calls == (0 if skipped else 1)
    if not skipped:
        return
    assert jobs.gaps[0]["budget"]
    # Accepted work releases enough time for the optional check.
    for _ in range(pending):
        jobs.budget.accepted("stride:remaining", "stride_analyzer", 0.01, 1)
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"}) == {"result": "accepted"}
    assert host.calls == 1


@pytest.mark.parametrize("value", [0, -1, 17, True, 1.5, "2"])
def test_assessment_budget_rejects_invalid_parallel_limits(value):
    with pytest.raises(ExchangeError, match="max_parallel"):
        AssessmentBudget(1.0, 0.05, 10, 60, max_parallel=value)


def test_optional_work_keeps_time_for_the_report_and_local_finalization(tmp_path):
    from runtime.assessment_jobs import FINALIZATION_SECONDS, REPORT_JOB

    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.plan_completion()
    jobs.budget.deadline = time.monotonic() + FINALIZATION_SECONDS + 30
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"}) == {"result": "not reviewed"}
    assert host.calls == 0
    assert jobs.execute(**{**kwargs, "role": "secarch_renderer", "selector": REPORT_JOB}) == {"result": "accepted"}
    assert host.calls == 1


@pytest.mark.parametrize("failure", ["cancelled", "unknown_cost", "tampered"])
def test_budget_fallback_never_masks_authority_or_accounting_failures(tmp_path, failure):
    jobs, host, kwargs, _ = setup(tmp_path)
    if failure == "tampered":
        jobs.execute(**kwargs)
        artifact = next(p for p in jobs.directory.glob("*.json") if not p.name.endswith(".receipt.json"))
        artifact.write_text(json.dumps({"result": "tampered"}))
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.spent_usd = 0.99
    if failure == "cancelled":
        jobs.should_stop = lambda: True
    elif failure == "unknown_cost":
        jobs.budget.failed = True
    with pytest.raises((ExchangeError, HostCancelled)):
        jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"})
    assert jobs.gaps == []


def test_completion_reservation_applies_to_each_correction_call(tmp_path):
    replies = [{"action": "complete", "reads": [], "artifact": {"result": "rejected"}}] * 3

    def reject(artifact, ranges):
        raise ExchangeError("correct the result")

    jobs, host, kwargs, _ = setup(tmp_path, replies=replies, validate=reject)
    jobs.budget.deadline += 3600
    jobs.budget.plan_completion()
    jobs.budget.spent_usd = 0.90
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "not reviewed"}) == {"result": "not reviewed"}
    assert host.calls == 1 and jobs.gaps[0]["budget"]
    assert jobs.budget.spent_usd == pytest.approx(0.91)


def test_parallel_optional_calls_cannot_spend_completion_reserve():
    from concurrent.futures import ThreadPoolExecutor

    from runtime.assessment_jobs import REPORT_JOB

    budget = AssessmentBudget(1.0, 0.2, 100, 6000)
    budget.plan_completion()
    reservations = []

    class Reply:
        def invoke(self, *args):
            time.sleep(0.01)
            return HostReply({}, 0.04)

    def factory(ceiling):
        with budget._lock:
            reservations.append(budget.spent_usd)
        return Reply()

    def call(index):
        with budget.job(f"review:{index}", "review", True):
            return budget.invoke(factory, "", "", {}, 60, lambda: False)

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert len(list(pool.map(call, range(8)))) == 8
    assert max(reservations) <= 0.8 + 1e-9
    assert budget.spent_usd == pytest.approx(0.32) and not budget.failed
    assert REPORT_JOB in budget.required


@pytest.mark.parametrize("remainder", [0.10, 0.20, 0.40])
def test_host_budget_cut_distinguishes_a_reduced_run_allowance_from_a_call_limit(tmp_path, remainder):
    from runtime.analyst_host import TransportError
    from runtime.multi_repo_discovery import BudgetExhausted

    cost = min(remainder, 0.20)
    host = Refused(1, "error_max_budget_usd", usd=cost)
    jobs, kwargs = _hanging(tmp_path, host)
    jobs.budget = AssessmentBudget(1.0, 0.20, 10, 60)
    jobs.budget.spent_usd = 1.0 - remainder
    expected = BudgetExhausted if remainder <= 0.20 else TransportError
    with pytest.raises(expected):
        jobs.execute(**kwargs)
    assert host.calls == 1 and not jobs.budget.failed
    assert jobs.budget.spent_usd == pytest.approx(1.0 - remainder + cost)


@pytest.mark.parametrize("reason", ["authentication_failed", "billing_error"])
def test_a_login_or_billing_failure_is_never_replaced(tmp_path, reason):
    from runtime.analyst_host import TransportError

    jobs, kwargs = _hanging(tmp_path, Refused(1, reason))
    with pytest.raises(TransportError, match=reason):
        jobs.execute(**kwargs, on_failure=lambda reason: {"result": "replacement"})
    assert jobs.gaps == []


def test_a_stopped_call_is_repeated_only_within_the_paid_retry_allowance(tmp_path):
    from runtime import multi_repo_discovery

    notices = []
    host = Hanging(1)
    jobs, kwargs = _hanging(tmp_path, host)
    jobs.budget.on_retry = notices.append
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert jobs.budget.retries == [{"reason": "timeout", "usd": 0.05, "paid": True}] and len(notices) == 1
    jobs.budget.retries = [{"reason": "timeout", "usd": 0.05, "paid": True}] * multi_repo_discovery.MAX_PAID_RETRIES
    host = Hanging(1)
    jobs.host_factory = lambda role, ceiling: host
    from runtime.analyst_host import HostTimeout

    with pytest.raises(HostTimeout):
        jobs.execute(**{**kwargs, "selector": "over-allowance"})
    assert host.calls == 1


def test_an_optional_job_past_its_own_time_limit_is_replaced(tmp_path):
    class Slow(Host):
        def invoke(self, *args):
            time.sleep(1.1)
            return super().invoke(*args)

    read = {"repository_id": RID, "path": "app.py", "start_line": 1, "end_line": 1}
    host = Slow([{"action": "read", "artifact": None, "reads": [read]}] * 6)
    jobs, kwargs = _hanging(tmp_path, host)
    jobs.budget = AssessmentBudget(1.0, 0.05, 10, 2)
    reported = []
    jobs.on_gap = reported.append
    result = jobs.execute(**kwargs, on_failure=lambda reason: {"result": "replacement"})
    assert result == {"result": "replacement"} and "time limit" in jobs.gaps[0]["reason"]
    assert reported == jobs.gaps and not reported[0].get("budget")


def test_a_retry_wait_ends_when_the_run_is_stopped(tmp_path, monkeypatch):
    from runtime import multi_repo_discovery

    monkeypatch.setattr(multi_repo_discovery, "TRANSIENT_RETRY_DELAYS", (30,))
    stops = iter([False] * 6 + [True] * 10)
    host = Refused(1, "server_error")
    jobs, kwargs = _hanging(tmp_path, host)
    jobs.should_stop = lambda: next(stops)
    started = time.monotonic()
    with pytest.raises((HostCancelled, ExchangeError)):
        jobs.execute(**kwargs)
    assert host.calls == 1 and time.monotonic() - started < 10


def test_the_receipt_records_the_normalized_artifact_and_names_its_normalizer(tmp_path):
    def normalize(artifact):
        artifact["result"] = artifact["result"].upper()
        return artifact

    normalize.version = "upper-1"
    reviewed = []
    jobs, host, kwargs, _ = setup(tmp_path, validate=lambda a, r: reviewed.append(a["result"]))
    assert jobs.execute(**kwargs, normalize=normalize) == {"result": "ACCEPTED"}
    # Resumed from the receipt: the stored result is the normalized one and passes unchanged.
    assert jobs.execute(**kwargs, normalize=normalize) == {"result": "ACCEPTED"}
    assert host.calls == 1 and set(reviewed) == {"ACCEPTED"}
    # A changed normalizer is a changed request, never a silent reuse.
    normalize.version = "upper-2"
    with pytest.raises(ExchangeError, match="stale"):
        jobs.execute(**kwargs, normalize=normalize)


def test_an_optional_job_the_model_cannot_answer_is_replaced_without_a_receipt(tmp_path):
    """OR-39: the replacement stands in, the gap is named, and a later run retries the job."""

    def reject(artifact, ranges):
        raise ValueError("never acceptable")

    replies = [{"action": "complete", "reads": [], "artifact": {"result": "draft"}}] * 3
    jobs, host, kwargs, _ = setup(tmp_path, replies=replies, validate=reject)
    result = jobs.execute(**kwargs, on_failure=lambda reason: {"result": "replacement"})
    assert result == {"result": "replacement"} and host.calls == 3
    assert [gap["selector"] for gap in jobs.gaps] == ["one"] and "never acceptable" in jobs.gaps[0]["reason"]
    assert not list(jobs.directory.glob("*.receipt.json"))


def test_a_required_job_still_stops_on_the_same_failure(tmp_path):
    def reject(artifact, ranges):
        raise ValueError("never acceptable")

    replies = [{"action": "complete", "reads": [], "artifact": {"result": "draft"}}] * 3
    jobs, _, kwargs, _ = setup(tmp_path, replies=replies, validate=reject)
    with pytest.raises(ExchangeError, match="rejected after"):
        jobs.execute(**kwargs)
    assert jobs.gaps == []


@pytest.mark.parametrize("breach", ["scope", "unsettled-cost"])
def test_a_trust_or_accounting_failure_is_never_replaced(tmp_path, breach):
    from runtime.analyst_host import TransportError

    if breach == "scope":
        replies = [
            {
                "action": "read",
                "artifact": None,
                "reads": [{"repository_id": "repo-ffffffffffffffff", "path": "x.py", "start_line": 1, "end_line": 1}],
            }
        ]
        jobs, _, kwargs, _ = setup(tmp_path, replies=replies)
    else:
        jobs, host, kwargs, _ = setup(tmp_path)

        def unsettled(*args):
            return HostReply({"action": "complete", "reads": [], "artifact": {"result": "x"}}, float("nan"))

        host.invoke = unsettled
    with pytest.raises((ExchangeError, TransportError)):
        jobs.execute(**kwargs, on_failure=lambda reason: {"result": "replacement"})
    assert jobs.gaps == []


def test_subscription_receipt_is_reused_without_inventing_cost(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget = AssessmentBudget(None, None, 10, 60, spent_usd=None, subscription=True)
    host.invoke = lambda *args: HostReply({"action": "complete", "reads": [], "artifact": {"result": "accepted"}}, None)
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    receipt = json.loads(next(jobs.directory.glob("*.receipt.json")).read_text())
    assert receipt["schema_version"] == 2 and receipt["usd"] is None
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert jobs.budget.calls == 1 and jobs.budget.spent_usd is None


def test_subscription_quota_error_cannot_be_replaced_by_optional_fallback(tmp_path):
    from runtime.analyst_host import TransportError

    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget = AssessmentBudget(None, None, 10, 60, spent_usd=None, subscription=True)

    def invoke(*args):
        raise TransportError("ChatGPT allowance exhausted", reason="quota_exhausted")

    host.invoke = invoke
    with pytest.raises(TransportError) as caught:
        jobs.execute(**kwargs, on_failure=lambda _: pytest.fail("quota failure was hidden"))
    assert caught.value.reason == "quota_exhausted"
    assert jobs.budget.calls == 1 and jobs.budget.spent_usd is None


def test_corrected_source_proposal_is_accounted_and_only_served_ranges_are_receipted(tmp_path):
    def proposal(path):
        return {
            "action": "read",
            "artifact": None,
            "reads": [{"repository_id": RID, "path": path, "start_line": 1, "end_line": 1}],
        }

    jobs, host, kwargs, _ = setup(
        tmp_path,
        replies=[
            proposal("guessed.ts"),
            proposal("app.py"),
            {"action": "complete", "reads": [], "artifact": {"result": "accepted"}},
        ],
    )
    result = jobs.execute(**kwargs)
    assert result == {"result": "accepted"}
    assert jobs.budget.calls == 3 and jobs.budget.spent_usd == pytest.approx(0.03)
    receipt = json.loads(next(jobs.directory.glob("*.receipt.json")).read_text())
    assert receipt["calls"] == 3 and receipt["usd"] == pytest.approx(0.03)
    assert [(row["repository_id"], row["path"]) for row in receipt["source_ranges"]] == [(RID, "app.py")]
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert host.calls == 3


def test_the_budget_itemises_reported_usage_per_model_and_names_what_no_host_reported():
    budget = AssessmentBudget(1.0, 0.05, 10, 60)

    def transport(reply):
        class Host:
            def __init__(self, ceiling):
                pass

            def invoke(self, *args):
                return reply

        return Host

    sonnet = {"input": 10, "output": 20, "cache_read": 300, "cache_write": 40, "usd": 0.02}
    with budget.job("stride:api", "stride_analyzer", False):
        budget.invoke(transport(HostReply({}, 0.02, {"claude-sonnet-5-5": sonnet})), "s", "p", {}, 30, lambda: False)
        # A host that reports no usage still costs and counts; only the itemisation lacks it.
        budget.invoke(transport(HostReply({}, 0.03)), "s", "p", {}, 30, lambda: False)
    report = budget.usage_report()
    assert report["models"] == {"claude-sonnet-5-5": {"calls": 1, **sonnet}}
    assert report["unitemised_calls"] == 1 and report["unitemised_usd"] == pytest.approx(0.03)
    # A group matches itself and its sub-jobs, never another group that merely starts with its name.
    assert budget.usage_of("stride:api")["output"] == 20 and budget.usage_of("stride:ap") == {}
    assert budget.usage_mark() == {
        "calls": 2,
        "usd": pytest.approx(0.05),
        "total_usd": pytest.approx(0.05),
        "itemised": 1,
        "tokens": 370,
    }
    # A job reused from an earlier run made no call in this one: its charge is not a step's cost,
    # but it is part of what the run cost in total.
    budget.reused_calls, budget.reused_usd = 1, 0.03
    assert budget.usage_mark()["calls"] == 1 and budget.usage_mark()["usd"] == pytest.approx(0.02)
    assert budget.usage_mark()["total_usd"] == pytest.approx(0.05)


@pytest.mark.parametrize(
    ("max_parallel", "default", "components", "expected"),
    [
        (4, True, 9, 3),
        (4, True, 10, 4),
        (4, True, 6, 3),
        (4, True, None, 4),
        (4, False, 9, 4),
        (2, True, 9, 2),
        (8, True, 9, 8),
    ],
)
def test_the_default_works_in_groups_of_three_only_where_components_divide_by_three(
    max_parallel, default, components, expected
):
    """A set value always applies; only the unchanged default narrows to three for an even split."""
    budget = AssessmentBudget(1.0, 0.05, 100, 3600, max_parallel=max_parallel, parallel_is_default=default)
    budget.components = components
    assert budget.workers == expected


def test_model_calls_over_the_runs_parallelism_wait_for_a_running_call():
    """Jobs inside a component share the parallelism of the components: at most `workers` calls run at once."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from runtime.multi_repo_discovery import DiscoveryBudget

    budget = AssessmentBudget(10.0, 0.05, 100, 600, max_parallel=2, parallel_is_default=False)
    lock, running, peak = threading.Lock(), [0], [0]

    class Host:
        def invoke(self, *args):
            with lock:
                running[0] += 1
                peak[0] = max(peak[0], running[0])
            time.sleep(0.05)
            with lock:
                running[0] -= 1
            return HostReply({}, 0.01)

    with ThreadPoolExecutor(max_workers=6) as pool:
        replies = list(
            pool.map(lambda _: budget.invoke(lambda ceiling: Host(), "s", "p", {}, 60, lambda: False), range(6))
        )
    assert len(replies) == 6 and budget.calls == 6
    assert peak[0] == 2
    # Without a limit the same six calls overlap more.
    free = DiscoveryBudget(1, 0.05, 20, 600)
    peak[0] = running[0] = 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda _: free.invoke(lambda ceiling: Host(), "s", "p", {}, 60, lambda: False), range(6)))
    assert peak[0] > 2
