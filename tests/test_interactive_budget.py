"""Only explicit operator input may increase an owned assessment's budget."""

import io
import os
import select
import termios
import threading
from types import SimpleNamespace

import pytest
from runtime import interactive_budget as interactive
from runtime.analyst_host import HostCancelled, HostReply, TransportError
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import AssessmentBudget


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def terminal(monkeypatch):
    """Yield the keyboard side of a pseudo-terminal that serves as stdin."""
    master, slave = os.openpty()
    try:
        with os.fdopen(slave, "r") as stdin:
            monkeypatch.setattr(interactive.sys, "stdin", stdin)
            yield master
    finally:
        os.close(master)


@pytest.mark.parametrize(
    "earlier,typed,approved",
    [
        (b"", b"2.50\n", [2.5]),
        (b"", b"\x04", []),
        # Keys pressed while the run was progressing neither decline nor approve.
        (b"\n", b"2.50\n", [2.5]),
        (b"9.00\n", b"\x04", []),
    ],
)
def test_prompt_reads_only_the_answer_typed_after_the_question(monkeypatch, terminal, earlier, typed, approved):
    amounts = []
    state = SimpleNamespace(budget=AssessmentBudget(1, 0.05, 10, 60), state={}, approve_budget_increase=amounts.append)
    prompt = interactive.BudgetPrompt(state, report=lambda text: None, pause=lambda value: None, role_labels={})
    if earlier:
        os.write(terminal, earlier)
        assert select.select([interactive.sys.stdin], [], [], 5)[0]
    flush = termios.tcflush

    def type_after_question(fd, queue):
        flush(fd, queue)
        os.write(terminal, typed)

    monkeypatch.setattr(termios, "tcflush", type_after_question)
    prompt(lambda: False)
    assert amounts == approved


@pytest.mark.parametrize(
    "blocked",
    [None, "CI", "GITHUB_ACTIONS", "JENKINS_URL", "stdin", "stderr", "quiet", "non_interactive", "json_output"],
)
def test_only_an_interactive_non_ci_terminal_can_prompt(monkeypatch, blocked):
    for name in interactive._CI_MARKERS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(interactive.sys, "stdin", io.StringIO() if blocked == "stdin" else Terminal())
    monkeypatch.setattr(interactive.sys, "stderr", io.StringIO() if blocked == "stderr" else Terminal())
    options = {}
    if blocked in interactive._CI_MARKERS:
        monkeypatch.setenv(blocked, "true")
    elif blocked in {"quiet", "non_interactive", "json_output"}:
        options[blocked] = True
    assert interactive.can_prompt(**options) == (blocked is None)


@pytest.mark.parametrize(
    "answer,approved",
    [
        ("2.50\n", 2.5),
        ("\n", None),
        ("", None),
        ("yes\n", None),
        ("0.5\n", None),
        ("1\n", None),
        ("nan\n", None),
        ("inf\n", None),
        ("1e6\n", None),
        ("2; command\n", None),
    ],
)
def test_prompt_requires_a_higher_literal_usd_amount(monkeypatch, answer, approved):
    budget = AssessmentBudget(1, 0.05, 10, 60)
    amounts, messages, paused = [], [], []
    state = SimpleNamespace(budget=budget, state={}, approve_budget_increase=amounts.append)
    prompt = interactive.BudgetPrompt(state, report=messages.append, pause=paused.append, role_labels={})
    monkeypatch.setattr(prompt, "_readline", lambda stop: answer)
    prompt(lambda: False)
    assert amounts == ([] if approved is None else [approved])
    assert paused == [True, False]
    if approved is None:
        assert prompt.declined
        count = len(messages)
        prompt(lambda: False)
        assert len(messages) == count


def test_cancellation_while_awaiting_input_never_approves(terminal):
    budget = AssessmentBudget(1, 0.05, 10, 60)
    amounts, paused = [], []
    state = SimpleNamespace(budget=budget, state={}, approve_budget_increase=amounts.append)
    prompt = interactive.BudgetPrompt(state, report=lambda text: None, pause=paused.append, role_labels={})
    with pytest.raises(HostCancelled):
        prompt(lambda: True)
    assert not amounts and paused == [True, False]


def test_budget_question_waits_for_running_calls_and_blocks_new_admission():
    budget = AssessmentBudget(0.05, 0.05, 10, 60)
    started, finish, asking, answer = (threading.Event() for _ in range(4))
    errors, completed = [], []

    class Host:
        def invoke(self, *args):
            if not started.is_set():
                started.set()
                assert finish.wait(5)
            return HostReply({"answer": "ok"}, 0.05)

    def authorize(stop):
        assert budget._inflight == 0 and budget.spent_usd == pytest.approx(0.05)
        asking.set()
        assert answer.wait(5)
        budget.max_usd = 0.20

    budget.on_budget_increase = authorize

    def invoke():
        try:
            budget.invoke(lambda ceiling: Host(), "s", "p", {}, 20, lambda: False)
            completed.append(True)
        except BaseException as exc:
            errors.append(exc)

    first, second, third = (threading.Thread(target=invoke) for _ in range(3))
    first.start()
    assert started.wait(5)
    second.start()
    assert not asking.wait(0.05)
    finish.set()
    assert asking.wait(5)
    third.start()
    assert budget.calls == 1  # no new reservation while confirmation is pending
    answer.set()
    for worker in (first, second, third):
        worker.join(5)
        assert not worker.is_alive()
    assert not errors and len(completed) == 3
    assert budget.spent_usd == pytest.approx(0.15)


def test_money_cannot_override_call_or_time_limits():
    budget = AssessmentBudget(0.05, 0.05, 1, 60)
    budget.spent_usd = 0.05
    budget.calls = 1
    asked = []
    budget.on_budget_increase = asked.append
    with pytest.raises(ExchangeError):
        budget.invoke(lambda ceiling: None, "s", "p", {}, 20, lambda: False)
    assert asked == []


def test_settled_host_budget_failure_needs_approval_before_retry():
    budget = AssessmentBudget(0.05, 0.05, 10, 60)
    attempts, approved = [], []

    class Host:
        def invoke(self, *args):
            attempts.append(True)
            if len(attempts) == 1:
                raise TransportError("limit", reason="error_max_budget_usd", usd=0.03)
            assert approved
            return HostReply({"ok": True}, 0.02)

    def authorize(stop):
        assert budget._inflight == 0
        approved.append(True)
        budget.max_usd = 0.20

    budget.on_budget_increase = authorize
    budget.invoke(lambda ceiling: Host(), "s", "p", {}, 20, lambda: False)
    assert len(attempts) == 2 and len(approved) == 1
    assert budget.spent_usd == pytest.approx(0.05)


def test_time_spent_answering_does_not_extend_or_charge_the_job(monkeypatch):
    from runtime import multi_repo_discovery as discovery

    now = [100.0]
    monkeypatch.setattr(discovery.time, "monotonic", lambda: now[0])
    budget = AssessmentBudget(0.05, 0.05, 10, 60)
    budget.spent_usd = 0.05

    def authorize(stop):
        budget.max_usd = 1.0
        now[0] += 2

    budget.on_budget_increase = authorize
    with pytest.raises(discovery.AdmissionTimeout):
        budget.invoke(lambda ceiling: pytest.fail("expired job must not start"), "s", "p", {}, 1, lambda: False)
    assert budget.calls == 0 and budget.spent_usd == 0.05 and not budget.retries
