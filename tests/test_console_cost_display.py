"""Cost visibility is presentation only, across API and subscription assessments."""

from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest
from orchestrator import assessment_test_cases
from orchestrator import orchestration_controller as controller

from appsec_analyzer.assessment.console import _AssessmentConsole, api_billing, usage_text, usd_at_api_prices


@pytest.mark.parametrize(
    "adapter", [None, "claude-cli", "openai", "lite", "bedrock", "gateway", "codex-cli", "copilot-cli"]
)
@pytest.mark.parametrize("api_key", [False, True])
def test_billing_defaults_and_explicit_override(monkeypatch, adapter, api_key):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-oauth-token")
    if api_key:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-api-key")
    expected = adapter in ("openai", "lite", "bedrock", "gateway") or (adapter in (None, "claude-cli") and api_key)
    cfg = {"host_profile": {"kind": adapter}}
    assert api_billing(adapter) is expected
    assert controller._assessment_show_costs(SimpleNamespace(show_costs=False), cfg) is expected
    assert controller._assessment_show_costs(SimpleNamespace(show_costs=True), cfg) is True
    assert usd_at_api_prices(adapter) is (adapter in (None, "claude-cli") and not api_key)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ({"loggedIn": True, "authMethod": "oauth_token", "apiProvider": "firstParty"}, False),
        (
            {
                "loggedIn": True,
                "authMethod": "oauth_token",
                "apiProvider": "firstParty",
                "apiKeySource": "apiKeyHelper",
            },
            True,
        ),
        ({"loggedIn": True, "authMethod": "third_party", "apiProvider": "bedrock"}, True),
        ([], False),
    ],
)
def test_claude_cli_credentials_decide_api_billing_without_environment_key(monkeypatch, status, expected):
    import json
    import subprocess

    from appsec_analyzer.assessment import console

    console._claude_cli_bills_api.cache_clear()
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 0, stdout=json.dumps(status).encode())
    )
    assert console.api_billing("claude-cli") is expected
    assert console.usd_at_api_prices("claude-cli") is (not expected)


def test_auth_token_in_the_environment_means_api_billing(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "synthetic-token")
    assert api_billing("claude-cli") is True
    assert usd_at_api_prices("claude-cli") is False


def test_unavailable_claude_cli_status_means_subscription(monkeypatch):
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    assert api_billing("claude-cli") is False


@pytest.mark.parametrize("api_prices", [False, True])
@pytest.mark.parametrize("compact", [False, True])
def test_claude_subscription_header_values_the_limit_at_api_prices(api_prices, compact):
    ns = controller._assessment_argument_parser().parse_args(["--repo", "/r", "--output", "/o", "--hard-budget", "5"])
    budget = controller._assessment_budget(ns)
    budget.api_prices = api_prices
    rows = dict(controller._assessment_intro(ns, budget, "standard", "Models: m1", "P", compact=compact))
    limit = "USD 5.00" if compact else "model calls stop at $5.00"
    assert rows["Budget"].startswith(f"{limit} of subscription usage at API prices" if api_prices else limit)
    assert ("API prices" in rows["Budget"]) is api_prices


def test_direct_api_host_keeps_default_cost_display(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    observed = []
    original = _AssessmentConsole.__init__

    def initialize(console, *args, **kwargs):
        observed.append(kwargs["show_costs"])
        original(console, *args, **kwargs)

    class StopBeforeSources(Exception):
        pass

    def stop(roots):
        raise StopBeforeSources

    monkeypatch.setattr(_AssessmentConsole, "__init__", initialize)
    monkeypatch.setattr(controller, "_assessment_preflight", stop)
    with pytest.raises(StopBeforeSources):
        controller.assess_repositories(
            ["--repo", "/r", "--output", str(tmp_path / "out"), "--hard-budget", "1", "--non-interactive"],
            api_profile=SimpleNamespace(kind="openai"),
        )
    assert observed == [True]


@pytest.mark.parametrize("enabled", [False, True])
def test_public_flag_reaches_structured_request_without_changing_configuration(tmp_path, monkeypatch, enabled):
    from appsec_analyzer import cli, hosts
    from tests.test_public_scan_cli import _repo

    repo = _repo(tmp_path / "repo")
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    seen = []

    def assess(request, **kwargs):
        seen.append(request)
        assert request.options.show_costs is enabled
        assert ("--show-costs" in request.arguments) is enabled
        assert "--show-costs" not in request.configuration
        assert request.namespace().show_costs is enabled
        return 0

    monkeypatch.setattr(controller, "assess_main", assess)
    arguments = ["assess", "--repo", str(repo), "--profile", "claude", "--skip-preflight", "--non-interactive"]
    assert cli.main(arguments + (["--show-costs"] if enabled else [])) == 0
    assert len(seen) == 1


def test_usage_hides_only_costs_and_never_invents_unavailable_amounts():
    before = {"calls": 1, "usd": 1.0, "itemised": 1, "tokens": 100}
    after = {"calls": 3, "usd": 1.5, "total_usd": 2.0, "itemised": 3, "tokens": 2100}
    assert usage_text(before, after, True, show_costs=False) == "2k tokens"
    assert usage_text(before, after, True, show_costs=True) == "≈ USD 0.50 (USD 2.00 in total) · 2k tokens"
    assert usage_text(before, {**after, "itemised": 2}, show_costs=False) == ""
    unknown = {**after, "usd": None, "total_usd": None}
    assert usage_text({**before, "usd": None}, unknown, show_costs=True) == "USD cost unavailable · 2k tokens"
    assert usage_text(before, before, show_costs=True) == ""


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_phase_progress_respects_cost_visibility_and_keeps_tokens(verbose, enabled):
    lines = []
    console = _AssessmentConsole(verbose, lines.append, clock=lambda: 100.0, show_costs=enabled)
    mark = {"calls": 0, "usd": 0.0, "total_usd": 0.0, "itemised": 0, "tokens": 0}
    console.usage_mark = lambda: dict(mark)
    console.step("Matching abuse cases")
    mark.update(calls=1, usd=0.5, total_usd=0.5, itemised=1, tokens=1200)
    console.close()
    text = "\n".join(lines)
    assert ("≈ USD 0.50" in text) is enabled
    assert "1k tokens" in text


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("spent", [None, 1.5])
def test_completion_preserves_counts_and_accounting(enabled, spent):
    outcome = {
        "show_costs": enabled,
        "spent_usd": spent,
        "calls": 5,
        "reused_calls": 1,
        "reused_usd": 0.2 if spent is not None else None,
        "usage": {
            "models": {
                "m1": {"calls": 2, "usd": 0.6 if spent is not None else None, "input": 1200},
                "m2": {"calls": 1, "input": 300},
            },
            "unitemised_calls": 2,
            "unitemised_usd": 0.7 if spent is not None else None,
        },
    }
    original = copy.deepcopy(outcome)
    rows = controller._completion_cost_rows(outcome)
    text = "\n".join(row[1] for row in rows)
    assert rows[0][0] == ("Cost" if enabled else "Usage")
    assert "5 model calls" in text and "2k tokens" in text and "1 call reused" in text
    assert ("USD" in text) is enabled
    if enabled and spent is None:
        assert "USD cost unavailable" in text
        assert "USD 0.00" not in text
    if enabled and spent is not None:
        assert "≈ USD 1.50" in text and "USD 0.20 of the total" in text
    assert outcome == original


@pytest.mark.parametrize("available", [1.0, 3.0])
def test_verification_estimate_without_costs_keeps_budget_coverage(available):
    from tests.test_verification_budget import _Budget, _Jobs

    jobs = _Jobs(_Budget(0.5, available))
    text = assessment_test_cases._budget_statement(jobs, 4, ["AuthZ"], 1, show_costs=False)
    assert "4 jobs" in text and "USD" not in text
    assert ("marked incomplete" in text) is (available < 2)
    assert bool(jobs.notes) is (available < 2)
    assert all("USD" not in note for note in jobs.notes)


def test_retry_and_resume_details_hide_costs_without_hiding_work():
    retries = [{"reason": "server_error", "paid": True, "usd": 0.5}]
    assert "USD" not in controller._assessment_retry_warning(retries, show_costs=False)
    assert "USD 0.50" in controller._assessment_retry_warning(retries, show_costs=True)
    budget = SimpleNamespace(subscription=False, calls=3, spent_usd=0.5)
    state = SimpleNamespace(
        resume=True, state={"started_at": 100, "expires_at": 200}, worked_before=50, runtime_changed=False
    )
    _, text = controller._assessment_continuation(state, budget, show_costs=False)
    assert "3 model calls used" in text and "deadline" in text and "USD" not in text
    # A new run that reuses an unfinished run's steps counts what they cost, in model calls when costs are hidden.
    reused = SimpleNamespace(
        resume=False,
        reused_run_started=100,
        reused_run_calls=6,
        reused_run_usd=0.5,
        resume_blocker=None,
        worked_before=50,
    )
    key, text = controller._assessment_continuation(reused, budget, show_costs=False)
    assert key == "Earlier run" and "6 model calls, counted toward the limit" in text and "USD" not in text
    reused.resume_blocker = "the assessment settings changed since it started"
    key, text = controller._assessment_continuation(reused, budget, show_costs=False)
    assert key == "Resumed" and "6 model calls used" in text and "USD" not in text


@pytest.mark.parametrize("api_prices", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_budget_skip_details_keep_coverage_and_respect_cost_visibility(enabled, api_prices):
    budget = SimpleNamespace(subscription=False, calls=3, spent_usd=0.5, max_usd=5.0, api_prices=api_prices)
    gaps = [{"role": "ms_renderer", "selector": "summary"}]
    text = controller._budget_skip_info(gaps, [], budget, show_costs=enabled)
    assert "did not run" in text and "deterministic replacements are used" in text
    used = "used at API prices" if api_prices else "spent"
    assert (f"USD 0.50 of 5.00 {used}" in text) is enabled
    if not enabled:
        assert "3 model calls" in text and "USD" not in text


@pytest.mark.parametrize("enabled", [False, True])
def test_saved_console_summary_respects_cost_visibility(tmp_path, enabled):
    from runtime.assessment_state import WORK_NAME

    directory = tmp_path / WORK_NAME
    directory.mkdir()
    (tmp_path / "security-assessment.yaml").write_text("threats: []\n")
    outcome = {
        "output": str(tmp_path),
        "repositories": ["solo"],
        "deliverables": [],
        "calls": 3,
        "spent_usd": 1.5,
        "show_costs": enabled,
    }
    controller._save_closing(outcome, "1m")
    summary = (directory / controller.ASSESSMENT_SUMMARY_NAME).read_text()
    assert ("USD 1.50" in summary) is enabled
    assert "3 model calls" in summary
    assert outcome["spent_usd"] == 1.5


@pytest.mark.parametrize("api_key,override,expected", [(False, False, False), (False, True, True), (True, False, True)])
def test_offline_assessment_applies_visibility_and_keeps_real_accounting(
    tmp_path, monkeypatch, capsys, api_key, override, expected
):
    from tests.test_multi_repo_assessment import _assess

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    if api_key:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-api-key")
    extra = ("--no-pdf", "--non-interactive", *(["--show-costs"] if override else []))
    outcome, _, _ = _assess(tmp_path, monkeypatch, ("solo",), extra, progress=None)
    assert outcome["show_costs"] is expected
    assert outcome["spent_usd"] > 0 and outcome["calls"] > 0
    text = capsys.readouterr().err
    assert ("≈ USD" in text) is expected
    assert "USD 5.00" in text  # The authorized limit stays visible in subscription mode too.
    rows = controller._completion_cost_rows(outcome)
    assert rows[0][0] == ("Cost" if expected else "Usage")


@pytest.mark.parametrize(
    ("harness", "shown"),
    [
        ("claude-cli", "Claude CLI"),
        ("codex-cli", "Codex CLI"),
        ("lite", "LiteLLM gateway"),
        ("bedrock", "Amazon Bedrock API"),
    ],
)
@pytest.mark.parametrize("compact", [False, True])
def test_header_names_the_model_host_before_billing(harness, shown, compact):
    ns = controller._assessment_argument_parser().parse_args(["--repo", "/r", "--output", "/o", "--hard-budget", "5"])
    ns.model_host = harness
    budget = controller._assessment_budget(ns)
    keys = [k for k, _ in controller._assessment_intro(ns, budget, "standard", "Models: m1", "P", compact=compact)]
    rows = dict(controller._assessment_intro(ns, budget, "standard", "Models: m1", "P", compact=compact))
    assert rows["Host"] == shown
    assert keys.index("Host") + 1 == keys.index("Billing")


def test_header_without_a_known_host_has_no_host_row():
    ns = controller._assessment_argument_parser().parse_args(["--repo", "/r", "--output", "/o", "--hard-budget", "5"])
    rows = dict(controller._assessment_intro(ns, controller._assessment_budget(ns), "standard", "Models: m1", "P"))
    assert "Host" not in rows
