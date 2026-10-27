"""REQ-002: `assess` asks for the depth only when a person at a terminal chose none."""

from __future__ import annotations

import io
import subprocess

import pytest


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    from appsec_analyzer import cli, hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller
    from runtime import interactive_budget

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    started = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda args, **kwargs: started.append(list(args)) or 0)

    def call(*options, typed="\n", terminal=True, profile="claude"):
        monkeypatch.setattr(
            interactive_budget, "can_prompt", lambda **kwargs: terminal and not kwargs["non_interactive"]
        )
        monkeypatch.setattr("sys.stdin", io.StringIO(typed))
        code = cli.main(["assess", "--repo", str(tmp_path), "--profile", profile, *options])
        depth = None
        if started:
            depth = started[-1][started[-1].index("--assessment-depth") + 1]
        return code, depth, capsys.readouterr().err

    call.started = started
    return call


def test_enter_picks_standard_and_the_question_names_cost_runtime_and_coverage(run):
    code, depth, err = run()
    assert (code, depth) == (0, "standard")
    for depth_name in ("quick", "standard", "thorough"):
        assert depth_name in err
    assert err.count("USD 20") == 3
    assert "Cost, runtime" in err and "lowest, shortest" in err and "highest, longest" in err
    assert "survey only" in err and "architect review" in err


@pytest.mark.parametrize("api_key", [False, True])
def test_a_claude_subscription_values_each_limit_at_api_prices(run, monkeypatch, api_key):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    if api_key:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-api-key")
    err = run()[2]
    assert err.count("at API prices") == (0 if api_key else 1)
    assert ("Limit: the most subscription usage a run may take, valued at API prices" in err) is not api_key
    assert ("Limit: the most a run may cost" in err) is api_key


@pytest.mark.parametrize(
    "typed, expected",
    [("1\n", "quick"), ("quick\n", "quick"), ("3\n", "thorough"), (" Thorough \n", "thorough"), ("2\n", "standard")],
)
def test_number_or_name_picks_that_depth(run, typed, expected):
    assert run(typed=typed)[:2] == (0, expected)


def test_a_depth_on_the_command_line_is_not_asked_again(run):
    code, depth, err = run("--assessment-depth", "quick", typed="3\n")
    assert (code, depth) == (0, "quick")
    assert "Depth (" not in err


@pytest.mark.parametrize("option", [["--non-interactive"], ["--quiet"]])
def test_modes_that_must_not_wait_keep_standard_without_a_question(run, option):
    code, depth, err = run(*option, typed="3\n")
    assert (code, depth) == (0, "standard") and "Depth (" not in err


def test_resuming_an_assessment_does_not_ask_for_a_new_depth(run):
    _, _, err = run("--resume", typed="3\n")
    assert "Depth (" not in err


def test_without_a_terminal_standard_runs_without_a_question(run):
    code, depth, err = run(terminal=False, typed="3\n")
    assert (code, depth) == (0, "standard") and "Depth (" not in err


def test_a_scan_profile_that_sets_the_depth_is_not_overruled(run, tmp_path_factory):
    profile = tmp_path_factory.mktemp("profiles") / "quick-scan.yaml"
    profile.write_text("schema_version: 1\nmodel_profile: claude\nassessment_depth: quick\n")
    code, depth, err = run(profile=str(profile), typed="3\n")
    assert (code, depth) == (0, "quick") and "Depth (" not in err


def test_a_scan_profile_without_a_depth_still_asks(run, tmp_path_factory):
    profile = tmp_path_factory.mktemp("profiles") / "plain-scan.yaml"
    profile.write_text("schema_version: 1\nmodel_profile: claude\n")
    assert run(profile=str(profile), typed="3\n")[:2] == (0, "thorough")


@pytest.mark.parametrize("typed", ["", "9\nx\n\x00\n"])
def test_cancelled_or_invalid_answers_start_nothing(run, typed):
    code, depth, err = run(typed=typed)
    assert code == 2 and run.started == []
    assert "nothing was started" in err


def test_the_typed_answer_is_never_echoed(run):
    _, _, err = run(typed="secret-token\nsecret-token\nsecret-token\n")
    assert "secret-token" not in err
