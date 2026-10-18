"""The public score summary preserves evidence limits while separating decisions."""

from __future__ import annotations

import io
import json
from copy import deepcopy

import pytest

from appsec_analyzer.cli import _engine_imports

_engine_imports()
from renderers.term_style import ANSI_RE, Style

from appsec_analyzer.scoring import render_text


@pytest.fixture
def result():
    return {
        "verdict": "scored",
        "score": 25,
        "repo": "/workspace/service",
        "checks_total": 15,
        "checks_applicable": 7,
        "findings_total": 4,
        "findings": {"critical": 1, "high": 3, "medium": 0},
        "unscored_findings": {"critical": 1},
        "excluded_findings": {"low": 2},
        "categories": [
            {"label": "Authentication", "score": 80, "checks": 5, "findings": 1},
            {"label": "Data Exposure", "score": None, "checks": 0, "findings": 1},
            {"label": "Output Handling", "score": 25, "checks": 2, "findings": 2},
        ],
        "top_findings": [
            {"severity": "critical", "title": "Untrusted command execution", "count": 1, "location": "worker.py:17"},
            {"severity": "high", "title": "Query construction", "count": 3, "location": "service.py:42"},
        ],
        "scanner_status": dict.fromkeys(
            ("route-inventory", "architecture-coverage", "config-iac", "source-auth"), "complete"
        ),
        "source": {"head": "a" * 40, "dirty": False, "captured_files": 17},
        "warnings": [],
    }


def test_summary_orders_score_coverage_ranked_areas_and_findings_without_mutating_result(result):
    before = deepcopy(result)
    text = render_text(result)
    assert text.startswith("Security Score\n")
    assert "  25 / 100  (limited quick check)\n" in text
    assert "Not a full security analysis; no exposure context." in text
    assert "7/15 applicable checks" in text and "4/4 scanners complete" in text
    assert "4 (unverified) · 1 critical · 3 high · 0 medium" in text
    assert text.index("Coverage:") < text.index("Areas · weakest first") < text.index("Top findings · unverified")
    assert text.index("Output Handling") < text.index("Authentication") < text.index("Data Exposure")
    assert "worker.py:17" in text and "service.py:42" in text
    assert "service.py:42  · 3 occurrences" in text
    assert "worker.py:17\n\n   2." in text
    assert "Source: aaaaaaaaaaaa (clean) · 17 captured files" in text
    assert result == before


def test_unscored_critical_findings_are_prominent_even_with_high_headline(result):
    result["score"] = 100
    text = render_text(result)
    assert "100 / 100" in text
    assert "Findings without a scored baseline: 1 critical" in text
    assert text.index("Findings without a scored baseline:") < text.index("Areas · weakest first")
    assert "Findings excluded by severity policy: 2 low" in text
    row = next(line for line in text.splitlines() if "Data Exposure" in line)
    assert row.split()[-3:] == ["unscored", "0", "1"]


@pytest.mark.parametrize("verdict", ["undetermined", "incomplete"])
def test_unfinished_or_unsupported_scan_cannot_display_numeric_area_scores(result, verdict):
    result.update(verdict=verdict, score=None, reason="Insufficient coverage or incomplete scanner output")
    if verdict == "incomplete":
        result["scanner_status"]["source-auth"] = "failed"
        result["warnings"] = ["source-auth: failed"]
    text = render_text(result)
    assert f"  {verdict}  (limited quick check)" in text and result["reason"] in text
    assert "Areas · unscored" in text and "weakest first" not in text
    assert "25/100" not in text and "80/100" not in text
    assert "Untrusted command execution" in text
    if verdict == "incomplete":
        assert "3/4 scanners complete" in text and "Warnings\n  - source-auth: failed" in text


def test_summary_retains_limitations_when_no_findings_are_reported(result):
    result.update(findings_total=0, findings={"critical": 0, "high": 0, "medium": 0}, top_findings=[])
    text = render_text(result)
    assert "No scored-severity findings reported by the completed scanners; this does not establish safety." in text
    assert "Compare only commits of this repository with matching scoring and coverage settings." in text


def test_summary_handles_no_applicable_areas_and_hides_internal_metadata(result):
    result.update(verdict="undetermined", score=None, reason="No applicable checks", categories=[])
    result["source"]["excluded_files"] = [{"path": ".env", "reason": "sensitive-name"}]
    text = render_text(result)
    assert "No applicable scoring areas." in text
    assert ".env" not in text and "Source policy:" not in text and "Source revision:" not in text


def test_summary_repository_identity_omits_url_credentials_and_parameters(result):
    result["repo"] = "https://test-user:artificial@git.example/team/service.git?key=artificial#artificial"
    text = render_text(result)
    assert "Repository: https://git.example/team/service.git" in text
    assert "artificial" not in text and "test-user" not in text


@pytest.mark.parametrize("truecolor", [False, True])
def test_colored_summary_preserves_all_plain_content_and_alignment(result, truecolor):
    before = deepcopy(result)
    text = render_text(result, style=Style(True, truecolor))
    assert "\x1b[" in text
    assert ANSI_RE.sub("", text) == render_text(result)
    assert "\x1b[38;2;" in text if truecolor else "\x1b[31m" in text
    assert result == before


def test_finding_blocks_wrap_full_titles_and_separate_locations_and_repetition_counts(result):
    title = (
        "JWT verify call missing algorithms allowlist with explicit verification of the permitted signature algorithm"
    )
    result["top_findings"][0]["title"] = title
    text = render_text(result, width=60)
    findings = text.split("Top findings · unverified\n\n", 1)[1].split("\nSource:", 1)[0]
    first, second = findings.strip().split("\n\n", 1)
    title_lines = first.splitlines()[:-1]
    reconstructed = " ".join(
        [title_lines[0].split("CRITICAL", 1)[1].strip(), *(line.strip() for line in title_lines[1:])]
    )
    assert reconstructed == title and "…" not in first
    assert first.endswith("      worker.py:17")
    assert "service.py:42  · 3 occurrences" in second
    assert "1 occurrences" not in findings
    assert all(len(line) <= 60 for line in findings.splitlines())


@pytest.mark.parametrize(
    "terminal, environment, colored",
    [
        (True, {}, True),
        (False, {}, False),
        (True, {"NO_COLOR": "1"}, False),
        (True, {"TERM": "dumb"}, False),
        (False, {"FORCE_COLOR": "1"}, True),
        (True, {"NO_COLOR": "1", "FORCE_COLOR": "1"}, False),
    ],
)
def test_score_cli_uses_shared_color_policy_for_stdout_only(result, monkeypatch, terminal, environment, colored):
    from appsec_analyzer import cli, scoring

    class Stream(io.StringIO):
        def isatty(self):
            return terminal

    for name in ("NO_COLOR", "FORCE_COLOR", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm")
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(scoring, "score_repository", lambda *a, **kw: deepcopy(result))
    stream = Stream()
    monkeypatch.setattr(cli.sys, "stdout", stream)
    assert cli.main(["score", "/workspace/service"]) == 0
    output = stream.getvalue()
    assert ("\x1b[" in output) is colored
    assert ANSI_RE.sub("", output).startswith("Security Score\n")
    assert "25 / 100" in output and "Query construction" in output


@pytest.mark.parametrize("flag", ["--json", "--yaml"])
def test_structured_score_never_gets_color_even_on_forced_color_terminal(result, monkeypatch, flag):
    import yaml

    from appsec_analyzer import cli, scoring

    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setattr(scoring, "score_repository", lambda *a, **kw: deepcopy(result))
    stream = Terminal()
    monkeypatch.setattr(cli.sys, "stdout", stream)
    assert cli.main(["score", "/workspace/service", flag]) == 0
    output = stream.getvalue()
    assert "\x1b" not in output
    assert (json.loads(output) if flag == "--json" else yaml.safe_load(output)) == result


def test_progress_status_colors_preserve_plain_content_and_column_alignment(monkeypatch):
    from renderers.term_style import Style

    from appsec_analyzer.score_progress import ScoreProgress

    monkeypatch.setattr("appsec_analyzer.score_progress.time.monotonic", lambda: 100.0)
    outputs = []
    for enabled in (False, True):
        stream = io.StringIO()
        with ScoreProgress(stream, style=Style(enabled)) as progress:
            progress("Discovering application routes...")
            progress("Scanner result: route-inventory: complete")
            progress("Checking architecture coverage...")
            progress("Scanner result: architecture-coverage: failed")
            progress("Scanning configuration and infrastructure...")
            progress("Scanner result: config-iac: invalid")
            progress("Scanning source code...")
            progress("Scanner result: source-auth: missing")
            progress("Checking source consistency...")
            progress.finish("cancelled")
        outputs.append(stream.getvalue())
    assert ANSI_RE.sub("", outputs[1]) == outputs[0]
    assert "\x1b[36m[running]" in outputs[1]
    assert "\x1b[32m[done]" in outputs[1]
    assert "\x1b[31m[failed]" in outputs[1] and "\x1b[31m[invalid]" in outputs[1]
    assert "\x1b[33m[missing]" in outputs[1] and "\x1b[33m[cancelled]" in outputs[1]


@pytest.mark.parametrize("terminal", [False, True])
def test_progress_and_result_choose_colors_from_their_own_streams(result, monkeypatch, terminal):
    from appsec_analyzer import cli, scoring

    class Output(io.StringIO):
        def isatty(self):
            return terminal

    class Progress(io.StringIO):
        def isatty(self):
            return not terminal

    for name in ("NO_COLOR", "FORCE_COLOR", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setattr(scoring, "score_repository", lambda *a, **kw: deepcopy(result))
    stdout, stderr = Output(), Progress()
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)
    assert cli.main(["score", "/workspace/service"]) == 0
    assert ("\x1b[32m[done]" in stderr.getvalue()) is (not terminal)
    assert ("\x1b[" in stdout.getvalue()) is terminal


@pytest.mark.parametrize(
    "selection, plain, prefix, name",
    [
        ("/workspace/juice-shop", "/workspace/juice-shop", "/workspace/", "juice-shop"),
        (
            "https://test-user:artificial@git.example/team/service.git?key=artificial",
            "https://git.example/team/service.git",
            "https://git.example/team/",
            "service.git",
        ),
        ("git@git.example:service.git", "git.example:service.git", "git.example:", "service.git"),
    ],
)
def test_repository_emphasis_is_inline_preserves_identity_and_hides_url_credentials(
    result, selection, plain, prefix, name
):
    from appsec_analyzer.score_progress import ScoreProgress

    style = Style(True)
    stream = io.StringIO()
    with ScoreProgress(stream, repository=selection, style=style) as progress:
        progress.finish("failed")
    header = stream.getvalue().splitlines()[0]
    assert ANSI_RE.sub("", header) == f"Calculating security score for {plain}"
    assert style(prefix, "muted") + style(name, "accent", "bold") in header
    result["repo"] = selection
    summary = render_text(result, style=style)
    repository_line = next(line for line in summary.splitlines() if line.startswith("Repository:"))
    assert ANSI_RE.sub("", repository_line) == f"Repository: {plain}"
    assert style(prefix, "muted") + style(name, "accent", "bold") in repository_line
    assert "artificial" not in header + summary and "test-user" not in header + summary
