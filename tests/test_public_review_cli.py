"""Offline review handoff, context, and artifact-boundary contracts."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pty
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from appsec_analyzer import cli, review
from appsec_analyzer.review_context import read_context
from tests.test_public_export_cli import _bundle

ROOT = Path(__file__).resolve().parents[1]


def test_capabilities_distinguish_external_review_from_preview():
    capability = cli._capabilities()["review"]
    assert capability["model_calls"] and capability["external_session"]
    assert capability["preview_model_calls"] is False
    assert capability["qualified"] is False


def _assessment(tmp_path, adapter="claude-cli", **kwargs):
    path = _bundle(tmp_path, **kwargs)
    state_path = path / ".assessment-state.json"
    state = json.loads(state_path.read_text())
    if adapter is not None:
        state["operator_profile"] = {
            "schema_version": 1,
            "definition_sha256": "d" * 64,
            "models": {},
            "adapter": adapter,
        }
    state_path.write_text(json.dumps(state))
    return path


@pytest.mark.parametrize("adapter,assistant", [("claude-cli", "claude"), ("codex-cli", "codex")])
def test_preview_uses_recorded_assistant_and_bundled_skill(tmp_path, monkeypatch, capsys, adapter, assistant):
    source = _assessment(tmp_path, adapter)
    before = {p.name: p.read_bytes() for p in source.iterdir()}
    monkeypatch.setattr(review.subprocess, "run", lambda *a, **kw: pytest.fail("preview must not launch"))
    assert cli.main(["review", str(source), "--preview"]) == 0
    output = capsys.readouterr().out
    assert f"Review with {assistant}" in output
    assert (ROOT / "skills/review-assessment/SKILL.md").read_text() in output
    assert str(source / "security-assessment.yaml") in output
    assert "query_argv" in output and "review_context.py" in output
    assert "assessment budget does not carry over" in output
    assert {p.name: p.read_bytes() for p in source.iterdir()} == before


@pytest.mark.parametrize("adapter", [None, "openai", "lite", "bedrock", "codex", ["claude-cli"]])
def test_api_and_unknown_adapters_require_selection(tmp_path, adapter, capsys):
    source = _assessment(tmp_path, adapter)
    assert cli.main(["review", str(source), "--preview"]) == 2
    assert "--with" in capsys.readouterr().err
    assert cli.main(["review", str(source), "--with", "codex", "--preview"]) == 0


def test_explicit_selection_overrides_recorded_assistant(tmp_path, capsys):
    source = _assessment(tmp_path)
    assert cli.main(["review", str(source), "--with", "codex", "--preview"]) == 0
    assert "Review with codex" in capsys.readouterr().out


def test_interactive_selection_accepts_only_fixed_assistants(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "codex")
    assert review._select({}, None, interactive=True) == "codex"
    monkeypatch.setattr("builtins.input", lambda _: "codex --dangerously-bypass-approvals-and-sandbox")
    with pytest.raises(review.ReviewError, match="no coding assistant"):
        review._select({}, None, interactive=True)


@pytest.mark.parametrize("assistant", ["claude", "codex"])
def test_launch_passes_context_without_export_or_shell(tmp_path, assistant):
    source = _assessment(tmp_path, assistant + "-cli")
    # Shell metacharacters must remain path data, even across the real exec.
    renamed = tmp_path / "assessment $(touch INJECTED) 'quoted'"
    source.rename(renamed)
    source = renamed
    (source / ".claude").mkdir()
    (source / ".claude/settings.json").write_text('{"hooks":{"SessionStart":[]}}')
    (source / "AGENTS.md").write_text("UNTRUSTED STARTUP INSTRUCTIONS")
    before = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    binary = tmp_path / "bin"
    binary.mkdir()
    record = binary / "invocation.json"
    executable = binary / assistant
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        f"pathlib.Path({str(record)!r}).write_text(json.dumps({{"
        "'argv':sys.argv[1:], 'cwd':os.getcwd(),"
        "'disable_mds':os.environ.get('CLAUDE_CODE_DISABLE_CLAUDE_MDS')}))\n"
        "sys.exit(7)\n"
    )
    executable.chmod(0o700)
    master, slave = pty.openpty()
    try:
        process = subprocess.run(
            [sys.executable, "-m", "appsec_analyzer.cli", "review", str(source)],
            cwd=ROOT,
            env={**os.environ, "PATH": str(binary), "PYTHONPATH": str(ROOT)},
            stdin=slave,
            stdout=slave,
            stderr=slave,
            timeout=25,
            check=False,
        )
    finally:
        os.close(slave)
        os.close(master)
    assert process.returncode == 7
    launch = json.loads(record.read_text())
    args = launch["argv"]
    assert args[-2] == "--"
    assert not any("dangerously" in arg or "disableAllHooks" in arg or "hooks=false" in arg for arg in args[:-1])
    assert str(source / "security-assessment.yaml") in args[-1]
    assert "UNTRUSTED STARTUP INSTRUCTIONS" not in args[-1]
    assert (ROOT / "skills/review-assessment/SKILL.md").read_text() in args[-1]
    work = Path(launch["cwd"])
    assert work != source and work != ROOT and not work.exists()
    if assistant == "codex":
        assert args[args.index("--sandbox") + 1] == "read-only"
        assert args[args.index("--ask-for-approval") + 1] == "on-request"
        assert "project_root_markers=[]" in args
    else:
        assert args[args.index("--permission-mode") + 1] == "plan"
        assert args[args.index("--setting-sources") + 1] == "user"
        assert launch["disable_mds"] == "1"
    assert not (ROOT / "INJECTED").exists()
    assert {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()} == before


@pytest.mark.parametrize(
    "defect",
    [
        "changed",
        "symlink",
        "hardlink",
        "fifo",
        "incomplete",
        "invalid-model",
        "public",
        "secret",
        "bad-name",
    ],
)
def test_invalid_assessment_never_launches(tmp_path, monkeypatch, defect):
    marker = "AKIA" + "A" * 16
    source = _assessment(tmp_path, markdown=marker if defect == "secret" else "# Saved report\n")
    model = source / "security-assessment.yaml"
    state_path = source / ".assessment-state.json"
    state = json.loads(state_path.read_text())
    if defect == "changed":
        model.write_text("changed")
    elif defect in ("symlink", "hardlink"):
        external = tmp_path / "external"
        model.rename(external)
        if defect == "symlink":
            model.symlink_to(external)
        else:
            os.link(external, model)
    elif defect == "fifo":
        model.unlink()
        os.mkfifo(model)
    elif defect == "incomplete":
        state["status"] = "running"
    elif defect == "invalid-model":
        model.write_text("meta: {}\n")
        state["deliverables"][model.name] = hashlib.sha256(model.read_bytes()).hexdigest()
    elif defect == "bad-name":
        state["deliverables"]["../external"] = "a" * 64
    elif defect == "public":
        source.chmod(0o755)
    state_path.write_text(json.dumps(state))
    monkeypatch.setattr(review.subprocess, "run", lambda *a, **kw: pytest.fail("invalid data must not launch"))
    with pytest.raises(review.ReviewError, match="private, completed") as error:
        review.review_assessment(str(source))
    assert marker not in str(error.value)
    with pytest.raises((ValueError, OSError)):
        read_context(str(source))


def test_state_from_newer_analyzer_names_the_cause_and_never_launches(tmp_path, monkeypatch):
    source = _assessment(tmp_path)
    state_path = source / ".assessment-state.json"
    state = json.loads(state_path.read_text())
    state["field_from_a_newer_analyzer"] = 1
    state_path.write_text(json.dumps(state))
    monkeypatch.setattr(review.subprocess, "run", lambda *a, **kw: pytest.fail("incompatible data must not launch"))
    with pytest.raises(review.ReviewError, match="not valid for this Analyzer version.*update the installed"):
        review.review_assessment(str(source))


def _newer_result(tmp_path):
    source = _assessment(tmp_path)
    state_path = source / ".assessment-state.json"
    state = json.loads(state_path.read_text())
    state["field_from_a_newer_analyzer"] = 1
    state_path.write_text(json.dumps(state))
    return source


def _update_setup(monkeypatch, *, answer="y", returncode=0, source="https://example.test/appsec-analyzer.git"):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode)

    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(review, "_pipx_source", lambda: source)
    monkeypatch.setattr(review.shutil, "which", lambda name, **kw: "/usr/bin/pipx")
    monkeypatch.setattr(review.subprocess, "run", run)
    monkeypatch.setattr("builtins.input", lambda *a: answer)
    return calls


def test_yes_updates_installation_and_does_not_start_review(tmp_path, monkeypatch, capsys):
    source = _newer_result(tmp_path)
    calls = _update_setup(monkeypatch)
    with pytest.raises(review.ReviewError, match="was updated, run the command again"):
        review.review_assessment(str(source))
    assert calls == [["/usr/bin/pipx", "upgrade", "appsec-analyzer"]]
    assert "https://example.test/appsec-analyzer.git" in capsys.readouterr().out


def test_failed_update_reports_failure(tmp_path, monkeypatch):
    source = _newer_result(tmp_path)
    _update_setup(monkeypatch, returncode=1)
    with pytest.raises(review.ReviewError, match="the update failed"):
        review.review_assessment(str(source))


@pytest.mark.parametrize("answer", ["", "n", "no", "maybe"])
def test_anything_but_yes_installs_nothing(tmp_path, monkeypatch, answer):
    source = _newer_result(tmp_path)
    calls = _update_setup(monkeypatch, answer=answer)
    with pytest.raises(review.ReviewError, match="not valid for this Analyzer version"):
        review.review_assessment(str(source))
    assert calls == []


def test_end_of_input_installs_nothing(tmp_path, monkeypatch):
    source = _newer_result(tmp_path)
    calls = _update_setup(monkeypatch)

    def closed(*args):
        raise EOFError

    monkeypatch.setattr("builtins.input", closed)
    with pytest.raises(review.ReviewError, match="not valid for this Analyzer version"):
        review.review_assessment(str(source))
    assert calls == []


@pytest.mark.parametrize("case", ["ci", "no-terminal", "not-pipx", "no-pipx-executable"])
def test_no_offer_when_it_cannot_or_must_not_be_made(tmp_path, monkeypatch, case):
    source = _newer_result(tmp_path)
    calls = _update_setup(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("must not ask"))
    if case == "ci":
        monkeypatch.setenv("CI", "true")
    elif case == "no-terminal":
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    elif case == "not-pipx":
        monkeypatch.setattr(review, "_pipx_source", lambda: None)
    else:
        monkeypatch.setattr(review.shutil, "which", lambda name, **kw: None)
    with pytest.raises(review.ReviewError, match="not valid for this Analyzer version"):
        review.review_assessment(str(source))
    assert calls == []


def test_no_offer_for_a_result_that_is_not_from_a_newer_analyzer(tmp_path, monkeypatch):
    source = _assessment(tmp_path)
    state_path = source / ".assessment-state.json"
    state = json.loads(state_path.read_text())
    state["status"] = "running"
    state_path.write_text(json.dumps(state))
    calls = _update_setup(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("must not ask"))
    with pytest.raises(review.ReviewError, match="private, completed") as error:
        review.review_assessment(str(source))
    assert "update the installed" not in str(error.value)
    assert calls == []


def _pipx_prefix(tmp_path, monkeypatch, main_package):
    (tmp_path / "pipx_metadata.json").write_text(json.dumps({"main_package": main_package}))
    monkeypatch.setattr(sys, "prefix", str(tmp_path))


def test_pipx_source_hides_credentials_in_the_recorded_url(tmp_path, monkeypatch):
    _pipx_prefix(
        tmp_path,
        monkeypatch,
        {
            "package": "appsec-analyzer",
            "package_or_url": "git+https://user:token@example.test/team/appsec-analyzer.git",
        },
    )
    shown = review._pipx_source()
    assert shown == "https://example.test/team/appsec-analyzer.git"
    assert "token" not in shown


@pytest.mark.parametrize(
    "main_package",
    [
        {"package": "nordlicht-appsec", "package_or_url": "git+https://example.test/org.git"},
        {"package": "appsec-analyzer", "package_or_url": ""},
        {"package": "appsec-analyzer"},
        "not-a-dict",
    ],
)
def test_pipx_source_ignores_other_installations(tmp_path, monkeypatch, main_package):
    _pipx_prefix(tmp_path, monkeypatch, main_package)
    assert review._pipx_source() is None


def test_pipx_source_is_none_without_pipx_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    assert review._pipx_source() is None


def test_noninteractive_review_never_starts_assistant(tmp_path, monkeypatch, capsys):
    source = _assessment(tmp_path)
    monkeypatch.setattr(review.subprocess, "run", lambda *a, **kw: pytest.fail("must not launch"))
    assert cli.main(["review", str(source)]) == 2
    assert "interactive terminal" in capsys.readouterr().err


def test_missing_assistant_is_actionable(tmp_path, monkeypatch):
    source = _assessment(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(review.shutil, "which", lambda *a, **kw: None)
    with pytest.raises(review.ReviewError, match="install and sign in"):
        review.review_assessment(str(source))


@pytest.mark.parametrize("marker", [".git", ".codex", ".claude", "AGENTS.md", "CLAUDE.md"])
def test_ancestor_configuration_is_excluded_by_native_launch_options(tmp_path, marker):
    parent = tmp_path / "project"
    parent.mkdir()
    (parent / marker).mkdir()
    work = parent / "fresh"
    work.mkdir(mode=0o700)
    review._validate_working_directory(work, tmp_path / "assessment")
    codex = review._arguments("codex", "codex", "review")
    assert "project_root_markers=[]" in codex and "project_doc_max_bytes=0" in codex
    claude = review._arguments("claude", "claude", "review")
    assert claude[claude.index("--setting-sources") + 1] == "user"
    assert "--strict-mcp-config" in claude
    assert not list(work.iterdir())


def test_query_returns_finding_and_linked_mitigations(tmp_path):
    source = _assessment(tmp_path)
    overview = read_context(str(source))
    finding = overview["findings"][0]
    result = read_context(str(source), identifier=finding["id"])
    assert result["found"] and result["finding"]["id"] == finding["id"]
    assert result["finding"]["evidence_check"] == finding["evidence_check"]
    assert result["mitigations"]
    assert not read_context(str(source), identifier="F-99999")["found"]
    filtered = read_context(str(source), severity=finding["severity"])
    assert filtered["findings"]
    assert all(f["severity"] == finding["severity"] for f in filtered["findings"])
    # No admission to private sidecars through the helper.
    (source / ".requirements.yaml").symlink_to(tmp_path / "missing-private-catalog")
    assert read_context(str(source)) == overview
    result = subprocess.run(
        [sys.executable, str(ROOT / "appsec_analyzer/review_context.py"), str(source), "--id", finding["id"]],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["finding"]["id"] == finding["id"]


def test_completion_offers_review(tmp_path):
    from orchestrator.orchestration_controller import _print_completion
    from renderers.term_style import Style

    source = _assessment(tmp_path)
    outcome = {
        "output": str(source),
        "repositories": ["example"],
        "calls": 2,
        "spent_usd": 0.1,
        "deliverables": {"security-assessment.yaml": "unused", "security-assessment.md": "unused"},
    }
    output = io.StringIO()
    _print_completion(outcome, "1s", Style.for_stream(output), stream=output)
    assert shlex.join(["appsec-analyzer", "review", str(source)]) in output.getvalue()


def test_legacy_artifact_names_remain_reviewable(tmp_path, capsys):
    source = _assessment(tmp_path)
    state_path = source / ".assessment-state.json"
    state = json.loads(state_path.read_text())
    for old in list(state["deliverables"]):
        new = old.replace("security-assessment", "threat-model")
        (source / old).rename(source / new)
        state["deliverables"][new] = state["deliverables"].pop(old)
    state_path.write_text(json.dumps(state))
    assert cli.main(["review", str(source), "--preview"]) == 0
    assert str(source / "threat-model.yaml") in capsys.readouterr().out
    assert read_context(str(source))["findings"]


def test_combined_context_keeps_repository_identity(tmp_path):
    import yaml

    from tests.test_multi_repo_builder import build_assessment_model, inputs

    scope, kwargs = inputs(tmp_path)
    model, _ = build_assessment_model(scope, **kwargs)
    source = _assessment(tmp_path, extra={"security-assessment.yaml": yaml.safe_dump(model).encode()})
    facts = read_context(str(source))
    locations = [f["location"] for f in facts["findings"]]
    assert len(set(locations)) == 2
    assert all("app.py" in location for location in locations)


def test_change_during_preparation_prevents_launch(tmp_path, monkeypatch):
    source = _assessment(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    def resolve(*args, **kwargs):
        (source / "security-assessment.md").write_text("changed after admission")
        return "/usr/bin/false"

    monkeypatch.setattr(review.shutil, "which", resolve)
    monkeypatch.setattr(review.subprocess, "run", lambda *a, **kw: pytest.fail("must revalidate before launch"))
    with pytest.raises(review.ReviewError, match="unchanged valid artifacts"):
        review.review_assessment(str(source))


@pytest.mark.parametrize("failure", ["timeout", "interrupt", "os-error"])
def test_launch_failures_preserve_assessment(tmp_path, monkeypatch, failure):
    source = _assessment(tmp_path)
    before = {p.name: p.read_bytes() for p in source.iterdir()}
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(review.shutil, "which", lambda *a, **kw: "/usr/bin/false")
    directories = []

    def run(*args, **kwargs):
        directories.append(kwargs["cwd"])
        assert kwargs["timeout"] == review.SESSION_TIMEOUT
        if failure == "timeout":
            raise subprocess.TimeoutExpired("private diagnostic", review.SESSION_TIMEOUT)
        if failure == "interrupt":
            raise KeyboardInterrupt
        raise OSError("private diagnostic")

    monkeypatch.setattr(review.subprocess, "run", run)
    expected = KeyboardInterrupt if failure == "interrupt" else review.ReviewError
    with pytest.raises(expected) as error:
        review.review_assessment(str(source))
    assert "private diagnostic" not in str(error.value)
    assert all(not p.exists() for p in directories)
    assert {p.name: p.read_bytes() for p in source.iterdir()} == before
