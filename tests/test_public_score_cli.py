"""Public score behavior, source isolation, failure handling and Git retrieval."""

from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from appsec_analyzer import cli, resource_root
from tests.test_remote_repositories import transport as transport

cli._engine_imports()
from appsec_analyzer import scoring

ROOT = Path(__file__).resolve().parents[1]


def _git(root, *args):
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.js").write_text(
        "const express = require('express');\n"
        "const session = require('express-session');\n"
        "const jwt = require('jsonwebtoken');\n"
        "const cors = require('cors');\n"
        "const app = express();\n"
        "app.use(session({cookie: {httpOnly: false, secure: false}}));\n"
        "app.use(cors({origin: '*', credentials: true}));\n"
        "app.get('/records/:id', (req, res) => {\n"
        "  jwt.decode(req.headers.authorization);\n"
        "  db.query('SELECT * FROM records WHERE id = ' + req.params.id);\n"
        "  res.send(req.query.message);\n"
        "});\n"
    )
    (root / "package.json").write_text(json.dumps({"dependencies": {"express": "4.0.0"}}))
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
    return root


def _validate(document):
    schema = yaml.safe_load((resource_root() / "schemas/security-score.schema.yaml").read_text())
    Draft202012Validator(schema).validate(document)


@pytest.mark.parametrize("flag", ["--json", "--yaml", None])
def test_score_runs_without_model_and_preserves_target(repo, flag):
    before = {p.relative_to(repo): p.read_bytes() for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts}
    args = [sys.executable, "-m", "appsec_analyzer.cli", "score", str(repo)]
    if flag:
        args.append(flag)
    env = {**os.environ, "PYTHONPATH": str(ROOT), "APPSEC_CLAUDE_EXECUTABLE": "/nonexistent/claude"}
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        env.pop(key, None)
    result = subprocess.run(args, cwd=repo, env=env, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr + result.stdout
    assert result.stderr.startswith(f"Calculating security score for {repo}\n\n  [1/3] Repository\n")
    assert "[2/3] Security checks" in result.stderr and "[3/3] Result" in result.stderr
    assert "Completed in" in result.stderr
    assert "\x1b" not in result.stderr and "\r" not in result.stderr
    assert "Cloning" not in result.stderr
    for step in scoring.SCANNER_PROGRESS.values():
        assert re.search(r"\[done\]\s+" + re.escape(step.removesuffix("...")) + r"\s+\d+\.\ds", result.stderr)
    if flag:
        doc = json.loads(result.stdout) if flag == "--json" else yaml.safe_load(result.stdout)
        _validate(doc)
        assert doc["verdict"] == "scored" and 0 <= doc["score"] <= 100
        assert doc["scanner_status"] == dict.fromkeys(scoring.security_score.SCANNER_SCHEMAS, "complete")
        assert doc["interface_version"] == 1
        assert doc["assessment_status"] == "not_run" and doc["evidence_status"] == "unverified"
        assert doc["source"]["head"] == _git(repo, "rev-parse", "HEAD").strip()
        assert doc["source"]["dirty"] is False
        assert doc["comparability"]["source_policy"] == scoring.SOURCE_POLICY
        assert doc["top_findings"]
        assert "excluded_files" not in doc["source"]
        _validate({**doc, "source": {**doc["source"], "excluded_files": []}})
    else:
        assert "Security Score" in result.stdout
        assert "Not a full security analysis" in result.stdout
        assert "Areas · weakest first" in result.stdout and "Top findings · unverified" in result.stdout
        assert "Source:" in result.stdout and "Source policy:" not in result.stdout
        assert "Excluded files:" not in result.stdout
    after = {p.relative_to(repo): p.read_bytes() for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts}
    assert before == after
    assert not _git(repo, "status", "--porcelain")


def test_startup_is_visible_before_runtime_preparation_even_with_piped_stderr(repo):
    harness = (
        "import sys\nfrom appsec_analyzer import cli\n"
        "original = cli._engine_imports\n"
        "def wait_for_operator():\n"
        "    sys.stdin.readline()\n"
        "    original()\n"
        "cli._engine_imports = wait_for_operator\n"
        f"raise SystemExit(cli.main(['score', {str(repo)!r}, '--json']))\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", harness],
        cwd=repo,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            assert selector.select(timeout=5), "Startup progress was buffered while runtime preparation waited"
        assert process.stderr.readline() == f"Calculating security score for {repo}\n"
        stdout, stderr = process.communicate(input="\n", timeout=45)
        assert process.returncode == 0, stderr
        assert json.loads(stdout)["verdict"] == "scored"
        assert "[3/3] Result" in stderr and "Completed in" in stderr
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def test_scanner_progress_is_visible_before_each_scanner_starts(repo, monkeypatch, capsys):
    from appsec_analyzer import score_progress

    class Terminal:
        def isatty(self):
            return True

        def write(self, text):
            sys.stderr.write(text)

        def flush(self):
            sys.stderr.flush()

    monkeypatch.setenv("TERM", "xterm")
    renderer = score_progress.ScoreProgress(Terminal())
    monkeypatch.setattr(score_progress, "ScoreProgress", lambda **kwargs: renderer)
    original = scoring.security_score._run
    started = []

    def run(argv, warnings, label):
        output = capsys.readouterr()
        assert not output.out
        if not started:
            assert "[2/3] Security checks" in output.err
        assert score_progress._STEPS[scoring.SCANNER_PROGRESS[label]][1] in output.err
        started.append(label)
        return original(argv, warnings, label)

    monkeypatch.setattr(scoring.security_score, "_run", run)
    assert cli.main(["score", str(repo), "--json"]) == 0
    assert started == list(scoring.SCANNER_PROGRESS)
    output = capsys.readouterr()
    assert json.loads(output.out)["verdict"] == "scored"
    assert "[3/3] Result" in output.err and "Completed in" in output.err
    assert not renderer._thread.is_alive()


def test_readable_score_omits_excluded_file_details(repo, capsys):
    (repo / ".env").write_text("private file that must not appear in the score")
    (repo / "internal-link.js").symlink_to(repo / "app.js")
    assert cli.main(["score", str(repo)]) == 0
    output = capsys.readouterr()
    assert "Security Score" in output.out
    assert "Excluded files" not in output.out
    for value in (".env", "internal-link.js"):
        assert value not in output.out + output.err


def test_sparse_score_is_undetermined_with_findings_visible(repo, capsys):
    (repo / "app.js").unlink()
    (repo / "service.py").write_text(
        'import jwt\njwt.decode(token, algorithms=["HS256"], options={"verify_signature": False})\n'
    )
    assert cli.main(["score", str(repo), "--json"]) == 2
    doc = json.loads(capsys.readouterr().out)
    _validate(doc)
    assert doc["verdict"] == "undetermined" and doc["score"] is None
    assert doc["top_findings"] and doc["findings_total"]


def test_failed_required_scanner_withholds_score(repo, monkeypatch, capsys):
    original = scoring.security_score._run
    monkeypatch.setattr(
        scoring.security_score,
        "_run",
        lambda argv, warnings, label: False if label == "source-auth" else original(argv, warnings, label),
    )
    assert cli.main(["score", str(repo), "--json"]) == 1
    output = capsys.readouterr()
    doc = json.loads(output.out)
    assert "Incomplete scan after" in output.err and "Completed in" not in output.err
    _validate(doc)
    assert doc["verdict"] == "incomplete" and doc["score"] is None
    assert doc["scanner_status"]["source-auth"] == "failed"
    assert doc["warnings"]
    assert re.search(r"\[failed\]\s+Scanning source code", output.err)
    assert not re.search(r"\[done\]\s+Scanning source code", output.err)


def test_snapshot_masks_secrets_excludes_private_files_and_cannot_run_hooks(repo, tmp_path, monkeypatch, capsys):
    artificial = "AKIA" + "A" * 16
    (repo / "credentials.py").write_text(f'cloud_access_key = "{artificial}"\n')
    (repo / ".env").write_text("must not be opened")
    marker = tmp_path / "executed"
    (repo / ".claude").mkdir()
    (repo / ".claude/settings.json").write_text(
        json.dumps({"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": f"touch {marker}"}]}]}})
    )
    _git(repo, "config", "core.fsmonitor", f"touch {marker}")
    original = scoring.security_score.collect
    snapshots = []

    def collect(snapshot, work, **kwargs):
        snapshots.append(snapshot)
        assert snapshot != repo and repo not in snapshot.parents
        assert snapshot.stat().st_mode & 0o777 == 0o700
        assert not (snapshot / ".git").exists() and not (snapshot / ".env").exists()
        masked = snapshot / "credentials.py"
        assert artificial not in masked.read_text()
        assert masked.stat().st_mode & 0o777 == 0o600
        return original(snapshot, work, **kwargs)

    monkeypatch.setattr(scoring.security_score, "collect", collect)
    assert cli.main(["score", str(repo), "--json"]) == 0
    output = capsys.readouterr().out
    doc = json.loads(output)
    assert artificial not in output
    assert "excluded_files" not in doc["source"] and ".env" not in output
    assert not marker.exists()
    assert all(not path.exists() for path in snapshots)


def test_escaping_link_is_rejected_before_scanners(repo, tmp_path, monkeypatch, capsys):
    outside = tmp_path / "private.py"
    outside.write_text("private data")
    (repo / "linked.py").symlink_to(outside)
    monkeypatch.setattr(scoring.security_score, "collect", lambda *a, **kw: pytest.fail("unsafe source scanned"))
    assert cli.main(["score", str(repo), "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and "symlink outside" in output.err
    assert "private data" not in output.err


def test_changed_source_is_not_published(repo, monkeypatch, capsys):
    original = scoring.security_score.collect

    def collect(*args, **kwargs):
        result = original(*args, **kwargs)
        (repo / "app.js").write_text("changed while scanning\n")
        return result

    monkeypatch.setattr(scoring.security_score, "collect", collect)
    assert cli.main(["score", str(repo), "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and "source state changed" in output.err


def test_scanner_cannot_cite_outside_snapshot(repo, monkeypatch, capsys):
    original = scoring.security_score.collect

    def collect(*args, **kwargs):
        rules, findings, warnings, statuses = original(*args, **kwargs)
        findings.append({"file": "../private.py"})
        return rules, findings, warnings, statuses

    monkeypatch.setattr(scoring.security_score, "collect", collect)
    assert cli.main(["score", str(repo), "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and "outside the admitted snapshot" in output.err


@pytest.mark.usefixtures("transport")
@pytest.mark.parametrize("failure", [False, True, "cancelled"])
def test_score_remote_uses_real_isolated_checkout_and_cleans_up(monkeypatch, capsys, failure):
    from runtime import remote_repositories

    original = remote_repositories.clone
    checkouts = []

    def clone(remote, root):
        output = capsys.readouterr()
        assert output.err.startswith(
            "Calculating security score for ssh://git.example/team/ledger.git\n\n  [1/3] Repository\n"
        )
        assert re.search(r"\[running\]\s+Cloning Git repository\s+0\.0s\n$", output.err)
        assert not output.out
        checkouts.append(root)
        original(remote, root)

    monkeypatch.setattr(remote_repositories, "clone", clone)
    if failure:

        def fail(*args, **kwargs):
            if failure == "cancelled":
                raise KeyboardInterrupt
            raise OSError("artificial confidential scanner detail")

        monkeypatch.setattr(scoring.security_score, "collect", fail)
    url = "ssh://git@git.example/team/ledger.git"
    expected = 130 if failure == "cancelled" else (1 if failure else 2)
    assert cli.main(["score", url, "--json"]) == expected
    output = capsys.readouterr()
    assert len(checkouts) == 1 and not checkouts[0].exists()
    if failure == "cancelled":
        assert not output.out and "Cancelled by user after" in output.err
        assert "Traceback" not in output.err and "Completed in" not in output.err
    elif failure:
        assert not output.out and "could not be computed" in output.err
        assert "artificial confidential scanner detail" not in output.err
    else:
        doc = json.loads(output.out)
        _validate(doc)
        assert doc["repo"] == url
        assert "[2/3] Security checks" in output.err and "Completed in" in output.err
        assert doc["source"]["head"] and doc["source"]["captured_files"] == 2


@pytest.mark.parametrize(
    "selection",
    [
        "https://user:artificial@git.example/team/a.git",
        "https://127.0.0.1/team/a.git",
        "file:///tmp/a",
        "/nonexistent/score-repo",
        "",
    ],
)
def test_score_rejects_invalid_sources_without_exposing_credentials(selection, capsys):
    assert cli.main(["score", selection, "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and output.err
    assert "artificial" not in output.err and "Traceback" not in output.err


@pytest.mark.parametrize(
    "selection, expected",
    [
        ("/home/operator/juice-shop", "/home/operator/juice-shop"),
        ("https://git.example/team/service.git", "https://git.example/team/service.git"),
        (
            "https://test-user:artificial@git.example/team/service.git?token=artificial#artificial",
            "https://git.example/team/service.git",
        ),
        ("ssh://test-user@git.example:2222/team/service.git", "ssh://git.example:2222/team/service.git"),
        ("git@git.example:team/service.git", "git.example:team/service.git"),
        ("git@git.example:service.git", "git.example:service.git"),
        ("https://test-user:artificial@git.example:bad/team/service.git", "selected repository"),
        ("/tmp/source\nforged\x1b[2J", "selected repository"),
        ("/tmp/source\u202eforged", "selected repository"),
        ("https://[::bad", "selected repository"),
        ("test-user:artificial@git.example:team/service.git", "selected repository"),
    ],
)
def test_score_startup_identifies_repository_without_credentials_or_terminal_injection(selection, expected):
    import io

    from appsec_analyzer.score_progress import ScoreProgress

    stream = io.StringIO()
    with ScoreProgress(stream, repository=selection) as progress:
        progress.finish("failed")
    header = stream.getvalue().splitlines()[0]
    assert header == f"Calculating security score for {expected}"
    assert "artificial" not in stream.getvalue() and "test-user" not in stream.getvalue()
    assert "\x1b" not in stream.getvalue() and "\r" not in stream.getvalue()


def test_score_startup_expands_relative_selection_safely(tmp_path, monkeypatch):
    from appsec_analyzer.score_progress import _repository_label

    monkeypatch.chdir(tmp_path)
    assert _repository_label(".") == str(tmp_path)
    assert len(_repository_label("/tmp/" + "a" * 500)) == 240
    injected = tmp_path / "source\nforged"
    injected.mkdir()
    monkeypatch.chdir(injected)
    assert _repository_label(".") == "selected repository"


def test_temporary_storage_inside_repository_is_rejected(repo, monkeypatch, capsys):
    before = set(repo.iterdir())
    monkeypatch.setattr(scoring.tempfile, "tempdir", str(repo))
    assert cli.main(["score", str(repo)]) == 1
    assert "Temporary storage must be outside" in capsys.readouterr().err
    assert set(repo.iterdir()) == before


def test_source_admission_limits_apply_before_scanning(repo, monkeypatch, capsys):
    from runtime import multi_repo_scope

    monkeypatch.setattr(multi_repo_scope, "MAX_TOTAL_BYTES", 4)
    monkeypatch.setattr(scoring.security_score, "collect", lambda *a, **kw: pytest.fail("oversized source scanned"))
    assert cli.main(["score", str(repo), "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and "aggregate admission limit" in output.err


def test_terminal_output_cannot_render_repository_control_characters(repo, monkeypatch, capsys):
    original = scoring.security_score.top_findings

    def top(findings, **kwargs):
        rows = original(findings, **kwargs)
        rows[0]["location"] = "file.js\x1b[2J\nforged\u202efile.txt\u2066"
        return rows

    monkeypatch.setattr(scoring.security_score, "top_findings", top)
    assert cli.main(["score", str(repo)]) == 0
    output = capsys.readouterr().out
    assert "\x1b" not in output and "\nforged" not in output
    assert "\u202e" not in output and "\u2066" not in output


@pytest.mark.parametrize(
    "arguments, expected", [(["--help"], 0), ([], 2), ([".", "--json", "--yaml"], 2), ([".", "--budget", "5"], 2)]
)
def test_score_parser_exits_before_source_access(arguments, expected, monkeypatch):
    monkeypatch.setattr(
        scoring, "score_repository", lambda *a, **kw: pytest.fail("source accessed during argument parsing")
    )
    with pytest.raises(SystemExit) as exc:
        cli.main(["score", *arguments])
    assert exc.value.code == expected


def test_score_is_discoverable_without_model(capsys):
    assert cli.main(["capabilities"]) == 0
    assert json.loads(capsys.readouterr().out)["score"] == {
        "available": True,
        "model_calls": False,
        "scoring_version": 2,
    }


def test_missing_runtime_is_an_operational_error_without_internal_details(monkeypatch, capsys):
    def missing():
        raise RuntimeError("artificial internal resource path")

    monkeypatch.setattr(cli, "_engine_imports", missing)
    assert cli.main(["score", ".", "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and "resources are unavailable" in output.err
    assert "artificial internal" not in output.err


def test_terminal_progress_refreshes_while_work_is_waiting_and_stops_on_error(monkeypatch):
    import io
    import threading

    from appsec_analyzer.score_progress import ScoreProgress

    class Terminal(io.StringIO):
        def __init__(self):
            super().__init__()
            self.refreshed = threading.Event()
            self.frames = 0

        def isatty(self):
            return True

        def write(self, text):
            self.frames += 1
            if self.frames >= 3:
                self.refreshed.set()
            return super().write(text)

    monkeypatch.setenv("TERM", "xterm")
    terminal = Terminal()
    renderer = ScoreProgress(terminal)
    with pytest.raises(KeyboardInterrupt), renderer:
        assert terminal.refreshed.wait(timeout=2), "No terminal refresh during a long-running phase"
        renderer("Scanning source code...")
        raise KeyboardInterrupt
    assert "Cancelled by user after" in terminal.getvalue()
    assert "Completed in" not in terminal.getvalue()
    assert not renderer._thread.is_alive()


@pytest.mark.parametrize("dumb_terminal", [False, True])
def test_plain_progress_keeps_every_step_and_reports_measured_durations(monkeypatch, dumb_terminal):
    import io

    from appsec_analyzer import score_progress

    now = [100.0]
    monkeypatch.setattr(score_progress.time, "monotonic", lambda: now[0])

    class Stream(io.StringIO):
        def isatty(self):
            return dumb_terminal

    monkeypatch.setenv("TERM", "dumb" if dumb_terminal else "xterm")
    stream = Stream()
    with score_progress.ScoreProgress(stream) as renderer:
        renderer("Cloning Git repository...")
        now[0] = 102.5
        renderer("Reading repository sources...")
        renderer("Discovering application routes...")
        renderer("Scanning source code...")
        now[0] = 109.0
        renderer("Calculating security score...")
        now[0] = 110.5
        renderer.finish("incomplete")
    output = stream.getvalue()
    assert re.search(r"\[done\]\s+Cloning Git repository\s+2\.5s", output)
    assert re.search(r"\[done\]\s+Scanning source code\s+6\.5s", output)
    assert re.search(r"\[done\]\s+Calculating security score\s+1\.5s", output)
    assert "\n\n  [2/3] Security checks\n" in output and "\n\n  [3/3] Result\n" in output
    assert "Incomplete scan after 10.5s" in output and "Completed in" not in output
    assert "\x1b" not in output and "\r" not in output
    assert output.index("Discovering application routes") < output.index("Scanning source code")


@pytest.mark.parametrize("terminal", [True, False])
def test_progress_retains_scanner_outcomes_and_never_marks_failed_checks_done(monkeypatch, terminal):
    import io

    from renderers.term_style import ANSI_RE

    from appsec_analyzer.score_progress import ScoreProgress

    class Stream(io.StringIO):
        def isatty(self):
            return terminal

    monkeypatch.setenv("TERM", "xterm")
    stream = Stream()
    with ScoreProgress(stream) as renderer:
        renderer("Preparing source scan...")
        renderer("Discovering application routes...")
        renderer("Scanner result: route-inventory: complete")
        renderer("Checking architecture coverage...")
        renderer("Scanner result: architecture-coverage: failed")
        renderer("Scanning configuration and infrastructure...")
        renderer("Scanner result: config-iac: invalid")
        renderer("Scanning source code...")
        renderer("Scanner result: source-auth: missing")
        renderer("untrusted forged step\nnot a status")
        renderer("Calculating security score...")
        renderer.finish("incomplete")
    output = ANSI_RE.sub("", stream.getvalue())
    expected = {
        "done": "Discovering application routes",
        "failed": "Checking architecture coverage",
        "invalid": "Scanning configuration and infrastructure",
        "missing": "Scanning source code",
    }
    for status, detail in expected.items():
        assert len(re.findall(r"\[" + status + r"\]\s+" + detail, output)) == 1
        if status != "done":
            assert not re.search(r"\[done\]\s+" + detail, output)
    assert "untrusted forged" not in output
    assert "Incomplete scan after" in output
    assert "\n\n  [2/3] Security checks\n" in output
    if terminal:
        assert not renderer._thread.is_alive()


@pytest.mark.parametrize("stage", ["startup", "redaction", "scanner", "running-scanner", "revalidation"])
def test_sigint_cancels_without_traceback_or_result_and_removes_temporary_files(repo, tmp_path, stage):
    scratch = tmp_path / "temporary"
    scratch.mkdir(mode=0o700)
    ready, notify = os.pipe()
    harness = (
        "import os, sys\nfrom appsec_analyzer import cli\n"
        "cli._engine_imports()\n"
        "from appsec_analyzer import scoring\n"
        "from runtime import multi_repo_scope\n"
        "def wait(*args, **kwargs):\n"
        f"    os.write({notify}, b'ready')\n"
        "    sys.stdin.readline()\n"
    )
    hooks = {
        "startup": "cli._engine_imports = wait",
        "redaction": "multi_repo_scope._masked_bytes = wait",
        "scanner": "scoring.security_score._run = wait",
        "revalidation": "multi_repo_scope.AssessmentScope.verify_unchanged = wait",
    }
    pid_file = tmp_path / "scanner-pid"
    if stage == "running-scanner":
        child_code = (
            "import os, time\nfrom pathlib import Path\n"
            f"Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
            f"os.write({notify}, b'ready')\ntime.sleep(60)\n"
        )
        harness += (
            "original_run = scoring.security_score._run\n"
            "original_process = scoring.security_score.subprocess.run\n"
            "def run_scanner(argv, warnings, label):\n"
            f"    scoring.security_score.subprocess.run = lambda *a, **kw: original_process(*a, pass_fds=({notify},), **kw)\n"
            f"    return original_run(['-c', {child_code!r}], warnings, label)\n"
            "scoring.security_score._run = run_scanner\n"
        )
    else:
        harness += hooks[stage] + "\n"
    harness += f"raise SystemExit(cli.main(['score', {str(repo)!r}, '--json']))\n"
    process = subprocess.Popen(
        [sys.executable, "-c", harness],
        cwd=repo,
        env={**os.environ, "PYTHONPATH": str(ROOT), "TMPDIR": str(scratch)},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(notify,),
        text=True,
    )
    os.close(notify)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(ready, selectors.EVENT_READ)
            assert selector.select(timeout=15), f"Score did not reach {stage}"
        assert os.read(ready, 5) == b"ready"
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 130, stderr
        assert not stdout
        assert "Cancelled by user after" in stderr
        assert "Traceback" not in stderr and "KeyboardInterrupt" not in stderr and "Completed in" not in stderr
        assert not list(scratch.iterdir())
        assert not _git(repo, "status", "--porcelain")
        if stage == "running-scanner":
            with pytest.raises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)
    finally:
        os.close(ready)
        if process.poll() is None:
            process.kill()
            process.communicate()


def test_directory_without_git_is_scored_and_named(repo, capsys):
    shutil.rmtree(repo / ".git")
    assert cli.main(["score", str(repo), "--json"]) == 0
    source = json.loads(capsys.readouterr().out)["source"]
    assert source["without_git"] is True and source["captured_files"] == 2
    assert cli.main(["score", str(repo)]) == 0
    assert "Source: directory without Git" in capsys.readouterr().out
    assert not (repo / ".git").exists()


@pytest.mark.parametrize(
    "kind, expected",
    [
        ("missing", "Selected repository does not exist"),
        ("file", "not a directory"),
        ("damaged-git", "Cannot read the Git checkout"),
        ("empty-git", "no readable commit"),
        ("subdirectory", "top-level Git checkout rather than a subdirectory"),
    ],
)
def test_local_source_errors_explain_recovery_before_scanners(repo, tmp_path, monkeypatch, capsys, kind, expected):
    selection = tmp_path / "selection"
    if kind == "file":
        selection.write_text("not a checkout")
    elif kind == "damaged-git":
        selection.mkdir()
        (selection / ".git").write_text("gitdir: /nowhere\n")
    elif kind == "empty-git":
        selection.mkdir()
        _git(selection, "init", "-q")
    elif kind == "subdirectory":
        selection = repo / "src"
        selection.mkdir()
    monkeypatch.setattr(scoring.security_score, "collect", lambda *a, **kw: pytest.fail("invalid source scanned"))
    assert cli.main(["score", str(selection), "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and expected in output.err
    assert "Traceback" not in output.err and "Stopped after" in output.err


@pytest.mark.parametrize("failure", ["timeout", "missing", "invalid-json", "invalid-schema", "parse-error"])
def test_scanner_failures_keep_findings_and_explain_why_score_is_withheld(repo, monkeypatch, capsys, failure):
    original = scoring.security_score._run

    def run(argv, warnings, label):
        if label != "source-auth":
            return original(argv, warnings, label)
        if failure == "timeout":
            warnings.append("source-auth: timed out, excluded")
            return False
        if failure == "missing":
            return True
        path = Path(argv[argv.index("--output-dir") + 1]) / ".source-auth-findings.json"
        if failure == "invalid-json":
            path.write_bytes(b"\xff artificial confidential scanner detail")
        elif failure == "invalid-schema":
            path.write_text(json.dumps({"findings": "artificial confidential scanner detail"}))
        else:
            assert original(argv, warnings, label)
            document = json.loads(path.read_text())
            document["parse_error"] = "artificial confidential scanner detail"
            path.write_text(json.dumps(document))
        return True

    monkeypatch.setattr(scoring.security_score, "_run", run)
    assert cli.main(["score", str(repo), "--json"]) == 1
    output = capsys.readouterr()
    document = json.loads(output.out)
    _validate(document)
    assert document["verdict"] == "incomplete" and document["score"] is None
    assert document["findings_total"] > 0 and document["top_findings"]
    assert document["scanner_status"]["config-iac"] == "complete"
    message = document["warnings"][0]
    assert message.startswith("Source code:") and "Retry the scan" in message
    if failure == "timeout":
        assert "exceeded its time limit" in message
    assert "No security score is available" in document["reason"]
    assert "artificial confidential" not in output.out + output.err and "Traceback" not in output.err


@pytest.mark.parametrize("stage", ["scanner", "schema", "renderer", "storage"])
def test_unexpected_score_errors_are_contained_without_publishing_or_exposing_details(
    repo, tmp_path, monkeypatch, capsys, stage
):
    def fail(*args, **kwargs):
        raise IndexError("artificial confidential internal detail")

    if stage == "scanner":
        monkeypatch.setattr(scoring.security_score, "collect", fail)
    elif stage == "renderer":
        from appsec_analyzer.score import render

        monkeypatch.setattr(render, "render_text", fail)
    elif stage == "storage":
        monkeypatch.setattr(scoring.tempfile, "TemporaryDirectory", fail)
    else:
        (tmp_path / "schemas").mkdir()
        (tmp_path / "schemas/security-score.schema.yaml").write_text("type: invalid-type\n")
        monkeypatch.setattr(scoring, "resource_root", lambda: tmp_path)
    assert cli.main(["score", str(repo)]) == 1
    output = capsys.readouterr()
    assert not output.out and "Security score could not finish" in output.err
    assert "Retry the command" in output.err and "Stopped after" in output.err
    assert "Traceback" not in output.err and "artificial confidential" not in output.err
    assert "Completed in" not in output.err


def test_closed_stdout_pipe_exits_without_traceback(repo):
    process = subprocess.Popen(
        [sys.executable, "-m", "appsec_analyzer.cli", "score", str(repo), "--json"],
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        process.stdout.close()
        stderr = process.stderr.read()
        assert process.wait(timeout=30) == 1
        assert "Traceback" not in stderr and "BrokenPipe" not in stderr and "Exception ignored" not in stderr
    finally:
        if process.poll() is None:
            process.kill()
        process.stderr.close()


def test_missing_git_explains_prerequisite_without_traceback(repo, tmp_path, monkeypatch, capsys):
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    assert cli.main(["score", str(repo), "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and "check Git installation and read permissions" in output.err
    assert "Traceback" not in output.err


@pytest.mark.usefixtures("transport")
def test_failed_remote_clone_is_actionable_private_and_cleans_up(monkeypatch, capsys):
    from runtime import remote_repositories

    original = remote_repositories.clone
    checkouts = []

    def clone(remote, root):
        checkouts.append(root)
        return original(remote, root)

    monkeypatch.setattr(remote_repositories, "clone", clone)
    assert cli.main(["score", "ssh://git@git.example/team/nonexistent.git", "--json"]) == 1
    output = capsys.readouterr()
    assert not output.out and "check repository access, credentials and trusted SSH host keys" in output.err
    assert "Traceback" not in output.err and "FIXTURE_SOURCES" not in output.err and "KeyError" not in output.err
    assert checkouts and all(not path.exists() for path in checkouts)


def test_sigterm_unwinds_like_ctrl_c_so_temporary_files_are_removed():
    import os
    import signal

    from appsec_analyzer import cli

    previous = signal.getsignal(signal.SIGTERM)
    cleaned = []
    with pytest.raises(KeyboardInterrupt):
        with cli._sigterm_as_interrupt():
            try:
                os.kill(os.getpid(), signal.SIGTERM)
                signal.pause()
            finally:
                cleaned.append(True)
    assert cleaned and signal.getsignal(signal.SIGTERM) == previous
