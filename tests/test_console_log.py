"""`assess --console-log`: a copy of the console in the output directory, without the status line."""

from __future__ import annotations

import os
import stat
import sys

import pytest
from orchestrator import orchestration_controller as controller

from appsec_analyzer.assessment.console import ConsoleLog, _AssessmentConsole, console_log

STATUS = _AssessmentConsole.FRAME_OPEN + "⠋ status\033[K\033[J" + _AssessmentConsole.FRAME_CLOSE


def test_the_log_holds_output_until_start_and_leaves_out_the_status_line(tmp_path, capsys):
    path = tmp_path / "console.log"
    with console_log() as log:
        print("before the output directory")
        sys.stderr.write(STATUS)
        sys.stderr.write("\r\033[K")
        sys.stderr.write("\r\033[K\033[1A\033[K\033[1A\033[K")
        log.start(path)
        print("entry", file=sys.stderr)
    assert path.read_text(encoding="utf-8") == "before the output directory\nentry\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # The console itself still shows everything, the status line included.
    assert "status" in capsys.readouterr().err


def test_the_log_is_plain_unless_color(tmp_path):
    for mode, expected in (("plain", "✓ done\n"), ("color", "\033[32m✓ done\033[0m\n")):
        path = tmp_path / f"{mode}.log"
        with console_log(plain=mode == "plain") as log:
            log.start(path)
            print("\033[32m✓ done\033[0m")
        assert path.read_text(encoding="utf-8") == expected


def test_resume_continues_the_log_and_a_new_run_replaces_it(tmp_path):
    path = tmp_path / "console.log"
    path.write_text("earlier run\n")
    path.chmod(0o644)
    with console_log() as log:
        log.start(path, append=True)
        print("resumed")
    assert path.read_text() == "earlier run\nresumed\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with console_log() as log:
        log.start(path)
        print("new run")
    assert path.read_text() == "new run\n"


def test_a_run_that_never_starts_the_log_writes_none(tmp_path):
    with console_log():
        print("refused before the output directory was accepted")
    assert not any(tmp_path.iterdir())
    assert ConsoleLog.active is None


@pytest.mark.parametrize("planted", ["symlink", "hardlink", "fifo", "directory"])
def test_the_log_is_never_written_through_what_was_left_at_its_name(tmp_path, capsys, planted):
    victim = tmp_path / "victim"
    victim.write_text("preserve")
    path = tmp_path / "console.log"
    if planted == "symlink":
        path.symlink_to(victim)
    elif planted == "hardlink":
        os.link(victim, path)
    elif planted == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    with console_log() as log:
        log.start(path)
        print("the run goes on")
    assert victim.read_text() == "preserve"
    assert log.path is None
    shown = capsys.readouterr()
    assert "⚠ console log disabled" in shown.err and "the run goes on" in shown.out


def test_a_failing_write_ends_the_log_not_the_run(tmp_path, capsys):
    class Full:
        def write(self, text):
            raise OSError(28, "No space left on device")

        def close(self):
            pass

    with console_log() as log:
        log.start(tmp_path / "console.log")
        log._file.close()
        log._file = Full()
        print("still shown")
        print("and this")
    shown = capsys.readouterr()
    assert "still shown\nand this\n" in shown.out
    assert "⚠ console log incomplete: No space left on device" in shown.err


@pytest.mark.parametrize("flag, plain", [((), None), (("--console-log",), True), (("--console-log", "color"), False)])
def test_the_flag_wraps_the_run_and_stays_out_of_the_request(tmp_path, monkeypatch, flag, plain):
    from appsec_analyzer import cli, hosts
    from tests.test_public_scan_cli import _repo

    repo = _repo(tmp_path / "repo")
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    seen = []

    def assess(request, **kwargs):
        seen.append(None if ConsoleLog.active is None else ConsoleLog.active._plain)
        # Where the console goes is no part of the run's identity.
        assert not any(argument.startswith("--console-log") for argument in request.arguments)
        return 0

    monkeypatch.setattr(controller, "assess_main", assess)
    arguments = ["assess", "--repo", str(repo), "--profile", "claude", "--skip-preflight", "--non-interactive"]
    assert cli.main([*arguments, *flag]) == 0
    assert seen == [plain] and ConsoleLog.active is None
