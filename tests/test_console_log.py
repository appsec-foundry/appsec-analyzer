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
        with console_log(mode=mode) as log:
            log.start(path)
            print("\033[32m✓ done\033[0m")
        assert path.read_text(encoding="utf-8") == expected


def test_html_shows_the_console_colours_on_a_page_without_script(tmp_path):
    path = tmp_path / "console.html"
    with console_log(mode="html") as log:
        print("\033[1;36mPreflight\033[0m held")
        log.start(path)
        sys.stderr.write(STATUS)
        print("\033[38;2;236;109;118mcritical\033[0m and \033[90mmuted\033[0m plain")
    page = path.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>") and page.count("<!doctype html>") == 1
    assert "default-src 'none'" in page and "<script" not in page and "status" not in page
    body = page.split("<body><pre>", 1)[1]
    assert body == (
        '<span style="color:rgb(124,196,228);font-weight:bold">Preflight</span> held\n'
        '<span style="color:rgb(236,109,118)">critical</span> and '
        '<span style="color:rgb(109,118,134)">muted</span> plain\n'
    )


def test_html_keeps_text_from_repositories_and_models_as_text(tmp_path):
    path = tmp_path / "console.html"
    with console_log(mode="html") as log:
        log.start(path)
        print('<script>alert(1)</script> & <img src=x onerror="x"> \033]8;;http://evil\a\033[2Jlink\r')
    body = path.read_text(encoding="utf-8").split("<body><pre>", 1)[1]
    assert body == '&lt;script&gt;alert(1)&lt;/script&gt; &amp; &lt;img src=x onerror="x"&gt; ]8;;http://evillink\n'


def test_html_resume_appends_without_a_second_head(tmp_path):
    path = tmp_path / "console.html"
    with console_log(mode="html") as log:
        log.start(path)
        print("first")
    with console_log(mode="html") as log:
        log.start(path, append=True)
        print("resumed")
    page = path.read_text(encoding="utf-8")
    assert page.count("<!doctype html>") == 1 and page.endswith("<body><pre>first\nresumed\n")


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


@pytest.mark.parametrize(
    "flag, mode",
    [
        ((), None),
        (("--console-log",), "plain"),
        (("--console-log", "color"), "color"),
        (("--console-log", "html"), "html"),
    ],
)
def test_the_flag_wraps_the_run_and_stays_out_of_the_request(tmp_path, monkeypatch, flag, mode):
    from appsec_analyzer import cli, hosts
    from tests.test_public_scan_cli import _repo

    repo = _repo(tmp_path / "repo")
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    seen = []

    def assess(request, **kwargs):
        seen.append(None if ConsoleLog.active is None else ConsoleLog.active._mode)
        # Where the console goes is no part of the run's identity.
        assert not any(argument.startswith("--console-log") for argument in request.arguments)
        return 0

    monkeypatch.setattr(controller, "assess_main", assess)
    arguments = ["assess", "--repo", str(repo), "--profile", "claude", "--skip-preflight", "--non-interactive"]
    assert cli.main([*arguments, *flag]) == 0
    assert seen == [mode] and ConsoleLog.active is None
