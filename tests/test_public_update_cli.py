"""Offline contracts of the `update` command: no installation without an explicit yes."""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

import pytest

from appsec_analyzer import cli, update

SOURCE = "https://example.test/appsec-analyzer.git"


def _setup(monkeypatch, *, answer="y", returncode=0, source=SOURCE):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode)

    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(update, "_pipx_source", lambda: source)
    monkeypatch.setattr(update.shutil, "which", lambda name, **kw: "/usr/bin/pipx")
    monkeypatch.setattr(update.subprocess, "run", run)
    monkeypatch.setattr("builtins.input", lambda *a: answer)
    return calls


@pytest.mark.parametrize("answer", ["y", "YES"])
def test_yes_upgrades_the_pipx_installation_and_names_the_source(monkeypatch, capsys, answer):
    calls = _setup(monkeypatch, answer=answer)
    assert cli.main(["update"]) == 0
    assert calls == [["/usr/bin/pipx", "upgrade", "--pip-args=--force-reinstall", "appsec-analyzer"]]
    output = capsys.readouterr().out
    assert SOURCE in output
    assert "Update finished" in output


@pytest.mark.parametrize("answer", ["", "n", "no", "maybe"])
def test_anything_but_yes_installs_nothing(monkeypatch, capsys, answer):
    calls = _setup(monkeypatch, answer=answer)
    assert cli.main(["update"]) == 0
    assert calls == []
    assert "Nothing was installed" in capsys.readouterr().out


def test_end_of_input_installs_nothing(monkeypatch):
    calls = _setup(monkeypatch)

    def closed(*args):
        raise EOFError

    monkeypatch.setattr("builtins.input", closed)
    assert cli.main(["update"]) == 0
    assert calls == []


def test_failed_upgrade_exits_with_an_error(monkeypatch, capsys):
    _setup(monkeypatch, returncode=1)
    assert cli.main(["update"]) == 2
    assert "the update failed" in capsys.readouterr().err


@pytest.mark.parametrize("case", ["ci", "no-terminal", "not-pipx", "no-pipx-executable"])
def test_nothing_is_asked_or_installed_when_it_must_not_be(monkeypatch, capsys, case):
    calls = _setup(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("must not ask"))
    if case == "ci":
        monkeypatch.setenv("CI", "true")
    elif case == "no-terminal":
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    elif case == "not-pipx":
        monkeypatch.setattr(update, "_pipx_source", lambda: None)
    else:
        monkeypatch.setattr(update.shutil, "which", lambda name, **kw: None)
    assert cli.main(["update"]) == 2
    assert calls == []
    assert "appsec-analyzer: error:" in capsys.readouterr().err


def test_update_takes_no_assume_yes_option(monkeypatch):
    calls = _setup(monkeypatch)
    with pytest.raises(SystemExit):
        cli.main(["update", "--yes"])
    assert calls == []


def test_organization_commands_do_not_offer_update():
    with pytest.raises(SystemExit):
        cli.main(["update"], organization=SimpleNamespace(command="acme-appsec"))
