"""`--version` shows a release version, or the commit and its date for any other build."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from appsec_analyzer import ENGINE_VERSION, version_info

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "17f22aa9" + "0" * 32
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def _stamp(tmp_path, monkeypatch, info):
    """An installed package: a stamp inside the package directory and no checkout beside it."""
    package = tmp_path / "site-packages" / "appsec_analyzer"
    package.mkdir(parents=True)
    if info is not None:
        (package / "build-info.json").write_text(info if isinstance(info, str) else json.dumps(info))
    monkeypatch.setattr(version_info, "PACKAGE", package)


def _info(**changes):
    return {"commit": COMMIT, "date": "2026-10-26", "tag": None, "dirty": False, **changes}


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, "17f22aa9 (2026-10-26)"),
        ({"dirty": True}, "17f22aa9 (2026-10-26) +local changes"),
        ({"tag": "v0.2.0"}, "0.2.0"),
        ({"tag": "v0.2.0", "dirty": True}, "0.2.0 +local changes"),
        ({"tag": "v1.0.0-rc.1"}, "1.0.0-rc.1"),
    ],
)
def test_stamp_gives_release_or_commit_and_date(tmp_path, monkeypatch, changes, expected):
    _stamp(tmp_path, monkeypatch, _info(**changes))
    assert version_info.describe() == expected


@pytest.mark.parametrize(
    "stamp",
    [
        None,
        "not json",
        "[]",
        _info(commit="zz"),
        _info(commit=COMMIT + "\x1b[31m"),
        _info(date="yesterday"),
        _info(tag="latest"),
        _info(tag="v1.0.0\x1b[2J"),
        _info(tag=5),
    ],
)
def test_missing_or_malformed_stamp_is_reported_as_unknown(tmp_path, monkeypatch, stamp):
    _stamp(tmp_path, monkeypatch, stamp)
    assert version_info.describe() == f"{ENGINE_VERSION} (commit unknown)"


def _repository(path):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.test",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.test",
        "GIT_COMMITTER_DATE": "2026-03-04T12:00:00+00:00",
        "GIT_AUTHOR_DATE": "2026-03-04T12:00:00+00:00",
    }

    def git(*args):
        return subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, text=True, env=env)

    path.mkdir(exist_ok=True)
    git("init", "-q")
    (path / "file.txt").write_text("one")
    git("add", "-A")
    git("commit", "-qm", "one")
    return git


def test_read_git_reports_commit_date_tag_and_local_changes(tmp_path):
    git = _repository(tmp_path / "repo")
    clean = version_info.read_git(tmp_path / "repo")
    assert clean["commit"] == git("rev-parse", "HEAD").stdout.strip()
    assert (clean["date"], clean["tag"], clean["dirty"]) == ("2026-03-04", None, False)

    git("tag", "v0.3.0")
    (tmp_path / "repo" / "file.txt").write_text("two")
    changed = version_info.read_git(tmp_path / "repo")
    assert (changed["tag"], changed["dirty"]) == ("v0.3.0", True)


def test_other_tags_are_not_releases(tmp_path):
    git = _repository(tmp_path / "repo")
    git("tag", "latest")
    assert version_info.read_git(tmp_path / "repo")["tag"] is None


def test_read_git_is_empty_outside_a_repository(tmp_path):
    assert version_info.read_git(tmp_path) == {}


def test_a_checkout_without_stamp_is_read_from_git(tmp_path, monkeypatch):
    _repository(tmp_path / "repo")
    package = tmp_path / "repo" / "appsec_analyzer"
    package.mkdir()
    monkeypatch.setattr(version_info, "PACKAGE", package)
    assert version_info.describe().endswith(" (2026-03-04)")


def test_built_package_reports_the_stamp_or_that_the_commit_is_unknown(tmp_path):
    source = tmp_path / "source"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "build", "dist", "__pycache__", "*.egg-info", ".pytest_cache", ".coverage-data"
        ),
    )
    lib = tmp_path / "lib"

    def build_and_ask():
        built = subprocess.run(
            [sys.executable, "setup.py", "-q", "build_py", "--build-lib", str(lib)],
            cwd=source,
            capture_output=True,
            text=True,
        )
        assert built.returncode == 0, built.stderr
        asked = subprocess.run(
            [sys.executable, "-m", "appsec_analyzer", "--version"],
            cwd=tmp_path,
            env={**os.environ, "PYTHONPATH": str(lib)},
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert asked.returncode == 0, asked.stderr
        return asked.stdout.strip()

    assert build_and_ask() == f"appsec-analyzer {ENGINE_VERSION} (commit unknown)"
    assert not (lib / "appsec_analyzer" / "build-info.json").exists()

    git = _repository(source)
    assert build_and_ask().startswith("appsec-analyzer ") and build_and_ask().endswith(" (2026-03-04)")
    git("tag", "v0.5.0")
    assert build_and_ask() == "appsec-analyzer 0.5.0"


def test_wheel_built_from_a_source_archive_keeps_the_stamp(tmp_path):
    source = tmp_path / "source"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "build", "dist", "__pycache__", "*.egg-info", ".pytest_cache", ".coverage-data"
        ),
    )
    git = _repository(source)
    git("tag", "v0.6.0")
    dist = tmp_path / "dist"
    made = subprocess.run(
        [sys.executable, "setup.py", "-q", "sdist", "--dist-dir", str(dist)],
        cwd=source,
        capture_output=True,
        text=True,
    )
    assert made.returncode == 0, made.stderr
    shutil.unpack_archive(next(dist.glob("*.tar.gz")), tmp_path / "unpacked")
    unpacked = next((tmp_path / "unpacked").iterdir())
    lib = tmp_path / "lib"
    built = subprocess.run(
        [sys.executable, "setup.py", "-q", "build_py", "--build-lib", str(lib)],
        cwd=unpacked,
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    asked = subprocess.run(
        [sys.executable, "-m", "appsec_analyzer", "--version"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(lib)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert asked.stdout.strip() == "appsec-analyzer 0.6.0", asked.stderr
