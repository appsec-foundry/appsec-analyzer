"""A local directory without Git reaches the analysis as a private temporary checkout (REQ-002)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from orchestrator.assessment_workspace import recon_summary, source_repositories
from orchestrator.orchestration_controller import _single_repository_meta
from runtime import remote_repositories as remote
from runtime.multi_repo_scope import MAX_FILE_BYTES, ScopeError, _selected_root, admit
from runtime.plain_directory import no_git_directory


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=True)


@pytest.fixture(autouse=True)
def private_area(tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(scratch))
    config = tmp_path / "operator.gitconfig"
    config.write_text("")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    return scratch


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "shop"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('app')\n")
    (root / "README.md").write_text("# Shop\n")
    return root


@pytest.fixture
def output(tmp_path):
    return tmp_path / "report"


def capture(source, output, *extra):
    """Admit the temporary checkout of ``source``; returns the scope and the checkout root."""
    with remote.checkout_arguments(["--repo", str(source), "--output", str(output), *extra]) as resolved:
        root = Path(resolved[1])
        return admit([str(root)], str(output), minimum=1), root


def tree(root):
    return sorted((str(path.relative_to(root)), path.lstat().st_mtime_ns) for path in root.rglob("*"))


def test_directory_is_analyzed_as_a_removed_checkout_and_stays_untouched(source, output, private_area):
    before = tree(source)
    with remote.checkout_arguments(["--repo", str(source), "--output", str(output)]) as resolved:
        root = Path(resolved[1])
        assert root != source and root.is_dir() and private_area in root.parents
        assert _selected_root(str(root)) == root
        assert (root / "src" / "app.py").read_text() == "print('app')\n"
    assert not root.exists()
    assert tree(source) == before and not (source / ".git").exists()


def test_scope_names_the_directory_and_marks_it_without_git(source, output):
    scope, _ = capture(source, output)
    row = scope.inventory()["repositories"][0]
    assert row["label"] == "shop" and row["without_git"] is True
    assert row["dirty"] is False
    assert {entry["path"] for entry in row["files"]} == {"README.md", "src/app.py"}


def test_gitignore_applies_also_in_a_subdirectory(source, output):
    (source / ".gitignore").write_text("runtime/\n*.tfstate\n")
    (source / "runtime").mkdir()
    (source / "runtime" / "finance.txt").write_text("salaries\n")
    (source / "main.tfstate").write_text("state\n")
    (source / "src" / ".gitignore").write_text("generated.py\n")
    (source / "src" / "generated.py").write_text("generated\n")
    scope, _ = capture(source, output)
    paths = {entry["path"] for entry in scope.inventory()["repositories"][0]["files"]}
    assert paths == {".gitignore", "README.md", "src/.gitignore", "src/app.py"}


@pytest.mark.parametrize("extra", [(), ("--quiet",)])
def test_a_missing_gitignore_is_named_before_any_model_call(source, output, capsys, extra):
    capture(source, output, *extra)
    assert "no .gitignore in shop" in capsys.readouterr().err


def test_a_gitignore_silences_the_notice(source, output, capsys):
    (source / ".gitignore").write_text("build/\n")
    capture(source, output)
    assert "no .gitignore" not in capsys.readouterr().err


def test_empty_git_directory_counts_as_no_git(source, output):
    (source / ".git").mkdir()
    assert no_git_directory(str(source)) == source
    scope, _ = capture(source, output)
    assert scope.repositories[0].without_git
    assert list((source / ".git").iterdir()) == []


@pytest.mark.parametrize(
    "damage",
    [
        lambda marker: marker.write_text("gitdir: /nowhere\n"),
        lambda marker: (marker.mkdir(), (marker / "HEAD").write_text("garbage\n")),
    ],
)
def test_damaged_git_is_rejected_with_a_message_that_names_it(source, damage):
    damage(source / ".git")
    assert no_git_directory(str(source)) is None
    with pytest.raises(ScopeError, match=r"\.git that Git cannot read"):
        _selected_root(str(source))


def test_git_checkout_keeps_its_own_path_and_inventory(source, output):
    git("init", "-q", cwd=source)
    git("add", ".", cwd=source)
    git("-c", "user.name=a", "-c", "user.email=a@invalid", "commit", "-qm", "x", cwd=source)
    arguments = ["--repo", str(source), "--output", str(output)]
    with remote.checkout_arguments(arguments) as resolved:
        assert resolved == arguments
    row = admit([str(source)], str(output), minimum=1).inventory()["repositories"][0]
    assert "without_git" not in row


def test_subdirectory_of_a_checkout_stays_rejected(source):
    git("init", "-q", cwd=source)
    assert no_git_directory(str(source / "src")) is None
    with pytest.raises(ScopeError, match="top-level"):
        _selected_root(str(source / "src"))


def test_inside_a_git_directory_is_no_plain_directory(source):
    git("init", "-q", cwd=source)
    assert no_git_directory(str(source / ".git")) is None


@pytest.mark.parametrize("value", ["", " ", "bad\nname"])
def test_invalid_selection_is_no_directory(value):
    assert no_git_directory(value) is None


def test_missing_path_and_file_are_no_directory(source):
    assert no_git_directory(str(source / "missing")) is None
    assert no_git_directory(str(source / "README.md")) is None


def test_output_must_be_named(source):
    with pytest.raises(remote.RemoteError, match="explicit --output"):
        with remote.checkout_arguments(["--repo", str(source)]):
            pass


@pytest.mark.parametrize("relative", [".", "reports", "reports/deep", ".."])
def test_output_cannot_lie_in_or_around_the_directory(source, relative):
    target = source / relative
    with pytest.raises(remote.RemoteError, match="outside the selected directory"):
        with remote.checkout_arguments(["--repo", str(source), "--output", str(target)]):
            pass


def test_nested_and_repeated_selections_are_rejected(source, output):
    for repeated in (source / "src", source):
        args = ["--repo", str(source), "--repo", str(repeated), "--output", str(output)]
        with pytest.raises(remote.RemoteError, match="overlapping"):
            with remote.checkout_arguments(args):
                pass


def test_two_separate_directories_combine(source, output, tmp_path):
    other = tmp_path / "ledger"
    other.mkdir()
    (other / "main.py").write_text("print('ledger')\n")
    args = ["--repo", str(source), "--repo", str(other), "--output", str(output)]
    with remote.checkout_arguments(args) as resolved:
        scope = admit([resolved[1], resolved[3]], str(output))
    assert sorted(row["label"] for row in scope.inventory()["repositories"]) == ["ledger", "shop"]


@pytest.mark.parametrize("marker", ["real", "empty"])
def test_nested_repository_stays_out_and_is_recorded(source, output, marker):
    nested = source / "vendor" / "lib"
    nested.mkdir(parents=True)
    (nested / "lib.py").write_text("nested = True\n")
    if marker == "real":
        git("init", "-q", cwd=nested)
    else:
        (nested / ".git").mkdir()
    scope, _ = capture(source, output)
    row = scope.inventory()["repositories"][0]
    assert {"path": "vendor/lib", "reason": "submodule"} in row["exclusions"]
    assert "vendor/lib/lib.py" not in {entry["path"] for entry in row["files"]}


def test_links_are_recorded_and_never_followed(source, output, tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("outside the directory\n")
    (source / "leak.txt").symlink_to(secret)
    (source / "linked").symlink_to(tmp_path)
    with remote.checkout_arguments(["--repo", str(source), "--output", str(output)]) as resolved:
        root = Path(resolved[1])
        assert (root / "leak.txt").is_symlink()
        scope = admit([str(root)], str(output), minimum=1)
    row = scope.inventory()["repositories"][0]
    assert {entry["path"] for entry in row["exclusions"]} == {"leak.txt", "linked"}
    assert {entry["reason"] for entry in row["exclusions"]} == {"symlink"}
    assert all(b"outside the directory" not in data for data in scope.repositories[0].files.values())


def test_secret_named_file_is_recorded_but_never_copied(source, output):
    (source / ".env").write_text("TOKEN=real-value\n")
    with remote.checkout_arguments(["--repo", str(source), "--output", str(output)]) as resolved:
        root = Path(resolved[1])
        assert (root / ".env").read_bytes() == b""
        assert b"real-value" not in git_objects(root)
        scope = admit([str(root)], str(output), minimum=1)
    assert {"path": ".env", "reason": "sensitive-name"} in scope.inventory()["repositories"][0]["exclusions"]


def git_objects(root):
    listing = git("rev-list", "--objects", "--all", cwd=root).stdout
    return "\n".join(git("cat-file", "-p", line.split()[0], cwd=root).stdout for line in listing.splitlines()).encode()


def test_oversized_files_keep_their_exclusion_and_stay_out(source, output):
    (source / "bundle.js").write_bytes(b"var a = 1;\n" * 120_000)
    (source / "image.bin").write_bytes(b"\0\1" * MAX_FILE_BYTES)
    with remote.checkout_arguments(["--repo", str(source), "--output", str(output)]) as resolved:
        root = Path(resolved[1])
        assert b"var a" not in (root / "bundle.js").read_bytes()
        scope = admit([str(root)], str(output), minimum=1)
    reasons = {entry["path"]: entry["reason"] for entry in scope.inventory()["repositories"][0]["exclusions"]}
    assert reasons == {"bundle.js": "oversized", "image.bin": "binary"}


def test_aggregate_limit_stops_the_copy_and_leaves_nothing(source, output, private_area, monkeypatch):
    monkeypatch.setattr("runtime.plain_directory.MAX_TOTAL_BYTES", 4)
    with pytest.raises(remote.RemoteError, match="add a .gitignore"):
        capture(source, output)
    assert not list(private_area.rglob("app.py"))


def test_file_limit_stops_the_copy(source, output, monkeypatch):
    monkeypatch.setattr("runtime.plain_directory.MAX_FILES", 1)
    with pytest.raises(remote.RemoteError, match="add a .gitignore"):
        capture(source, output)


def test_unchanged_content_keeps_its_source_identity(source, output):
    first, first_root = capture(source, output)
    second, second_root = capture(source, output)
    assert first_root == second_root
    assert first.inventory() == second.inventory()
    (source / "README.md").write_text("# Changed\n")
    third, _ = capture(source, output)
    assert third.inventory()["repositories"][0]["head"] != first.inventory()["repositories"][0]["head"]
    assert third.inventory()["scope_sha256"] != first.inventory()["scope_sha256"]


def test_repository_content_cannot_claim_to_be_a_directory(tmp_path, output):
    root = tmp_path / "directory-claimed" / "repo"
    root.mkdir(parents=True)
    git("init", "-q", cwd=root)
    (root / "a.py").write_text("a = 1\n")
    git("add", ".", cwd=root)
    git("-c", "user.name=a", "-c", "user.email=a@invalid", "commit", "-qm", "x", cwd=root)
    assert not admit([str(root)], str(output), minimum=1).repositories[0].without_git


def test_report_inputs_show_no_commit(source, output):
    scope, _ = capture(source, output)
    head = scope.repositories[0].head
    meta = _single_repository_meta(scope)
    assert meta["git"] == {"commit_sha": "", "branch": ""}
    assert source_repositories(scope)[0]["without_git"] is True
    summary = recon_summary("Shop", scope)
    assert "directory without Git" in summary and head[:12] not in summary


def test_scan_sources_accepts_a_directory(source, output):
    output.mkdir()
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "appsec_analyzer",
            "scan-sources",
            "--repo",
            str(source),
            "--output",
            str(output),
            "--json",
        ],
        cwd=ROOT,
        env={**os.environ, "TMPDIR": str(output.parent / "scratch")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    assert "no .gitignore in shop" in run.stderr
    row = json.loads(run.stdout)["repositories"][0]
    assert row["label"] == "shop" and row["without_git"] is True and row["captured_files"] == 2
