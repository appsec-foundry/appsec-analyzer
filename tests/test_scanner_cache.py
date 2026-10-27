"""Scanner results kept for a later start of the same run, without running a scanner."""

import json
from types import SimpleNamespace

import pytest
from model import assessment_scanner_findings as findings

RESULT = ([{"findings": [{"file": "app.py"}]}, {"findings": []}, {"findings": []}], {"findings": []}, None)


def scope_of(files):
    repo = SimpleNamespace(
        repository_id="repo-1", exclusions=(), inventory=lambda: {"files": [{"path": p, "sha256": h} for p, h in files]}
    )
    return SimpleNamespace(repositories=(repo,))


@pytest.fixture
def computed(monkeypatch):
    calls = []

    def compute(scope, rid, depth, *, architecture):
        calls.append((rid, depth, architecture))
        return tuple(json.loads(json.dumps(RESULT)))

    monkeypatch.setattr(findings, "_compute_snapshot_outputs", compute)
    yield calls
    findings.use_scanner_cache(None)


def run(files=(("app.py", "a"),), depth="standard", architecture="thorough"):
    return findings._snapshot_outputs(scope_of(files), "repo-1", depth, architecture=architecture)


def test_an_identical_snapshot_reuses_the_stored_result(tmp_path, computed):
    findings.use_scanner_cache(tmp_path / "derived", "a" * 64)
    first = run()
    assert run() == first == RESULT
    assert len(computed) == 1
    assert (tmp_path / "derived").stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "change",
    [
        {"files": (("app.py", "b"),)},
        {"files": (("app.py", "a"), ("new.py", "c"))},
        {"depth": "quick"},
        {"architecture": None},
    ],
)
def test_a_changed_source_or_setting_runs_the_scanners_again(tmp_path, computed, change):
    findings.use_scanner_cache(tmp_path / "derived", "a" * 64)
    run()
    run(**change)
    assert len(computed) == 2


def test_a_changed_plugin_runs_the_scanners_again(tmp_path, computed):
    findings.use_scanner_cache(tmp_path / "derived", "a" * 64)
    run()
    findings.use_scanner_cache(tmp_path / "derived", "b" * 64)
    run()
    assert len(computed) == 2


def test_an_altered_or_damaged_file_is_not_used(tmp_path, computed):
    findings.use_scanner_cache(tmp_path / "derived", "a" * 64)
    run()
    (path,) = (tmp_path / "derived").glob("scan-*.json")
    stored = json.loads(path.read_text())
    stored["payload"][0] = []
    path.write_text(json.dumps(stored))
    run()
    assert len(computed) == 2
    path.write_text("{ not json")
    run()
    assert len(computed) == 3


def test_a_linked_file_is_not_used(tmp_path, computed):
    findings.use_scanner_cache(tmp_path / "derived", "a" * 64)
    run()
    (path,) = (tmp_path / "derived").glob("scan-*.json")
    target = tmp_path / "elsewhere.json"
    target.write_text(path.read_text())
    path.unlink()
    path.symlink_to(target)
    run()
    assert len(computed) == 2


def test_without_a_configured_cache_every_call_runs_the_scanners(computed):
    run()
    run()
    assert len(computed) == 2
