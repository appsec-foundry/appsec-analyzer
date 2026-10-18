"""Saved assessment exports are model-free and enforce artifact boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from appsec_analyzer.exports import ExportError, export_assessment
from tests.test_public_assessment_operations import _state

ROOT = Path(__file__).resolve().parents[1]


def _bundle(tmp_path, *, markdown="# Saved assessment\n\nVerified findings.\n", extra=None):
    source = tmp_path / "assessment"
    files = {
        "security-assessment.yaml": (ROOT / "tests/fixtures/report-anatomy/quick-run/threat-model.yaml").read_bytes(),
        "security-assessment.md": markdown.encode(),
        **(extra or {}),
    }
    _state(source, deliverables={name: hashlib.sha256(body).hexdigest() for name, body in files.items()})
    source.chmod(0o700)
    for name, body in files.items():
        (source / name).write_bytes(body)
    return source


def test_public_export_runs_without_provider_and_preserves_model(tmp_path):
    source = _bundle(tmp_path)
    before = {p.name: p.read_bytes() for p in source.iterdir()}
    output = tmp_path / "export"
    env = os.environ.copy()
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        env.pop(key, None)
    env["APPSEC_CLAUDE_EXECUTABLE"] = "/nonexistent/claude"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "appsec_analyzer.cli",
            "export",
            "--assessment",
            str(source),
            "--output",
            str(output),
            "--formats",
            "markdown",
            "yaml",
            "sarif",
            "threatdragon",
            "pentest-tasks",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    public = json.loads(result.stdout)
    assert public["model_calls"] == 0 and public["export_status"] == "complete"
    assert {p.name: p.read_bytes() for p in source.iterdir()} == before
    assert (output / "security-assessment.yaml").read_bytes() == before["security-assessment.yaml"]
    assert json.loads((output / "security-assessment.sarif.json").read_text())["version"] == "2.1.0"
    assert json.loads((output / "security-assessment.threatdragon.json").read_text())
    assert yaml.safe_load((output / "pentest-tasks.yaml").read_text())
    assert output.stat().st_mode & 0o777 == 0o700
    for name, digest in public["deliverables"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
        assert (output / name).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "defect", ["modified", "symlink", "hardlink", "fifo", "incomplete", "invalid-model", "public-directory"]
)
def test_export_rejects_untrusted_saved_state(tmp_path, defect):
    source = _bundle(tmp_path)
    path = source / "security-assessment.yaml"
    if defect == "modified":
        path.write_text("changed")
    elif defect in ("symlink", "hardlink"):
        external = tmp_path / "external"
        path.rename(external)
        if defect == "symlink":
            path.symlink_to(external)
        else:
            os.link(external, path)
    elif defect == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif defect == "incomplete":
        state = source / ".assessment-state.json"
        body = json.loads(state.read_text())
        body["status"] = "running"
        state.write_text(json.dumps(body))
    elif defect == "invalid-model":
        path.write_text("meta: {}\n")
        state = source / ".assessment-state.json"
        body = json.loads(state.read_text())
        body["deliverables"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        state.write_text(json.dumps(body))
    else:
        source.chmod(0o755)
    output = tmp_path / "export"
    with pytest.raises(ExportError):
        export_assessment(str(source), str(output), ("yaml",))
    assert not output.exists()


def test_export_preserves_existing_destination(tmp_path):
    source = _bundle(tmp_path)
    output = tmp_path / "export"
    output.mkdir()
    (output / "sentinel").write_text("owned by someone else")
    with pytest.raises(ExportError, match="already exists"):
        export_assessment(str(source), str(output), ("yaml",))
    assert [p.name for p in output.iterdir()] == ["sentinel"]


def test_export_secret_rejection_does_not_disclose_input(tmp_path):
    marker = "AKIA" + "A" * 16
    source = _bundle(tmp_path, markdown=f"# Saved report\n\n{marker}\n")
    output = tmp_path / "export"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "appsec_analyzer.cli",
            "export",
            "--assessment",
            str(source),
            "--output",
            str(output),
            "--formats",
            "yaml",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 2 and "unmasked secret" in result.stderr
    assert marker not in result.stdout + result.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "markdown",
    [
        "![outside](../outside.svg)",
        "```text\n![outside](../outside.svg)\n```",
        "![remote](https://example.invalid/private.png)",
        '<img src="file:///etc/passwd">',
        '<div style="background: url(https://example.invalid/x)">x</div>',
        "<script>alert(1)</script>",
        "[bad](javascript:alert%281%29)",
    ],
)
def test_document_export_rejects_external_resources_before_embedding(tmp_path, monkeypatch, markdown):
    if not shutil.which("pandoc"):
        pytest.skip("Pandoc is not installed")
    from appsec_analyzer import exports

    source = _bundle(tmp_path, markdown=markdown)
    calls = []
    real_run = exports._run

    def checked_run(arguments, work):
        calls.append(arguments)
        assert arguments[0] == "pandoc" and "json" in arguments
        real_run(arguments, work)

    monkeypatch.setattr(exports, "_run", checked_run)
    output = tmp_path / "export"
    with pytest.raises(ExportError):
        export_assessment(str(source), str(output), ("html",))
    assert len(calls) == 1
    assert not list(output.glob("*.html"))


@pytest.mark.parametrize(
    "svg",
    [
        b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg"><use href="file:///etc/passwd"/></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
    ],
)
def test_export_rejects_active_svg(tmp_path, svg):
    source = _bundle(tmp_path, extra={"figure.svg": svg})
    with pytest.raises(ExportError):
        export_assessment(str(source), str(tmp_path / "export"), ("markdown",))


@pytest.mark.parametrize("format_", ["html", "pdf"])
def test_document_export_with_recorded_svg(tmp_path, format_):
    if not shutil.which("pandoc") or (format_ == "pdf" and not shutil.which("weasyprint")):
        pytest.skip("Document converter is not installed")
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100"><text x="10" y="20">Saved diagram</text></svg>'
    source = _bundle(tmp_path, markdown="# Saved assessment\n\n![Figure](figure.svg)\n", extra={"figure.svg": svg})
    output = tmp_path / "export"
    public = export_assessment(str(source), str(output), (format_,))
    body = (output / ("security-assessment." + format_)).read_bytes()
    assert public["model_calls"] == 0
    assert body.startswith(b"%PDF") if format_ == "pdf" else b"data:image/svg+xml" in body


def test_export_rechecks_source_after_conversion(tmp_path, monkeypatch):
    from appsec_analyzer import exports

    source = _bundle(tmp_path)
    real_run = exports._run

    def change_after_conversion(arguments, work):
        real_run(arguments, work)
        (source / "security-assessment.md").write_text("concurrent change")

    monkeypatch.setattr(exports, "_run", change_after_conversion)
    output = tmp_path / "export"
    with pytest.raises(ExportError, match="changed during export"):
        export_assessment(str(source), str(output), ("sarif",))
    assert not list(output.glob("*.json"))


def test_export_rejects_git_destination_and_missing_document_tool(tmp_path, monkeypatch):
    source = _bundle(tmp_path)
    checkout = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    with pytest.raises(ExportError, match="outside Git"):
        export_assessment(str(source), str(checkout / "export"), ("yaml",))
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(ExportError, match="pandoc is required"):
        export_assessment(str(source), str(tmp_path / "export"), ("html",))


def test_current_composed_report_exports_to_html(tmp_path):
    if not shutil.which("pandoc"):
        pytest.skip("Pandoc is not installed")
    from tests.test_report_anatomy import DETERMINISTIC_FRAGMENTS, QUICK_RUN, _render

    markdown = _render(QUICK_RUN, tmp_path, DETERMINISTIC_FRAGMENTS)
    images = {p.name: p.read_bytes() for p in (tmp_path / QUICK_RUN.name).glob("*.svg")}
    source = _bundle(tmp_path, markdown=markdown, extra=images)
    output = tmp_path / "export"
    public = export_assessment(str(source), str(output), ("html",))
    assert public["export_status"] == "complete"
    assert (output / "security-assessment.html").stat().st_size > 1000


def test_converter_timeout_terminates_process(tmp_path, monkeypatch):
    from appsec_analyzer import exports

    real_popen = subprocess.Popen
    children = []

    class ShortDeadlineProcess(real_popen):
        def wait(self, timeout=None):
            return super().wait(timeout=0.05 if timeout is not None else None)

    def spawn(*args, **kwargs):
        child = ShortDeadlineProcess(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", spawn)
    with pytest.raises(ExportError, match="time limit"):
        exports._run([sys.executable, "-c", "import time; time.sleep(60)"], tmp_path)
    assert children[0].poll() is not None and children[0].returncode != 0


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX permissions")
def test_export_accepts_a_parent_writable_only_by_the_users_private_group(tmp_path, monkeypatch):
    import grp
    import pwd
    from types import SimpleNamespace

    parent = tmp_path / "home"
    parent.mkdir(mode=0o700)
    if parent.lstat().st_gid != os.getgid():
        pytest.skip("temporary directory does not carry the primary group")
    source = _bundle(parent)
    parent.chmod(0o775)
    monkeypatch.setattr(grp, "getgrgid", lambda _gid: SimpleNamespace(gr_mem=[]))
    monkeypatch.setattr(pwd, "getpwall", lambda: [])
    output = parent / "export"
    export_assessment(str(source), str(output), ("yaml",))
    assert output.stat().st_mode & 0o777 == 0o700
    monkeypatch.setattr(grp, "getgrgid", lambda _gid: SimpleNamespace(gr_mem=["someone-else"]))
    with pytest.raises(ExportError, match="writable by other users"):
        export_assessment(str(source), str(parent / "second"), ("yaml",))
    assert not (parent / "second").exists()
