"""Model-free exports of completed, integrity-checked assessment artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from appsec_analyzer import INTERFACE_VERSION, resource_root
from appsec_analyzer.artifacts import publish_exclusive, read_bounded

FORMATS = ("markdown", "yaml", "html", "pdf", "sarif", "threatdragon", "pentest-tasks")
MAX_FILE = 33_554_432
MAX_TOTAL = 134_217_728


class ExportError(ValueError):
    """Only controller-authored diagnostics may cross the public export boundary."""


def _directory(path: Path, *, private: bool = True) -> None:
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ExportError("export paths must contain only real directories")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise ExportError("export paths must not be writable by other users")
    info = path.stat()
    if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ExportError("assessment and export directories must be owned by you and private (mode 0700)")


def _load(source: Path) -> tuple[bytes, dict, dict[str, bytes], str]:
    from runtime.assessment_state import MAX_STATE_BYTES, SCHEMA, STATE_NAME
    from validators.secret_scan import scan_text
    from validators.validate_intermediate import validate_threat_model_output

    _directory(source)
    state_body = read_bounded(source / STATE_NAME, MAX_STATE_BYTES)
    state = json.loads(state_body)
    if not Draft202012Validator(json.loads(SCHEMA.read_text())).is_valid(state) or state["status"] != "complete":
        raise ExportError("export requires a completed compatible assessment state")
    if len(state["deliverables"]) > 128:
        raise ExportError("too many saved assessment artifacts")
    files = {}
    total = 0
    for name, expected in state["deliverables"].items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
            raise ExportError("invalid saved artifact name")
        body = read_bounded(source / name, MAX_FILE)
        total += len(body)
        if total > MAX_TOTAL or hashlib.sha256(body).hexdigest() != expected:
            raise ExportError("saved assessment artifacts exceed limits or no longer match their recorded hashes")
        files[name] = body
    stems = [s for s in ("security-assessment", "threat-model") if s + ".yaml" in files]
    if len(stems) != 1:
        raise ExportError("assessment needs one unambiguous recorded YAML model")
    stem = stems[0]
    model = yaml.safe_load(files[stem + ".yaml"])
    if not validate_threat_model_output(model)[0]:
        raise ExportError("saved model fails the current assessment contract; migrate or reassess explicitly")
    for name, body in files.items():
        if name.endswith((".yaml", ".json", ".md", ".svg", ".html")) and scan_text(body.decode("utf-8")):
            raise ExportError("saved artifacts contain an unmasked secret; no export was published")
    return state_body, state, files, stem


def _run(arguments: list[str], work: Path) -> None:
    # Converter diagnostics can contain source text. Keep them private and never echo them.
    with tempfile.TemporaryFile(dir=work) as diagnostics:
        process = subprocess.Popen(arguments, cwd=work, stdout=diagnostics, stderr=diagnostics, start_new_session=True)
        try:
            if process.wait(timeout=120):
                raise ExportError("export conversion failed; check the selected format and installed converter tools")
        except subprocess.TimeoutExpired:
            raise ExportError("export conversion exceeded its time limit") from None
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _documents(work: Path, stem: str, files: dict[str, bytes], formats: tuple[str, ...]) -> None:
    from exporters.export_pdf import PANDOC_FORMAT, light_images, rewrite_vscode_links

    from appsec_analyzer.export_assets import validate_document

    for tool in ("pandoc", *(("weasyprint",) if "pdf" in formats else ())):
        if not shutil.which(tool):
            raise ExportError(f"{tool} is required for the selected document export; install it and retry")
    # Validate the same image/link normalization used by the retained converters.
    markdown = light_images(rewrite_vscode_links(files[stem + ".md"].decode("utf-8")))
    (work / (stem + ".md")).write_text(markdown, encoding="utf-8")
    ast_path = work / "report-ast.json"
    _run(["pandoc", stem + ".md", "-f", PANDOC_FORMAT, "-t", "json", "-o", str(ast_path)], work)
    validate_document(json.loads(read_bounded(ast_path, MAX_FILE)), files, markdown)


def export_assessment(assessment: str, output: str, formats: tuple[str, ...]) -> dict:
    try:
        return _export_assessment(assessment, output, formats)
    except ExportError:
        raise
    except Exception:
        raise ExportError(
            "export input or conversion is invalid; check the saved assessment, paths and selected formats"
        ) from None


def _export_assessment(assessment: str, output: str, formats: tuple[str, ...]) -> dict:
    from appsec_analyzer.engine import initialize

    initialize()
    from runtime.assessment_state import STATE_NAME
    from validators.secret_scan import scan_text

    if not formats or len(set(formats)) != len(formats) or set(formats) - set(FORMATS):
        raise ExportError("select distinct supported export formats")
    source, destination = Path(assessment).absolute(), Path(output).absolute()
    if ".." in source.parts or ".." in destination.parts:
        raise ExportError("export paths cannot contain parent traversal")
    original, state, files, stem = _load(source)
    if destination == source or source in destination.parents or destination in source.parents:
        raise ExportError("export destination must be separate from the saved assessment")
    git_markers = [parent / ".git" for parent in (destination, *destination.parents)]
    if any(
        marker.is_symlink() or marker.is_file() or (marker.is_dir() and any(marker.iterdir())) for marker in git_markers
    ):
        raise ExportError("export destination must be outside Git checkouts")
    if any(f in formats for f in ("markdown", "html", "pdf")) and stem + ".md" not in files:
        raise ExportError("the selected format requires the recorded Markdown report")
    # A fresh destination is the exclusive claim; another run cannot take it over.
    _directory(destination.parent, private=False)
    try:
        destination.mkdir(mode=0o700)
    except FileExistsError:
        raise ExportError("export destination already exists; select a new directory") from None
    selected = {}
    warnings = []
    with tempfile.TemporaryDirectory(prefix=".export-", dir=destination) as temporary:
        work = Path(temporary)
        for name, body in files.items():
            with (work / name).open("xb") as handle:
                os.chmod(work / name, 0o600)
                handle.write(body)
        if "markdown" in formats:
            selected[stem + ".md"] = files[stem + ".md"]
            selected.update(
                {name: body for name, body in files.items() if name.endswith((".svg", ".png", ".jpg", ".jpeg"))}
            )
        if "yaml" in formats:
            selected[stem + ".yaml"] = files[stem + ".yaml"]
        if "html" in formats or "pdf" in formats:
            _documents(work, stem, files, formats)
            warnings.append("Document exports retain Mermaid source blocks as text; recorded SVG figures are embedded.")
        exporters = {
            "sarif": ("exporters/export_sarif.py", stem + ".sarif.json", "--threat-model"),
            "threatdragon": ("exporters/export_threat_dragon.py", stem + ".threatdragon.json", "--threat-model"),
            "pentest-tasks": ("renderers/render_pentest_tasks.py", "pentest-tasks.yaml", "--threat-model"),
            "html": ("exporters/export_html.py", stem + ".html", "--input"),
            "pdf": ("exporters/export_pdf.py", stem + ".pdf", "--input"),
        }
        for format_ in formats:
            if format_ not in exporters:
                continue
            script, name, flag = exporters[format_]
            target = work / ("new-" + name)
            args = [
                sys.executable,
                str(resource_root() / "scripts" / script),
                flag,
                stem + (".md" if flag == "--input" else ".yaml"),
                "--output",
                str(target),
            ]
            if format_ in ("html", "pdf"):
                args.append("--no-mermaid")
            _run(args, work)
            selected[name] = read_bounded(target, MAX_FILE)
        if set(formats) & {"sarif", "pentest-tasks"}:
            warnings.append(
                "SARIF and pentest tasks use their existing evidence/CWE filters; YAML retains the complete model."
            )
        if "threatdragon" in formats:
            warnings.append(
                "Threat Dragon is a lossy diagram projection; YAML retains the complete findings and evidence."
            )
        for name, body in selected.items():
            if name.endswith(".svg"):
                from appsec_analyzer.export_assets import validate_svg

                validate_svg(body)
            if name.endswith((".md", ".yaml", ".json", ".html", ".svg")) and scan_text(body.decode("utf-8")):
                raise ExportError("generated export contains an unmasked secret; no export was published")
        # Recheck the exact snapshot after conversion; neither state nor assets may drift.
        if read_bounded(source / STATE_NAME, len(original)) != original:
            raise ExportError("assessment changed during export; no export was published")
        for name, body in files.items():
            if read_bounded(source / name, MAX_FILE) != body:
                raise ExportError("assessment changed during export; no export was published")
        for name, body in selected.items():
            publish_exclusive(destination / name, body)
    return {
        "interface_version": INTERFACE_VERSION,
        "kind": "assessment-export",
        "export_status": "complete",
        "run_id": state["run_id"],
        "model_calls": 0,
        "output": str(destination),
        "deliverables": {name: hashlib.sha256(body).hexdigest() for name, body in selected.items()},
        "warnings": warnings,
    }
