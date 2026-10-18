"""Shared validation of completed assessment artifacts; no model or writes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from appsec_analyzer.artifacts import read_bounded

MAX_FILE = 33_554_432
MAX_TOTAL = 134_217_728


class SavedAssessmentError(ValueError):
    """Safe diagnostics for saved assessment admission."""


def validate_directory(path: Path, *, private: bool = True) -> None:
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise SavedAssessmentError("export paths must contain only real directories")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise SavedAssessmentError("export paths must not be writable by other users")
    info = path.stat()
    if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise SavedAssessmentError("assessment and export directories must be owned by you and private (mode 0700)")


def load_assessment(source: Path) -> tuple[bytes, dict, dict[str, bytes], str]:
    from runtime.assessment_state import MAX_STATE_BYTES, SCHEMA, STATE_NAME
    from validators.secret_scan import scan_text
    from validators.validate_intermediate import validate_threat_model_output

    validate_directory(source)
    state_body = read_bounded(source / STATE_NAME, MAX_STATE_BYTES)
    state = json.loads(state_body)
    if not Draft202012Validator(json.loads(SCHEMA.read_text())).is_valid(state) or state["status"] != "complete":
        raise SavedAssessmentError("operation requires a completed compatible assessment state")
    if len(state["deliverables"]) > 128:
        raise SavedAssessmentError("too many saved assessment artifacts")
    files = {}
    total = 0
    for name, expected in state["deliverables"].items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
            raise SavedAssessmentError("invalid saved artifact name")
        body = read_bounded(source / name, MAX_FILE)
        total += len(body)
        if total > MAX_TOTAL or hashlib.sha256(body).hexdigest() != expected:
            raise SavedAssessmentError(
                "saved assessment artifacts exceed limits or no longer match their recorded hashes"
            )
        files[name] = body
    stems = [s for s in ("security-assessment", "threat-model") if s + ".yaml" in files]
    if len(stems) != 1:
        raise SavedAssessmentError("assessment needs one unambiguous recorded YAML model")
    stem = stems[0]
    model = yaml.safe_load(files[stem + ".yaml"])
    if not validate_threat_model_output(model)[0]:
        raise SavedAssessmentError("saved model fails the current assessment contract; migrate or reassess explicitly")
    for name, body in files.items():
        if name.endswith((".yaml", ".json", ".md", ".svg", ".html")) and scan_text(body.decode("utf-8")):
            raise SavedAssessmentError("saved artifacts contain an unmasked secret; operation was refused")
    return state_body, state, files, stem
