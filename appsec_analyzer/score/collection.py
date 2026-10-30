"""Collect validated scanner signals for repository scoring.

This module owns the score's scanner selection and partial-result policy.
Execution primitives are shared with other workflows.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from appsec_analyzer import resource_root
from appsec_analyzer.scanners.execution import run_python, validate_output
from appsec_analyzer.score.calculation import compute as compute
from appsec_analyzer.score.calculation import top_findings as top_findings

HERE = resource_root() / "scripts"
SCANNER_TIMEOUT_S = 600
UNPARSED_CONFIG = "config-iac: configuration files could not be parsed"

SCANNER_SCHEMAS = {
    "route-inventory": "route-inventory.schema.json",
    "architecture-coverage": "architecture-coverage.schema.json",
    "config-iac": "config-scan-findings.schema.yaml",
    "source-auth": "source-auth-findings.schema.yaml",
}


def _run(argv: list[str], warnings: list[str], label: str) -> bool:
    """Run one scanner. Returns whether it produced output; never raises."""
    try:
        proc = run_python(argv, timeout_s=SCANNER_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        warnings.append(f"{label}: timed out, excluded")
        return False
    except OSError as exc:
        warnings.append(f"{label}: could not run, excluded ({exc})")
        return False
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit {proc.returncode}"
        warnings.append(f"{label}: failed, excluded ({tail})")
        return False
    return True


def _load(path: Path, warnings: list[str], label: str) -> tuple[dict[str, Any], str]:
    """Validate successful producer output; error stubs are never clean scans."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        warnings.append(f"{label}: missing output")
        return {}, "missing"
    except (OSError, ValueError) as exc:
        warnings.append(f"{label}: unreadable output ({exc})")
        return {}, "invalid"
    try:
        schema = yaml.safe_load((HERE.parent / "schemas" / SCANNER_SCHEMAS[label]).read_text(encoding="utf-8"))
        validate_output(data, schema)
    except ValueError:
        warnings.append(f"{label}: producer reported an error")
        return {}, "failed"
    except jsonschema.ValidationError as exc:
        warnings.append(f"{label}: invalid output at {list(exc.absolute_path)}")
        return {}, "invalid"
    return data, "complete"


def collect(
    repo_root: Path,
    work_dir: Path,
    *,
    progress: Callable[[str], None] | None = None,
    completed: Callable[[str, str], None] | None = None,
    runner=None,
) -> tuple[list[dict], list[dict], list[str], dict[str, str]]:
    """Run and validate every required producer outside the target repository."""
    runner = runner or _run
    warnings: list[str] = []
    statuses: dict[str, str] = {}
    repo, out = str(repo_root), str(work_dir)
    scanners = (
        (
            "route-inventory",
            [str(HERE / "analyzers/route_inventory.py"), "--repo-root", repo, "--output-dir", out],
            ".route-inventory.json",
        ),
        (
            "architecture-coverage",
            [str(HERE / "analyzers/architecture_coverage_checks.py"), "--repo-root", repo, "--output-dir", out],
            ".architecture-coverage.json",
        ),
        (
            "config-iac",
            [
                str(HERE / "analyzers/config_iac_scanner.py"),
                "--repo-root",
                repo,
                "--output",
                str(work_dir / ".config-scan.json"),
            ],
            ".config-scan.json",
        ),
        (
            "source-auth",
            [str(HERE / "analyzers/source_auth_scanner.py"), "--repo-root", repo, "--output-dir", out, "--quiet"],
            ".source-auth-findings.json",
        ),
    )
    rules: list[dict] = []
    findings: list[dict] = []
    for label, argv, sidecar in scanners:
        if progress is not None:
            progress(label)
        if not runner(argv, warnings, label):
            statuses[label] = "failed"
            if completed is not None:
                completed(label, statuses[label])
            continue
        data, statuses[label] = _load(work_dir / sidecar, warnings, label)
        if completed is not None:
            completed(label, statuses[label])
        if statuses[label] != "complete":
            continue
        if label == "architecture-coverage":
            rules = data["rules_evaluated"]
        elif label in {"config-iac", "source-auth"}:
            findings.extend({**finding, "_scanner": label} for finding in data["findings"])
            if "unparsed_iac" in data:
                warnings.append(UNPARSED_CONFIG)
    return rules, findings, warnings, statuses
