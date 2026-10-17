"""Versioned public command boundary for deterministic scans and assessments."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
import stat
import sys
import tempfile
from pathlib import Path

import yaml

from appsec_analyzer import ENGINE_VERSION, INTERFACE_VERSION, resource_root


def _engine_imports() -> None:
    scripts = str(resource_root() / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="appsec-analyzer")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="Show engine and public interface versions")
    commands.add_parser("capabilities", help="Show scanner and provider qualification")
    scan = commands.add_parser("scan", help="Run deterministic source scanners without a model")
    scan.add_argument("--repo", action="append", required=True, metavar="PATH")
    scan.add_argument("--output", metavar="DIR", help="Existing directory outside every selected checkout")
    scan.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"), default="standard")
    scan.add_argument("--trust-mode", choices=("untrusted", "trusted"), default="untrusted")
    assess = commands.add_parser("assess", help="Run a full semantic assessment")
    assess.add_argument("--repo", action="append", required=True, metavar="PATH")
    assess.add_argument("--host", choices=("claude-cli", "openai", "gateway"), required=True)
    assess.add_argument("--output", metavar="DIR")
    assess.add_argument("--hard-budget", type=float, required=True, metavar="USD")
    assess.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"), default="standard")
    assess.add_argument("--trust-mode", choices=("untrusted", "trusted"), default="untrusted")
    assess.add_argument("--resume", action="store_true")
    assess.add_argument("--rebuild", action="store_true")
    assess.add_argument("--quiet", action="store_true")
    assess.add_argument("--progress-file", metavar="PATH")
    assess.add_argument("--model", metavar="MODEL")
    for role in ("stride", "triage", "merger"):
        assess.add_argument(f"--{role}-model", metavar="MODEL")
    assess.add_argument("--max-duration", type=int, metavar="SECONDS")
    assess.add_argument("--fail-on", choices=("critical", "high", "medium"))
    assess.add_argument("--evidence-verifier-cap", type=int, metavar="N")
    assess.add_argument("--requirements", nargs="?", const="", metavar="SOURCE")
    assess.add_argument("--context", metavar="SOURCE")
    for flag in ("sarif", "threatdragon", "pdf", "html", "pentest-tasks",
                 "no-requirements", "skip-context", "no-qa", "strict-urls",
                 "ignore-legacy", "migrate-legacy"):
        assess.add_argument("--" + flag, action="store_true")
    for name, help_text in (
        ("status", "Inspect a versioned assessment state"),
        ("progress", "Read the bounded assessment progress feed"),
        ("stop", "Request bounded cancellation of a running assessment"),
        ("results", "List and verify published assessment deliverables"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--output", required=True, metavar="DIR")
    analyst = commands.add_parser("analyst", help="Focused design, change, and hypothesis analysis")
    analyst.add_argument("args", nargs=argparse.REMAINDER)
    return parser


def _capabilities() -> dict:
    return {
        "interface_version": INTERFACE_VERSION,
        "engine_version": ENGINE_VERSION,
        "scan": {"available": True, "model_calls": False},
        "assessment": {
            "providers": {
                "claude-cli": {"adapter": "compatibility", "qualified": False},
                "openai": {"adapter": "pending", "qualified": False},
                "gateway": {"adapter": "pending", "qualified": False},
            }
        },
    }


def _scan(ns: argparse.Namespace) -> int:
    _engine_imports()
    from runtime.remote_repositories import checkout_arguments

    selected = [part for repo in ns.repo for part in ("--repo", repo)]
    if ns.output:
        selected += ["--output", ns.output]
    with checkout_arguments(selected) as local_args:
        local = argparse.Namespace(**vars(ns))
        local.repo = [local_args[i + 1] for i, item in enumerate(local_args[:-1]) if item == "--repo"]
        return _scan_local(local)


def _scan_local(ns: argparse.Namespace) -> int:
    _engine_imports()
    from jsonschema import Draft202012Validator
    from model.assessment_scanner_findings import SIDECARS, _scanner_outputs
    from orchestrator.orchestration_controller import _assessment_preflight
    from runtime.multi_repo_scope import ScopeError, admit

    if ns.trust_mode == "untrusted":
        _assessment_preflight(ns.repo)
    with tempfile.TemporaryDirectory(prefix="appsec-scan-output-") as temporary:
        requested_output = ns.output or temporary
        # The scan never writes into a checkout. This avoids changing the
        # admitted source while checking it and makes output authority explicit.
        if ns.output:
            selected = Path(ns.output)
            if not selected.is_dir() or selected.resolve() != selected.absolute():
                raise ValueError("--output must name an existing real directory")
        try:
            scope = admit(ns.repo, requested_output, minimum=1)
        except ScopeError as exc:
            raise ValueError(f"repository selection rejected: {exc}") from exc
        if scope.output_in_checkout():
            raise ValueError("scan output must be outside every selected checkout")
        inventory = scope.inventory()
        sidecar_schema = yaml.safe_load(
            (resource_root() / "schemas/source-auth-findings.schema.yaml").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(sidecar_schema)
        repositories = []
        for view in sorted(scope.repositories, key=lambda row: row.repository_id):
            documents, config = _scanner_outputs(scope, view.repository_id, ns.assessment_depth)
            records = []
            for name, document in zip(SIDECARS, documents, strict=True):
                if list(validator.iter_errors(document)) or "parse_error" in document:
                    raise ValueError("a deterministic scanner produced an invalid sidecar")
                for finding in document["findings"]:
                    path = finding["file"]
                    if path not in view.files or type(finding.get("line")) is not int or finding["line"] < 1:
                        raise ValueError("a scanner finding cites source outside the admitted snapshot")
                    records.append({
                        "scanner": name.removeprefix(".").removesuffix("-findings.json"),
                        "source_sha256": hashlib.sha256(view.files[path]).hexdigest(),
                        "finding": finding,
                    })
            if config is not None:
                for finding in config["findings"]:
                    paths = finding.get("searched_files") if finding.get("evidence_kind") == "absence" else [finding["file"]]
                    if not isinstance(paths, list) or any(p not in view.files for p in paths):
                        raise ValueError("a config finding cites source outside the admitted snapshot")
                    records.append({"scanner": "config-iac", "finding": finding})
            repositories.append({
                "repository_id": view.repository_id,
                "label": view.root.name,
                "head": view.head,
                "state_sha256": view.state_sha256,
                "captured_files": len(view.files),
                "excluded_files": list(view.exclusions),
                "config_iac_applicable": config is not None,
                "findings": records,
            })
        scope.verify_unchanged()
        result = {
            "interface_version": INTERFACE_VERSION,
            "kind": "deterministic-scan",
            "scan_status": "completed",
            "assessment_status": "not_run",
            "scope_sha256": inventory["scope_sha256"],
            "depth": ns.assessment_depth,
            "coverage": {
                "scanners": ["source-auth", "authz-confirm", "mass-assignment", "config-iac"],
                "semantic_analysis": False,
                "component_assignment": False,
                "evidence_verification": False,
            },
            "repositories": repositories,
        }
        schema = json.loads((resource_root() / "schemas/deterministic-scan-result.schema.json").read_text())
        if list(Draft202012Validator(schema).iter_errors(result)):
            raise ValueError("deterministic scan result failed its public schema")
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        if ns.output:
            _write_result(Path(ns.output), payload)
        else:
            sys.stdout.write(payload)
    return 0


def _write_result(directory: Path, payload: str) -> None:
    """Publish one complete result without following an output-file symlink."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(directory, flags)
    try:
        name = "scan-result.json"
        tmp = f".{name}.{os.getpid()}.tmp"
        item = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(item, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(tmp, dir_fd=fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(fd)


def _assess(ns: argparse.Namespace) -> int:
    _engine_imports()
    if ns.host != "claude-cli":
        raise ValueError(f"{ns.host} has no qualified model/depth profile")
    # The host-specific preflight runs only after explicit host selection.
    from appsec_analyzer.hosts import claude_preflight
    from orchestrator.orchestration_controller import assess_main
    from runtime.remote_repositories import checkout_arguments

    claude_preflight()
    args = ["--repo", ns.repo[0]]
    for repo in ns.repo[1:]:
        args += ["--repo", repo]
    args += ["--hard-budget", str(ns.hard_budget), "--assessment-depth", ns.assessment_depth,
             "--trust-mode", ns.trust_mode]
    for flag in ("output", "progress_file", "model", "stride_model", "triage_model",
                 "merger_model", "max_duration", "fail_on", "evidence_verifier_cap", "context"):
        if value := getattr(ns, flag):
            args += ["--" + flag.replace("_", "-"), str(value)]
    if ns.requirements is not None:
        args.append("--requirements")
        if ns.requirements:
            args.append(ns.requirements)
    for flag in ("resume", "rebuild", "quiet", "sarif", "threatdragon", "pdf", "html",
                 "pentest_tasks", "no_requirements", "skip_context", "no_qa", "strict_urls",
                 "ignore_legacy", "migrate_legacy"):
        if getattr(ns, flag):
            args.append("--" + flag)
    with checkout_arguments(args) as local_args:
        return assess_main(local_args)


def _state(ns: argparse.Namespace) -> tuple[Path, dict]:
    _engine_imports()
    from runtime.assessment_state import STATE_NAME, _read_state, _real_directory

    output = Path(ns.output).absolute()
    _real_directory(output)
    state = _read_state(output / STATE_NAME)
    return output, state


def _bounded_file(path: Path, limit: int) -> bytes:
    """Read a regular, singly linked owned artifact without following links."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError("assessment artifact is not a bounded regular file")
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError("assessment artifact exceeds its size limit")
        return data
    finally:
        os.close(fd)


def _inspect(ns: argparse.Namespace) -> int:
    output, state = _state(ns)
    if ns.command == "status":
        document = {
            "interface_version": INTERFACE_VERSION,
            "kind": "assessment-status",
            "run_id": state["run_id"],
            "assessment_status": state["status"],
            "started_at": state["started_at"],
            "expires_at": state["expires_at"],
            "accounting": state["accounting"],
            "deliverables": sorted(state["deliverables"]),
        }
    elif ns.command == "progress":
        from runtime.assessment_state import PROGRESS_NAME

        data = _bounded_file(output / PROGRESS_NAME, 1_048_576)
        entries = [json.loads(line) for line in data.splitlines()[-100:]]
        if any(not isinstance(row, dict) for row in entries):
            raise ValueError("assessment progress contains a non-object event")
        document = {"interface_version": INTERFACE_VERSION, "kind": "assessment-progress",
                    "run_id": state["run_id"], "events": entries}
    elif ns.command == "stop":
        from orchestrator.orchestration_controller import assess_stop

        action = assess_stop(output)
        document = {"interface_version": INTERFACE_VERSION, "kind": "assessment-stop", **action}
    else:
        from runtime.assessment_state import _deliverable

        if state["status"] != "complete":
            raise ValueError("assessment results are available only after completion")
        for name, expected in state["deliverables"].items():
            if _deliverable(output, name) != expected:
                raise ValueError("assessment deliverable no longer matches its recorded digest")
        document = {"interface_version": INTERFACE_VERSION, "kind": "assessment-results",
                    "run_id": state["run_id"], "assessment_status": "complete",
                    "deliverables": state["deliverables"]}
    print(json.dumps(document, sort_keys=True))
    return 0


def _analyst(ns: argparse.Namespace) -> int:
    _engine_imports()
    script = resource_root() / "scripts" / "appsec-analyst-cli"
    return runpy.run_path(str(script), run_name="appsec_analyzer.analyst")["main"](ns.args)


def main(argv: list[str] | None = None) -> int:
    ns = _parser().parse_args(argv)
    try:
        if ns.command == "version":
            print(json.dumps({"engine_version": ENGINE_VERSION, "interface_version": INTERFACE_VERSION}))
            return 0
        if ns.command == "capabilities":
            print(json.dumps(_capabilities(), sort_keys=True))
            return 0
        if ns.command == "scan":
            return _scan(ns)
        if ns.command == "assess":
            return _assess(ns)
        if ns.command in ("status", "progress", "stop", "results"):
            return _inspect(ns)
        if ns.command == "analyst":
            return _analyst(ns)
        raise ValueError(f"{ns.command} is not implemented")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"appsec-analyzer: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
