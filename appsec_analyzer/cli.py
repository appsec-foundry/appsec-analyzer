"""Versioned public command boundary for deterministic scans and assessments."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import runpy
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from appsec_analyzer import ENGINE_VERSION, INTERFACE_VERSION, resource_root
from appsec_analyzer.execution_limits import DEFAULT_MAX_PARALLEL, MAX_PARALLEL

# Operator-selected built-ins only; repository content cannot select a provider.
_PROFILE_HOSTS = {
    "claude": "claude-cli",
    "codex": "openai",
    "codex-cli": "codex-cli",
    "lite": "lite",
    "bedrock": "bedrock",
}
_LEGACY_CODEX_PROFILES = ("codex-quick", "codex-standard", "codex-thorough")


class _Explicit(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        namespace.explicit = {*getattr(namespace, "explicit", ()), self.dest}


def _engine_imports() -> None:
    scripts = str(resource_root() / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)


def _parser(*, organization=None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=organization.command if organization else "appsec-analyzer")
    commands = parser.add_subparsers(dest="command", required=True)
    if organization is not None:
        org = commands.add_parser("organization", help="Inspect or validate the bundled defaults without model calls")
        org.add_argument("action", choices=("show", "validate"))
    commands.add_parser("version", help="Show engine and public interface versions")
    commands.add_parser("capabilities", help="Show scanner and provider qualification")
    profiles = commands.add_parser("profiles", help="List, inspect, or validate profiles without model calls")
    actions = profiles.add_subparsers(dest="profile_action", required=True)
    actions.add_parser("list", help="List built-in and user scan/model profiles")
    for action in ("show", "validate"):
        command = actions.add_parser(action, help=f"{action.capitalize()} a scan profile and its models")
        command.add_argument("selection", metavar="NAME_OR_FILE")
        command.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"))
        command.add_argument("--budget", type=_positive_budget)
        command.add_argument("--max-calls", type=int, metavar="N")
        command.add_argument("--max-parallel", type=int, choices=range(1, MAX_PARALLEL + 1), metavar="N")
        command.add_argument("--model", help="Provider selection, for example 'lite claude' or 'bedrock claude'")
        command.add_argument(
            "--outputs",
            nargs="+",
            choices=("markdown", "yaml", "html", "pdf", "sarif", "threatdragon", "pentest-tasks"),
        )
    scan = commands.add_parser(
        "scan",
        help="Run the full headless security assessment with live progress",
        description="Assess the selected repository with live progress and publish security reports.",
        epilog=(
            "Bundled organization and scan profiles are selected automatically; explicit options override defaults."
            if organization
            else "Example: appsec-analyzer scan (USD 20 budget); override with --budget USD"
        ),
    )
    _add_assessment_arguments(scan, default_repo=True, organization=organization)
    sources = commands.add_parser("scan-sources", help="Run deterministic source scanners without a model")
    sources.add_argument("--repo", action="append", required=True, metavar="PATH")
    sources.add_argument("--output", metavar="DIR", help="Existing directory outside every selected checkout")
    sources.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"), default="standard")
    sources.add_argument("--trust-mode", choices=("untrusted", "trusted"), default="untrusted")
    sources.add_argument("--json", action="store_true", help="Print the complete machine-readable result")
    score = commands.add_parser(
        "score",
        help="Compute a deterministic security score without a model",
        description="Compute a limited scanner-based score for one local Git checkout or explicit Git URL.",
        epilog=(
            "Text colors follow terminal settings (NO_COLOR/FORCE_COLOR). "
            "Exit codes: 0 scored; 2 undetermined or invalid arguments; 1 incomplete scan or operational error; 130 cancelled."
        ),
    )
    score.add_argument("repo", metavar="REPO", help="Top-level local Git checkout or HTTPS/SSH Git URL")
    formats = score.add_mutually_exclusive_group()
    formats.add_argument("--json", action="store_true", help="Print the complete machine-readable JSON result")
    formats.add_argument("--yaml", action="store_true", help="Print the same result as YAML")
    assess = commands.add_parser(
        "assess",
        help="Run a full semantic assessment"
        if organization
        else "Run a full semantic assessment with an explicit scan profile",
    )
    _add_assessment_arguments(assess, default_repo=False, organization=organization)

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
    audit = commands.add_parser("audit-requirements", help="Run a separate, bounded requirements audit")
    audit.add_argument("--repo", required=True, metavar="PATH")
    audit.add_argument("--output", required=True, metavar="DIR")
    audit.add_argument("--host", choices=("claude-cli",), required=True)
    source = audit.add_mutually_exclusive_group(required=True)
    source.add_argument("--requirements", metavar="FILE")
    source.add_argument("--demo", action="store_true")
    audit.add_argument(
        "--budget",
        "--hard-budget",
        dest="hard_budget",
        type=_positive_budget,
        default=5.0,
        metavar="USD",
        help="Maximum model cost in USD (default: %(default)g)",
    )
    audit.add_argument("--model", default="sonnet", metavar="MODEL")
    audit.add_argument("--category", metavar="FILTER")
    audit.add_argument("--md", action="store_true")
    audit.add_argument("--gate", action="store_true")
    audit.add_argument("--gate-on", choices=("fail", "partial"), default="fail")
    audit.add_argument("--priority-floor", choices=("MUST", "SHOULD", "MAY"), default="MUST")
    return parser


def _positive_budget(value: str) -> float:
    try:
        amount = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive finite USD amount") from exc
    if not math.isfinite(amount) or amount <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite USD amount")
    return amount


def _pentest_target(value: str) -> str:
    if any(char.isspace() or ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise argparse.ArgumentTypeError("must be an HTTP or HTTPS URL without control characters")
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in ("http", "https") and bool(parsed.hostname) and not parsed.username and not parsed.password
        )
        _ = parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError("must be an HTTP or HTTPS URL without embedded credentials")
    return value


def _slug(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
        raise argparse.ArgumentTypeError("must contain 1-64 letters, digits, dots, underscores, or hyphens")
    return value


def _add_assessment_arguments(parser: argparse.ArgumentParser, *, default_repo: bool, organization=None) -> None:
    parser.add_argument(
        "--repo",
        action="append",
        required=not default_repo,
        metavar="PATH",
        help="Repository to assess (default: current directory)" if default_repo else "Repository to assess",
    )
    parser.add_argument(
        "--host",
        choices=("claude-cli", "openai", "gateway", "codex-cli", "lite", "bedrock"),
        help="Legacy provider selection; --profile selects the host automatically",
    )
    parser.add_argument(
        "--profile",
        metavar="NAME_OR_FILE",
        help=(
            "Override the bundled scan profile with NAME_OR_FILE"
            if organization
            else "Scan profile name or external YAML file (default: claude; built-ins: claude, codex, codex-cli, lite, bedrock; also 'lite MODEL')"
        ),
    )
    parser.add_argument("--output", metavar="DIR", help="Assessment directory outside the repository")
    parser.add_argument(
        "--budget",
        "--hard-budget",
        dest="hard_budget",
        type=_positive_budget,
        action=_Explicit,
        default=20.0,
        metavar="USD",
        help="Maximum model cost in USD (built-in default: %(default)g; user profile may override; unavailable with codex-cli)",
    )
    parser.add_argument(
        "--assessment-depth", choices=("quick", "standard", "thorough"), default="standard", action=_Explicit
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        choices=range(1, MAX_PARALLEL + 1),
        metavar="N",
        help=f"Assess at most N components at once (1–{MAX_PARALLEL}; default: {DEFAULT_MAX_PARALLEL}; overrides profile)",
    )
    parser.add_argument(
        "--outputs",
        nargs="+",
        choices=("markdown", "yaml", "html", "pdf", "sarif", "threatdragon", "pentest-tasks"),
        help="Replace profile export selection; Markdown and YAML remain the base result",
    )
    parser.add_argument("--trust-mode", choices=("untrusted", "trusted"), default="untrusted")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--non-interactive", action="store_true", help="Never prompt to increase the assessment budget (use in CI)"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Show correlated model calls and sanitized correction details"
    )
    parser.add_argument("--progress-file", metavar="PATH")
    parser.add_argument(
        "--model",
        metavar="MODEL",
        help="Model selection; 'lite NAME' or 'bedrock NAME' selects a configured provider model",
    )
    parser.add_argument(
        "--reasoning-model", choices=("sonnet", "opus-cheap", "opus", "sonnet-economy", "haiku-economy")
    )
    parser.add_argument("--project", metavar="NAME")
    parser.add_argument("--width", type=int, metavar="COLUMNS")
    parser.add_argument(
        "--slug",
        nargs="?",
        const="__auto__",
        type=_slug,
        metavar="NAME",
        help="Also publish copies with this filename suffix; bare flag chooses one",
    )
    parser.add_argument(
        "--pentest-format",
        choices=("generic", "strix"),
        default="generic",
        help="Format for --pentest-tasks (default: generic)",
    )
    parser.add_argument(
        "--pentest-target",
        type=_pentest_target,
        metavar="URL",
        help="HTTP(S) target URL to include in exported pentest tasks",
    )
    parser.add_argument("--org-profile", metavar="FILE")
    parser.add_argument("--preset", metavar="NAME")
    parser.add_argument("--no-org-profile", action="store_true")
    for role in ("stride", "triage", "merger"):
        parser.add_argument(f"--{role}-model", metavar="MODEL")
    parser.add_argument(
        "--max-calls",
        type=int,
        metavar="N",
        help="Maximum Codex CLI model exchanges including retries (default: 1000; subscription only)",
    )
    parser.add_argument("--max-duration", type=int, metavar="SECONDS")
    parser.add_argument("--fail-on", choices=("critical", "high", "medium"))
    parser.add_argument("--evidence-verifier-cap", type=int, metavar="N")
    parser.add_argument("--requirements", nargs="?", const="", metavar="SOURCE")
    parser.add_argument("--context", metavar="SOURCE")
    parser.add_argument(
        "--abuse-case-file",
        action="append",
        metavar="PATH",
        help="Repository-relative YAML case file; repeat for several files (replaces profile selection)",
    )
    parser.add_argument(
        "--keep-runtime-files", action="store_true", help="Retain private intermediate assessment files for debugging"
    )
    for flag in (
        "sarif",
        "threatdragon",
        "pdf",
        "html",
        "pentest-tasks",
        "no-requirements",
        "skip-context",
        "no-qa",
        "ignore-legacy",
        "migrate-legacy",
    ):
        parser.add_argument("--" + flag, action="store_true")


def _capabilities() -> dict:
    return {
        "interface_version": INTERFACE_VERSION,
        "engine_version": ENGINE_VERSION,
        "scan": {"available": True, "model_calls": True},
        "scan_sources": {"available": True, "model_calls": False},
        "score": {"available": True, "model_calls": False, "scoring_version": 2},
        "profiles": {"schema_version": 1, "user_defined": True, "inspection_model_calls": False},
        "organization_distributions": {
            "available": True,
            "manifest_schema_version": 1,
            "inspection_model_calls": False,
        },
        "assessment": {
            "providers": {
                "claude-cli": {"adapter": "compatibility", "qualified": False, "profiles": ["claude"]},
                "openai": {"adapter": "responses", "qualified": False, "profiles": ["codex", *_LEGACY_CODEX_PROFILES]},
                "gateway": {"adapter": "offline-only", "qualified": False},
                "lite": {"adapter": "responses", "qualified": False, "profiles": ["lite"], "model_prefix": "lite "},
                "bedrock": {
                    "adapter": "converse",
                    "qualified": False,
                    "profiles": ["bedrock"],
                    "model_prefix": "bedrock ",
                },
                "codex-cli": {
                    "adapter": "cli",
                    "billing": "chatgpt-subscription",
                    "qualified": False,
                    "profiles": ["codex-cli"],
                },
            }
        },
        "requirements_audit": {"available": True, "host": "claude-cli", "qualified": False},
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


def _score(ns: argparse.Namespace) -> int:
    try:
        return _run_score(ns)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # Prevent a second error when Python flushes a closed output pipe at exit.
        with open(os.devnull, "w") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        return 1
    except Exception:  # noqa: BLE001 — public CLI boundary; never expose raw internal exceptions
        print(
            "appsec-analyzer: error: Security score could not finish. "
            "Retry the command; if it persists, check the Analyzer installation and report the failing stage.",
            file=sys.stderr,
        )
        return 1


def _run_score(ns: argparse.Namespace) -> int:
    from appsec_analyzer.score_progress import ScoreProgress

    with ScoreProgress(repository=ns.repo) as progress:
        try:
            _engine_imports()
            from renderers.term_style import Style

            from appsec_analyzer.scoring import ScoreError, render_text, score_repository
        except (ImportError, OSError, RuntimeError):
            progress.finish("failed")
            print(
                "appsec-analyzer: error: Security score runtime resources are unavailable. "
                "Check or reinstall Analyzer in the active Python environment.",
                file=sys.stderr,
            )
            return 1

        try:
            result = score_repository(ns.repo, progress=progress)
        except ScoreError as exc:
            progress.finish("failed")
            print(f"appsec-analyzer: error: {exc}", file=sys.stderr)
            return 1
        if ns.json:
            output = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        elif ns.yaml:
            output = yaml.safe_dump(result, sort_keys=False, allow_unicode=False)
        else:
            output = (
                render_text(
                    result,
                    style=Style.for_stream(sys.stdout),
                    width=shutil.get_terminal_size(fallback=(88, 24)).columns,
                )
                + "\n"
            )
        progress.finish(result["verdict"])
    print(output, end="", flush=True)
    return {"scored": 0, "undetermined": 2, "incomplete": 1}[result["verdict"]]


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
                    records.append(
                        {
                            "scanner": name.removeprefix(".").removesuffix("-findings.json"),
                            "source_sha256": hashlib.sha256(view.files[path]).hexdigest(),
                            "finding": finding,
                        }
                    )
            if config is not None:
                for finding in config["findings"]:
                    paths = (
                        finding.get("searched_files")
                        if finding.get("evidence_kind") == "absence"
                        else [finding["file"]]
                    )
                    if not isinstance(paths, list) or any(p not in view.files for p in paths):
                        raise ValueError("a config finding cites source outside the admitted snapshot")
                    records.append({"scanner": "config-iac", "finding": finding})
            repositories.append(
                {
                    "repository_id": view.repository_id,
                    "label": view.root.name,
                    "head": view.head,
                    "state_sha256": view.state_sha256,
                    "captured_files": len(view.files),
                    "excluded_files": list(view.exclusions),
                    "config_iac_applicable": config is not None,
                    "findings": records,
                }
            )
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
        if ns.json:
            sys.stdout.write(payload)
        else:
            sys.stdout.write(_scan_summary(result, output=ns.output))
    return 0


def _terminal_field(value: object) -> str:
    """Keep repository-controlled names and scanner text on one terminal line."""
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))).strip()[:240]


def _scan_summary(result: dict, *, output: str | None) -> str:
    lines = ["Deterministic scan completed."]
    for repository in result["repositories"]:
        findings = repository["findings"]
        lines.extend(
            [
                f"\nRepository: {_terminal_field(repository['label'])}",
                f"Files scanned: {repository['captured_files']}; excluded: {len(repository['excluded_files'])}",
                f"Scanner findings: {len(findings)} (unverified)",
            ]
        )
        for record in findings:
            finding = record["finding"]
            severity = _terminal_field(finding.get("severity", "Unknown"))
            path = _terminal_field(finding.get("file", ""))
            line = finding.get("line")
            location = f"{path}:{line}" if type(line) is int else path
            title = _terminal_field(finding.get("title", finding.get("check_id", "Finding")))
            lines.append(f"  {severity}: {location}: {title}")
    if output:
        lines.append(f"\nComplete JSON result: {_terminal_field(Path(output) / 'scan-result.json')}")
    lines.extend(
        [
            "\nFull assessment was not run.",
            "For the full assessment: appsec-analyzer scan --repo PATH --budget USD",
        ]
    )
    return "\n".join(lines) + "\n"


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


def _assessment_host(ns: argparse.Namespace) -> str:
    """Resolve operator options before host preflight or source retrieval."""
    if getattr(ns, "run_profile", None):
        host = ns.run_profile["adapter"]
        if ns.host is not None and ns.host != host:
            raise ValueError("selected profile conflicts with --host")
        return host
    if ns.profile in _PROFILE_HOSTS:
        host = _PROFILE_HOSTS[ns.profile]
        if ns.host is not None and ns.host != host:
            raise ValueError(f"--profile {ns.profile} conflicts with --host {ns.host}")
        return host
    if ns.profile:
        if ns.host != "openai":
            raise ValueError("legacy --profile codex-<depth> requires --host openai; use --profile codex")
        if ns.profile != f"codex-{ns.assessment_depth}":
            raise ValueError("legacy --profile must match --assessment-depth; use --profile codex")
    if ns.host is not None:
        return ns.host
    if ns.command == "scan":
        return _PROFILE_HOSTS["claude"]
    raise ValueError("assess requires --profile (claude, codex, or codex-cli) or a legacy --host")


def _prepare_profile(ns: argparse.Namespace) -> None:
    if getattr(ns, "run_profile", None):
        return
    from appsec_analyzer.profiles import OUTPUTS, resolve_scan
    from appsec_analyzer.providers import selection as provider_selection

    selection = ns.profile
    model_prefix = provider_selection(ns.model) if ns.model else None
    if selection is None and ns.host is None and model_prefix:
        selection = model_prefix[0]
    if selection in _LEGACY_CODEX_PROFILES or (selection is None and ns.host):
        host = _assessment_host(ns)
        selection = {
            "openai": "codex",
            "claude-cli": "claude",
            "codex-cli": "codex-cli",
            "lite": "lite",
            "bedrock": "bedrock",
        }.get(host)
        if not selection:
            raise ValueError(f"{host} has no configured model/depth profile")
    if not selection:
        if ns.command == "assess":
            _assessment_host(ns)
        selection = "claude"
    explicit = getattr(ns, "explicit", ())
    profile = resolve_scan(
        selection,
        depth=ns.assessment_depth if "assessment_depth" in explicit else None,
        budget=ns.hard_budget if "hard_budget" in explicit else None,
        max_parallel=ns.max_parallel,
        max_calls=ns.max_calls,
        outputs=ns.outputs,
        abuse_case_files=ns.abuse_case_file,
        repositories=ns.repo or [str(Path.cwd())],
        model_override=ns.model if model_prefix or selection in ("lite", "bedrock") else None,
    )
    selected = set(profile["settings"]["outputs"]) | {"markdown", "yaml"}
    for output in OUTPUTS[2:]:
        if getattr(ns, output.replace("-", "_"), False):
            selected.add(output)
            profile["origins"]["settings"]["outputs"] = "CLI export flags"
    profile["settings"]["outputs"] = [item for item in OUTPUTS if item in selected]
    ns.assessment_depth = profile["settings"]["assessment_depth"]
    ns.hard_budget = profile["settings"]["budget"]
    ns.max_parallel = profile["settings"]["max_parallel"]
    ns.abuse_case_file = profile["settings"]["abuse_case_files"]
    for output in OUTPUTS[2:]:
        setattr(ns, output.replace("-", "_"), output in selected)
    ns.run_profile = profile


def _assess(ns: argparse.Namespace) -> int:
    _prepare_profile(ns)
    host = _assessment_host(ns)
    _engine_imports()
    api_profile = None
    if host == "openai":
        from appsec_analyzer.codex_profiles import CODEX_PROFILES
        from appsec_analyzer.profiles import api_profile as make_api_profile

        api_profile = (
            CODEX_PROFILES[ns.assessment_depth]
            if not ns.run_profile["files"]
            else make_api_profile(ns.run_profile["models"]["stride_analyzer"])
        )
        if ns.model and ns.model not in (
            api_profile.model,
            ns.run_profile["models"]["stride_analyzer"]["requested_model"],
        ):
            raise ValueError("--model differs from the selected OpenAI profile")
        if ns.reasoning_model or any(getattr(ns, f"{role}_model") for role in ("stride", "triage", "merger")):
            raise ValueError("Claude reasoning and role-model overrides cannot be used with the OpenAI profile")
        if ns.model:
            ns.model = api_profile.model
    elif host == "codex-cli":
        if ns.reasoning_model or any(getattr(ns, f"{role}_model") for role in ("stride", "triage", "merger")):
            raise ValueError("use a model profile for codex-cli role overrides")
        selected = ns.run_profile["models"]["stride_analyzer"]
        if ns.model and ns.model not in (selected["model"], selected["requested_model"]):
            raise ValueError("--model differs from the selected Codex CLI profile")
        ns.model = selected["model"]
    elif host in ("lite", "bedrock"):
        from appsec_analyzer.api_hosts import ApiTransportError, credential
        from appsec_analyzer.profiles import api_profile as make_api_profile

        if ns.reasoning_model or any(getattr(ns, f"{role}_model") for role in ("stride", "triage", "merger")):
            raise ValueError("use a model profile for provider role and reasoning overrides")
        selected = ns.run_profile["models"]["stride_analyzer"]
        if ns.model and ns.model not in (selected["model"], selected["requested_model"]):
            raise ValueError("--model differs from the selected provider profile; use a provider-prefixed model")
        api_profile = make_api_profile(selected)
        ns.model = selected["model"]
        try:
            credential(api_profile)
        except ApiTransportError:
            raise ValueError(
                f"{api_profile.key_env} is required and must contain a valid external credential"
            ) from None
    elif host != "claude-cli":
        raise ValueError(f"{host} has no configured model/depth profile")
    if ns.keep_runtime_files and ns.output:
        output = Path(ns.output).absolute()
        try:
            info = output.stat()
            private = (
                output.resolve(strict=True) == output
                and stat.S_ISDIR(info.st_mode)
                and info.st_mode & 0o077 == 0
                and (not hasattr(os, "getuid") or info.st_uid == os.getuid())
            )
        except OSError:
            private = False
        if not private:
            raise ValueError("--keep-runtime-files requires an existing private --output directory (mode 0700)")
    # The host-specific preflight runs only after resolving the selected profile.
    from orchestrator.orchestration_controller import assess_main
    from runtime.remote_repositories import checkout_arguments

    if host == "claude-cli":
        from appsec_analyzer.hosts import claude_preflight

        claude_preflight()
    elif host == "codex-cli":
        from appsec_analyzer.codex_cli import preflight

        runtime = preflight(repositories=ns.repo or [str(Path.cwd())])
        ns.run_profile["cli_version"] = runtime["version"]
    repositories = ns.repo or [str(Path.cwd())]
    args = ["--repo", repositories[0]]
    for repo in repositories[1:]:
        args += ["--repo", repo]
    if host == "codex-cli":
        args += ["--max-calls", str(ns.run_profile["settings"]["max_calls"])]
    else:
        args += ["--hard-budget", str(ns.hard_budget)]
    args += [
        "--max-parallel",
        str(ns.max_parallel),
        "--assessment-depth",
        ns.assessment_depth,
        "--trust-mode",
        ns.trust_mode,
    ]
    for flag in (
        "output",
        "progress_file",
        "model",
        "reasoning_model",
        "project",
        "width",
        "pentest_format",
        "pentest_target",
        "org_profile",
        "preset",
        "stride_model",
        "triage_model",
        "merger_model",
        "max_duration",
        "fail_on",
        "evidence_verifier_cap",
        "context",
    ):
        if value := getattr(ns, flag):
            args += ["--" + flag.replace("_", "-"), str(value)]
    if ns.requirements is not None:
        args.append("--requirements")
        if ns.requirements:
            args.append(ns.requirements)
    for path in ns.abuse_case_file:
        args.append(f"--abuse-case-file={path}")
    if ns.slug is not None:
        args.append("--slug")
        if ns.slug != "__auto__":
            args.append(ns.slug)
    for flag in (
        "resume",
        "rebuild",
        "quiet",
        "non_interactive",
        "verbose",
        "sarif",
        "threatdragon",
        "pdf",
        "html",
        "pentest_tasks",
        "keep_runtime_files",
        "no_requirements",
        "skip_context",
        "no_qa",
        "ignore_legacy",
        "migrate_legacy",
        "no_org_profile",
    ):
        if getattr(ns, flag):
            args.append("--" + flag.replace("_", "-"))
    with checkout_arguments(args) as local_args:
        from appsec_analyzer.profiles import reject_source_paths

        reject_source_paths(
            ns.run_profile["files"], [local_args[i + 1] for i, arg in enumerate(local_args[:-1]) if arg == "--repo"]
        )
        if api_profile is not None:
            return assess_main(local_args, api_profile=api_profile, run_profile=ns.run_profile)
        return assess_main(local_args, run_profile=ns.run_profile)


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

        feed = output / PROGRESS_NAME
        data = _bounded_file(feed, 1_048_576) if os.path.lexists(feed) else b""
        entries = [json.loads(line) for line in data.splitlines()[-100:]]
        if any(not isinstance(row, dict) for row in entries):
            raise ValueError("assessment progress contains a non-object event")
        document = {
            "interface_version": INTERFACE_VERSION,
            "kind": "assessment-progress",
            "run_id": state["run_id"],
            "assessment_status": state["status"],
            "feed_available": bool(data),
            "events": entries,
        }
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
        document = {
            "interface_version": INTERFACE_VERSION,
            "kind": "assessment-results",
            "run_id": state["run_id"],
            "assessment_status": "complete",
            "deliverables": state["deliverables"],
        }
    print(json.dumps(document, sort_keys=True))
    return 0


def _analyst(ns: argparse.Namespace) -> int:
    _engine_imports()
    script = resource_root() / "scripts" / "appsec-analyst-cli"
    return runpy.run_path(str(script), run_name="appsec_analyzer.analyst")["main"](ns.args)


def _audit(ns: argparse.Namespace) -> int:
    _engine_imports()
    from runtime.analyst_host import HostCancelled, TransportError
    from runtime.remote_repositories import checkout_arguments

    from appsec_analyzer.hosts import claude_preflight
    from appsec_analyzer.requirements_audit import audit_repository

    claude_preflight()
    catalog = (resource_root() / "examples/appsec-requirements-example.yaml") if ns.demo else Path(ns.requirements)
    try:
        with checkout_arguments(["--repo", ns.repo, "--output", ns.output]) as local:
            code, result = audit_repository(
                repo=local[1],
                output=ns.output,
                catalog_path=catalog,
                model=ns.model,
                hard_budget=ns.hard_budget,
                category_filter=ns.category,
                demo=ns.demo,
                gate=ns.gate,
                gate_on=ns.gate_on,
                priority_floor=ns.priority_floor,
                write_md=ns.md,
            )
    except (HostCancelled, TransportError) as exc:
        raise ValueError(f"requirements audit stopped: {getattr(exc, 'reason', 'interrupted')}") from None
    print(json.dumps(result, sort_keys=True))
    return code


def main(argv: list[str] | None = None, *, organization=None) -> int:
    ns = _parser(organization=organization).parse_args(argv)
    try:
        if organization is not None:
            if ns.command == "organization":
                document = organization.describe()
                if ns.action == "validate":
                    document["valid"] = True
                print(json.dumps(document, indent=2, sort_keys=True))
                return 0
            if ns.command in ("scan", "assess"):
                organization.apply(ns)
        if ns.command == "profiles":
            from appsec_analyzer.profiles import DEPTHS, list_profiles, resolve_scan

            if ns.profile_action == "list":
                document = {"profiles": list_profiles()}
            else:
                document = resolve_scan(
                    ns.selection,
                    depth=ns.assessment_depth,
                    budget=ns.budget,
                    max_calls=ns.max_calls,
                    outputs=ns.outputs,
                    max_parallel=ns.max_parallel,
                    model_override=ns.model,
                )
                if ns.profile_action == "validate":
                    depths = [ns.assessment_depth] if ns.assessment_depth else list(DEPTHS)
                    for depth in depths:
                        resolve_scan(
                            ns.selection,
                            depth=depth,
                            budget=ns.budget,
                            max_calls=ns.max_calls,
                            outputs=ns.outputs,
                            max_parallel=ns.max_parallel,
                            model_override=ns.model,
                        )
                    document = {
                        "valid": True,
                        "name": document["name"],
                        "assessment_depths": depths,
                    }
            print(json.dumps(document, indent=2, sort_keys=True))
            return 0
        if ns.command in ("scan", "assess"):
            _prepare_profile(ns)
        if ns.command == "audit-requirements":
            print(f"Model budget limit: USD {ns.hard_budget:g}", file=sys.stderr)
        if ns.command == "version":
            version = {"engine_version": ENGINE_VERSION, "interface_version": INTERFACE_VERSION}
            if organization is not None:
                version["organization"] = organization.identity
            print(json.dumps(version))
            return 0
        if ns.command == "capabilities":
            print(json.dumps(_capabilities(), sort_keys=True))
            return 0
        if ns.command == "scan-sources":
            return _scan(ns)
        if ns.command == "score":
            return _score(ns)
        if ns.command in ("scan", "assess"):
            return _assess(ns)
        if ns.command in ("status", "progress", "stop", "results"):
            return _inspect(ns)
        if ns.command == "analyst":
            return _analyst(ns)
        if ns.command == "audit-requirements":
            return _audit(ns)
        raise ValueError(f"{ns.command} is not implemented")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"appsec-analyzer: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
