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

import yaml

from appsec_analyzer import ENGINE_VERSION, INTERFACE_VERSION, resource_root
from appsec_analyzer.artifacts import read_bounded as _bounded_file
from appsec_analyzer.execution_limits import DEFAULT_MAX_PARALLEL, MAX_PARALLEL
from appsec_analyzer.targets import pentest_target as _pentest_target
from appsec_analyzer.terminal import field as _terminal_field

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
    """Compatibility entry for callers predating the engine boundary."""
    from appsec_analyzer.engine import initialize

    initialize()


def _parser(*, organization=None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=organization.command if organization else "appsec-analyzer")
    commands = parser.add_subparsers(dest="command", required=True)
    if organization is not None:
        org = commands.add_parser("organization", help="Inspect or validate the bundled defaults without model calls")
        org.add_argument("action", choices=("show", "validate"))
    config = commands.add_parser(
        "organization-config",
        allow_abbrev=False,
        help="Validate, inspect or run an engine-only organization projection",
    )
    config_actions = config.add_subparsers(dest="config_action", required=True)
    for action in ("show", "validate", "run"):
        operation = config_actions.add_parser(action, allow_abbrev=False)
        operation.add_argument("--config", required=True, metavar="FILE")
        operation.add_argument("--preset", dest="config_preset")
        operation.add_argument(
            "--profile-source", metavar="FILE", help="Original operator profile before host projection"
        )
        operation.add_argument("--assessment-depth", dest="config_depth", choices=("quick", "standard", "thorough"))
        operation.add_argument("arguments", nargs=argparse.REMAINDER)
    if organization is None:
        distribution = commands.add_parser(
            "distribution",
            help="Create an organization distribution or align its engine pins, without model calls",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=(
                "Prepare your organization's own command on top of this engine. Both actions only read and write\n"
                "files in the directory you name; no model calls, no network, no build, no publication.\n"
                "Building and releasing stay manual: see docs/organization-distributions.md."
            ),
            epilog=(
                "Examples:\n"
                "  appsec-analyzer distribution init northstar ./northstar-appsec\n"
                "  appsec-analyzer distribution update-engine ./northstar-appsec"
            ),
        )
        distribution_actions = distribution.add_subparsers(dest="distribution_action", required=True)
        init = distribution_actions.add_parser(
            "init", help="Create the organization repository files; nothing existing is overwritten"
        )
        init.add_argument("name", metavar="NAME", help="Organization name: 2-30 lowercase letters and digits")
        init.add_argument("target", nargs="?", metavar="DIR", help="New or empty directory (default: ./NAME-appsec)")
        update = distribution_actions.add_parser(
            "update-engine", help="Set every engine pin to the installed engine version"
        )
        update.add_argument("repo", nargs="?", default=".", metavar="DIR", help="Organization repository (default: .)")
    commands.add_parser("version", help="Show engine and public interface versions")
    commands.add_parser("capabilities", help="Show scanner and provider qualification")
    from appsec_analyzer.assessment_entry import add_arguments as entry_arguments

    entry_arguments(commands)
    query = commands.add_parser("query", help="Read validated saved assessment facts without model calls")
    query.add_argument("--output", required=True)
    query.add_argument("--id", dest="identifier")
    query.add_argument("--grep")
    query.add_argument("--severity")
    query.add_argument("--component")
    query.add_argument("--summary", action="store_true")
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
    preflight = commands.add_parser(
        "preflight",
        help="Check Git read access and provider setup without starting an assessment",
        description="Check local/remote repositories and provider setup. No generation unless --test-model is selected.",
    )
    preflight.add_argument("--repo", action="append", metavar="PATH_OR_URL")
    preflight.add_argument("--profile", metavar="NAME_OR_FILE")
    preflight.add_argument("--host", choices=("claude-cli", "codex-cli", "openai", "lite", "bedrock"))
    preflight.add_argument("--model", metavar="MODEL")
    preflight.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"), action=_Explicit)
    preflight.add_argument(
        "--budget",
        dest="hard_budget",
        type=_positive_budget,
        action=_Explicit,
        metavar="USD",
        help="Explicit separate spending limit required with --test-model (except codex-cli)",
    )
    preflight.add_argument(
        "--max-calls", type=int, help="Explicit plan-use limit required with --test-model for codex-cli"
    )
    preflight.add_argument(
        "--test-model",
        action="store_true",
        help="Authorize one primary-model call using a synthetic prompt; may consume money or plan allowance",
    )
    preflight.add_argument("--quiet", action="store_true")
    preflight.add_argument("--json", action="store_true")
    sources = commands.add_parser("scan-sources", help="Run deterministic source scanners without a model")
    sources.add_argument("--repo", action="append", required=True, metavar="PATH")
    sources.add_argument("--output", metavar="DIR", help="Existing directory outside every selected checkout")
    sources.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"), default="standard")
    sources.add_argument("--trust-mode", choices=("untrusted", "trusted"), default="untrusted")
    sources.add_argument("--json", action="store_true", help="Print the complete machine-readable result")
    score = commands.add_parser(
        "score",
        help="Get a quick deterministic security score without model calls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Get a quick security score (0-100) for one local Git checkout or HTTPS/SSH Git URL.\n"
            "Reuses the existing Analyzer analysis engine without model calls or model charges.\n"
            "Text output highlights the score, findings, coverage, and limitations.\n"
            "Progress and errors appear on stderr; results appear on stdout."
        ),
        epilog=(
            "Examples:\n"
            "  appsec-analyzer score /path/to/project\n"
            "  appsec-analyzer score https://github.com/your-org/your-project.git --json\n"
            "\n"
            "Runtime depends on repository size, scanner work, and any Git download.\n"
            "This is a limited quick check, not a full assessment or security approval.\n"
            "Text colors follow terminal settings (NO_COLOR/FORCE_COLOR).\n"
            "Exit codes: 0 scored; 2 undetermined or invalid arguments;\n"
            "            1 incomplete scan or operational error; 130 cancelled.\n"
            "Guide: docs/security-score.md"
        ),
    )
    score.add_argument("repo", metavar="REPO", help="Top-level local Git checkout or HTTPS/SSH Git URL")
    formats = score.add_mutually_exclusive_group()
    formats.add_argument("--json", action="store_true", help="Print the complete machine-readable JSON result")
    formats.add_argument("--yaml", action="store_true", help="Print the same result as YAML")
    profile = commands.add_parser(
        "repo-profile",
        help="Show a repository's size, languages, and build manifests without model calls",
        description=(
            "Profile a local directory before scanning it: working-tree size, language split by bytes,\n"
            "build manifests and their roots, and tracked versus untracked content.\n"
            "Reads directory entries only, never file contents. It is not a security check."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    profile.add_argument("repo", nargs="?", default=".", metavar="REPO", help="Local directory (default: current)")
    profile.add_argument("--json", action="store_true", help="Print the profile as machine-readable JSON")
    platform = commands.add_parser(
        "platform-settings",
        help="Check security settings of a GitHub or GitLab repository without model calls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Check security settings of a repository on github.com or gitlab.com, such as branch protection,\n"
            "secret scanning, and workflow permissions. Sends read requests to the platform API only;\n"
            "no model calls, no source code, and no writes to the repository or the platform.\n"
            "Each setting is reported as set, not set, or not checkable, with the reason."
        ),
        epilog=(
            "Without --token-env only public data is checked, so most results are usually not checkable.\n"
            "The token is read from the named environment variable, sent only to the platform host,\n"
            "and should be read-only. Results describe the settings at check time only.\n"
            "Examples:\n"
            "  appsec-analyzer platform-settings https://github.com/your-org/your-project\n"
            "  GITHUB_READ_TOKEN=... appsec-analyzer platform-settings URL --token-env GITHUB_READ_TOKEN --json"
        ),
    )
    platform.add_argument("url", metavar="URL", help="HTTPS or SSH URL of a github.com or gitlab.com repository")
    platform.add_argument("--token-env", metavar="NAME", help="Environment variable holding a read-only platform token")
    platform_formats = platform.add_mutually_exclusive_group()
    platform_formats.add_argument("--json", action="store_true", help="Print the result as JSON")
    platform_formats.add_argument("--yaml", action="store_true", help="Print the result as YAML")
    cases = commands.add_parser(
        "abuse-cases",
        help="List the defined abuse cases, or show one with its recorded result, without model calls",
        description=(
            "List the technical and business abuse cases a run in this repository would load, each with\n"
            "origin, kind, and title. With an ID, show that case's definition and what the saved assessment\n"
            "records for it. Read-only; it does not check a case against the code."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    cases.add_argument("case_id", nargs="?", metavar="ID", help="Show this case instead of listing all")
    cases.add_argument("--repo", default=".", metavar="PATH", help="Repository whose own cases to include")
    profile_choice = cases.add_mutually_exclusive_group()
    profile_choice.add_argument("--org-profile", metavar="PATH", help="Use this organization profile")
    profile_choice.add_argument("--no-org-profile", action="store_true", help="Ignore the active organization profile")

    for name, help_text in (
        ("status", "Inspect a versioned assessment state"),
        ("progress", "Read the bounded assessment progress feed"),
        ("stop", "Request bounded cancellation of a running assessment"),
        ("results", "List and verify published assessment deliverables"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--output", required=True, metavar="DIR")
        if name == "progress":
            command.add_argument("--after", type=int, default=0, help="Public event cursor from the preceding response")
    export = commands.add_parser("export", help="Export a saved completed assessment without model calls")
    export.add_argument(
        "--assessment",
        required=True,
        metavar="DIR",
        help="Private saved assessment directory with its completion state",
    )
    export.add_argument(
        "--output", required=True, metavar="NEW_DIR", help="New private destination outside Git checkouts"
    )
    export.add_argument(
        "--formats",
        nargs="+",
        choices=("markdown", "yaml", "html", "pdf", "sarif", "threatdragon", "pentest-tasks"),
        default=["markdown", "yaml"],
    )
    review = commands.add_parser(
        "review",
        help="Work on a saved assessment with Claude Code or Codex",
        description="Start an interactive coding assistant with the existing assessment and bundled review skill.",
        epilog=(
            "Defaults to the recorded Claude Code or Codex CLI adapter; otherwise choose with --with. "
            "Launch needs an interactive terminal and an installed, signed-in assistant. "
            "Uses the assistant's own account and usage limits, not the assessment budget. "
            "No export or new scan. Example: appsec-analyzer review /path/to/assessment --with codex"
        ),
    )
    review.add_argument("assessment", metavar="RESULT_DIR", help="Completed scan result directory")
    review.add_argument(
        "--with",
        dest="assistant",
        choices=("claude", "codex"),
        help="Override the coding assistant recorded in the assessment",
    )
    review.add_argument("--preview", action="store_true", help="Inspect the handoff without starting an assistant")
    analyst = commands.add_parser("analyst", help="Focused design, change, and hypothesis analysis", add_help=False)
    analyst.add_argument("-h", "--help", action="store_true", dest="analyst_help")
    analyst.add_argument("args", nargs=argparse.REMAINDER)
    from appsec_analyzer.analyze_threats.cli import add_arguments as threat_arguments

    focused = commands.add_parser(
        "analyze-threats",
        help="Ask a focused security question or review changes, an MR or a PR",
        description="Analyze a question, design or selected change with existing project context. Uses Claude CLI; USD 1 per model call by default.",
    )
    threat_arguments(focused)
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
    authnz = commands.add_parser(
        "authnz-review",
        help="Run a standalone model-backed authentication and authorization review",
        description="Review AuthN/AuthZ signals without a prior assessment. Model calls use Claude CLI.",
        epilog="Exit codes: 0 complete; 1 selected gate failed; 2 incomplete or invalid; 130 cancelled.",
    )
    authnz.add_argument(
        "--repo", default=".", metavar="PATH", help="One local Git checkout (default: current directory)"
    )
    authnz.add_argument("--host", choices=("claude-cli",), default="claude-cli")
    authnz.add_argument("--model", default="sonnet", metavar="MODEL")
    authnz.add_argument(
        "--budget",
        "--hard-budget",
        dest="hard_budget",
        type=_positive_budget,
        default=5.0,
        metavar="USD",
        help="Maximum model cost in USD (default: %(default)g)",
    )
    authnz.add_argument("--requirements", metavar="FILE", help="Optional local requirements catalog")
    authnz.add_argument("--output", metavar="DIR", help="Existing empty private directory outside the checkout")
    authnz.add_argument("--save", action="store_true", help="Save reports to a fresh private application directory")
    authnz.add_argument(
        "--outputs",
        nargs="+",
        choices=("markdown", "json", "yaml", "pentest-tasks"),
        help="Select saved outputs; implies --save (default: markdown json yaml)",
    )
    formats = authnz.add_mutually_exclusive_group()
    formats.add_argument("--json", action="store_true", help="Print the complete result as JSON")
    formats.add_argument("--yaml", action="store_true", help="Print the same result as YAML")
    authnz.add_argument("--pentest-tasks", action="store_true", help="Export the legacy endpoint catalog and test plan")
    authnz.add_argument(
        "--pentest-format", choices=("generic", "strix"), default="generic", help="Pentest plan dialect"
    )
    authnz.add_argument(
        "--pentest-output-format",
        choices=("json", "yaml", "both"),
        default="yaml",
        help="Pentest plan serialization (default: yaml)",
    )
    authnz.add_argument(
        "--pentest-target", type=_pentest_target, metavar="URL", help="Target metadata only; never contacted"
    )
    authnz.add_argument("--gate", action="store_true", help="Fail on Critical/High findings or an incomplete review")
    return parser


def _positive_budget(value: str) -> float:
    try:
        amount = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive finite USD amount") from exc
    if not math.isfinite(amount) or amount <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite USD amount")
    return amount


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
        "--platform-token-env",
        metavar="NAME",
        help=(
            "Environment variable holding a read-only GitHub or GitLab token for the Platform Security Settings "
            "phase; without it only public data is checked"
        ),
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
        "--max-budget",
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
    parser.add_argument(
        "--launch-defaults", choices=("advisor",), help="Apply Advisor depth budgets and component concurrency defaults"
    )
    parser.add_argument(
        "--interactive-launch",
        action="store_true",
        help="Compatibility alias for Advisor defaults, Claude CLI, width 72 and unattended execution",
    )
    parser.add_argument(
        "--soft-budget", "--max-cost", type=_positive_budget, help="Deprecated: a hard limit of 1.25 times this amount"
    )
    parser.add_argument(
        "--component-workers",
        dest="max_parallel",
        type=int,
        choices=range(1, 5),
        metavar="N",
        default=argparse.SUPPRESS,
    )
    parser.add_argument("--trust-mode", choices=("untrusted", "trusted"), default="untrusted")
    parser.add_argument("--resume", action="store_true", help="Continue the unfinished assessment in --output")
    parser.add_argument(
        "--rebuild", action="store_true", help="Start over, discarding earlier accepted steps and history in --output"
    )
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt for a higher budget or how to start beside an unfinished assessment (use in CI)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show full startup details, correlated model calls and sanitized correction details",
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
    from appsec_analyzer.organization import CONFIG_CAPABILITY

    return {
        "interface_version": INTERFACE_VERSION,
        "engine_version": ENGINE_VERSION,
        "scan": {"available": True, "model_calls": True},
        "assessment_entry": {"available": True, "schema_version": 1, "model_calls": False},
        "query": {"available": True, "model_calls": False},
        **{name: {"available": True} for name in ("status", "progress", "stop", "results")},
        "preflight": {"available": True, "default_model_calls": False, "optional_primary_model_test": True},
        "scan_sources": {"available": True, "model_calls": False},
        "score": {"available": True, "model_calls": False, "scoring_version": 2},
        "repo_profile": {"available": True, "model_calls": False},
        "abuse_cases": {"available": True, "model_calls": False},
        "export": {"available": True, "model_calls": False, "requires_completed_assessment": True},
        "review": {
            "available": True,
            "model_calls": True,
            "assistants": ["claude", "codex"],
            "interactive": True,
            "requires_completed_assessment": True,
            "preview_model_calls": False,
            "external_session": True,
            "qualified": False,
        },
        "analyze_threats": {
            "available": True,
            "model_calls": True,
            "hosts": ["claude-cli"],
            "scopes": ["design", "staged", "worktree", "commits", "hypothesis", "abuse-case", "mr", "pr"],
            "document_context": True,
            "preview_model_calls": False,
            "remote_preview_network": True,
            "qualified": False,
        },
        "authnz_review": {
            "available": True,
            "model_calls": True,
            "hosts": ["claude-cli"],
            "outputs": ["markdown", "json", "yaml", "pentest-tasks"],
            "qualified": False,
        },
        "profiles": {"schema_version": 1, "user_defined": True, "inspection_model_calls": False},
        "organization_config": CONFIG_CAPABILITY,
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
    from appsec_analyzer.score.progress import ScoreProgress

    with ScoreProgress(repository=ns.repo) as progress:
        try:
            _engine_imports()
            from renderers.term_style import Style

            from appsec_analyzer.score.render import render_text
            from appsec_analyzer.score.service import ScoreError, score_repository
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


def _distribution(ns: argparse.Namespace) -> int:
    from appsec_analyzer.distribution import diverged, init, update_engine

    if ns.distribution_action == "init":
        created = init(ns.name, ns.target or f"{ns.name}-appsec")
        print(f"Created {created}. Replace the sample content, then build and test it as described in the guide.")
        return 0
    changes = update_engine(ns.repo)
    for change in changes:
        print(f"{change['file']}: {change['pin']} {change['old']} -> {change['new']}")
    if diverged(changes):
        print("The files named different engine versions before this update; they now agree.", file=sys.stderr)
    print("Rebuild both wheels and test them before approving the release.")
    return 0


def _platform_settings(ns: argparse.Namespace) -> int:
    from appsec_analyzer.platform_settings.render import render_text
    from appsec_analyzer.platform_settings.service import PlatformSettingsError, check_platform_settings
    from appsec_analyzer.platform_settings.source import SourceError, parse_repository

    token = None
    if ns.token_env:
        token = os.environ.get(ns.token_env, "").strip()
        if not token:
            raise ValueError(f"--token-env {ns.token_env} names an unset or empty environment variable")
    try:
        repo = parse_repository(ns.url)
    except SourceError as exc:
        raise ValueError(str(exc)) from None
    access = "with your read-only token" if token else "anonymously (public data only)"
    print(
        f"Sending read requests to {repo.host} {access}. No model is used and no source code is sent.",
        file=sys.stderr,
    )
    try:
        result = check_platform_settings(ns.url, token)
    except PlatformSettingsError as exc:
        print(f"appsec-analyzer: error: {exc}", file=sys.stderr)
        return 1
    if ns.json:
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
    elif ns.yaml:
        print(yaml.safe_dump(result, sort_keys=False, allow_unicode=False), end="")
    else:
        print(render_text(result))
    return 0


def _scan_local(ns: argparse.Namespace) -> int:
    _engine_imports()
    from jsonschema import Draft202012Validator
    from model.assessment_scanner_findings import SIDECARS, _scanner_outputs
    from runtime.multi_repo_scope import ScopeError, admit
    from runtime.source_preflight import check_repositories as _assessment_preflight

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
    """Claim the result name atomically; never overwrite another run or user file."""
    from appsec_analyzer.artifacts import publish_exclusive

    try:
        publish_exclusive(directory / "scan-result.json", payload.encode("utf-8"))
    except FileExistsError:
        raise ValueError("scan result already exists or is being written; select a fresh --output directory") from None


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
    return _PROFILE_HOSTS["claude"]


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
    from appsec_analyzer.assessment_entry import apply_launch_defaults

    apply_launch_defaults(ns, profile, explicit)
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

    runtime = None
    if host == "claude-cli":
        from appsec_analyzer.hosts import claude_preflight

        claude_preflight()
    elif host == "codex-cli":
        from appsec_analyzer.codex_cli import preflight

        runtime = preflight(repositories=ns.repo or [str(Path.cwd())])
        ns.run_profile["cli_version"] = runtime["version"]
    if ns.launch_defaults and ns.output and ns.progress_file is None:
        from appsec_analyzer.assessment_entry import progress_path

        ns.progress_file = progress_path(ns.output)
    if getattr(ns, "platform_token_env", None) and not os.environ.get(ns.platform_token_env, "").strip():
        raise ValueError(f"--platform-token-env {ns.platform_token_env} names an unset or empty environment variable")
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
    from appsec_analyzer.preflight import print_result
    from appsec_analyzer.preflight import run as run_preflight

    if ns.command == "preflight" and getattr(ns, "test_model", False):
        if host == "codex-cli":
            if ns.max_calls is None:
                raise ValueError("preflight --test-model with codex-cli requires explicit --max-calls (one exchange)")
        elif "hard_budget" not in getattr(ns, "explicit", ()) or ns.hard_budget < 0.01:
            raise ValueError("preflight --test-model requires an explicit --budget of at least USD 0.01")
    result = run_preflight(ns, api_profile=api_profile, runtime=runtime)
    if ns.command == "preflight":
        print_result(result, as_json=ns.json)
        return 0

    def report_clone(number, total, remote):
        # Shown with the other start checks, after the repository rows.
        checks = tuple(getattr(ns, "preflight_checks", ()))
        at = sum(label.startswith(("Repo", "Checkout")) for _, label, _ in checks)
        label = "Checkout" if total == 1 else f"Checkout {number}/{total}"
        row = ("✓", label, f"shallow {remote.scheme.upper()} clone into a temporary directory, removed after the run")
        ns.preflight_checks = (*checks[:at], row, *checks[at:])

    with checkout_arguments(args, on_clone=report_clone) as local_args:
        from appsec_analyzer.profiles import reject_source_paths

        reject_source_paths(
            ns.run_profile["files"], [local_args[i + 1] for i, arg in enumerate(local_args[:-1]) if arg == "--repo"]
        )
        from appsec_analyzer.assessment.request import AssessmentRequest

        request = AssessmentRequest.from_cli(ns, local_args)
        if api_profile is not None:
            return assess_main(request, api_profile=api_profile, run_profile=ns.run_profile)
        return assess_main(request, run_profile=ns.run_profile)


def _state(ns: argparse.Namespace) -> tuple[Path, dict]:
    _engine_imports()
    from runtime.assessment_state import STATE_NAME, _read_state, _real_directory

    output = Path(ns.output).absolute()
    _real_directory(output)
    state = _read_state(output / STATE_NAME)
    return output, state


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
        if ns.after < 0:
            raise ValueError("progress cursor must be nonnegative")
        lines = data.splitlines()
        start = max(min(ns.after, len(lines)), len(lines) - 100)
        entries = [json.loads(line) for line in lines[start:]]
        if any(not isinstance(row, dict) for row in entries):
            raise ValueError("assessment progress contains a non-object event")
        document = {
            "interface_version": INTERFACE_VERSION,
            "kind": "assessment-progress",
            "run_id": state["run_id"],
            "assessment_status": state["status"],
            "feed_available": bool(data),
            "events": entries,
            "next_offset": len(lines),
            "events_omitted": start > ns.after,
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
    print(
        "Requirements audit sends selected masked source excerpts, the file inventory and selected catalog "
        "requirements to Claude CLI. Git retrieval is separate. Provider retention is not verified.",
        file=sys.stderr,
    )
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


def _authnz(ns: argparse.Namespace) -> int:
    _engine_imports()
    from runtime.analyst_host import HostCancelled, TransportError

    from appsec_analyzer.authnz_review import ReviewError, markdown, review_repository
    from appsec_analyzer.hosts import claude_preflight

    print(f"Model budget limit: USD {ns.hard_budget:g}", file=sys.stderr)
    print(
        "AuthNZ review sends masked scanner evidence and optional catalog context to Claude CLI. "
        "It performs no dynamic penetration test.",
        file=sys.stderr,
    )
    try:
        claude_preflight()
        code, result = review_repository(
            repo=ns.repo,
            output=ns.output,
            save=ns.save or ns.outputs is not None,
            model=ns.model,
            hard_budget=ns.hard_budget,
            requirements_path=Path(ns.requirements) if ns.requirements else None,
            outputs=tuple(ns.outputs) if ns.outputs else ("markdown", "json", "yaml"),
            pentest_tasks=ns.pentest_tasks,
            pentest_format=ns.pentest_format,
            pentest_output_format=ns.pentest_output_format,
            pentest_target=ns.pentest_target,
            gate=ns.gate,
            progress=lambda message: print(f"authnz-review: {message}", file=sys.stderr),
        )
        body = (
            json.dumps(result, indent=2) + "\n"
            if ns.json
            else (yaml.safe_dump(result, sort_keys=False, allow_unicode=True) if ns.yaml else markdown(result))
        )
        print(body, end="")
        return code
    except KeyboardInterrupt:
        print("authnz-review: cancelled; no completed review was reported", file=sys.stderr)
        return 130
    except (HostCancelled, TransportError) as exc:
        reason = getattr(exc, "reason", "time_limit")
        if reason not in ("time_limit", "authentication_failed", "rate_limit", "billing_error", "host_arguments"):
            reason = "host_failure"
        print(
            f"authnz-review: stopped ({reason}); select a fresh output and retry",
            file=sys.stderr,
        )
        return 2
    except ReviewError as exc:
        print(f"authnz-review: {exc}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, ValueError):
        print(
            "authnz-review: review or export failed; check source admission, private empty output, "
            "catalog, host and budget; select a fresh output and retry",
            file=sys.stderr,
        )
        return 2


def main(argv: list[str] | None = None, *, organization=None) -> int:
    ns = _parser(organization=organization).parse_args(argv)
    if ns.command == "preflight":
        # Share scan defaults and profile resolution without accepting assessment-only options.
        supplied = {key: value for key, value in vars(ns).items() if value is not None}
        ns = _parser(organization=organization).parse_args(["scan"])
        vars(ns).update(supplied)
    try:
        if ns.command == "assessment-entry":
            from appsec_analyzer.assessment_entry import run

            try:
                return run(ns)
            except (OSError, RuntimeError, ValueError):
                raise ValueError(
                    "assessment preparation refused: check source, private output and live ownership"
                ) from None
        if ns.command == "query":
            from appsec_analyzer.review_context import read_context

            if ns.identifier and any((ns.grep, ns.severity, ns.component, ns.summary)):
                raise ValueError("--id cannot be combined with filters or --summary")
            if ns.summary:
                if any((ns.grep, ns.severity, ns.component)):
                    raise ValueError("--summary cannot be combined with filters")
                _engine_imports()
                from renderers.summarize_threat_model import build_summary, render_text
                from shared.assessment_sources import is_portable_model, labelled_model

                from appsec_analyzer.saved_assessment import load_assessment

                path = Path(ns.output).absolute()
                _, _, files, stem = load_assessment(path)
                model = yaml.safe_load(files[stem + ".yaml"])
                if is_portable_model(model):
                    model = labelled_model(model)
                print(
                    render_text(
                        build_summary(model, path),
                        None,
                        False,
                        next_steps=[
                            "Questions: use query --output <assessment-directory> with the relevant finding or filter.",
                            "Re-export: use export --assessment <assessment-directory> --output <new-directory> --formats <formats>.",
                        ],
                    )
                )
            else:
                print(
                    json.dumps(
                        read_context(
                            ns.output,
                            identifier=ns.identifier,
                            grep=ns.grep,
                            severity=ns.severity,
                            component=ns.component,
                        ),
                        ensure_ascii=True,
                    )
                )
            return 0
        if ns.command == "organization-config":
            from appsec_analyzer.organization import config_command

            return config_command(ns)
        if ns.command == "distribution":
            return _distribution(ns)
        if organization is not None:
            if ns.command == "organization":
                document = organization.describe()
                if ns.action == "validate":
                    document["valid"] = True
                print(json.dumps(document, indent=2, sort_keys=True))
                return 0
            if ns.command in ("scan", "preflight"):
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
        if ns.command == "scan" and ns.non_interactive and not (ns.repo and (ns.profile or ns.host)):
            raise ValueError("scan --non-interactive requires --repo and an explicit --profile (or legacy --host)")
        if ns.command in ("scan", "preflight"):
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
        if ns.command == "abuse-cases":
            _engine_imports()
            from model.resolve_abuse_cases import main as abuse_cases

            selection = ["--show", ns.case_id] if ns.case_id else ["--list"]
            profile = ["--org-profile", ns.org_profile] if ns.org_profile else []
            return abuse_cases(
                [*selection, "--repo-root", str(Path(ns.repo).resolve()), *profile]
                + (["--no-org-profile"] if ns.no_org_profile else [])
            )
        if ns.command == "platform-settings":
            return _platform_settings(ns)
        if ns.command == "repo-profile":
            _engine_imports()
            from analyzers.repo_profile import main as repo_profile

            return repo_profile(["--repo", ns.repo, *(["--json"] if ns.json else [])])
        if ns.command in ("scan", "preflight"):
            return _assess(ns)
        if ns.command in ("status", "progress", "stop", "results"):
            return _inspect(ns)
        if ns.command == "export":
            from appsec_analyzer.exports import export_assessment

            print(json.dumps(export_assessment(ns.assessment, ns.output, tuple(ns.formats)), sort_keys=True))
            return 0
        if ns.command == "review":
            from appsec_analyzer.review import review_assessment

            return review_assessment(ns.assessment, assistant=ns.assistant, preview=ns.preview)
        if ns.command == "analyst":
            if ns.analyst_help:
                ns.args = ["--help"]
            return _analyst(ns)
        if ns.command == "analyze-threats":
            _engine_imports()
            from appsec_analyzer.analyze_threats.cli import run

            return run(ns)
        if ns.command == "audit-requirements":
            return _audit(ns)
        if ns.command == "authnz-review":
            return _authnz(ns)
        raise ValueError(f"{ns.command} is not implemented")
    except KeyboardInterrupt:
        print("appsec-analyzer: cancelled", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"appsec-analyzer: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
