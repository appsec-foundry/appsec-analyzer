"""Compact planned assessment scope, resolved from the admitted case sources."""

from __future__ import annotations

from collections import Counter
from contextlib import nullcontext
from pathlib import Path

import yaml

from appsec_analyzer.terminal import field


def scope_facts(scope, cfg: dict) -> list[tuple[str, str]]:
    """Describe loaded sources, not matched, verified, or future derived cases."""
    return [
        ("Focus", "Security design, code, and configuration"),
        ("Abuse cases", _abuse_case_sources(scope, cfg)),
        ("Coverage", "Depends on models, context, depth, and budget"),
        ("Excludes", "SCA/CVE scanning, comprehensive secret scanning, and runtime testing"),
    ]


def _abuse_case_sources(scope, cfg: dict) -> str:
    from model import resolve_abuse_cases as resolver
    from orchestrator.assessment_review import AssessmentReviewError, scan_case_files
    from orchestrator.assessment_workspace import Namespaces

    if cfg.get("skip_abuse_case_verification"):
        return "Dedicated verification disabled"

    names = Namespaces(scope)
    files = scan_case_files(scope, names, cfg.get("abuse_case_files"))
    profile_path = Path(cfg["org_profile_path"]) if cfg.get("org_profile_path") else None
    origins: dict[str, str] = {}
    try:
        profile = resolver._load_yaml(profile_path) if profile_path else None
        # The later matcher reads the same masked, admitted source, never the
        # live checkout. A combined run cannot load repository-local cases.
        snapshot = scope.scanner_snapshot(names.single) if names.single else nullcontext(None)
        with snapshot as root:
            cases, errors, rejected = resolver.resolve_abuse_case_sources(
                profile,
                profile_path.parent if profile_path else None,
                repo_root=root,
                extra_case_files=files,
                origins=origins,
            )
    except (OSError, ValueError, yaml.YAMLError):
        raise AssessmentReviewError(
            "abuse-case sources could not be loaded; check selected files and organization settings"
        ) from None
    if errors:
        # Resolver errors can quote untrusted case content and private paths.
        raise AssessmentReviewError("abuse-case sources are invalid; check selected files and organization settings")
    selected = set(cfg.get("only_abuse_case_ids") or [])
    if selected:
        if selected - origins.keys():
            raise AssessmentReviewError("selected abuse-case IDs are not active; check the case selection")
        cases = [case for case in cases if case["id"] in selected]
    counts = Counter(origins[case["id"]] for case in cases)
    sources = []
    if counts["library"]:
        sources.append("Built-in")
    if counts["org"]:
        sources.append("organization")
    supplied = counts["repo"] + counts["explicit"]
    if supplied:
        label = f"{supplied} user-supplied"
        unique_files = sorted(set(files))
        if counts["explicit"] and not counts["repo"] and len(unique_files) == 1:
            label += f" ({field(unique_files[0])})"
        sources.append(label)
    summary = " + ".join(sources) or "None loaded"
    if rejected:
        summary += f"; {len(rejected)} case file(s) rejected"
    return summary
