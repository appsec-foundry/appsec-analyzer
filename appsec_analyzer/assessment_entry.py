"""Public adapters for the existing Claude-host assessment launch and consumers."""

from __future__ import annotations

import json
import os
from pathlib import Path

from appsec_analyzer import INTERFACE_VERSION
from appsec_analyzer.artifacts import read_bounded
from appsec_analyzer.engine import initialize


def add_arguments(commands):
    entry = commands.add_parser("assessment-entry", help="Prepare an existing host assessment without model calls")
    actions = entry.add_subparsers(dest="entry_action", required=True)
    for action in ("destination", "trust", "legacy", "context-preview", "context-save", "holder", "clean"):
        parser = actions.add_parser(action, allow_abbrev=False)
        if action not in {"holder", "clean"}:
            parser.add_argument("--repo", required=True)
        if action != "trust":
            parser.add_argument("--output", required=action != "destination")
        if action == "destination":
            parser.add_argument("--storage", choices=("analyzer", "advisor"), default="analyzer")
        if action == "context-save":
            parser.add_argument("--context-answer", choices=("answered", "skip", "unchanged"), required=True)
            parser.add_argument("--impact-choice", choices=("no-material-harm", "declared-harm"))
            parser.add_argument("--use-case-choice", choices=("confirmed", "corrected"))
        if action == "clean":
            parser.add_argument(
                "--apply", action="store_true", help="Remove only stale transient state; default is inspection"
            )


def _output(value: str, *, create: bool = False) -> Path:
    from shared.assessment_location import _check_private

    path = Path(os.path.abspath(value))
    if ".." in Path(value).parts or path.resolve() != path:
        raise ValueError("assessment output must use a canonical path without links")
    if any(os.path.lexists(parent / ".git") for parent in (path, *path.parents)):
        raise ValueError("assessment output must be outside source checkouts")
    from shared.assessment_location import data_base

    base = data_base()
    for application in (base.parent, base.parent.parent / "appsec-advisor"):
        if path.is_relative_to(application):
            current = application
            for part in (None, *path.relative_to(application).parts):
                if part is not None:
                    current = current / part
                if current.exists():
                    _check_private(current)
    if create:
        # Match existing application storage privacy for both installed hosts.
        missing = []
        current = path
        while not current.exists():
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
    if path.exists():
        from appsec_analyzer.saved_assessment import validate_directory

        validate_directory(path)
        _check_private(path)
    return path


def run(ns) -> int:
    initialize()
    from runtime import acquire_lock
    from runtime.multi_repo_scope import checkout_report_directory
    from shared.assessment_location import application_directory, data_base

    action = ns.entry_action
    root = checkout_report_directory(ns.repo)[0] if hasattr(ns, "repo") else None
    if action == "destination":
        base = data_base()
        if ns.storage == "advisor":
            base = base.parent.parent / "appsec-advisor" / "assessments"
        output = _output(ns.output or str(application_directory(root, base)))
        document = {"output": str(output), "repo": str(root)}
    elif action == "trust":
        from validators.preflight_untrusted import run as trust

        document = trust(root, strict=True, strict_urls=True, isolated_host=True)
        print(json.dumps({"interface_version": INTERFACE_VERSION, "kind": "assessment-trust", **document}))
        return 2 if document["finding_count"] else 0
    else:
        output = _output(ns.output)
        if action == "holder":
            # A missing state is ordinary before launch, never evidence of completion.
            live = acquire_lock.lock_held_by_live_other_run(output / ".appsec-lock")
            document = {"live": live, "run_id": acquire_lock.read_run_id(output / ".appsec-lock") if live else None}
        elif action == "legacy":
            from runtime.legacy_import import offer

            legacy = offer(root, output)
            document = {"action": "none" if legacy is None else "offer" if legacy.complete else "incomplete"}
            if legacy is not None and not legacy.complete:
                document["reason"] = legacy.reason
        elif action in {"context-preview", "context-save"}:
            from orchestrator.orchestration_controller import assess_context_preview, assess_context_save

            _output(ns.output, create=True)
            if action == "context-preview":
                prepared = assess_context_preview(str(root), str(output))
                document = {"preview": json.loads(read_bounded(Path(prepared["preview"]), 65536))}
            else:
                document = assess_context_save(
                    str(root),
                    output=str(output),
                    context_answer=ns.context_answer,
                    impact_choice=ns.impact_choice,
                    use_case_choice=ns.use_case_choice,
                )
        elif action == "clean":
            from runtime import check_state

            if not output.exists():
                document = {"state": "clean", "removed": []}
            elif not ns.apply:
                document = check_state.classify(output)
            else:
                # Serialize mutation against new launches as well as checking liveness.
                with acquire_lock.serialization_guard(output):
                    report = check_state.classify(output)
                    document = check_state.clean(output, report)
                    if document.get("skipped"):
                        raise ValueError("an active assessment holds this output; cleanup refused")
        else:
            raise ValueError("unsupported assessment entry operation")
    print(
        json.dumps(
            {"interface_version": INTERFACE_VERSION, "kind": "assessment-entry", "operation": action, **document},
            sort_keys=True,
        )
    )
    return 0
