"""Question-first focused analysis and terminal dialogue over the analyst controller."""

from __future__ import annotations

import argparse
import math
import os
import re
import signal
import sys
from contextlib import nullcontext
from pathlib import Path

from appsec_analyzer.analyze_threats.preparation import Selection, _text, local_repository, prepare


def _budget(value: str) -> float:
    try:
        amount = float(value)
        if not math.isfinite(amount) or amount < 0.01:
            raise ValueError
        return amount
    except ValueError:
        raise argparse.ArgumentTypeError("must be a finite USD amount of at least 0.01") from None


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("question", nargs="?", help="Security question; asks for it when needed in a terminal")
    parser.add_argument("--repo", metavar="PATH", help="Local Git repository (default: current repository)")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--staged", action="store_true", help="Review staged changes")
    scope.add_argument("--worktree", action="store_true", help="Review current tracked and untracked changes")
    scope.add_argument("--design", action="store_true", help="Discuss the question as a planned design")
    scope.add_argument("--design-file", metavar="FILE", help="Review a supplied design document")
    scope.add_argument("--mr", metavar="URL", help="Review a GitLab merge request through read-only HTTPS and Git")
    scope.add_argument("--pr", metavar="URL", help="Review a GitHub pull request through read-only HTTPS and Git")
    parser.add_argument("--resume", metavar="JOB", help="Continue a waiting job; use the same --repo or MR/PR URL")
    parser.add_argument(
        "--path", action="append", default=[], metavar="PATH", help="Committed file or directory to examine; repeatable"
    )
    parser.add_argument("--revision", metavar="REV", help="Revision for --path or --abuse-case (default: HEAD)")
    parser.add_argument("--base", metavar="REV", help="Base revision of a local change review")
    parser.add_argument("--head", metavar="REV", help="Proposed revision; required together with --base")
    parser.add_argument("--exact-base", action="store_true", help="Compare --base directly rather than its merge base")
    parser.add_argument(
        "--abuse-case", action="append", default=[], metavar="ID", help="Check a defined abuse case; repeatable"
    )
    parser.add_argument(
        "--context",
        action="append",
        default=[],
        metavar="FILE",
        help="Repository-relative document; repeatable, captured at selected revisions",
    )
    parser.add_argument(
        "--no-context", action="store_true", help="Disable automatic document and existing assessment discovery"
    )
    parser.add_argument(
        "--threat-model", metavar="FILE", help="Explicit structured YAML model or repository Markdown document"
    )
    parser.add_argument(
        "--requirements", metavar="FILE", help="Explicit YAML catalog or repository Markdown requirements"
    )
    parser.add_argument(
        "--isolated", action="store_true", help="Exclude existing threat models; keep selected requirements/specs"
    )
    parser.add_argument(
        "--explore", action="store_true", help="Allow design/review to read a redacted tracked-source snapshot"
    )
    parser.add_argument("--model", default="sonnet", help="Claude CLI model (default: sonnet)")
    parser.add_argument(
        "--max-budget-usd",
        type=_budget,
        default=1.0,
        metavar="USD",
        help="Ceiling per model call, not total job cost (default: 1); with a Claude subscription, usage at API prices",
    )
    parser.add_argument("--output", metavar="DIR", help="Existing private result directory outside the repository")
    parser.add_argument("--state-dir", metavar="DIR", help="Private analyst job state root")
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Show scope and document selection without a job or model call; MR/PR reads still use the network",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; require an explicit scope and report unanswered questions as incomplete",
    )


def _terminal(ns) -> bool:
    return not ns.non_interactive and not os.environ.get("CI") and sys.stdin.isatty() and sys.stderr.isatty()


def _ask(prompt: str) -> str:
    from appsec_analyzer.terminal import field as _terminal_field

    print(_terminal_field(prompt), file=sys.stderr, end=" ", flush=True)
    answer = sys.stdin.readline(20002)
    if not answer or not answer.strip():
        raise ValueError("No answer supplied; nothing was assumed. Rerun with an explicit scope or resume the job.")
    if len(answer) > 20000:
        raise ValueError("Answer exceeds 20000 characters.")
    return answer.rstrip("\r\n")


def _validate(ns) -> None:
    groups = [
        bool(ns.staged or ns.worktree),
        bool(ns.design or ns.design_file),
        bool(ns.mr or ns.pr),
        bool(ns.path or ns.abuse_case),
        bool(ns.base or ns.head),
    ]
    if sum(groups) > 1:
        raise ValueError(
            "Choose one scope: changes, design, MR/PR, selected paths/abuse cases, commit comparison, or resume."
        )
    if bool(ns.base) != bool(ns.head):
        raise ValueError("--base and --head are required together.")
    if ns.resume and any((ns.staged, ns.worktree, ns.design, ns.design_file, ns.path, ns.abuse_case, ns.base)):
        raise ValueError("Resume retains the original scope; select only --repo or the original MR/PR URL.")
    if ns.abuse_case and ns.question:
        raise ValueError("Abuse cases define their own question; use --path for a custom question.")
    if ns.exact_base and not ns.base:
        raise ValueError("--exact-base requires --base and --head.")
    if ns.revision and not (ns.path or ns.abuse_case):
        raise ValueError("--revision applies only to selected paths or abuse cases.")
    if ns.isolated and (
        ns.threat_model
        or any(
            Path(p).stem.lower() in {"threat-model", "threatmodel", "threat_model", "security-assessment"}
            for p in ns.context
        )
    ):
        raise ValueError("--isolated excludes explicit threat-model context.")
    if ns.explore and (ns.path or ns.abuse_case or ns.non_interactive):
        raise ValueError("--explore requires an interactive design or change review.")
    if (ns.mr or ns.pr) and ns.repo:
        raise ValueError("MR/PR URLs select their own repository; omit --repo.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", ns.model):
        raise ValueError("Invalid Claude model name.")
    if ns.resume and (
        ns.question
        or ns.context
        or ns.threat_model
        or ns.requirements
        or ns.no_context
        or ns.isolated
        or ns.explore
        or ns.preview
        or ns.output
    ):
        raise ValueError(
            "Resume uses the job's frozen question, context, model and output; do not supply new analysis options."
        )
    _text(ns.question)


def _display(ns, mode, scope, sources, structured, origin=None):
    from contexts.resolve_analyst_catalog import load_limits

    from appsec_analyzer.terminal import field as _terminal_field

    label = {
        "design": "planned design",
        "staged": "staged changes",
        "worktree": "current worktree changes",
        "commits": "commit comparison",
        "hypothesis": "selected committed files",
    }[scope["kind"]]
    print(f"Scope: {label}", file=sys.stderr)
    if scope.get("revision"):
        print(f"Revision: {_terminal_field(scope['revision'])}", file=sys.stderr)
    if scope.get("base"):
        print(f"Comparison: {_terminal_field(scope['base'])} → {_terminal_field(scope['head'])}", file=sys.stderr)
    for path in scope.get("paths", []):
        print(f"Source: {path}", file=sys.stderr)
    if origin:
        print(f"Review: {origin['url']}", file=sys.stderr)
    for source in sources:
        print(
            f"Context: {_terminal_field(source['label'])} @ {source.get('revision', '')} ({source['status']})",
            file=sys.stderr,
        )
    for name, path in structured.items():
        print(f"Context: {name} · {_terminal_field(path)}", file=sys.stderr)
    if not sources and not structured:
        print("Context: no project documents selected; packaged requirements baseline still applies.", file=sys.stderr)
    calls = load_limits()["host_calls"]
    from appsec_analyzer.assessment.console import usd_at_api_prices

    ceiling = (
        f"Usage ceiling: USD {ns.max_budget_usd:g} per call at API prices"
        if usd_at_api_prices("claude-cli")
        else f"Spending ceiling: USD {ns.max_budget_usd:g} per call"
    )
    print(
        f"Model: Claude CLI / {ns.model}. Selected source, design, documents and answers are sent to this host.\n{ceiling}; up to {calls} calls per job (no total-job budget guarantee).",
        file=sys.stderr,
    )


def _transport(ns):
    from runtime.analyst_host import ClaudeCliTransport

    def create(job, request):
        return ClaudeCliTransport(
            job.root / "work",
            model=request["host"]["model"],
            max_budget_usd=ns.max_budget_usd,
            read_root=job.root / "explore" if request.get("explore") else None,
        )

    return create


def _terminal_text(text):
    return "".join(c if c in "\n\t" or ord(c) >= 32 and not 127 <= ord(c) <= 159 else "?" for c in text)


def _print_outcome(outcome):
    print(_terminal_text(outcome.report))
    if outcome.job_id:
        print(f"Job: {outcome.job_id}\nState: {outcome.state}")


def _dialogue(outcome, repo, state_root, transport, interactive):
    from orchestrator import analyst_controller as ctl

    while True:
        _print_outcome(outcome)
        if outcome.state != "awaiting_answers" or not interactive:
            return outcome.exit_code if outcome.state != "awaiting_answers" else 2
        try:
            answers = {}
            for question in outcome.questions:
                if question["required"]:
                    answers[question["id"]] = _ask(
                        f"{question['id']}: {question['asks']} Why: {question['why']} (blank/EOF leaves the job waiting)"
                    )
        except ValueError:
            print(
                f"Job remains waiting. Continue with appsec-analyzer analyze-threats --resume {outcome.job_id} and the original --repo or --mr/--pr selection (and --state-dir if selected).",
                file=sys.stderr,
            )
            return 2
        except (KeyboardInterrupt, ctl.Terminated):
            _print_outcome(ctl.cancel(outcome.job_id, repo, state_root))
            return 130
        outcome = ctl.answer(outcome.job_id, repo, None, transport, state_root, inline_answers=answers)


def _run_local(ns, repo, origin, interactive):
    from orchestrator import analyst_controller as ctl

    state_root = Path(ns.state_dir).absolute() if ns.state_dir else None
    if ns.resume:
        transport = _transport(ns)
        waiting = ctl.waiting_job(ns.resume, repo, state_root)
        ns.model = waiting.model
        _display(ns, waiting.mode, waiting.scope, waiting.sources, {}, waiting.review_origin)
        return _dialogue(
            waiting.outcome,
            repo,
            state_root,
            transport,
            interactive,
        )
    prepared = prepare(
        Selection.from_arguments(ns),
        repo,
        origin,
        ask=_ask,
        announce=lambda text: print(_terminal_text(text), file=sys.stderr),
        interactive=interactive,
    )
    mode, scope, question, design = prepared.mode, prepared.scope, prepared.question, prepared.design
    docs, sources, structured = prepared.documents, prepared.sources, prepared.structured
    _display(ns, mode, scope, sources, structured, origin)
    if ns.preview:
        print("Preview only: no analyst job or model call was started.")
        return 0
    transport = _transport(ns)
    invocation = ctl.Invocation(
        mode=mode,
        scope=scope,
        repo_root=repo,
        output_dir=Path(ns.output).absolute() if ns.output else None,
        design_text=design,
        question=question if mode == "review" else None,
        hypothesis=question if mode == "hypothesis" else None,
        explore=ns.explore,
        state_root=state_root,
        model=ns.model,
        requirements_path=structured.get("requirements"),
        requirements_required=bool(ns.requirements and "requirements" in structured),
        threat_model_path=structured.get("threat_model"),
        threat_model_required=bool(ns.threat_model and "threat_model" in structured),
        documents=docs,
        document_sources=sources,
        repository_context=False,
        review_origin=origin,
    )
    previous = signal.getsignal(signal.SIGTERM)

    def terminate(signum, frame):
        raise ctl.Terminated()

    signal.signal(signal.SIGTERM, terminate)
    try:
        outcome = ctl.run(invocation, transport, interactive=interactive)
        return _dialogue(outcome, repo, state_root, transport, interactive)
    finally:
        signal.signal(signal.SIGTERM, previous)


def run(ns) -> int:
    from appsec_analyzer.engine import initialize

    initialize()
    from contexts.build_analyst_context import ContextError
    from contexts.build_analyst_snapshot import SnapshotError
    from model.abuse_case_hypothesis import AbuseCaseError
    from orchestrator.analyst_controller import Terminated
    from runtime.analyst_state import AnalystStateError

    try:
        _validate(ns)
        interactive = _terminal(ns)
        if ns.explore and not interactive:
            raise ValueError(
                "--explore needs an interactive terminal; use analyst for an explicitly managed agent session."
            )
        origin = None
        if ns.mr or ns.pr:
            from appsec_analyzer.review_sources import checkout, parse, resolve

            review = parse(ns.mr or ns.pr, "mr" if ns.mr else "pr")
            print(
                f"Reading review metadata and selected commits from {review.host} (no model call yet).", file=sys.stderr
            )
            origin = resolve(review)
            workspace = checkout(review, origin)
        else:
            workspace = nullcontext(local_repository(ns.repo))
        with workspace as repo:
            return _run_local(ns, repo, origin, interactive)
    except (KeyboardInterrupt, Terminated):
        return 130
    except (ValueError, OSError, SnapshotError, AbuseCaseError, AnalystStateError, ContextError) as exc:
        from appsec_analyzer.terminal import field as _terminal_field

        message = (
            str(exc)
            if isinstance(exc, ValueError)
            else "Could not prepare the analysis; check source scope, document paths and private job state."
        )
        print(f"analyze-threats: {_terminal_field(message)}", file=sys.stderr)
        return 2
