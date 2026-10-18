"""Resolve explicit analysis scope and capture context before dispatch."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Selection:
    question: str | None = None
    staged: bool = False
    worktree: bool = False
    design: bool = False
    design_file: str | None = None
    path: list[str] = field(default_factory=list)
    abuse_case: list[str] = field(default_factory=list)
    base: str | None = None
    head: str | None = None
    exact_base: bool = False
    revision: str | None = None
    context: list[str] = field(default_factory=list)
    threat_model: str | None = None
    requirements: str | None = None
    no_context: bool = False
    isolated: bool = False
    prepared_context: tuple | None = None

    @classmethod
    def from_arguments(cls, arguments):
        from dataclasses import fields

        return cls(**{f.name: getattr(arguments, f.name) for f in fields(cls) if hasattr(arguments, f.name)})


@dataclass(frozen=True)
class PreparedAnalysis:
    mode: str
    scope: dict
    question: str | None
    design: str | None
    documents: list[dict]
    sources: list[dict]
    structured: dict


def prepare(selection: Selection, repo: Path, origin=None, *, ask, announce, interactive=False) -> PreparedAnalysis:
    mode, scope, question, design = select_scope(selection, repo, interactive, origin, ask=ask, announce=announce)
    document_scope = dict(scope, base=origin["target"]) if origin else scope
    documents, sources, structured = selection.prepared_context or capture_context(
        selection, repo, document_scope, interactive, ask=ask, announce=announce
    )
    return PreparedAnalysis(mode, scope, question, design, documents, sources, structured)


def _text(value: str | None) -> str | None:
    from validators.secret_scan import scan_text

    if value is not None and (not value.strip() or len(value) > 20000 or scan_text(value)):
        raise ValueError("Question must be nonempty, at most 20000 characters, and contain no secret values.")
    return value


def local_repository(value: str | None) -> Path:
    from contexts.build_analyst_snapshot import _git

    path = Path(value or Path.cwd()).absolute()
    root = Path(_git(path, "rev-parse", "--show-toplevel").decode().strip())
    if not root.is_dir() or not (root / ".git").exists():
        raise ValueError("Select a local Git working tree with --repo.")
    return root.resolve()


def select_scope(ns, repo, interactive, origin, *, ask, announce):
    from contexts.analyst_documents import read_local, safe_path
    from contexts.build_analyst_snapshot import _commit, _git, _tree

    question = ns.question
    if origin:
        return (
            "review",
            {"kind": "commits", "base": origin["base"], "head": origin["head"], "comparison": "exact"},
            question,
            None,
        )
    if not any((ns.staged, ns.worktree, ns.design, ns.design_file, ns.path, ns.abuse_case, ns.base)):
        if not interactive:
            raise ValueError(
                "Select --path, --staged, --worktree, --design, --design-file, --base/--head, --mr or --pr; a question alone has no implied source scope."
            )
        question = question or _text(ask("What security question should be examined?"))
        choice = ask("Scope: 1 planned design, 2 staged changes, 3 worktree changes, 4 committed files:")
        if choice not in {"1", "2", "3", "4"}:
            raise ValueError("Choose a scope from 1 to 4; no default was selected.")
        ns.design, ns.staged, ns.worktree = choice == "1", choice == "2", choice == "3"
        if choice == "4":
            ns.path = [ask("Repository-relative file or directory to examine:")]
    if ns.base:
        base, head = _commit(repo, ns.base), _commit(repo, ns.head)
        if not ns.exact_base:
            base = _git(repo, "merge-base", base, head).decode().strip()
        return "review", {"kind": "commits", "base": base, "head": head, "comparison": "exact"}, question, None
    if ns.staged or ns.worktree:
        return "review", {"kind": "staged" if ns.staged else "worktree"}, question, None
    if ns.design or ns.design_file:
        if ns.design_file:
            path = Path(ns.design_file).absolute()
            design = read_local(Path(path.anchor), path.as_posix().lstrip("/")).decode("utf-8")
            if question:
                design = f"Question: {question}\n\nDesign:\n{design}"
        else:
            design = question or (ask("Describe the planned design or your question:") if interactive else None)
        if not design:
            raise ValueError("A design question or --design-file is required.")
        return "design", {"kind": "design", "source": "text"}, None, _text(design)
    revision = _commit(repo, ns.revision or "HEAD")
    if ns.abuse_case:
        from model.abuse_case_hypothesis import build as build_hypothesis

        ns.prepared_context = capture_context(
            ns, repo, {"kind": "hypothesis", "revision": revision}, interactive, ask=ask, announce=announce
        )
        documents, _, structured = ns.prepared_context
        model = structured.get("threat_model")
        question, paths, summary = build_hypothesis(
            repo,
            revision,
            ns.abuse_case,
            ns.path,
            with_threat_model=model is not None or any(d["role"] == "threat_model" for d in documents),
            threat_model_path=model,
        )
        summary = summary.replace("/appsec-advisor:appsec-analyzer", "appsec-analyzer scan")
        announce(summary)
    else:
        paths = ns.path
        question = question or (ask("What security question should these files answer?") if interactive else None)
    if not question:
        raise ValueError("Supply a question with --path.")
    if not 1 <= len(paths) <= 20 or len(set(paths)) != len(paths):
        raise ValueError("Select between one and twenty distinct source paths.")
    tree = _tree(repo, revision)
    for path in paths:
        safe_path(path, max_length=1024)
        if not any(p == path or p.startswith(path + "/") for p in tree):
            raise ValueError(
                "A selected source path is absent from the requested revision; select an existing file or directory."
            )
    return "hypothesis", {"kind": "hypothesis", "revision": revision, "paths": paths}, _text(question), None


def capture_context(ns, repo, scope, interactive, *, ask, announce):
    from contexts.analyst_documents import AmbiguousModels, capture

    paths = list(ns.context)
    structured = {}
    for name in ("threat_model", "requirements"):
        value = getattr(ns, name)
        if not value:
            continue
        path = Path(value)
        if path.suffix.lower() in {".md", ".txt", ".rst"}:
            paths.append(path.relative_to(repo).as_posix() if path.is_absolute() else value)
        else:
            if scope["kind"] == "commits" and not path.is_absolute():
                paths.append(value)
            else:
                structured[name] = path.absolute() if path.is_absolute() else repo / path
    try:
        docs, sources = capture(
            repo,
            scope,
            paths,
            discover=not ns.no_context,
            include_models=not ns.isolated and "threat_model" not in structured,
        )
    except AmbiguousModels as exc:
        if not interactive:
            raise
        for number, path in enumerate(exc.paths, 1):
            announce(f"  {number}. {path}")
        choice = ask("Which existing threat model should be used? Enter its number:")
        if not choice.isdigit() or not 1 <= int(choice) <= len(exc.paths):
            raise ValueError("No threat model selected.") from None
        paths.append(exc.paths[int(choice) - 1])
        docs, sources = capture(
            repo,
            scope,
            paths,
            discover=not ns.no_context,
            include_models=not ns.isolated and "threat_model" not in structured,
        )
    if not ns.isolated and not ns.no_context and "threat_model" not in structured and scope["kind"] != "commits":
        from model.resolve_abuse_cases import assessment_model

        existing = assessment_model(repo)
        if existing is not None and existing.is_file() and not any(d["role"] == "threat_model" for d in docs):
            structured["threat_model"] = existing
    from contexts.build_analyst_context import validate_selected_context

    validate_selected_context(structured)
    return docs, sources, structured
