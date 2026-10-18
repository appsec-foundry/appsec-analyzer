"""Bounded document context, captured independently from executable source evidence."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

from validators.secret_scan import scan_text

from contexts.build_analyst_snapshot import SnapshotError, _blobs, _commit, _git, _index, _tree

MAX_FILES = 24
MAX_FILE_BYTES = 65536
MAX_TOTAL_BYTES = 196608
SUFFIXES = {".md", ".txt", ".rst", ".yaml", ".yml", ".json"}
THREAT_NAMES = {"threat-model", "threatmodel", "threat_model", "security-assessment"}


class DocumentError(ValueError):
    """Safe diagnostic; no document contents are included."""


class AmbiguousModels(DocumentError):
    def __init__(self, paths):
        self.paths = sorted(paths)
        super().__init__("Several threat models were found; select one with --context or --threat-model.")


def safe_path(value: str, *, max_length: int = 180) -> str:
    if (
        not value
        or len(value) > max_length
        or value.startswith("/")
        or any(p in {"", ".", ".."} for p in value.split("/"))
        or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
        or "\\" in value
    ):
        raise DocumentError("Context paths must be literal repository-relative paths without links or traversal.")
    return value


def role(path: str) -> str:
    p = PurePosixPath(path)
    if p.stem.lower() in THREAT_NAMES:
        return "threat_model"
    if p.stem.lower() in {"requirements", "security-requirements"}:
        return "requirements"
    return "specification"


def automatic(path: str) -> bool:
    p = PurePosixPath(path)
    if p.suffix.lower() not in SUFFIXES:
        return False
    return (
        (role(path) != "specification" and str(p.parent) in {".", "docs", "docs/security"})
        or path.startswith(("specs/", "docs/specs/", "docs/architecture/"))
        or path in {"docs/security/business-context.md", "docs/business-context.md"}
    )


def read_local(repo: Path, path: str) -> bytes:
    """Open each path component without following a symlink, including parents."""
    parts = safe_path(path).split("/")
    fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise DocumentError("Context must be a regular file.")
            data = stream.read(MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        raise DocumentError("Context file exceeds 64 KiB; select a smaller document.")
    return data


def _local_names(repo: Path) -> set[str]:
    names = set()
    count = 0
    for parent, dirs, files in os.walk(repo, followlinks=False):
        relative_parent = Path(parent).relative_to(repo).as_posix()
        if relative_parent != "." and (Path(parent) / ".git").exists():
            dirs[:] = []
            continue
        dirs[:] = sorted(
            d
            for d in dirs
            if not d.startswith(".")
            and not (Path(parent) / d).is_symlink()
            and (
                relative_parent == "."
                and d in {"docs", "specs"}
                or relative_parent == "docs"
                and d in {"security", "specs", "architecture"}
                or relative_parent == "specs"
                or relative_parent.startswith("specs/")
                or relative_parent in {"docs/specs", "docs/architecture"}
                or relative_parent.startswith(("docs/specs/", "docs/architecture/"))
            )
        )
        count += len(dirs) + len(files)
        if count > 20000:
            raise DocumentError(
                "Document discovery exceeds 20000 entries; use --no-context and explicit --context files."
            )
        for name in files:
            relative = (Path(parent) / name).relative_to(repo).as_posix()
            if automatic(relative):
                names.add(safe_path(relative))
    return names


def capture(
    repo: Path, scope: dict, paths: list[str], *, discover: bool = True, include_models: bool = True
) -> tuple[list[dict], list[dict]]:
    """Freeze baseline/proposed documents. Changed declarations never replace their baseline."""
    explicit = set(map(safe_path, paths))
    if len(explicit) > MAX_FILES:
        raise DocumentError("Select at most 24 context files.")
    views = []
    kind = scope["kind"]
    if kind == "commits":
        base, head = _commit(repo, scope["base"]), _commit(repo, scope["head"])
        if scope.get("comparison") == "merge_base":
            base = _git(repo, "merge-base", base, head).decode().strip()
        views = [("baseline", base, _tree(repo, base)), ("proposed", head, _tree(repo, head))]
    elif kind in {"staged", "worktree"}:
        head = _commit(repo, "HEAD")
        views = [("baseline", head, _tree(repo, head))]
        views.append(
            ("proposed", "index" if kind == "staged" else "worktree", _index(repo) if kind == "staged" else None)
        )
    elif kind == "hypothesis":
        head = _commit(repo, scope["revision"])
        views = [("selected", head, _tree(repo, head))]
    else:
        views = [("selected", "worktree", None)]
    names = set(explicit)
    for _, _, tree in views:
        if discover:
            names.update(p for p in (tree if tree is not None else _local_names(repo)) if automatic(p))
    if discover and any(tree is None for _, _, tree in views):
        candidates = sorted(names - explicit)
        for offset in range(0, len(candidates), 100):
            ignored = _git(
                repo,
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
                "--",
                *candidates[offset : offset + 100],
            )
            names.difference_update(p.decode("utf-8", "surrogateescape") for p in ignored.split(b"\0") if p)
    models = {p for p in names if role(p) == "threat_model"}
    if not include_models:
        names -= models
        models = set()
    selected_models = models & explicit
    if selected_models:
        names -= models - selected_models
    elif len(models) > 1:
        raise AmbiguousModels(models)
    if len(explicit) * len(views) > MAX_FILES:
        raise DocumentError("Document selection exceeds 24 versions; use --no-context and explicit --context files.")
    ordered = sorted(
        names,
        key=lambda p: (
            p not in explicit,
            {"threat_model": 0, "requirements": 1, "specification": 2}[role(p)],
            p.startswith("specs/changes/"),
            p,
        ),
    )
    omitted = max(0, len(ordered) - MAX_FILES // len(views))
    names = set(ordered[: MAX_FILES // len(views)])
    documents, sources = [], []
    total = 0
    found = set()
    for path in sorted(names):
        safe_path(path)
        if PurePosixPath(path).suffix.lower() not in SUFFIXES:
            raise DocumentError("Context supports Markdown, text, reStructuredText, YAML and JSON files.")
        for side, revision, tree in views:
            if tree is not None and path not in tree:
                continue
            record = {
                "kind": "document",
                "origin": "caller" if path in explicit else "repository",
                "label": f"{side}:{path}",
                "revision": revision,
                "required": path in explicit,
                "status": "delivered",
            }
            try:
                if tree is None:
                    body = read_local(repo, path)
                else:
                    mode, oid = tree[path]
                    if mode not in {"100644", "100755"}:
                        raise DocumentError("Linked context is not admitted.")
                    if int(_git(repo, "cat-file", "-s", oid)) > MAX_FILE_BYTES:
                        raise DocumentError("Context exceeds its byte limit.")
                    body = _blobs(repo, [oid])[oid]
                text = body.decode("utf-8")
                if "\x00" in text or any(ord(c) < 32 and c not in "\n\r\t" for c in text):
                    raise DocumentError("Context contains unsupported control characters.")
                digest = hashlib.sha256(body).hexdigest()
                record["sha256"] = digest
                if scan_text(text):
                    record["status"] = "sensitive"
                else:
                    total += len(body)
                    if total > MAX_TOTAL_BYTES:
                        raise DocumentError("Combined context exceeds 192 KiB; select fewer documents.")
                    documents.append(
                        {
                            "id": f"doc-{len(documents) + 1:03d}",
                            "path": path,
                            "side": side,
                            "revision": revision,
                            "sha256": digest,
                            "role": role(path),
                            "text": text,
                        }
                    )
                    record["document_id"] = documents[-1]["id"]
                    found.add(path)
            except FileNotFoundError:
                record["status"] = "absent"
            except (OSError, UnicodeError, SnapshotError):
                record["status"] = "invalid"
            if record["required"] and record["status"] not in {"delivered", "absent"}:
                raise DocumentError("An explicitly selected context document is invalid or contains sensitive data.")
            sources.append(record)
    if explicit - found:
        raise DocumentError("An explicitly selected context document is absent from the selected revision or scope.")
    if omitted:
        sources.append(
            {
                "kind": "document",
                "origin": "repository",
                "label": f"{omitted} additional document paths omitted by selection limit",
                "required": False,
                "status": "truncated",
            }
        )
    return documents, sources
