#!/usr/bin/env python3
"""Validate the product requirements and their technical implementation bindings.

`requirements.md` contains only normative product behavior. Volatile path,
decision, document, and test references live in
`data/requirement-bindings.yaml`. This checker keeps that separation honest and
supports file-to-requirement lookup without making refactors specification
changes.

The checker validates structure and exact references. It cannot decide whether
a named test semantically proves a requirement; the binding's direct, partial,
or advisory coverage label makes that review judgement explicit.
"""

from __future__ import annotations

import argparse
import ast
import glob
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "requirements.md"
BINDINGS = ROOT / "data" / "requirement-bindings.yaml"
BINDING_SCHEMA = ROOT / "schemas" / "requirement-bindings.schema.yaml"
REGISTER = ROOT / "docs" / "internal" / "decisions.md"

REGISTER_PATH = "docs/internal/decisions.md"
ACCEPTANCE_PATH = "docs/internal/contracts/requirement-acceptance.md"
HELD_PATHS = ("requirements.md", ACCEPTANCE_PATH, REGISTER_PATH)
CHANGE_DIR = "specs/changes/"

SECTION_RE = re.compile(r"^## (.+?)\s*$")
ENTRY_RE = re.compile(r"^- \*\*(REQ-[^:*\s]+):\*\*\s*(.*?)\s*$")
ID_SHAPE_RE = re.compile(r"^REQ-[0-9]{3}$")
DECISION_RE = re.compile(r"^[A-Z]{2,3}-\d+$")
DECISION_ROW_RE = re.compile(r"^\|\s*([A-Z]{2,3}-\d+)\s*\|(.*)$")
TECHNICAL_FIELD_RE = re.compile(r"\*\*(?:Applies to|Source|Guard):\*\*")
PROPOSAL_RE = re.compile(r"^specs/changes/[^/]+/proposal\.md$")
ACCEPTANCE_RE = re.compile(r"^## (REQ-[^:\s]+):\s+(.+)$")
MAX_DOCUMENT_BYTES = 1024 * 1024
PROPOSAL_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["reason", "affected_ids", "compatibility", "verification"],
    "properties": {
        **{key: {"type": "string", "pattern": r"\S"} for key in ("reason", "compatibility", "verification")},
        "affected_ids": {
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "pattern": r"^(REQ-([A-Z]{2,5}-)?[0-9]{3}|[A-Z]{2,3}-[0-9]+)$"},
        },
    },
}


@dataclass(frozen=True)
class Entry:
    rid: str
    section: str
    line: int
    text: str = ""


@dataclass(frozen=True)
class Binding:
    rid: str
    paths: tuple[str, ...]
    decisions: tuple[str, ...]
    documents: tuple[str, ...]
    coverage: str
    guards: tuple[str, ...]


def parse(text: str) -> list[Entry]:
    """Parse the normative Markdown catalog without implementation metadata."""
    entries: list[Entry] = []
    section = ""
    current: Entry | None = None
    text_lines: list[str] = []

    def finish() -> None:
        nonlocal current, text_lines
        if current is not None:
            entries[-1] = Entry(
                current.rid,
                current.section,
                current.line,
                " ".join(line for line in text_lines if line).strip(),
            )
        current = None
        text_lines = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        entry_match = ENTRY_RE.match(line)
        if entry_match:
            finish()
            current = Entry(entry_match.group(1), section, number)
            text_lines = [entry_match.group(2)]
            entries.append(current)
            continue
        section_match = SECTION_RE.match(line)
        if section_match:
            finish()
            section = section_match.group(1)
            continue
        if current is not None and line:
            text_lines.append(line)
    finish()
    return entries


def load_binding_document(path: Path = BINDINGS) -> object:
    """Load the binding YAML without silently normalizing an empty document."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def read_document(path: str) -> str:
    """Read a bounded UTF-8 document confined to this checkout."""
    candidate = ROOT / path
    if not safe_binding_pattern(path) or not _inside_root(candidate, ROOT):
        raise ValueError(f"{path!r}: document escapes the repository")
    if any(part.is_symlink() for part in (candidate, *candidate.parents) if part != ROOT and ROOT in part.parents):
        raise ValueError(f"{path!r}: document must not be a link")
    if not candidate.is_file():
        raise ValueError(f"{path!r}: cannot read a regular document")
    try:
        with candidate.open("rb") as stream:
            data = stream.read(MAX_DOCUMENT_BYTES + 1)
        if len(data) > MAX_DOCUMENT_BYTES:
            raise ValueError(f"{path!r}: document exceeds 1 MiB")
        return data.decode("utf-8")
    except (OSError, UnicodeError):
        raise ValueError(f"{path!r}: cannot read a UTF-8 document") from None


def acceptance_entries(text: str) -> list[Entry]:
    """Parse requirement sections; preserve duplicates for validation."""
    entries = []
    current = None
    body = []
    fence = None
    for number, line in enumerate(text.splitlines(), start=1):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence is not None:
            if current is not None:
                body.append(line.strip())
            if marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence):
                fence = None
            continue
        if marker:
            fence = marker.group(1)
        if not marker and line.startswith("## "):
            if current is not None:
                entries.append(Entry(current[0], current[2], current[1], " ".join(body).strip()))
            match = ACCEPTANCE_RE.fullmatch(line)
            if not match or not match.group(2).strip():
                raise ValueError(f"{ACCEPTANCE_PATH}:{number}: expected '## REQ-NNN: Title'")
            current = (match.group(1), number, match.group(2).strip())
            body = []
        elif current is not None:
            body.append(line.strip())
    if current is not None:
        entries.append(Entry(current[0], current[2], current[1], " ".join(body).strip()))
    return entries


def validate_acceptance(entries: list[Entry], text: str) -> list[str]:
    """Require exactly one nonempty acceptance section per active ID."""
    sections = acceptance_entries(text)
    active = {entry.rid for entry in entries}
    seen = set()
    problems = []
    for section in sections:
        where = f"{ACCEPTANCE_PATH}:{section.line} {section.rid}"
        if section.rid in seen:
            problems.append(f"{where}: duplicate acceptance section")
        seen.add(section.rid)
        if section.rid not in active:
            problems.append(f"{where}: acceptance section names inactive requirement")
        if not section.text:
            problems.append(f"{where}: empty acceptance section")
    for rid in sorted(active - seen):
        problems.append(f"{ACCEPTANCE_PATH}: missing acceptance section for {rid}")
    return problems


def binding_schema_problems(document: object, schema_path: Path = BINDING_SCHEMA) -> list[str]:
    """Return deterministic JSON Schema errors for the binding document."""
    schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    problems = []
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        problems.append(f"{BINDINGS.name}:{location}: {error.message}")
    return problems


def parse_bindings(document: object) -> dict[str, Binding]:
    """Convert a schema-valid binding document to immutable records."""
    if not isinstance(document, dict) or not isinstance(document.get("requirements"), dict):
        return {}
    bindings: dict[str, Binding] = {}
    for rid, raw in document["requirements"].items():
        if not isinstance(raw, dict):
            continue
        bindings[rid] = Binding(
            rid=rid,
            paths=tuple(raw.get("applies_to", [])),
            decisions=tuple(raw.get("decisions", [])),
            documents=tuple(raw.get("documents", [])),
            coverage=str(raw.get("coverage", "")),
            guards=tuple(raw.get("guards", [])),
        )
    return bindings


def known_test_nodes(root: Path = ROOT) -> set[str]:
    """Return exact pytest node IDs defined by test modules and Test classes."""
    nodes: set[str] = set()
    tests_dir = root / "tests"
    for path in tests_dir.rglob("test_*.py") if tests_dir.exists() else ():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        relative = path.relative_to(root).as_posix()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                nodes.add(f"{relative}::{node.name}")
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name.startswith("test_"):
                        nodes.add(f"{relative}::{node.name}::{child.name}")
    return nodes


def known_decisions(root: Path = ROOT) -> set[str]:
    register = root / REGISTER.relative_to(ROOT)
    if not register.exists():
        return set()
    return set(re.findall(r"^\| ([A-Z]{2,3}-\d+) \|", register.read_text(encoding="utf-8"), re.M))


def path_matches(pattern: str, root: Path = ROOT) -> list[str]:
    return glob.glob(pattern, root_dir=root, recursive=True)


def safe_binding_pattern(pattern: str) -> bool:
    """Return whether a binding glob is a repository-relative POSIX path."""
    if not pattern or "\\" in pattern or "://" in pattern or "\x00" in pattern:
        return False
    if re.match(r"^[A-Za-z]:/", pattern):
        return False
    path = PurePosixPath(pattern)
    return not path.is_absolute() and ".." not in path.parts


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def validate(
    entries: list[Entry],
    document: object,
    root: Path = ROOT,
    schema_path: Path = BINDING_SCHEMA,
) -> list[str]:
    """Return every catalog and binding problem as one message per problem."""
    problems = binding_schema_problems(document, schema_path)
    if problems:
        return problems
    bindings = parse_bindings(document)
    retired = set(document.get("retired_ids", [])) if isinstance(document, dict) else set()

    if not entries:
        return [f"{CATALOG.name}: no requirements found"]

    seen: dict[str, int] = {}
    active: set[str] = set()
    for entry in entries:
        where = f"{CATALOG.name}:{entry.line} {entry.rid}"
        if not ID_SHAPE_RE.fullmatch(entry.rid):
            problems.append(f"{where}: malformed id")
        if entry.rid in seen:
            problems.append(f"{where}: duplicate id, first seen at line {seen[entry.rid]}")
        seen.setdefault(entry.rid, entry.line)
        active.add(entry.rid)
        if not entry.section:
            problems.append(f"{where}: entry sits outside any section")
        if not entry.text:
            problems.append(f"{where}: no requirement text")
        if TECHNICAL_FIELD_RE.search(entry.text):
            problems.append(f"{where}: implementation metadata belongs in {BINDINGS.relative_to(ROOT)}")

    for rid in sorted(active - set(bindings)):
        problems.append(f"{BINDINGS.name}: missing binding for active requirement {rid}")
    for rid in sorted(set(bindings) - active):
        problems.append(f"{BINDINGS.name}: binding names inactive requirement {rid}")
    for rid in sorted(active & retired):
        problems.append(f"{BINDINGS.name}: active requirement is also retired: {rid}")

    tests = known_test_nodes(root)
    decisions = known_decisions(root)
    for rid, binding in sorted(bindings.items()):
        for pattern in binding.paths:
            if not safe_binding_pattern(pattern):
                problems.append(
                    f"{BINDINGS.name}:{rid}: applies_to must be a safe repository-relative pattern: {pattern}"
                )
                continue
            if not path_matches(pattern, root):
                problems.append(f"{BINDINGS.name}:{rid}: applies_to pattern matches nothing: {pattern}")
        for decision in binding.decisions:
            if not DECISION_RE.fullmatch(decision) or decision not in decisions:
                problems.append(f"{BINDINGS.name}:{rid}: unknown decision: {decision}")
        for document_path in binding.documents:
            candidate = root / document_path
            if not _inside_root(candidate, root):
                problems.append(f"{BINDINGS.name}:{rid}: document escapes the repository: {document_path}")
            elif not candidate.is_file():
                problems.append(f"{BINDINGS.name}:{rid}: document does not exist: {document_path}")
        if binding.coverage == "advisory" and binding.guards:
            problems.append(f"{BINDINGS.name}:{rid}: advisory coverage cannot name guards")
        if binding.coverage in {"direct", "partial"} and not binding.guards:
            problems.append(f"{BINDINGS.name}:{rid}: {binding.coverage} coverage requires a guard")
        for guard in binding.guards:
            if guard not in tests:
                problems.append(f"{BINDINGS.name}:{rid}: guard node does not exist: {guard}")
    return problems


def applicable(
    entries: list[Entry],
    bindings: dict[str, Binding],
    target: str,
    root: Path = ROOT,
) -> list[tuple[Entry, Binding]]:
    """Return requirements whose technical binding covers ``target``."""
    candidate = Path(target)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError:
            return []
    wanted = candidate.as_posix()
    hits = []
    for entry in entries:
        binding = bindings.get(entry.rid)
        if binding is None:
            continue
        if any(wanted in path_matches(pattern, root) or wanted == pattern for pattern in binding.paths):
            hits.append((entry, binding))
    return hits


def render(entry: Entry, binding: Binding) -> str:
    guards = ", ".join(binding.guards) if binding.guards else "none"
    decisions = ", ".join(binding.decisions) if binding.decisions else "none"
    documents = ", ".join(binding.documents) if binding.documents else "none"
    return (
        f"{entry.rid} ({entry.section})\n"
        f"  {entry.text}\n"
        f"  Technical context: decisions: {decisions}; documents: {documents}\n"
        f"  Guard coverage: {binding.coverage}; guards: {guards}"
    )


def register_entries(text: str) -> tuple[dict[str, str], list[str]]:
    """Return the decision register's rows by ID and the prose lines around them."""
    rows: dict[str, str] = {}
    prose: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        row = DECISION_ROW_RE.match(line)
        if row:
            rows[row.group(1)] = row.group(2).strip()
        elif line:
            prose.append(line)
    return rows, prose


def _git(*args: str) -> str:
    """Run read-only Git commands without shell interpretation or external diffs."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise ValueError("cannot read Git history (command failed or timed out)") from None
    if result.returncode:
        raise ValueError("cannot read Git history; check the base revision and available history")
    return result.stdout


def resolve_revision(ref: str) -> str:
    """Resolve an explicit revision to a commit before using it in Git arguments."""
    return _git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").strip()


def _file_at(ref: str, path: str) -> str | None:
    """Distinguish absent historical documents from unreadable Git history."""
    listing = _git("ls-tree", "-z", ref, "--", path)
    if not listing:
        return None
    metadata, _ = listing.rstrip("\x00").split("\t", 1)
    mode, kind, oid = metadata.split()
    if kind != "blob" or mode not in {"100644", "100755"}:
        raise ValueError(f"{path!r}: historical document must be a regular file")
    if int(_git("cat-file", "-s", oid)) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"{path!r}: historical document exceeds 1 MiB")
    return _git("cat-file", "blob", oid)


def register_change_needing_approval(ref: str | None) -> str | None:
    """Return why the register's change needs the operator, or ``None``.

    The register asks the operator before an entry is loosened, widened or
    retired, and recording a new decision is ordinary reviewed work. Telling the
    two apart needs the base revision: without one they are indistinguishable
    and the change is held.

    Only the rows are additive. The text around them states how every later
    decision is made, so a sentence added to it steers as much as one removed.
    """
    if not ref:
        return "cannot be compared against a base revision"
    base = _file_at(ref, REGISTER_PATH)
    if base is None:
        return None
    path = ROOT / REGISTER_PATH
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    base_rows, base_prose = register_entries(base)
    rows, prose = register_entries(current)
    touched = sorted(rid for rid, body in base_rows.items() if rows.get(rid) != body)
    if touched:
        return f"{', '.join(touched)} changed or removed"
    if base_prose != prose:
        return "the rules around its entries changed"
    return None


def proposal_ids(path: str) -> set[str]:
    """Validate the four required fields in a changed proposal's YAML front matter."""
    lines = read_document(path).splitlines()
    if not lines or lines[0] != "---" or "---" not in lines[1:]:
        raise ValueError(
            f"{path!r}: proposal needs YAML front matter with reason, affected_ids, compatibility, verification"
        )
    header = "\n".join(lines[1 : lines.index("---", 1)])
    try:
        node = yaml.compose(header)
        if isinstance(node, yaml.MappingNode):
            keys = [key.value for key, _ in node.value if isinstance(key, yaml.ScalarNode)]
            if len(keys) != len(node.value) or len(keys) != len(set(keys)):
                raise ValueError(f"{path!r}: duplicate or invalid proposal field")
        metadata = yaml.safe_load(header)
    except (yaml.YAMLError, RecursionError):
        raise ValueError(f"{path!r}: invalid proposal YAML") from None
    if not Draft202012Validator(PROPOSAL_SCHEMA).is_valid(metadata):
        raise ValueError(
            f"{path!r}: invalid proposal fields; require nonempty reason, compatibility, verification and an affected_ids list"
        )
    return set(metadata["affected_ids"])


def unapproved_changes(
    paths: list[str],
    ref: str | None = None,
    affected_ids: set[str] | None = None,
    known_ids: set[str] | None = None,
) -> list[str]:
    """Require valid changed proposals covering the affected requirement/decision IDs.

    A proposal records a change; this check cannot establish user approval.
    """
    touched = [path for path in paths if path in HELD_PATHS]
    proposals = [path for path in paths if PROPOSAL_RE.fullmatch(path)]
    problems: list[str] = []
    recorded = set()
    for path in proposals:
        try:
            ids = proposal_ids(path)
            if known_ids is not None and ids - known_ids:
                problems.append(f"{path!r}: unknown affected IDs: {', '.join(sorted(ids - known_ids))}")
            recorded.update(ids)
        except ValueError as error:
            problems.append(str(error))
    if proposals:
        for rid in sorted((affected_ids or set()) - recorded):
            problems.append(f"{rid}: changed ID is not recorded in a valid changed proposal")
        return problems
    for path in touched:
        if path == REGISTER_PATH:
            reason = register_change_needing_approval(ref)
            if reason is not None:
                problems.append(f"{path}: {reason}, with no proposal under {CHANGE_DIR}")
            continue
        problems.append(f"{path} changed with no proposal under {CHANGE_DIR}")
    return problems


def changed_since(ref: str) -> list[str]:
    """Return tracked and untracked paths that differ from ``ref``."""
    tracked = _git("diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", ref, "--")
    untracked = _git("ls-files", "--others", "--exclude-standard", "-z")
    return sorted(set(path for path in (tracked + untracked).split("\x00") if path))


def changed_requirement_ids(ref: str, entries: list[Entry], document: dict) -> tuple[set[str], list[str]]:
    """Compare normative entries and keep the retirement history monotonic."""
    previous = parse(_file_at(ref, "requirements.md") or "")
    old_acceptance = acceptance_entries(_file_at(ref, ACCEPTANCE_PATH) or "")
    current_acceptance = acceptance_entries(read_document(ACCEPTANCE_PATH))
    affected = set()
    for old, new in ((previous, entries), (old_acceptance, current_acceptance)):
        before = {entry.rid: (entry.section, " ".join(entry.text.split())) for entry in old}
        after = {entry.rid: (entry.section, " ".join(entry.text.split())) for entry in new}
        affected.update(rid for rid in before.keys() | after.keys() if before.get(rid) != after.get(rid))
    previous_bindings = yaml.safe_load(_file_at(ref, "data/requirement-bindings.yaml") or "{}")
    if not isinstance(previous_bindings, dict):
        raise ValueError("base revision has invalid requirement bindings")
    old_retired = previous_bindings.get("retired_ids", [])
    if not isinstance(old_retired, list) or any(not isinstance(rid, str) for rid in old_retired):
        raise ValueError("base revision has invalid retired_ids")
    old_retired = set(old_retired)
    retired = set(document["retired_ids"])
    active = {entry.rid for entry in entries}
    removed = {entry.rid for entry in previous} - active
    problems = [f"{rid}: removed requirement must be recorded in retired_ids" for rid in sorted(removed - retired)]
    problems += [f"{rid}: historical retired ID must be preserved" for rid in sorted(old_retired - retired)]
    problems += [f"{rid}: historical retired ID cannot be reused" for rid in sorted(old_retired & active)]
    return affected, problems


def _load_current() -> tuple[list[Entry], object]:
    if not CATALOG.exists():
        raise ValueError(f"{CATALOG} is missing")
    if not BINDINGS.exists():
        raise ValueError(f"{BINDINGS} is missing")
    try:
        document = yaml.safe_load(read_document("data/requirement-bindings.yaml"))
    except (yaml.YAMLError, RecursionError):
        raise ValueError("data/requirement-bindings.yaml: invalid YAML") from None
    return parse(read_document("requirements.md")), document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--for", dest="target", help="print the requirements that govern a file")
    parser.add_argument(
        "--changed-against",
        dest="ref",
        help="also check changes, proposal fields, affected IDs and retirements against an explicit base commit",
    )
    args = parser.parse_args(argv)
    if args.ref is not None and not args.ref.strip():
        print("an explicit base revision is required; set BASE=<base-commit> for the Make gate", file=sys.stderr)
        return 2

    try:
        entries, document = _load_current()
        problems = validate(entries, document, root=ROOT)
        problems.extend(validate_acceptance(entries, read_document(ACCEPTANCE_PATH)))
        if args.ref and not problems:
            ref = resolve_revision(args.ref)
            paths = changed_since(ref)
            affected, history_problems = changed_requirement_ids(ref, entries, document)
            known_ids = {entry.rid for entry in entries} | set(document["retired_ids"]) | known_decisions(ROOT)
            if REGISTER_PATH in paths:
                before, _ = register_entries(_file_at(ref, REGISTER_PATH) or "")
                after, _ = register_entries(read_document(REGISTER_PATH))
                affected.update(rid for rid in before if before[rid] != after.get(rid))
                known_ids.update(before)
            problems.extend(history_problems)
            problems.extend(unapproved_changes(paths, ref, affected, known_ids))
    except (yaml.YAMLError, RecursionError):
        print("invalid YAML in requirement history", file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2

    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1

    bindings = parse_bindings(document)
    if args.target:
        hits = applicable(entries, bindings, args.target)
        if not hits:
            # Say so explicitly: silence reads the same as the tool not running.
            print(f"No requirement is bound to {args.target}.")
            return 0
        print(f"Requirements for {args.target}:")
        for entry, binding in hits:
            print(render(entry, binding))
        return 0

    counts = {coverage: 0 for coverage in ("direct", "partial", "advisory")}
    for binding in bindings.values():
        counts[binding.coverage] += 1
    print(
        f"specs: {len(entries)} requirements "
        f"({counts['direct']} direct, {counts['partial']} partial, {counts['advisory']} advisory)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
