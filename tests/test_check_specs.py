"""Guards for the separated product catalog and technical bindings."""

from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_specs  # noqa: E402


def entry(
    rid: str = "REQ-001",
    text: str = "The stable product requirement.",
) -> str:
    return f"# Analyzer requirements\n\n## A section\n\n- **{rid}:** {text}\n"


def binding_document(
    *,
    rid: str = "REQ-001",
    applies: list[str] | None = None,
    decisions: list[str] | None = None,
    documents: list[str] | None = None,
    coverage: str = "direct",
    guards: list[str] | None = None,
    retired: list[str] | None = None,
) -> dict:
    return {
        "version": 2,
        "retired_ids": retired or [],
        "requirements": {
            rid: {
                "applies_to": applies or ["target.py"],
                "decisions": decisions or [],
                "documents": documents or [],
                "coverage": coverage,
                "guards": guards if guards is not None else ["tests/test_guard.py::test_rule"],
            }
        },
    }


@pytest.fixture
def catalog_root(tmp_path: Path) -> Path:
    (tmp_path / "target.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_guard.py").write_text("def test_rule():\n    pass\n", encoding="utf-8")
    (tmp_path / "docs" / "internal").mkdir(parents=True)
    (tmp_path / "docs" / "internal" / "decisions.md").write_text(
        "| ID | Decision | Guard | Rationale |\n|---|---|---|---|\n| XY-1 | A decision | test | reason |\n",
        encoding="utf-8",
    )
    return tmp_path


def problems(markdown: str, document: object, root: Path) -> list[str]:
    return check_specs.validate(check_specs.parse(markdown), document, root=root)


def test_shipped_catalog_and_bindings_are_valid():
    entries = check_specs.parse(check_specs.CATALOG.read_text(encoding="utf-8"))
    document = check_specs.load_binding_document()
    assert entries
    assert check_specs.validate(entries, document) == []


def test_parses_only_normative_text():
    parsed = check_specs.parse(entry())
    assert parsed == [
        check_specs.Entry(
            rid="REQ-001",
            section="A section",
            line=5,
            text="The stable product requirement.",
        )
    ]


def test_bullets_keep_their_text_topic_and_source_line():
    markdown = (
        "# Requirements\n\n## Evidence\n\n"
        "- **REQ-001:** Cite inspected code.\n"
        "- **REQ-002:** Keep uncertainty visible.\n\n"
        "## Exports\n\n- **REQ-003:** Preserve references.\n"
    )
    assert check_specs.parse(markdown) == [
        check_specs.Entry("REQ-001", "Evidence", 5, "Cite inspected code."),
        check_specs.Entry("REQ-002", "Evidence", 6, "Keep uncertainty visible."),
        check_specs.Entry("REQ-003", "Exports", 10, "Preserve references."),
    ]


def test_malformed_bullet_id_is_not_silently_dropped(catalog_root):
    markdown = entry() + "\n- **REQ-12:** Another promise.\n"
    assert any("malformed id" in problem for problem in problems(markdown, binding_document(), catalog_root))


@pytest.mark.parametrize("rid", ["REQ-001", "REQ-042", "REQ-999"])
def test_plain_ids_are_valid_without_category_or_sequence_requirements(catalog_root, rid):
    assert problems(entry(rid), binding_document(rid=rid), catalog_root) == []


@pytest.mark.parametrize("rid", ["REQ-XYZ-001", "REQ-12", "REQ-0001", "REQ-abc", "REQ-１２３", "REQ-001/extra"])
def test_invalid_active_ids_are_rejected_in_catalog_and_bindings(catalog_root, rid):
    assert any("malformed id" in issue for issue in problems(entry(rid), binding_document(), catalog_root))
    assert check_specs.binding_schema_problems(binding_document(rid=rid))


def test_legacy_and_plain_retirements_are_preserved(catalog_root):
    document = binding_document(retired=["REQ-XYZ-001", "REQ-002"])
    assert problems(entry(), document, catalog_root) == []


@pytest.mark.parametrize("rid", ["REQ-12", "REQ-XYZ-12", "REQ-XYZ-１２３"])
def test_malformed_retired_ids_are_rejected(rid):
    assert check_specs.binding_schema_problems(binding_document(retired=[rid]))


def test_old_binding_version_requires_explicit_migration(catalog_root):
    document = binding_document()
    document["version"] = 1
    assert any("version" in issue for issue in problems(entry(), document, catalog_root))


def test_requirement_outside_a_topic_is_rejected(catalog_root):
    markdown = "# Requirements\n\n- **REQ-001:** A promise.\n"
    assert any("outside any section" in problem for problem in problems(markdown, binding_document(), catalog_root))


def test_lookup_renders_bullet_text_once(catalog_root):
    parsed = check_specs.parse(entry())[0]
    binding = check_specs.parse_bindings(binding_document())[parsed.rid]
    rendered = check_specs.render(parsed, binding)
    assert "REQ-001 (A section)" in rendered
    assert rendered.count(parsed.text) == 1


def test_duplicate_id_is_rejected(catalog_root):
    doubled = entry() + entry(text="Another requirement.").split("# Analyzer requirements\n\n", 1)[1]
    assert any("duplicate id" in problem for problem in problems(doubled, binding_document(), catalog_root))


def test_missing_requirement_text_is_rejected(catalog_root):
    assert any(
        "no requirement text" in problem for problem in problems(entry(text=""), binding_document(), catalog_root)
    )


def test_implementation_metadata_is_rejected_from_catalog(catalog_root):
    markdown = entry(text="The promise.\n\n**Guard:** tests/test_guard.py::test_rule")
    assert any("implementation metadata" in problem for problem in problems(markdown, binding_document(), catalog_root))


def test_binding_schema_requires_every_field(catalog_root):
    document = binding_document()
    del document["requirements"]["REQ-001"]["coverage"]
    assert any("coverage" in problem for problem in problems(entry(), document, catalog_root))


def test_active_requirement_requires_exactly_one_binding(catalog_root):
    document = binding_document(rid="REQ-002")
    found = problems(entry(), document, catalog_root)
    assert any("missing binding" in problem for problem in found)
    assert any("inactive requirement" in problem for problem in found)


def test_retired_requirement_id_cannot_be_active(catalog_root):
    document = binding_document(retired=["REQ-001"])
    assert any("also retired" in problem for problem in problems(entry(), document, catalog_root))


def test_exact_guard_node_must_exist(catalog_root):
    document = binding_document(guards=["tests/test_elsewhere.py::test_rule"])
    assert any("guard node does not exist" in problem for problem in problems(entry(), document, catalog_root))


def test_class_method_guard_node_is_resolved(catalog_root):
    (catalog_root / "tests" / "test_guard.py").write_text(
        "class TestRule:\n    def test_rule(self):\n        pass\n",
        encoding="utf-8",
    )
    document = binding_document(guards=["tests/test_guard.py::TestRule::test_rule"])
    assert problems(entry(), document, catalog_root) == []


def test_direct_and_partial_coverage_require_guards(catalog_root):
    for coverage in ("direct", "partial"):
        document = binding_document(coverage=coverage, guards=[])
        assert any("requires a guard" in problem for problem in problems(entry(), document, catalog_root))


def test_advisory_coverage_requires_an_empty_guard_list(catalog_root):
    document = binding_document(coverage="advisory")
    assert any("advisory coverage" in problem for problem in problems(entry(), document, catalog_root))
    document = binding_document(coverage="advisory", guards=[])
    assert problems(entry(), document, catalog_root) == []


def test_unknown_decision_is_rejected(catalog_root):
    document = binding_document(decisions=["ZZ-99"])
    assert any("unknown decision" in problem for problem in problems(entry(), document, catalog_root))


def test_known_decision_is_accepted(catalog_root):
    document = binding_document(decisions=["XY-1"])
    assert problems(entry(), document, catalog_root) == []


def test_missing_or_escaping_document_is_rejected(catalog_root):
    missing = binding_document(documents=["docs/missing.md"])
    assert any("document does not exist" in problem for problem in problems(entry(), missing, catalog_root))
    escaping = binding_document(documents=["../outside.md"])
    assert any("document escapes" in problem for problem in problems(entry(), escaping, catalog_root))


def test_applies_to_pattern_must_match(catalog_root):
    document = binding_document(applies=["scripts/missing.py"])
    assert any("matches nothing" in problem for problem in problems(entry(), document, catalog_root))


@pytest.mark.parametrize(
    "pattern",
    [
        "/etc/passwd",
        "../outside.py",
        "C:/outside.py",
        "https://example.invalid/file.py",
        r"scripts\outside.py",
    ],
)
def test_applies_to_pattern_must_be_repository_relative(catalog_root, pattern):
    document = binding_document(applies=[pattern])
    assert any("safe repository-relative" in problem for problem in problems(entry(), document, catalog_root))


def test_applicable_uses_external_bindings(catalog_root):
    entries = check_specs.parse(entry())
    bindings = check_specs.parse_bindings(binding_document(applies=["*.py"]))
    hits = check_specs.applicable(entries, bindings, "target.py", root=catalog_root)
    assert [(item.rid, binding.coverage) for item, binding in hits] == [("REQ-001", "direct")]
    assert check_specs.applicable(entries, bindings, "README.md", root=catalog_root) == []


def test_applicable_ignores_paths_outside_repository(catalog_root):
    entries = check_specs.parse(entry())
    bindings = check_specs.parse_bindings(binding_document())
    assert check_specs.applicable(entries, bindings, "/etc/passwd", root=catalog_root) == []


def test_main_reports_requirement_and_coverage_counts(capsys):
    assert check_specs.main([]) == 0
    output = capsys.readouterr().out
    assert "35 requirements" in output
    assert "direct" in output and "partial" in output and "advisory" in output


def test_main_for_prints_governing_requirement_and_coverage(capsys):
    assert check_specs.main(["--for", "scripts/model/merge_threats.py"]) == 0
    output = capsys.readouterr().out
    assert "REQ-008" in output
    assert "Guard coverage: partial" in output


def test_main_for_unbound_file_says_no_requirement_is_bound(capsys):
    assert check_specs.main(["--for", "scripts/does_not_exist.py"]) == 0
    assert "No requirement is bound to scripts/does_not_exist.py." in capsys.readouterr().out


def test_held_file_without_changed_proposal_is_unapproved():
    assert check_specs.unapproved_changes(["requirements.md"]) == [
        "requirements.md changed with no proposal under specs/changes/"
    ]


def write_proposal(root: Path, *, ids: list[str] | None = None, name: str = "some-change") -> str:
    path = f"specs/changes/{name}/proposal.md"
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "---\n"
        + yaml.safe_dump(
            {
                "reason": "Clarify the observable result.",
                "affected_ids": ids if ids is not None else ["REQ-001"],
                "compatibility": "Existing invocations remain valid.",
                "verification": "Run the intended and negative catalog cases.",
            }
        )
        + "---\n\n# Reviewed change\n",
        encoding="utf-8",
    )
    return path


def test_held_file_with_changed_proposal_is_recorded(tmp_path, monkeypatch):
    monkeypatch.setattr(check_specs, "ROOT", tmp_path)
    changed = [
        "docs/internal/decisions.md",
        write_proposal(tmp_path, ids=[]),
    ]
    assert check_specs.unapproved_changes(changed) == []


def test_tasks_file_alone_is_not_a_change_proposal():
    changed = ["requirements.md", "specs/changes/some-change/tasks.md"]
    assert check_specs.unapproved_changes(changed)


def test_ordinary_changes_need_no_proposal():
    assert check_specs.unapproved_changes(["scripts/model/merge_threats.py", "README.md"]) == []


def register_text() -> str:
    return check_specs.REGISTER.read_text(encoding="utf-8")


def register_rows() -> list[str]:
    return [line for line in register_text().splitlines() if check_specs.DECISION_ROW_RE.match(line)]


def with_base(monkeypatch, base: str) -> None:
    """Compare the live register against a doctored base of itself."""
    monkeypatch.setattr(check_specs, "_file_at", lambda ref, path: base)


def register_problems() -> list[str]:
    return check_specs.unapproved_changes([check_specs.REGISTER_PATH], "HEAD")


def test_adding_a_decision_needs_no_proposal(monkeypatch):
    with_base(monkeypatch, register_text().replace(register_rows()[-1] + "\n", ""))
    assert register_problems() == []


def test_changing_a_decision_needs_a_proposal(monkeypatch):
    row = register_rows()[0]
    rid = check_specs.DECISION_ROW_RE.match(row).group(1)
    with_base(monkeypatch, register_text().replace(row, row + " and something wider"))
    problems = register_problems()
    assert problems and f"{rid} changed or removed" in problems[0]


def test_removing_a_decision_needs_a_proposal(monkeypatch):
    with_base(monkeypatch, register_text() + "\n| ZZ-9 | A retired rule | — | — |\n")
    problems = register_problems()
    assert problems and "ZZ-9 changed or removed" in problems[0]


def without_the_entry_rule(text: str) -> str:
    """The register as it read before its entry rule was added."""
    return "\n".join(line for line in text.splitlines() if not line.startswith("**Adding a decision:**"))


@pytest.mark.parametrize(
    "doctor",
    [lambda text: "A rule that was dropped.\n" + text, without_the_entry_rule],
    ids=["rule-dropped", "rule-added"],
)
def test_changing_the_registers_own_rules_needs_a_proposal(monkeypatch, doctor):
    with_base(monkeypatch, doctor(register_text()))
    assert register_problems() == [
        "docs/internal/decisions.md: the rules around its entries changed, with no proposal under specs/changes/"
    ]


def test_the_register_is_held_when_no_base_revision_can_be_read():
    assert check_specs.unapproved_changes([check_specs.REGISTER_PATH]) == [
        "docs/internal/decisions.md: cannot be compared against a base revision, with no proposal under specs/changes/"
    ]


@pytest.mark.parametrize("path", ["requirements.md", check_specs.ACCEPTANCE_PATH])
def test_requirements_and_acceptance_rules_are_held_for_any_change(monkeypatch, tmp_path, path):
    with_base(monkeypatch, register_text())
    monkeypatch.setattr(check_specs, "ROOT", tmp_path)
    assert check_specs.unapproved_changes([path], "HEAD") == [f"{path} changed with no proposal under specs/changes/"]
    assert check_specs.unapproved_changes([path, write_proposal(tmp_path)], "HEAD") == []


def test_changed_against_unknown_ref_reports_and_exits_two(capsys):
    assert check_specs.main(["--changed-against", "no-such-ref-xyz"]) == 2
    assert capsys.readouterr().err


def test_invalid_binding_document_does_not_mutate_fixture(catalog_root):
    document = binding_document()
    original = copy.deepcopy(document)
    assert problems(entry(), document, catalog_root) == []
    assert document == original


def acceptance(rid: str = "REQ-001", body: str = "The result must be observable.") -> str:
    return f"# Acceptance\n\n## {rid}: User outcome\n\n{body}\n"


def test_shipped_acceptance_matches_every_active_requirement():
    entries = check_specs.parse(check_specs.CATALOG.read_text(encoding="utf-8"))
    text = (ROOT / check_specs.ACCEPTANCE_PATH).read_text(encoding="utf-8")
    assert check_specs.validate_acceptance(entries, text) == []


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("# Empty contract\n", "missing acceptance section"),
        (acceptance() + acceptance(), "duplicate acceptance section"),
        (acceptance("REQ-002"), "inactive requirement"),
        (acceptance(body=""), "empty acceptance section"),
    ],
)
def test_acceptance_rejects_missing_duplicate_stale_and_empty_sections(text, message):
    assert any(message in problem for problem in check_specs.validate_acceptance(check_specs.parse(entry()), text))


@pytest.mark.parametrize("heading", ["## REQ-001", "## REQ-001:", "## Acceptance without an ID"])
def test_acceptance_rejects_malformed_headings(heading):
    with pytest.raises(ValueError, match="expected"):
        check_specs.validate_acceptance(check_specs.parse(entry()), heading + "\nText.\n")


def test_fenced_examples_do_not_supply_acceptance_sections():
    fenced = "```markdown\n" + acceptance() + "```\n"
    assert check_specs.validate_acceptance(check_specs.parse(entry()), fenced) == [
        f"{check_specs.ACCEPTANCE_PATH}: missing acceptance section for REQ-001"
    ]
    assert check_specs.validate_acceptance(check_specs.parse(entry()), acceptance() + fenced) == []


@pytest.mark.parametrize("field", ["reason", "affected_ids", "compatibility", "verification"])
@pytest.mark.parametrize("value", [None, "", " ", 12])
def test_proposal_rejects_missing_or_invalid_fields(tmp_path, monkeypatch, field, value):
    monkeypatch.setattr(check_specs, "ROOT", tmp_path)
    path = write_proposal(tmp_path)
    metadata = yaml.safe_load((tmp_path / path).read_text().split("---")[1])
    if value is None:
        del metadata[field]
    else:
        metadata[field] = value
    (tmp_path / path).write_text("---\n" + yaml.safe_dump(metadata) + "---\n")
    assert check_specs.unapproved_changes(["requirements.md", path], affected_ids={"REQ-001"})


def test_unrelated_or_unknown_ids_do_not_document_a_change(tmp_path, monkeypatch):
    monkeypatch.setattr(check_specs, "ROOT", tmp_path)
    path = write_proposal(tmp_path, ids=["REQ-002", "REQ-999"])
    problems = check_specs.unapproved_changes(
        ["requirements.md", path],
        affected_ids={"REQ-001"},
        known_ids={"REQ-001", "REQ-002"},
    )
    assert any("REQ-001: changed ID" in problem for problem in problems)
    assert any("unknown affected IDs: REQ-999" in problem for problem in problems)


def test_multiple_valid_proposals_can_cover_a_combined_change(tmp_path, monkeypatch):
    monkeypatch.setattr(check_specs, "ROOT", tmp_path)
    paths = [
        "requirements.md",
        write_proposal(tmp_path),
        write_proposal(tmp_path, ids=["REQ-002"], name="second"),
    ]
    assert check_specs.unapproved_changes(paths, affected_ids={"REQ-001", "REQ-002"}) == []


@pytest.mark.parametrize(
    "kind",
    ["missing", "empty", "symlink", "parent-symlink", "oversize", "unsafe-yaml", "duplicate-field", "nested-yaml"],
)
def test_invalid_proposal_cannot_satisfy_the_gate(tmp_path, monkeypatch, kind):
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(check_specs, "ROOT", root)
    monkeypatch.chdir(root)
    path = write_proposal(root)
    target = root / path
    if kind == "missing":
        target.unlink()
    elif kind == "empty":
        target.write_text("")
    elif kind == "symlink":
        outside = tmp_path / "outside.md"
        target.rename(outside)
        target.symlink_to(outside)
    elif kind == "parent-symlink":
        outside = tmp_path / "outside"
        target.parent.rename(outside)
        target.parent.symlink_to(outside, target_is_directory=True)
    elif kind == "oversize":
        target.write_text("x" * (check_specs.MAX_DOCUMENT_BYTES + 1))
    elif kind == "unsafe-yaml":
        target.write_text("---\nreason: !!python/object/apply:os.system ['touch forbidden']\n---\n")
    elif kind == "nested-yaml":
        target.write_text("---\nreason: " + "[" * 2000 + "0" + "]" * 2000 + "\n---\n")
    else:
        target.write_text(target.read_text().replace("---\n", "---\nreason: Duplicate\n", 1))
    assert check_specs.unapproved_changes(["requirements.md", path], affected_ids={"REQ-001"})
    assert not (root / "forbidden").exists()


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout.strip()


@pytest.fixture
def history_root(catalog_root, monkeypatch):
    root = catalog_root
    (root / "requirements.md").write_text(entry())
    (root / check_specs.ACCEPTANCE_PATH).parent.mkdir(parents=True, exist_ok=True)
    (root / check_specs.ACCEPTANCE_PATH).write_text(acceptance())
    (root / "data").mkdir()
    (root / "data/requirement-bindings.yaml").write_text(yaml.safe_dump(binding_document(retired=["REQ-009"])))
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "-c", "user.name=Spec test", "-c", "user.email=spec@example.invalid", "commit", "-qm", "Base catalog")
    monkeypatch.setattr(check_specs, "ROOT", root)
    monkeypatch.setattr(check_specs, "CATALOG", root / "requirements.md")
    monkeypatch.setattr(check_specs, "BINDINGS", root / "data/requirement-bindings.yaml")
    monkeypatch.setattr(check_specs, "REGISTER", root / check_specs.REGISTER_PATH)
    monkeypatch.chdir(root)
    return root


@pytest.mark.parametrize("path", ["requirements.md", check_specs.ACCEPTANCE_PATH])
def test_git_change_requires_matching_proposal(history_root, capsys, path):
    target = history_root / path
    target.write_text(target.read_text() + "\nAdditional required behavior.\n")
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "no proposal" in capsys.readouterr().err
    proposal = write_proposal(history_root, ids=[])
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "REQ-001: changed ID" in capsys.readouterr().err
    write_proposal(history_root)
    assert check_specs.main(["--changed-against", "HEAD"]) == 0
    assert (history_root / proposal).is_file()


def test_changed_mode_still_checks_catalog_and_acceptance(history_root, capsys):
    (history_root / check_specs.ACCEPTANCE_PATH).write_text(acceptance("REQ-002"))
    write_proposal(history_root, ids=["REQ-001", "REQ-002"])
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "missing acceptance section for REQ-001" in capsys.readouterr().err
    (history_root / check_specs.ACCEPTANCE_PATH).write_text(acceptance())
    (history_root / "tests/test_guard.py").write_text("# Deleted test\n")
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "guard node does not exist" in capsys.readouterr().err


def test_removed_id_requires_retirement_even_with_a_valid_proposal(history_root, capsys):
    (history_root / "requirements.md").write_text(entry("REQ-002"))
    (history_root / check_specs.ACCEPTANCE_PATH).write_text(acceptance("REQ-002"))
    bindings = binding_document(rid="REQ-002", retired=["REQ-009"])
    check_specs.BINDINGS.write_text(yaml.safe_dump(bindings))
    write_proposal(history_root, ids=["REQ-001", "REQ-002"])
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "REQ-001: removed requirement" in capsys.readouterr().err
    bindings["retired_ids"].append("REQ-001")
    check_specs.BINDINGS.write_text(yaml.safe_dump(bindings))
    assert check_specs.main(["--changed-against", "HEAD"]) == 0


@pytest.mark.parametrize("reuse", [False, True])
def test_historical_retirements_cannot_be_erased_or_reused(history_root, capsys, reuse):
    bindings = binding_document(retired=[])
    if reuse:
        (history_root / "requirements.md").write_text(entry() + entry("REQ-009"))
        (history_root / check_specs.ACCEPTANCE_PATH).write_text(acceptance() + acceptance("REQ-009"))
        bindings["requirements"]["REQ-009"] = copy.deepcopy(bindings["requirements"]["REQ-001"])
        write_proposal(history_root, ids=["REQ-009"])
    check_specs.BINDINGS.write_text(yaml.safe_dump(bindings))
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "REQ-009: historical retired ID" in capsys.readouterr().err


def test_git_comparison_includes_committed_staged_and_untracked_changes(history_root, capsys):
    base = git(history_root, "rev-parse", "HEAD")
    check_specs.CATALOG.write_text(entry(text="Changed outcome."))
    git(history_root, "add", "requirements.md")
    git(history_root, "-c", "user.name=Spec test", "-c", "user.email=spec@example.invalid", "commit", "-qm", "Change")
    contract = history_root / check_specs.ACCEPTANCE_PATH
    contract.write_text(acceptance(body="Changed acceptance."))
    git(history_root, "add", check_specs.ACCEPTANCE_PATH)
    proposal = write_proposal(history_root)
    assert set(check_specs.changed_since(base)) == {"requirements.md", check_specs.ACCEPTANCE_PATH, proposal}
    assert check_specs.main(["--changed-against", base]) == 0
    assert "35 requirements" not in capsys.readouterr().out


def test_deleted_proposal_does_not_authorize_a_requirement_change(history_root, capsys):
    path = write_proposal(history_root)
    git(history_root, "add", path)
    git(history_root, "-c", "user.name=Spec test", "-c", "user.email=spec@example.invalid", "commit", "-qm", "Proposal")
    (history_root / path).unlink()
    check_specs.CATALOG.write_text(entry(text="Changed result."))
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_acceptance_title_changes_require_the_affected_id(history_root, capsys):
    (history_root / check_specs.ACCEPTANCE_PATH).write_text(acceptance().replace("User outcome", "Changed outcome"))
    write_proposal(history_root, ids=[])
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "REQ-001: changed ID" in capsys.readouterr().err


def test_unchanged_historical_proposal_needs_no_new_fields_and_cannot_cover_new_changes(history_root, capsys):
    path = history_root / "specs/changes/history/proposal.md"
    path.parent.mkdir(parents=True)
    path.write_text("# Historical proposal without structured fields\n")
    git(history_root, "add", ".")
    git(history_root, "-c", "user.name=Spec test", "-c", "user.email=spec@example.invalid", "commit", "-qm", "History")
    assert check_specs.main(["--changed-against", "HEAD"]) == 0
    check_specs.CATALOG.write_text(entry(text="Changed outcome."))
    assert check_specs.main(["--changed-against", "HEAD"]) == 1
    assert "no proposal" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["missing", "symlink", "unsafe-yaml"])
def test_current_documents_reject_missing_links_and_unsafe_yaml(history_root, capsys, kind):
    if kind == "missing":
        (history_root / check_specs.ACCEPTANCE_PATH).unlink()
    elif kind == "symlink":
        target = history_root / check_specs.ACCEPTANCE_PATH
        target.unlink()
        target.symlink_to(history_root / "requirements.md")
    else:
        check_specs.BINDINGS.write_text("!!python/object/apply:os.system ['touch forbidden']\n")
    assert check_specs.main([]) == 2
    assert capsys.readouterr().err
    assert not (history_root / "forbidden").exists()


@pytest.mark.parametrize("ref", ["", " ", "--help", "missing-revision"])
def test_missing_invalid_or_option_like_base_fails_closed(history_root, capsys, ref):
    assert check_specs.main(["--changed-against=" + ref]) == 2
    assert capsys.readouterr().err


def test_make_gate_requires_base_and_runs_change_check_first(history_root):
    (history_root / "scripts").mkdir()
    (history_root / "scripts/check_specs.py").write_text((ROOT / "scripts/check_specs.py").read_text())
    (history_root / "schemas").mkdir()
    (history_root / "schemas/requirement-bindings.schema.yaml").write_text(check_specs.BINDING_SCHEMA.read_text())
    command = ["make", "--no-print-directory", "-f", str(ROOT / "Makefile"), f"PYTHON={sys.executable}"]
    missing = subprocess.run(command + ["check-analyzer", "BASE="], cwd=history_root, capture_output=True, text=True)
    assert missing.returncode != 0
    assert "explicit base revision" in missing.stderr
    injected = subprocess.run(
        command + ["check-specs", "BASE=HEAD' ; touch forbidden ; '"],
        cwd=history_root,
        capture_output=True,
        text=True,
    )
    assert injected.returncode != 0
    assert not (history_root / "forbidden").exists()
    check_specs.CATALOG.write_text(entry(text="Changed result."))
    failed = subprocess.run(command + ["check-analyzer", "BASE=HEAD"], cwd=history_root, capture_output=True, text=True)
    assert failed.returncode != 0
    assert "no proposal" in failed.stderr
    assert "ruff" not in failed.stdout
    write_proposal(history_root)
    passed = subprocess.run(command + ["check-specs", "BASE=HEAD"], cwd=history_root, capture_output=True, text=True)
    assert passed.returncode == 0, passed.stderr
