"""Document selection follows revision, path, sensitivity and size boundaries."""

from __future__ import annotations

import subprocess

import pytest
from contexts import analyst_documents as docs

from tests.test_analyst_controller import git
from tests.test_threat_analysis_cli import project as project_fixture

project = project_fixture


def test_default_discovery_and_explicit_context(project):
    (project / "threatmodel.md").write_text("T-04: Exports cross a tenant boundary.\n")
    (project / "design.txt").write_text("The API uses a tenant key.\n")
    documents, sources = docs.capture(project, {"kind": "design"}, ["design.txt"])
    assert {d["path"] for d in documents} == {"requirements.md", "threatmodel.md", "design.txt"}
    assert len(sources) == 3 and all(s["status"] == "delivered" for s in sources)


def test_hypothesis_documents_are_read_from_revision_not_worktree(project):
    (project / "requirements.md").write_text("This later change is not selected.\n")
    documents, _ = docs.capture(project, {"kind": "hypothesis", "revision": "HEAD"}, [])
    assert "REQ-017" in documents[0]["text"]
    assert (
        documents[0]["revision"]
        == subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"]).decode().strip()
    )


@pytest.mark.parametrize("path", ["../secret.md", "/etc/passwd", "docs/../private.md", "a\nb.md", "a\\b.md", "./a.md"])
def test_context_paths_cannot_escape_or_inject_labels(project, path):
    with pytest.raises(docs.DocumentError):
        docs.capture(project, {"kind": "design"}, [path])


def test_external_and_parent_symlinks_never_deliver_content(project, tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    (external / "secret.md").write_text("outside scope\n")
    (project / "link").symlink_to(external, target_is_directory=True)
    (project / "threat-model.md").symlink_to(external / "secret.md")
    documents, sources = docs.capture(project, {"kind": "design"}, [])
    assert all("outside scope" not in d["text"] for d in documents)
    assert any(s["status"] == "invalid" for s in sources)
    with pytest.raises(docs.DocumentError):
        docs.capture(project, {"kind": "design"}, ["link/secret.md"], discover=False)


def test_committed_symlink_is_not_followed(project):
    (project / "requirements.md").unlink()
    (project / "requirements.md").symlink_to("api.py")
    git(project, "add", ".")
    git(project, "commit", "-qm", "link")
    with pytest.raises(docs.DocumentError, match="Linked"):
        docs.capture(project, {"kind": "hypothesis", "revision": "HEAD"}, [])


def test_multiple_models_require_explicit_selection(project):
    (project / "threatmodel.md").write_text("model one")
    (project / "threat-model.md").write_text("model two")
    with pytest.raises(docs.AmbiguousModels):
        docs.capture(project, {"kind": "design"}, [])
    documents, _ = docs.capture(project, {"kind": "design"}, ["threatmodel.md"])
    assert {d["path"] for d in documents} == {"requirements.md", "threatmodel.md"}


def test_isolated_and_no_discovery_preserve_explicit_spec(project):
    (project / "threatmodel.md").write_text("A model")
    documents, _ = docs.capture(project, {"kind": "design"}, [], include_models=False)
    assert {d["path"] for d in documents} == {"requirements.md"}
    documents, _ = docs.capture(project, {"kind": "design"}, ["requirements.md"], discover=False)
    assert {d["path"] for d in documents} == {"requirements.md"}


def test_secret_document_is_withheld_and_required_secret_document_fails(project):
    from tests.test_build_analyst_context import SECRET

    (project / "requirements.md").write_text(SECRET)
    documents, sources = docs.capture(project, {"kind": "design"}, [])
    assert not documents and sources[0]["status"] == "sensitive"
    with pytest.raises(docs.DocumentError, match="sensitive"):
        docs.capture(project, {"kind": "design"}, ["requirements.md"])


def test_limits_reject_oversized_files_and_selection(project):
    (project / "requirements.md").write_text("x" * (docs.MAX_FILE_BYTES + 1))
    with pytest.raises(docs.DocumentError, match="64 KiB"):
        docs.capture(project, {"kind": "design"}, [])
    with pytest.raises(docs.DocumentError, match="24"):
        docs.capture(project, {"kind": "design"}, [f"{i}.md" for i in range(25)])


def test_explicit_missing_file_fails_even_without_auto_discovery(project):
    with pytest.raises(docs.DocumentError, match="absent"):
        docs.capture(project, {"kind": "hypothesis", "revision": "HEAD"}, ["missing.md"], discover=False)


def test_staged_documents_are_not_replaced_by_unstaged_edits(project):
    (project / "requirements.md").write_text("REQ-017: Support role may export.\n")
    git(project, "add", ".")
    (project / "requirements.md").write_text("REQ-017: Everybody may export.\n")
    documents, _ = docs.capture(project, {"kind": "staged"}, [])
    assert "Only administrators" in documents[0]["text"]
    assert "Support role" in documents[1]["text"]
    assert all("Everybody" not in d["text"] for d in documents)


def test_large_automatic_selection_records_omissions_and_keeps_explicit_file(project):
    (project / "specs").mkdir()
    for number in range(30):
        (project / "specs" / f"{number:02d}.md").write_text(f"Specification {number}.\n")
    documents, sources = docs.capture(project, {"kind": "design"}, ["specs/29.md"])
    assert len(documents) == docs.MAX_FILES
    assert {"requirements.md", "specs/29.md"} <= {d["path"] for d in documents}
    assert sources[-1]["status"] == "truncated" and sources[-1]["label"].startswith("7 ")


def test_aggregate_byte_limit_is_enforced(project):
    for number in range(4):
        (project / f"spec{number}.md").write_text("x" * 60000)
    with pytest.raises(docs.DocumentError, match="192 KiB"):
        docs.capture(project, {"kind": "design"}, [f"spec{i}.md" for i in range(4)], discover=False)


def test_discovery_does_not_read_ignored_or_nested_repository_documents(project):
    (project / "specs").mkdir()
    (project / "specs" / "private.md").write_text("Ignored draft")
    (project / ".gitignore").write_text("specs/private.md\n")
    nested = project / "specs" / "nested"
    nested.mkdir()
    git(nested, "init", "-q")
    (nested / "design.md").write_text("Other repository")
    documents, _ = docs.capture(project, {"kind": "design"}, [])
    assert {d["path"] for d in documents} == {"requirements.md"}
    documents, _ = docs.capture(project, {"kind": "design"}, ["specs/private.md"], discover=False)
    assert documents[0]["text"] == "Ignored draft"
