"""Requirements catalogs in other formats: OSCAL is read as an Analyzer catalog, never half-read."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import requirements.catalog_formats as cf
import requirements.fetch_requirements as fr
import yaml
from contexts import build_analyst_context as bc
from orchestrator import assessment_context as context
from requirements.requirements_state import validate_catalog

from appsec_analyzer.catalogs import read_catalog

REPO_ROOT = Path(__file__).parent.parent
FETCH = REPO_ROOT / "scripts" / "requirements" / "fetch_requirements.py"


def _statement(prose: str, **extra) -> dict:
    return {"id": "x_smt", "name": "statement", "prose": prose, **extra}


CATALOG = {
    "catalog": {
        "uuid": "11111111-1111-4111-8111-111111111111",
        "metadata": {
            "title": "Web baseline",
            "version": "1.2",
            "oscal-version": "1.1.2",
            "last-modified": "2025-01-02T03:04:05Z",
        },
        "params": [{"id": "p-global", "values": ["24 hours"]}],
        "controls": [{"id": "x-1", "title": "Loose control", "parts": [_statement("Loose.")]}],
        "groups": [
            {
                "id": "ac",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "ac-1",
                        "title": "Policy",
                        "params": [
                            {"id": "ac-1_prm_1", "label": "organization-defined roles"},
                            {
                                "id": "ac-1_prm_2",
                                "select": {"how-many": "one-or-more", "choice": ["system-level", "mission-level"]},
                            },
                        ],
                        "parts": [
                            _statement(
                                "Develop a policy for {{ insert: param, ac-1_prm_1 }} at the "
                                "{{ insert: param, ac-1_prm_2 }} within {{ insert: param, p-global }}.",
                                parts=[
                                    {
                                        "name": "item",
                                        "props": [{"name": "label", "value": "a."}],
                                        "prose": "Review it\n  yearly.",
                                    }
                                ],
                            ),
                            {"name": "guidance", "prose": "Guidance is not a requirement."},
                        ],
                        "controls": [
                            {"id": "ac-1.1", "title": "Enhancement", "parts": [_statement("Check it.")]},
                        ],
                    },
                    {"id": "ac-9", "title": "Old", "props": [{"name": "status", "value": "withdrawn"}]},
                ],
                "groups": [
                    {
                        "id": "ac-sub",
                        "title": "Account Management",
                        "controls": [{"id": "ac-2", "title": "Accounts", "parts": [_statement("Manage accounts.")]}],
                    }
                ],
            }
        ],
    }
}


def _json(document: dict) -> bytes:
    return json.dumps(document).encode()


def _yaml(document: dict) -> bytes:
    return yaml.safe_dump(document).encode()


def _with(**changes) -> dict:
    document = copy.deepcopy(CATALOG)
    document["catalog"].update(changes)
    return document


@pytest.mark.parametrize("dump", [_json, _yaml], ids=["json", "yaml"])
def test_an_oscal_catalog_becomes_an_analyzer_catalog(dump):
    raw = dump(CATALOG)
    body, info = cf.normalize(raw)

    assert validate_catalog(body) == ([], [])
    catalog = yaml.safe_load(body)
    assert [(c["id"], c["title"]) for c in catalog["categories"]] == [
        ("controls", "Controls"),
        ("ac", "Access Control"),
        ("ac-sub", "Access Control / Account Management"),
    ]
    by_id = {r["id"]: r for c in catalog["categories"] for r in c["requirements"]}
    assert list(by_id) == ["x-1", "ac-1", "ac-1.1", "ac-2"]
    assert by_id["ac-1"]["text"] == (
        "Develop a policy for [Assignment: organization-defined roles] at the "
        "[Selection (one or more): system-level; mission-level] within 24 hours. a. Review it yearly."
    )
    assert by_id["ac-1"]["title"] == "Policy"
    assert {r["priority"] for r in by_id.values()} == {"MUST"}
    assert (info["format"], info["title"], info["version"], info["oscal_version"]) == (
        cf.FORMAT_OSCAL,
        "Web baseline",
        "1.2",
        "1.1.2",
    )
    assert (info["requirements"], info["withdrawn_left_out"]) == (4, 1)
    assert info["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert catalog["conversion"] == info and catalog["generated"] == "2025-01-02T03:04:05Z"


def test_the_json_and_yaml_forms_of_a_catalog_convert_identically():
    from_json, from_yaml = (yaml.safe_load(cf.normalize(dump(CATALOG))[0]) for dump in (_json, _yaml))
    assert from_json["categories"] == from_yaml["categories"]


def test_describe_names_the_format_and_the_assigned_priority():
    line = cf.describe(cf.normalize(_json(CATALOG))[1])
    assert line.startswith('OSCAL catalog "Web baseline" 1.2 (OSCAL 1.1.2): 4 requirements, 1 withdrawn left out;')
    assert "priority MUST assigned to every control" in line
    assert cf.describe({"format": cf.FORMAT_ANALYZER}) is None


def test_a_converted_catalog_read_back_from_the_cache_reports_its_conversion():
    body, info = cf.normalize(_json(CATALOG))
    assert cf.conversion_of(body) == info
    assert cf.conversion_of(_yaml({"categories": [{"id": "A"}]})) is None
    assert cf.conversion_of(b"not: [a catalog") is None


def test_control_characters_in_the_title_never_reach_the_console():
    document = _with(metadata={**CATALOG["catalog"]["metadata"], "title": "Evil\x1b[31m\nname"})
    info = cf.normalize(_json(document))[1]
    assert "\x1b" not in info["title"] and "\n" not in info["title"]
    assert "\x1b" not in cf.describe(info)


@pytest.mark.parametrize(
    "raw",
    [
        _json({"categories": [{"id": "A", "requirements": [{"id": "A-1", "text": "t", "priority": "MUST"}]}]}),
        b"categories:\n  - id: A\n",
        b"<html><body>404</body></html>",
        b"",
        b"[1, 2]",
        _json({"catalog": {"uuid": "x"}}),
    ],
    ids=["json", "yaml", "html", "empty", "list", "catalog-without-oscal-version"],
)
def test_anything_but_an_oscal_catalog_passes_through_unchanged(raw):
    body, info = cf.normalize(raw)
    assert body == raw
    assert info == {"format": cf.FORMAT_ANALYZER, "source_sha256": hashlib.sha256(raw).hexdigest()}


def _deep_groups(depth: int) -> dict:
    group: dict = {"id": "leaf", "title": "Leaf", "controls": [{"id": "c-1", "title": "T"}]}
    for n in range(depth):
        group = {"id": f"g{n}", "title": "G", "groups": [group]}
    return _with(groups=[group])


def _document(root: str) -> dict:
    return {root: {"metadata": {"title": "x", "oscal-version": "1.1.2"}}}


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (_document("profile"), "OSCAL profile is not supported"),
        (_document("system-security-plan"), "OSCAL system-security-plan is not supported"),
        ({**_document("catalog"), **_document("profile")}, "more than one document"),
        ({**CATALOG, "categories": []}, "supply only one format"),
        ({**CATALOG, "extra": 1}, "more than one document"),
        (_with(controls=[{"title": "no id"}]), "has no id"),
        (_with(controls=[{"id": "d-1"}, {"id": "d-1"}]), "more than once"),
        (_deep_groups(cf.MAX_DEPTH + 2), "nested deeper"),
    ],
    ids=["profile", "ssp", "two-roots", "both-formats", "extra-key", "no-id", "duplicate-id", "too-deep"],
)
def test_unsupported_or_ambiguous_oscal_is_refused(document, message):
    with pytest.raises(cf.CatalogFormatError, match=message):
        cf.normalize(_json(document))


def test_a_schema_key_beside_the_catalog_is_allowed():
    body, info = cf.normalize(_json({"$schema": "https://example.invalid/oscal.json", **CATALOG}))
    assert info["requirements"] == 4 and validate_catalog(body)[0] == []


def test_limits_stop_oversized_and_exploding_input(monkeypatch):
    monkeypatch.setattr(cf, "MAX_CONTROLS", 3)
    with pytest.raises(cf.CatalogFormatError, match="more than 3 controls"):
        cf.normalize(_json(CATALOG))
    monkeypatch.undo()

    monkeypatch.setattr(cf, "MAX_RAW_BYTES", 100)
    with pytest.raises(cf.CatalogFormatError, match="larger than"):
        cf.normalize(_json(CATALOG))
    monkeypatch.undo()

    monkeypatch.setattr(cf, "MAX_YAML_BYTES", 100)
    with pytest.raises(cf.CatalogFormatError, match="not JSON and larger than"):
        cf.normalize(_yaml(CATALOG))
    assert cf.normalize(_json(CATALOG))[1]["requirements"] == 4  # JSON keeps its higher limit


def test_a_yaml_alias_cannot_multiply_text_beyond_the_budget(monkeypatch):
    monkeypatch.setattr(cf, "MAX_TEXT_CHARS", 10_000)
    shared = "x" * 1000
    items = ", ".join(["*big"] * 50)
    raw = (
        "catalog:\n  metadata: {title: t, version: '1', oscal-version: 1.1.2}\n"
        f"  controls:\n    - id: c-1\n      parts:\n        - name: statement\n          parts: [{items}]\n"
        f"        - &big {{name: item, prose: {shared}}}\n"
    ).replace("parts: [", "parts: [", 1)
    # the anchor must precede its aliases
    raw = raw.replace("          parts: [" + items + "]\n        - &big {name: item, prose: " + shared + "}\n", "")
    raw += ""
    document = (
        "catalog:\n  metadata: {title: t, version: '1', oscal-version: 1.1.2}\n"
        f"  big: &big {{name: item, prose: {shared}}}\n"
        f"  controls:\n    - id: c-1\n      parts:\n        - name: statement\n          parts: [{items}]\n"
    )
    with pytest.raises(cf.CatalogFormatError, match="too large to convert"):
        cf.normalize(document.encode())


def test_parameters_that_refer_to_each_other_stop_expanding():
    params = [
        {"id": "a", "values": ["A {{ insert: param, b }}"]},
        {"id": "b", "values": ["B {{ insert: param, a }}"]},
    ]
    document = _with(params=params, controls=[{"id": "c-1", "parts": [_statement("{{ insert: param, a }}")]}])
    body, _ = cf.normalize(_json(document))
    text = yaml.safe_load(body)["categories"][0]["requirements"][0]["text"]
    assert text.startswith("A B A B") and len(text) < 200


def test_an_unknown_parameter_stays_an_open_slot():
    document = _with(controls=[{"id": "c-1", "parts": [_statement("Use {{ insert: param, missing_1 }}.")]}])
    text = yaml.safe_load(cf.normalize(_json(document))[0])["categories"][0]["requirements"][0]["text"]
    assert text == "Use [Assignment: missing_1]."


# --- read_catalog: audit, authnz-review --------------------------------------------------------


def test_read_catalog_returns_the_converted_catalog_and_the_checksum_of_the_supplied_file(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_bytes(_json(CATALOG))
    body, catalog, source = read_catalog(path)
    assert validate_catalog(body)[0] == [] and catalog["categories"][1]["requirements"][0]["id"] == "ac-1"
    assert source["format"] == cf.FORMAT_OSCAL
    assert source["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_read_catalog_keeps_the_analyzer_format_as_it_was(tmp_path):
    path = tmp_path / "catalog.yaml"
    path.write_bytes(b"categories:\n  - id: A\n    requirements:\n      - id: A-1\n")
    body, _, source = read_catalog(path)
    assert body == path.read_bytes() and source["format"] == cf.FORMAT_ANALYZER
    assert source["source_sha256"] == hashlib.sha256(body).hexdigest()


@pytest.mark.parametrize("document", [_document("profile"), {"catalog": {"metadata": {"oscal-version": "1"}}, "x": 1}])
def test_read_catalog_refuses_what_it_cannot_convert(tmp_path, document):
    path = tmp_path / "catalog.json"
    path.write_bytes(_json(document))
    with pytest.raises(ValueError, match="cannot be read"):
        read_catalog(path)


def test_read_catalog_still_bounds_the_converted_catalog(tmp_path, monkeypatch):
    path = tmp_path / "catalog.json"
    path.write_bytes(_json(CATALOG))
    monkeypatch.setattr("appsec_analyzer.catalogs.MAX_CATALOG_BYTES", 200)
    with pytest.raises(ValueError, match="size limit"):
        read_catalog(path)


# --- assess: the fetch gate and the context limits -------------------------------------------


def _fetch(tmp_path: Path, source: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(FETCH), "--output-dir", str(tmp_path), "--requirements", str(source)],
        capture_output=True,
        text=True,
    )


def test_the_fetch_gate_writes_a_converted_catalog_and_records_the_conversion(tmp_path):
    source = tmp_path / "catalog.json"
    source.write_bytes(_json(CATALOG))
    result = _fetch(tmp_path, source)
    assert result.returncode == 0, result.stderr
    assert 'OSCAL catalog "Web baseline"' in result.stdout
    assert validate_catalog((tmp_path / ".requirements.yaml").read_bytes())[0] == []
    resolution = json.loads((tmp_path / ".requirements-resolution.json").read_text())
    assert resolution["conversion"]["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert resolution["conversion"]["withdrawn_left_out"] == 1


def test_the_fetch_gate_aborts_on_an_oscal_profile(tmp_path):
    source = tmp_path / "profile.json"
    source.write_bytes(_json(_document("profile")))
    result = _fetch(tmp_path, source)
    assert result.returncode == 2 and "OSCAL profile is not supported" in result.stderr


def test_a_local_file_is_read_up_to_its_limit_only(tmp_path, monkeypatch):
    source = tmp_path / "catalog.json"
    source.write_bytes(b"x" * 50)
    monkeypatch.setattr(cf, "MAX_RAW_BYTES", 40)
    with pytest.raises(ValueError, match="larger than"):
        fr._read_local(str(source))


def test_a_remote_catalog_is_read_with_the_validated_opener_and_a_size_limit(monkeypatch):
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            seen["size"] = size
            return b"x" * size

    class Opener:
        def open(self, request, timeout):
            seen["accept"] = request.get_header("Accept")
            return Response()

    monkeypatch.setattr(fr._url_guard, "validated_opener", lambda **kw: Opener())
    with pytest.raises(ValueError, match="larger than"):
        fr._http_get("https://catalogs.example.invalid/c.json", 5)
    assert seen["size"] == cf.MAX_RAW_BYTES + 1 and "application/json" in seen["accept"]


def _catalog_with_groups(count: int) -> dict:
    groups = [
        {"id": f"g{n}", "title": f"Group {n}", "controls": [{"id": f"c-{n}", "parts": [_statement("Do it.")]}]}
        for n in range(count)
    ]
    return _with(groups=groups, controls=[])


def test_assess_accepts_a_catalog_that_fits_and_reports_its_conversion(tmp_path):
    source = tmp_path / "catalog.json"
    source.write_bytes(_json(CATALOG))
    directory = tmp_path / "work"
    directory.mkdir()
    captured = context._requirements({"requirements_url_override": str(source)}, directory)
    assert captured["ids"] == ["x-1", "ac-1", "ac-1.1", "ac-2"]
    assert captured["resolution"]["conversion"]["format"] == cf.FORMAT_OSCAL


def test_assess_refuses_a_catalog_with_too_many_context_rows_before_any_model_call(tmp_path):
    source = tmp_path / "catalog.json"
    source.write_bytes(_json(_catalog_with_groups(context.MAX_REQUIREMENT_ROWS + 1)))
    directory = tmp_path / "work"
    directory.mkdir()
    with pytest.raises(context.ContextError, match=rf"{context.MAX_REQUIREMENT_ROWS + 1} context rows .* supports 32"):
        context._requirements({"requirements_url_override": str(source)}, directory)


def test_assess_refuses_a_catalog_that_stage_two_could_not_assess(tmp_path, monkeypatch):
    source = tmp_path / "catalog.json"
    source.write_bytes(_json(CATALOG))
    directory = tmp_path / "work"
    directory.mkdir()
    monkeypatch.setattr(context, "MAX_STAGE2_REQUIREMENT_BYTES", 100)
    with pytest.raises(context.ContextError, match="too large for the requirements assessment"):
        context._requirements({"requirements_url_override": str(source)}, directory)


# --- analyze-threats ---------------------------------------------------------------------------


def test_analyze_threats_delivers_an_oscal_catalog_with_the_checksum_of_the_supplied_file(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_bytes(_json(CATALOG))
    record, entries = bc._requirements(path, True)
    assert [e["id"] for e in entries] == ["x-1", "ac-1", "ac-1.1", "ac-2"]
    assert record["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert (record["catalog_format"], record["catalog_title"], record["catalog_version"]) == (
        cf.FORMAT_OSCAL,
        "Web baseline",
        "1.2",
    )


def test_analyze_threats_reads_a_catalog_above_its_native_limit_when_the_conversion_is_small(tmp_path):
    padding = {"id": "pad", "title": "Pad", "controls": [], "props": [{"name": "x", "value": "y" * 600_000}]}
    path = tmp_path / "catalog.json"
    path.write_bytes(_json(_with(groups=[padding, *CATALOG["catalog"]["groups"]])))
    assert path.stat().st_size > bc.MAX_SOURCE_BYTES["requirements"]
    assert len(bc._requirements(path, True)[1]) == 4


def test_a_required_oscal_profile_never_reaches_the_analysis(tmp_path):
    path = tmp_path / "profile.json"
    path.write_bytes(_json(_document("profile")))
    with pytest.raises(bc.ContextError, match="is invalid"):
        bc._requirements(path, True)


def test_a_required_catalog_with_too_many_requirements_names_the_limit(tmp_path, monkeypatch):
    path = tmp_path / "catalog.json"
    path.write_bytes(_json(CATALOG))
    monkeypatch.setattr(bc, "MAX_REQUIREMENTS", 2)
    with pytest.raises(bc.ContextError, match="has 4 requirements; the analysis delivers at most 2"):
        bc._requirements(path, True)
