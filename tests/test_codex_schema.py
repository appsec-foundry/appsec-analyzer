"""Structured wire data stays lossless without embedding JSON in strings."""

import json

import pytest
from jsonschema import Draft202012Validator

from appsec_analyzer.codex_schema import CodexSchema


def closed(properties, required=None):
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties) if required is None else required,
        "additionalProperties": False,
    }


def test_source_strings_are_data_even_when_they_contain_invalid_json_syntax():
    schema = CodexSchema(closed({"quote": {"type": "string"}, "line": {"type": "integer"}}))
    quote = 'socket.on("event", () => { console.log("\\path"); }); /* {broken JSON */'
    wire = json.loads(json.dumps({"payload": {"quote": quote, "line": 12}}))
    assert schema.decode(wire) == {"quote": quote, "line": 12}
    assert "payload_json" not in json.dumps(schema.schema)
    with pytest.raises(ValueError):
        schema.decode({"payload": json.dumps({"quote": quote, "line": 12})})


def test_management_summary_regex_is_local_and_still_enforced():
    from orchestrator.assessment_stage2 import ms_schema
    from runtime.assessment_host import host_schema, response_schema

    # Use the actual summary restriction, rather than a schema invented for the test.
    complete = CodexSchema(host_schema(response_schema(ms_schema())))
    assert all("pattern" not in node for node in complete.definitions.values())
    canonical = ms_schema()["properties"]["verdict"]["properties"]["opening"]
    schema = CodexSchema(closed({"headline": canonical}))
    assert all("pattern" not in node for node in schema.definitions.values())
    valid = "The customer service exposes stored information to callers without a reliable ownership check."
    assert schema.decode({"payload": {"headline": valid}}) == {"headline": valid}
    with pytest.raises(ValueError, match="wire schema"):
        schema.decode({"payload": {"headline": valid + " F-001"}})


def test_local_patterns_are_enforced_in_recursive_contracts():
    canonical = closed(
        {
            "name": {"type": "string", "pattern": "^(?!forbidden).+$"},
            "children": {"type": "array", "items": {"$ref": "#"}},
        }
    )
    schema = CodexSchema(canonical)
    assert schema.decode({"payload": {"name": "allowed", "children": []}}) == {"name": "allowed", "children": []}
    with pytest.raises(ValueError, match="wire schema"):
        schema.decode({"payload": {"name": "allowed", "children": [{"name": "forbidden", "children": []}]}})


@pytest.mark.parametrize("present,value", [(False, None), (True, None), (True, "value")])
def test_optional_fields_preserve_absence_and_explicit_null(present, value):
    schema = CodexSchema(closed({"optional": {"type": ["string", "null"]}}, []))
    member = {"present": True, "value": value} if present else {"present": False}
    assert schema.decode({"payload": {"optional": member}}) == ({"optional": value} if present else {})


@pytest.mark.parametrize(
    "member", [{"present": False, "value": None}, {"present": True}, None, {"present": 1, "value": "v"}]
)
def test_malformed_presence_wrappers_are_rejected(member):
    schema = CodexSchema(closed({"optional": {"type": ["string", "null"]}}, []))
    with pytest.raises(ValueError):
        schema.decode({"payload": {"optional": member}})


def test_explicit_null_is_not_substituted_for_a_nonnullable_optional_value():
    schema = CodexSchema(closed({"optional": {"type": "string"}}, []))
    with pytest.raises(ValueError):
        schema.decode({"payload": {"optional": {"present": True, "value": None}}})


def test_dynamic_maps_preserve_keys_nulls_and_empty_maps():
    schema = CodexSchema({"type": "object", "additionalProperties": {"type": ["string", "null"]}})
    assert schema.decode({"payload": {"__extra": [{"key": 'key/"~', "value": None}, {"key": "é", "value": "✓"}]}}) == {
        'key/"~': None,
        "é": "✓",
    }
    assert schema.decode({"payload": {"__extra": []}}) == {}
    with pytest.raises(ValueError):
        schema.decode({"payload": {"__extra": [{"key": "x", "value": None}, {"key": "x", "value": "other"}]}})


def test_extra_entries_cannot_override_declared_fields_even_if_absent():
    schema = CodexSchema(
        {"type": "object", "properties": {"x": {"type": "string"}}, "additionalProperties": {"type": "string"}}
    )
    with pytest.raises(ValueError):
        schema.decode({"payload": {"x": {"present": False}, "__extra": [{"key": "x", "value": "injected"}]}})


def test_generic_json_preserves_arrays_and_objects_without_reserved_key_collisions():
    schema = CodexSchema({})
    wire = {
        "payload": {
            "entries": [
                {"key": "entries", "value": [None, True, 2, "text"]},
                {"key": "__extra", "value": {"entries": [{"key": "present", "value": False}]}},
            ]
        }
    }
    assert schema.decode(wire) == {"entries": [None, True, 2, "text"], "__extra": {"present": False}}


def test_recursive_local_references_and_resource_scopes_are_resolved_without_network():
    canonical = closed({"name": {"type": "string"}, "children": {"type": "array", "items": {"$ref": "#"}}})
    schema = CodexSchema(canonical)
    data = {"name": "root", "children": [{"name": "child", "children": []}]}
    assert schema.decode({"payload": data}) == data
    child = {"$id": "urn:child", "$defs": {"text": {"type": "string"}}, **closed({"x": {"$ref": "#/$defs/text"}})}
    scoped = CodexSchema({"$defs": {"child": child}, **closed({"child": {"$ref": "#/$defs/child"}})})
    assert scoped.decode({"payload": {"child": {"x": "v"}}}) == {"child": {"x": "v"}}
    with pytest.raises(ValueError):
        CodexSchema(closed({"external": {"$ref": "https://example.invalid/schema"}}))


def test_ambiguous_wire_unions_cannot_choose_a_different_canonical_object():
    entry = closed({"key": {"type": "string"}, "value": {"type": "string"}})
    schema = CodexSchema(
        {
            "anyOf": [
                {"type": "object", "additionalProperties": {"type": "string"}},
                closed({"__extra": {"type": "array", "items": entry}}),
            ]
        }
    )
    with pytest.raises(ValueError, match="Ambiguous"):
        schema.decode({"payload": {"__extra": [{"key": "x", "value": "v"}]}})


def test_real_discovery_contract_keeps_its_native_json_shape():
    from contexts.reconcile_multi_repo_architecture import SCHEMA
    from runtime.assessment_host import host_schema, response_schema

    contract = json.loads(SCHEMA.read_text())
    schema = CodexSchema(host_schema(response_schema(contract)))
    data = {
        "action": "read",
        "reads": [{"repository_id": "repo-0123456789abcdef", "path": "server.ts", "start_line": 1, "end_line": 40}],
        "artifact": None,
    }
    assert schema.decode({"payload": data}) == data
    Draft202012Validator(response_schema(contract)).validate(data)
    for node in schema.definitions.values():
        if node.get("type") == "object":
            assert node["additionalProperties"] is False
            assert set(node["required"]) == set(node["properties"])


@pytest.mark.parametrize(
    "raw", ['{"payload":NaN}', '{"payload":Infinity}', '{"payload":1e309}', '{"payload":{},"payload":{}}']
)
def test_transport_parser_rejects_nonfinite_and_duplicate_json(raw):
    from appsec_analyzer.codex_cli import _json

    with pytest.raises(ValueError):
        _json(raw)


def test_all_stage_contracts_compile_to_closed_structured_schemas():
    from contexts.multi_repo_analysis import CONTRACTS, contract
    from runtime.assessment_host import host_schema, response_schema

    def check(node):
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            if "$ref" in node:
                assert node["$ref"].startswith("#/$defs/")
            for value in node.values():
                check(value)
        elif isinstance(node, list):
            for value in node:
                check(value)

    for name in CONTRACTS:
        schema = CodexSchema(host_schema(response_schema(contract(name))))
        check(schema.schema)
        assert "payload_json" not in json.dumps(schema.schema)


def test_invalid_contract_is_rejected_before_starting_cli(tmp_path, monkeypatch):
    from runtime.analyst_host import TransportError

    from appsec_analyzer import codex_cli

    def forbidden(*args, **kwargs):
        pytest.fail("invalid contract must not start CLI")

    monkeypatch.setattr(codex_cli, "_run", forbidden)
    transport = codex_cli.CodexCliTransport(tmp_path, "gpt-6-luna", "medium", {"executable": "codex", "features": {}})
    with pytest.raises(TransportError) as caught:
        transport.invoke("trusted", "source", {"type": "invalid-private-value"}, 5, lambda: False)
    assert caught.value.reason == "invalid_request"
    assert "invalid-private-value" not in str(caught.value)


def test_generic_duplicate_members_and_excessive_nesting_are_rejected():
    schema = CodexSchema({})
    with pytest.raises(ValueError, match="Duplicate"):
        schema.decode({"payload": {"entries": [{"key": "x", "value": 1}, {"key": "x", "value": 2}]}})
    value = None
    for _ in range(66):
        value = [value]
    with pytest.raises(ValueError, match="nesting"):
        schema.decode({"payload": value})
    canonical = {"type": "string"}
    for _ in range(66):
        canonical = {"type": "array", "items": canonical}
    with pytest.raises(ValueError, match="depth"):
        CodexSchema(canonical)


def test_extra_wire_field_does_not_collide_with_a_declared_name():
    schema = CodexSchema({"type": "object", "properties": {"__extra": {"type": "string"}}, "required": ["__extra"]})
    assert schema.decode({"payload": {"__extra": "declared", "__extra_": [{"key": "present", "value": None}]}}) == {
        "__extra": "declared",
        "present": None,
    }
