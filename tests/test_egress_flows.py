"""Observed outbound calls survive model omissions and context truncation."""

import copy
import json
from pathlib import Path

import pytest
from analyzers.egress_clients import scan
from analyzers.egress_flows import reconcile, uncovered
from contexts.build_architecture_analysis_context import project_egress
from jsonschema import Draft202012Validator


def _source(tmp_path, text):
    source = tmp_path / "src/client.ts"
    source.parent.mkdir(parents=True)
    source.write_text(text)
    return [{"id": "api", "paths": ["src/client.ts"]}], scan(tmp_path)


def test_every_observed_destination_survives_the_model_context_limit(tmp_path):
    components, destinations = _source(
        tmp_path,
        "".join(f"fetch('https://service{n:02d}.vendorhub.io/orders')\n" for n in range(26))
        + "".join(f"fetch(process.env.SERVICE_{n}_URL)\n" for n in range(8)),
    )
    projection = project_egress(tmp_path, sources=destinations)
    assert len(projection["destinations"]) == 24
    assert projection["limits"]["omitted_destinations"] == 10
    original = {"external_entities": [], "data_flows": []}
    result = reconcile(components, original, destinations)
    assert len(result["external_entities"]) == len(result["data_flows"]) == 34
    assert original == {"external_entities": [], "data_flows": []}
    assert uncovered(destinations, components, result) == []
    assert reconcile(components, result, destinations) == result
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    checked = {"schema_version": 1, "component_inventory_fingerprint": "sha256:" + "0" * 64, **result}
    assert [error.message for error in Draft202012Validator(schema).iter_errors(checked)] == []
    assert all("authentication" not in f for f in result["data_flows"])


def test_a_new_configured_lead_does_not_displace_a_fixed_host(tmp_path):
    _, destinations = _source(
        tmp_path,
        "".join(f"fetch('https://service{n:02d}.vendorhub.io/orders')\n" for n in range(24))
        + "fetch(process.env.WEBHOOK_URL)\nfetch(process.env.WEBHOOK_URL)\n",
    )
    projected = project_egress(tmp_path, sources=destinations)
    assert len([r for r in projected["destinations"] if r["host"]]) == 24
    assert projected["limits"]["omitted_destinations"] == 1


def test_an_authored_access_keeps_its_identity_authentication_and_classification(tmp_path):
    components, destinations = _source(tmp_path, "fetch('https://billing.vendorhub.io')\n")
    entity = {"id": "ext-billing", "name": "Billing", "kind": "external-service"}
    authored = {
        "external_entities": [entity],
        "data_flows": [
            {
                "id": "df-001",
                "from": "api",
                "to": "external",
                "to_entity": entity["id"],
                "authentication": {"scheme": "mtls"},
                "data_classification": "Restricted",
                "evidence": destinations[0]["evidence"],
            }
        ],
    }
    assert reconcile(components, authored, destinations) == authored


def test_an_unrelated_login_flow_cannot_cover_an_outbound_rest_call(tmp_path):
    components, destinations = _source(tmp_path, "fetch('https://billing.vendorhub.io')\n")
    original = {
        "external_entities": [{"id": "ext-login", "kind": "identity-provider"}],
        "data_flows": [
            {
                "id": "df-001",
                "from": "api",
                "to": "external",
                "to_entity": "ext-login",
                "evidence": [{"file": "src/login.ts", "line": 1}],
            }
        ],
    }
    assert len(uncovered(destinations, components, original)) == 1
    result = reconcile(components, original, destinations)
    assert len(result["external_entities"]) == len(result["data_flows"]) == 2
    assert uncovered(destinations, components, result) == []


def test_a_generic_authored_flow_gets_its_missing_destination(tmp_path):
    components, destinations = _source(tmp_path, "fetch('https://billing.vendorhub.io')\n")
    original = {
        "data_flows": [
            {
                "id": "df-001",
                "from": "api",
                "to": "external",
                "label": "Orders",
                "evidence": destinations[0]["evidence"],
            }
        ]
    }
    result = reconcile(components, original, destinations)
    assert len(result["data_flows"]) == 1
    assert result["data_flows"][0]["label"] == "Orders"
    assert result["data_flows"][0]["to_entity"] == result["external_entities"][0]["id"]


def test_a_reviewed_internal_connection_does_not_become_an_external_service(tmp_path):
    components, destinations = _source(tmp_path, "fetch('https://billing.vendorhub.io')\n")
    original = {
        "external_entities": [],
        "data_flows": [
            {
                "id": "df-001",
                "from": "api",
                "to": "billing",
                "connection_id": "conn-reviewed",
                "evidence": destinations[0]["evidence"],
            }
        ],
    }
    assert reconcile(components, original, destinations) == original


def test_distinct_calls_on_one_line_remain_distinct_and_idempotent(tmp_path):
    components, destinations = _source(
        tmp_path,
        "fetch(process.env.BILLING_URL); fetch(process.env.NOTIFY_URL); "
        "fetch('https://gateway.vendorhub.io:8443'); fetch('https://gateway.vendorhub.io:9443');\n",
    )
    result = reconcile(components, {}, destinations)
    assert len(result["external_entities"]) == len(result["data_flows"]) == 4
    assert reconcile(components, result, destinations) == result
    assert uncovered(destinations, components, result) == []


def test_equal_settings_in_different_repositories_do_not_establish_one_service(tmp_path):
    _, destinations = _source(tmp_path, "fetch(process.env.SERVICE_URL)\n")
    qualified, components = [], []
    for rid in ("repo-a", "repo-b"):
        row = copy.deepcopy(destinations[0])
        row["evidence"][0]["repository_id"] = rid
        qualified.append(row)
        components.append({"id": rid, "paths": [{"repository_id": rid, "path": "src/client.ts"}]})
    result = reconcile(components, {}, qualified)
    assert len(result["external_entities"]) == 2
    assert {f["from"] for f in result["data_flows"]} == {"repo-a", "repo-b"}


def test_ambiguous_ownership_and_contract_exhaustion_never_drop_destinations_silently(tmp_path):
    components, destinations = _source(
        tmp_path, "".join(f"fetch('https://service{n:02d}.vendorhub.io')\n" for n in range(65))
    )
    with pytest.raises(ValueError, match="capacity"):
        reconcile(components, {}, destinations)
    with pytest.raises(ValueError, match="ambiguous"):
        reconcile([*components, {"id": "other", "paths": ["src/client.ts"]}], {}, destinations)
