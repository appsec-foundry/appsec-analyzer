"""Source-bound Spring authentication survives architectural model omissions."""

import copy
import hashlib

import pytest
from analyzers.spring_flows import reconcile
from analyzers.spring_security import control_sources
from renderers.figure1_security import profile_catalog


def fixture():
    files = {"Api.java": b"@GetMapping\nhandler\n", "Security.java": b"@Bean\nauthenticated\n"}
    paths = [
        {"repository_id": "repo-a", "path": p, "sha256": hashlib.sha256(body).hexdigest()} for p, body in files.items()
    ]
    components = [{"id": "api", "paths": paths[:1]}, {"id": "security", "paths": paths[1:]}]
    route = {
        "framework": "spring",
        "method": "GET",
        "path": "/api/private",
        "handler_file": "Api.java",
        "handler_line": 1,
        "authn_signal": "middleware_present",
        "authz_signal": "unknown",
        "authn_handler_signal": "verified",
        "authentication_methods": ["basic", "cookie", "bearer", "password"],
        "authn_handler_evidence": [{"file": "Security.java", "line": 2}],
    }
    return components, {"data_flows": [], "external_entities": []}, {"repo-a": {"routes": [route]}}, {"repo-a": files}


def test_evidenced_authentication_alternatives_survive_and_render():
    args = fixture()
    original = copy.deepcopy(args)
    result = reconcile(*args)
    assert {f["authentication"]["scheme"] for f in result["data_flows"]} == {"basic", "cookie", "bearer", "password"}
    assert {p["scheme"] for p in profile_catalog(result["data_flows"]).values()} == {
        "basic",
        "cookie",
        "bearer",
        "password",
    }
    assert args == original
    assert reconcile(args[0], result, args[2], args[3]) == result
    # A plain role name, as the report shows it ("<project> User").
    assert [(e["name"], e["access"]) for e in result["external_entities"]] == [("User", "internet-user")]


def test_authored_access_is_preserved():
    components, doc, inventories, repositories = fixture()
    authored = {"id": "df-001", "to": "api", "authentication": {"scheme": "bearer"}, "label": "Original"}
    doc["data_flows"].append(authored)
    result = reconcile(components, doc, inventories, repositories)
    assert result["data_flows"][0] == authored
    assert len(result["data_flows"]) == 4


@pytest.mark.parametrize("defect", ["unknown", "foreign-file", "bad-line"])
def test_unproven_or_unadmitted_enforcement_adds_no_flow(defect):
    components, doc, inventories, repositories = fixture()
    row = inventories["repo-a"]["routes"][0]
    if defect == "unknown":
        row["authn_handler_signal"] = "unresolved"
    elif defect == "foreign-file":
        row["authn_handler_evidence"][0]["file"] = "outside.java"
    else:
        row["authn_handler_evidence"][0]["line"] = 900
    assert reconcile(components, doc, inventories, repositories) == doc


def test_control_context_grants_only_exact_admitted_enforcement_files():
    components, _, inventories, _ = fixture()
    components[1]["paths"].append({"repository_id": "repo-a", "path": "Unrelated.java", "sha256": "0" * 64})
    inventories["repo-a"]["routes"][0]["authn_handler_evidence"].append({"file": "../outside.java", "line": 1})
    routes, refs, supporting = control_sources(components[0], components, inventories)
    assert routes[0]["path"] == "/api/private"
    assert [p["path"] for c in supporting for p in c["paths"]] == ["Security.java"]
    assert {r["file"] for r in refs} == {"Api.java", "Security.java"}


def test_imported_security_dependency_stays_in_its_selected_repository():
    components, _, inventories, repositories = fixture()
    name = "src/example/LegacyJwtVerifier.java"
    body = b"class LegacyJwtVerifier {}\n"
    repositories["repo-a"]["Api.java"] = b"import example.LegacyJwtVerifier;\nclass Api {}\n"
    repositories["repo-a"][name] = body
    components[1]["paths"].append({"repository_id": "repo-a", "path": name, "sha256": hashlib.sha256(body).hexdigest()})
    components.append({"id": "foreign", "paths": [{"repository_id": "repo-b", "path": name, "sha256": "f" * 64}]})
    _, refs, supporting = control_sources(components[0], components, inventories, repositories)
    assert {c["id"] for c in supporting} == {"security"}
    assert any(r["file"] == name and r["repository_id"] == "repo-a" for r in refs)
    assert all(r["repository_id"] != "repo-b" for r in refs)
