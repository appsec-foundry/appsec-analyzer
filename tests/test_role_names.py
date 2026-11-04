"""Every legitimate role gets one plain name, and no two cards share one."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from model import emit_role_names
from renderers.role_names import (
    GENERIC_USER,
    MAX_NAME,
    apply_role_names,
    card_aliases,
    role_names,
)


def _role(key, name, access=None, **extra):
    row = {"id": key, "name": name, "kind": "legitimate-role", "description": f"{name} role", "evidence": []}
    if access:
        row["access"] = access
    return {**row, **extra}


def _model(*roles, project="Shop", **meta):
    return {"meta": {"project_name": project, **meta}, "external_entities": list(roles), "data_flows": []}


@pytest.mark.parametrize(
    ("access", "registration", "expected"),
    [
        ("internet-user", False, "Shop User"),
        ("internet-anon", False, "Shop Visitor"),
        ("internet-anon", True, "Shop User"),
        (None, False, "Shop User"),
        ("internet-priv-user", False, "Shop Admin"),
    ],
)
def test_roles_are_named_after_the_project_and_their_access(access, registration, expected):
    data = _model(_role("ext-a", "Shop customer account", access), open_user_registration=registration)
    assert role_names(data)["ext-a"] == expected
    assert role_names(data)[GENERIC_USER] == "Shop User"


def test_a_combined_assessment_drops_the_product_prefix():
    data = _model(_role("ext-a", "Customer", "internet-user"), _role("ext-b", "Operator", "internet-priv-user"))
    data["meta"]["source_repositories"] = [{"label": "edge"}, {"label": "api"}]
    assert role_names(data) == {"ext-a": "User", "ext-b": "Admin", GENERIC_USER: "User"}


def test_several_admins_keep_their_authored_name_as_qualifier():
    data = _model(
        _role("ext-a", "Administrator", "internet-priv-user"),
        _role("ext-b", "Support agent", "internet-priv-user"),
        _role("ext-c", "Shop Auditor", "internet-priv-user"),
    )
    assert [role_names(data)[key] for key in ("ext-a", "ext-b", "ext-c")] == [
        "Shop Admin",
        "Shop Admin (Support agent)",
        "Shop Admin (Auditor)",
    ]


def test_admins_without_a_distinguishing_name_are_numbered():
    data = _model(_role("ext-a", "Admin", "internet-priv-user"), _role("ext-b", "admin", "internet-priv-user"))
    assert [role_names(data)[key] for key in ("ext-a", "ext-b")] == ["Shop Admin", "Shop Admin 2"]


def test_declared_names_stay_and_a_derived_name_yields():
    declared = {"source": ".appsec/actors.yaml"}
    data = _model(
        _role("ext-a", "Customer", "internet-user"),
        _role("ext-ops", "Shop User", "internet-priv-user", declared=declared),
    )
    names = role_names(data)
    assert names["ext-ops"] == "Shop User"
    assert names["ext-a"] == names[GENERIC_USER] == "Shop User 2"
    assert len({names["ext-a"], names["ext-ops"]}) == 2


def test_regular_roles_of_one_name_share_a_card_hosted_by_a_declared_role():
    declared = {"source": ".appsec/actors.yaml"}
    data = _model(
        _role("ext-b", "Customer", "internet-user"),
        _role("ext-a", "Buyer"),
        _role("ext-z", "Shop User", "internet-user", declared=declared),
        _role("ext-v", "Guest", "internet-anon"),
        _role("ext-p", "Admin", "internet-priv-user"),
    )
    assert card_aliases(data) == {"ext-a": "ext-z", "ext-b": "ext-z", GENERIC_USER: "ext-z"}


def test_regular_roles_without_a_declared_host_fold_into_the_smallest_id():
    data = _model(_role("ext-b", "Customer", "internet-user"), _role("ext-a", "Buyer"))
    assert card_aliases(data) == {"ext-b": "ext-a", GENERIC_USER: "ext-a"}
    assert card_aliases(_model(_role("ext-v", "Guest", "internet-anon"))) == {}


@pytest.mark.parametrize("project", ["Shop", "A" * 70, ""])
def test_names_fit_the_schema_and_applying_them_twice_changes_nothing(project):
    data = _model(
        _role("ext-a", "Customer", "internet-user"),
        _role("ext-b", "Support agent with a long description of duties", "internet-priv-user"),
        _role("ext-c", "Superadmin", "internet-priv-user"),
        _role("ext-d", "Admin", "internet-priv-user"),
        _role("ext-e", "Administrator", "internet-priv-user"),
        project=project,
    )
    once = copy.deepcopy(data)
    apply_role_names(once)
    twice = copy.deepcopy(once)
    apply_role_names(twice)
    assert once == twice
    names = [row["name"] for row in once["external_entities"]]
    assert all(0 < len(name) <= MAX_NAME for name in names)
    assert len(set(names[1:])) == 4
    assert [row["id"] for row in once["external_entities"]] == [row["id"] for row in data["external_entities"]]


def test_the_yaml_pass_writes_the_names_once(tmp_path):
    data = _model(_role("ext-a", "Authenticated application client", "internet-user"))
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert emit_role_names.main([str(tmp_path)]) == 0
    written = path.read_text(encoding="utf-8")
    assert yaml.safe_load(written)["external_entities"][0]["name"] == "Shop User"
    assert emit_role_names.main([str(tmp_path)]) == 0
    assert path.read_text(encoding="utf-8") == written
    assert emit_role_names.main([str(tmp_path / "missing")]) == 1
