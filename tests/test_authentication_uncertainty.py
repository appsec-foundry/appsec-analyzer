"""Unresolved authentication is preserved across saved-model consumers."""

from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from model.build_threat_model_yaml import build_attack_surface
from model.query_threat_model import _surface_record
from renderers.pregenerate_fragments import gen_attack_surface
from validators.validate_intermediate import _check_attack_surface_shape


@pytest.mark.parametrize(
    ("signal", "expected"), [("absent", False), ("unknown", None), ("inherited_unknown", None), ("present", True)]
)
def test_authentication_states_survive_model_query_and_report(signal, expected):
    rows, _ = build_attack_surface({"routes": [{"method": "GET", "path": "/entry", "authn_signal": signal}]})
    assert rows[0]["auth_required"] is expected
    assert _surface_record(rows[0])["auth_required"] is expected
    model = {"meta": {"analysis_version": 6}, "attack_surface": rows}
    assert _check_attack_surface_shape(model) == []
    report = gen_attack_surface(model)
    title = (
        "Authentication Not Determined"
        if expected is None
        else "Authenticated Entry Points"
        if expected
        else "Unauthenticated Entry Points"
    )
    assert title + " (1)" in report
    if expected is None:
        assert "Unauthenticated Entry Points (0)" in report


@pytest.mark.parametrize(
    ("states", "expected"),
    [(["present", "unknown"], None), (["absent", "unknown"], False), (["present", "present"], True)],
)
def test_duplicate_routes_keep_uncertain_authentication(states, expected):
    rows, _ = build_attack_surface({"routes": [{"method": "GET", "path": "/entry", "authn_signal": s} for s in states]})
    assert len(rows) == 1 and rows[0]["auth_required"] is expected


def test_nullable_authentication_is_versioned_and_boolean_artifacts_stay_valid():
    schema = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "schemas/threat-model.output.schema.yaml").read_text()
    )
    validator = Draft202012Validator(schema["properties"]["attack_surface"])
    for value in (True, False, None):
        assert validator.is_valid([{"entry_point": "GET /entry", "protocol": "HTTP", "auth_required": value}])
    assert not validator.is_valid([{"entry_point": "GET /entry", "protocol": "HTTP", "auth_required": "unknown"}])
    assert _check_attack_surface_shape(
        {"meta": {"analysis_version": 5}, "attack_surface": [{"entry_point": "GET /entry", "auth_required": None}]}
    )
