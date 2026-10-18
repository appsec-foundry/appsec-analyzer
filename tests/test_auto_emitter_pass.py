"""Deterministic enrichment remains ordered and publishes only with a receipt."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from model.enrichment_pass import valid_receipt
from orchestrator import orchestration_controller as controller

EXPECTED_SEQUENCE = (
    "validators/guard_evidence_verification.py",
    "validators/validate_evidence_lines.py",
    "model/emit_meta_findings.py",
    "model/emit_review_mitigations.py",
    "model/emit_config_scan_mitigations.py",
    "model/emit_finding_fix_mitigations.py",
    "model/emit_clean_finding_titles.py",
    "model/emit_general_mitigation_titles.py",
    "model/backfill_scanner_remediation.py",
    "model/hydrate_mitigation_details.py",
    "model/sanitize_perimeter_claims.py",
    "model/reclassify_components.py",
    "model/enforce_control_taxonomy.py",
    "model/emit_auth_coverage.py",
    "model/emit_threat_vektors.py",
    "model/emit_severity_rationale.py",
    "analyzers/detect_open_registration.py",
    "analyzers/detect_public_repo.py",
    "model/enrich_asset_links.py",
    "validators/secret_scan.py",
)
MINIMAL = {"meta": {}, "threats": [], "security_controls": [], "assets": [], "mitigations": []}


def _run(directory: Path, *, dry_run: bool = False) -> None:
    controller._run_auto_emitter_pass(directory, {"repo_root": str(directory), "dry_run": dry_run}, [])


def test_order_dry_run_and_required_receipt(monkeypatch, tmp_path: Path) -> None:
    calls = []
    monkeypatch.setattr(controller, "_best_effort_script", lambda output, name, args, receipts: calls.append(name))
    monkeypatch.setattr(controller, "_run_script", lambda name, args: calls.append(name))
    _run(tmp_path, dry_run=True)
    assert calls == []
    _run(tmp_path)
    assert tuple(calls) == (*EXPECTED_SEQUENCE, "model/enrichment_pass.py")


def test_a_failing_receipt_blocks_completion(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(controller, "_best_effort_script", lambda *args: None)

    def fail(name, args):
        raise controller.ControllerError("receipt unavailable")

    monkeypatch.setattr(controller, "_run_script", fail)
    with pytest.raises(controller.ControllerError, match="receipt unavailable"):
        _run(tmp_path)


def test_refuted_candidate_is_removed_before_derivation(tmp_path: Path) -> None:
    data = {
        **MINIMAL,
        "threats": [
            {
                "id": "T-001",
                "title": "Refuted SQL injection",
                "risk": "High",
                "cwe": "CWE-89",
                "source": "stride",
                "component": "api",
                "evidence": [{"file": "missing.ts", "line": 1}],
                "evidence_check": "refuted",
            }
        ],
    }
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    _run(tmp_path)
    written = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert written["threats"] == []
    assert not any(m.get("auto_source") == "evidence-check-refuted" for m in written["mitigations"])
    assert valid_receipt(written)


@pytest.mark.parametrize("route", ["/register", "/auth/signup"])
def test_repeated_pass_keeps_cards_and_controls_stable(tmp_path: Path, route: str) -> None:
    data = {
        **MINIMAL,
        "threats": [
            {
                "id": "T-001",
                "title": "Missing request validation",
                "risk": "High",
                "cwe": "CWE-20",
                "mitigation_title": "Validate request fields",
                "source": "stride",
                "remediation": {
                    "steps": ["Validate incoming fields against the request schema."],
                    "verification": "Submit an unexpected field and confirm rejection.",
                },
            }
        ],
    }
    sidecar = {"routes": [{"method": "POST", "path": route}]}
    inventory = tmp_path / ".route-inventory.json"
    inventory.write_text(json.dumps(sidecar), encoding="utf-8")
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    models = []
    for _ in range(2):
        _run(tmp_path)
        models.append(yaml.safe_load(path.read_text(encoding="utf-8")))
        assert valid_receipt(models[-1])
    for key in ("threats", "mitigations", "security_controls"):
        assert len(models[0][key]) == len(models[1][key])
    assert models[1]["threats"][0]["vektor"]
    assert json.loads(inventory.read_text(encoding="utf-8")) == sidecar
