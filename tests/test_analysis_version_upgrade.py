"""Release contract for upgrading compatible analysis baselines to v5."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import renderers.compose_threat_model as compose
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ENGINE_JSON = REPO_ROOT / "engine.json"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
COMPOSE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "compose"


def test_analysis_v5_declares_prior_read_compatibility() -> None:
    manifest = json.loads(ENGINE_JSON.read_text(encoding="utf-8"))

    assert manifest["analysis_version"] == 5
    assert manifest["compatible_analysis_versions"] == [1, 2, 3, 4, 5]


def test_v2_report_remains_renderable_and_is_not_rewritten(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    shutil.copytree(COMPOSE_FIXTURE, output_dir)
    yaml_path = output_dir / "threat-model.yaml"
    before = yaml_path.read_bytes()
    yaml_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert yaml_data["meta"]["analysis_version"] == 2

    rendered, _warnings = compose.render(CONTRACT, output_dir)

    assert "## Management Summary" in rendered
    assert "analysis v5" in rendered
    assert yaml_path.read_bytes() == before
    integrity = json.loads((output_dir / ".render-integrity.json").read_text(encoding="utf-8"))
    assert integrity["schema_version"] == 1
    assert integrity["sections"]
