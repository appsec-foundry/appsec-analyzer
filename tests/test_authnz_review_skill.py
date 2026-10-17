"""Exercise the retained org-profile resolver, pentest exporter, and authn agent."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _authnz_report() -> dict:
    return {
        "partial": False,
        "analyzed_at": "2026-08-30T10:00:00Z",
        "summary": {"total_findings": 2, "critical": 1, "medium": 1},
        "findings": [
            {
                "id": "AZ-001",
                "title": "Basket lookup accepts any basket id",
                "severity": "Critical",
                "cwe": "CWE-639",
                "stride": "Elevation of Privilege",
                "component_id": "api",
                "source": "confirmed-instance",
                "evidence": [{"file": "routes/basket.ts", "line": 12, "snippet": "findByPk(req.params.id)"}],
                "attack_path": "Any user reads another user's basket.",
                "remediation": {"summary": "Scope to the session owner.", "reference": "CWE-639"},
            },
            {
                "id": "AZ-002",
                "title": "No brute-force protection on login",
                "severity": "Medium",
                "cwe": "CWE-1188",
                "stride": "Spoofing",
                "component_id": None,
                "source": "hypothesis",
                "evidence": [{"file": "routes/login.ts", "line": 9}],
                "attack_path": "Credential stuffing.",
                "remediation": {"summary": "Add rate limiting.", "reference": "CWE-1188"},
            },
        ],
    }


def _route_inventory() -> dict:
    return {
        "version": 1,
        "routes": [
            {
                "route_id": "R-001",
                "method": "GET",
                "path": "/rest/basket/:id",
                "framework": "express",
                "handler_file": "routes/basket.ts",
                "handler_line": 12,
                "authn_signal": "middleware_present",
                "authz_signal": "unknown",
                "management_surface": False,
                "confidence": "high",
            }
        ],
        "coverage": {"frameworks_detected": ["express"], "unsupported_route_files": []},
    }


# ---------------------------------------------------------------------------
# Org-profile defaults the skill reads
# ---------------------------------------------------------------------------


def test_resolver_stays_silent_without_a_profile(tmp_path):
    """No profile must not enable the export: the skill falls back to off."""
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "runtime/resolve_org_profile.py"), "--no-org-profile"],
        capture_output=True,
        text=True,
        check=True,
        cwd=tmp_path,
    )
    effective = json.loads(out.stdout)
    assert effective["org_profile"]["active"] is False
    assert not effective["defaults"].get("write_pentest_tasks")


# ---------------------------------------------------------------------------
# Exporter CLI the skill calls
# ---------------------------------------------------------------------------


def test_exporter_cli_writes_tasks_from_an_authnz_report(tmp_path):
    report = tmp_path / ".authnz-report.json"
    report.write_text(json.dumps(_authnz_report()))
    routes = tmp_path / ".route-inventory.json"
    routes.write_text(json.dumps(_route_inventory()))
    out = tmp_path / "docs" / "security" / "pentest-tasks-authnz.yaml"

    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "renderers/render_pentest_tasks.py"),
            "--authnz",
            str(report),
            "--route-inventory",
            str(routes),
            "--output",
            str(out),
            "--dialect",
            "strix",
            "--target-url",
            "http://localhost:3000",
            "--project",
            "shop",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "wrote 1 pentest tasks" in proc.stdout
    doc = yaml.safe_load(out.read_text())
    assert doc["meta"]["target"]["base_url"] == "http://localhost:3000"
    assert [t["threat_id"] for t in doc["tasks"]] == ["AZ-001"]
    assert doc["endpoints"][0]["path"] == "/rest/basket/:id"


def test_exporter_cli_reports_an_unreadable_report(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "renderers/render_pentest_tasks.py"),
            "--authnz",
            str(tmp_path / "missing.json"),
            "--output",
            str(tmp_path / "out.yaml"),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "cannot read authnz report" in proc.stderr


# ---------------------------------------------------------------------------
# Wiring named in the skill body
# ---------------------------------------------------------------------------


def test_agent_maps_every_authn_signal_value():
    sys.path.insert(0, str(ROOT / "scripts"))
    import analyzers.route_inventory as ri

    agent = (ROOT / "agents" / "appsec-authnz-analyzer.md").read_text(encoding="utf-8")
    for value in (*ri._AUTHN_PRESENT, "absent", "unknown"):
        assert f"`{value}`" in agent, value
    assert "post-Phase-9" not in agent
