"""Shipped analyst packages, the Manifesto profile, limits, and authoring examples."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from contexts import resolve_analyst_catalog as rc  # noqa: E402

EXAMPLES = sorted((ROOT / "examples" / "analyst").glob("*-package.yaml"))


@pytest.mark.parametrize("pid", sorted(rc.PACKAGED))
def test_every_packaged_package_validates(pid):
    data, digest = rc.load_package(rc.PACKAGED[pid], rc.load_limits()["package_kib"])
    assert data["id"] == pid and len(digest) == 64


def test_manifesto_profile_is_attributed_optional_and_not_a_certification():
    profile, _ = rc.load_package(rc.PACKAGED["tmm/threat-modeling-manifesto"], 256)
    provenance = profile["provenance"]
    assert provenance["url"] == "https://www.threatmodelingmanifesto.org/"
    assert provenance["license"] == "CC BY 4.0" and "release 1" in provenance["revision"]
    text = (rc.PACKAGED["tmm/threat-modeling-manifesto"]).read_text(encoding="utf-8").lower()
    assert "certifies no compliance" in text
    assert {"plausible-failures", "practical-responses", "investigation-adequate", "missing-perspectives"} <= {
        c["id"] for c in profile["criteria"]
    }
    assert rc.resolve([], rc.load_limits())["criteria"] == []


def test_limits_are_finite_with_units():
    raw = yaml.safe_load((ROOT / "data" / "analyst-limits.yaml").read_text())
    assert raw["status"] == "provisional"
    assert all(entry["unit"] and entry["value"] > 0 for entry in raw["limits"].values())
    limits = rc.load_limits()
    assert limits["call_seconds"] <= limits["job_seconds"] and limits["file_kib"] <= limits["job_kib"]


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.name)
def test_authoring_examples_validate(example):
    data, _ = rc.load_package(example, 256)
    assert "/" in data["id"]


def test_authoring_examples_exist():
    assert EXAMPLES
