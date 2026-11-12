"""Fixtures with and without the weakness for each verified test case (REQ-040).

Every test case of an aspect that a depth verifies has `vulnerable/` and `safe/` code under its
`fixtures` path. The safe code builds the same feature without the weakness, so the test case
applies to both. Without a model, the vulnerable code must also give the test case candidates
where it names starting point facts. Whether the model tells the two apart is a recorded-response
evaluation, which these tests do not run.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml
from analyzers.route_inventory import build_inventory
from model import case_candidates as cc
from model.case_outcomes import load_catalog

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = ("vulnerable", "safe")


def _verified_cases() -> list[dict]:
    depths = yaml.safe_load((ROOT / "data" / "assessment-depths.yaml").read_text(encoding="utf-8"))["depths"]
    aspects = {aspect for depth in depths.values() for aspect in depth["verify"]}
    return [case for case in load_catalog()["test_cases"] if case["aspect"] in aspects and case["mode"] != "rules"]


VERIFIED = _verified_cases()


def _facts(case: dict, variant: str, tmp_path: Path) -> dict:
    # The scanners skip directories named tests or fixtures, so each fixture is read from a copy.
    root = shutil.copytree(ROOT / case["fixtures"] / variant, tmp_path / variant)
    files = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    return cc.route_facts(root, build_inventory(root), [], components={"app": files})


def test_verified_aspects_have_test_cases():
    assert VERIFIED


@pytest.mark.parametrize("case", VERIFIED, ids=lambda case: case["id"])
def test_every_verified_test_case_has_code_with_and_without_the_weakness(case):
    for variant in VARIANTS:
        directory = ROOT / case["fixtures"] / variant
        assert directory.is_dir() and any(path.is_file() for path in directory.rglob("*")), f"{directory} is empty"


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("case", VERIFIED, ids=lambda case: case["id"])
def test_the_test_case_applies_to_its_fixture_by_its_own_signal(case, variant, tmp_path):
    applies, reason = cc.applies(case, _facts(case, variant, tmp_path), "app")
    # A signal without an evaluator also applies; the fixture must show one of the case's own signals.
    assert applies and reason in {cc.APPLIES_REASONS[entry["signal"]] for entry in case["applies_when"]}, reason


@pytest.mark.parametrize("case", [c for c in VERIFIED if c["starting_points"].get("facts")], ids=lambda c: c["id"])
def test_the_vulnerable_fixture_gives_the_test_case_candidates(case, tmp_path):
    facts = _facts(case, "vulnerable", tmp_path)
    assert cc.starting_candidates(case, "app", facts, [])["candidates"]
