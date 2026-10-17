"""Versioned engine identity for canonical artifacts and resume checks."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_meta() -> dict:
    data = json.loads((ROOT / "engine.json").read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("engine_version"), str)
        or type(data.get("analysis_version")) is not int
        or type(data.get("interface_version")) is not int
    ):
        raise ValueError("invalid Analyzer engine metadata")
    return data
