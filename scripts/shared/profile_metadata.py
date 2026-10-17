"""Render bounded operator metadata as literal report text."""

from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


def render_attributes(attributes: dict) -> str:
    if not attributes:
        return ""
    schema = yaml.safe_load((Path(__file__).resolve().parents[2] / "schemas/scan-profile.schema.yaml").read_text())
    document = {"schema_version": 1, "report": {"attributes": attributes}}
    if next(Draft202012Validator(schema).iter_errors(document), None):
        raise ValueError("invalid report attributes")

    def literal(value):
        return "".join(char if char.isalnum() or char in " .,-_" else f"&#{ord(char)};" for char in value)

    lines = ["| Report attribute | Value |", "| --- | --- |"]
    lines.extend(f"| {literal(key)} | {literal(value)} |" for key, value in sorted(attributes.items()))
    return "\n".join(lines)
