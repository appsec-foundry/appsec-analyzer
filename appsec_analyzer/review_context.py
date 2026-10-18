"""Read-only, validated facts for the bundled assessment review skill."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from appsec_analyzer.engine import initialize
from appsec_analyzer.saved_assessment import load_assessment


def read_context(assessment: str, *, identifier=None, grep=None, severity=None, component=None) -> dict:
    initialize()
    from model.query_threat_model import build_facts, lookup_id
    from shared.assessment_sources import is_portable_model, labelled_model

    path = Path(assessment).absolute()
    if ".." in path.parts:
        raise ValueError("parent traversal is not allowed")
    _, _, files, stem = load_assessment(path)
    model = yaml.safe_load(files[stem + ".yaml"])
    if is_portable_model(model):
        model = labelled_model(model)
    # No unrecorded requirements sidecars or repository configuration are read.
    facts = build_facts(model, grep, severity=severity, component=component)
    return lookup_id(facts, identifier) if identifier else facts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assessment")
    parser.add_argument("--id", dest="identifier")
    parser.add_argument("--grep")
    parser.add_argument("--severity")
    parser.add_argument("--component")
    args = parser.parse_args(argv)
    if args.identifier and any((args.grep, args.severity, args.component)):
        parser.error("--id cannot be combined with filters")
    try:
        print(json.dumps(read_context(**vars(args)), ensure_ascii=True))
    except Exception:
        print("review context: saved assessment is invalid or unreadable; no facts returned", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
