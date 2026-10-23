"""What each assessment depth does: the shipped defaults, an organization's defaults, and a team's values (REQ-018).

The shipped file ``data/assessment-depths.yaml`` states every value for every depth. An
organization profile and a team's scan profile each may change single values for single depths
under ``depths``; the scan profile wins over the organization, and command-line flags win over
both where they exist. Profiles are validated by their own schemas, which carry the same block
definition as ``schemas/assessment-depths.schema.yaml``.
"""

from __future__ import annotations

import copy
import functools

import yaml
from jsonschema import Draft202012Validator

from appsec_analyzer import resource_root

SHIPPED = "data/assessment-depths.yaml"
KEYS = ("verify", "abuse_cases", "derived_abuse_cases", "architect_review", "actor_discovery", "budget")


class DepthSettingsError(ValueError):
    """The shipped depth settings do not match their schema."""


def schema() -> dict:
    return yaml.safe_load((resource_root() / "schemas/assessment-depths.schema.yaml").read_text())


@functools.cache
def _shipped() -> dict:
    document = yaml.safe_load((resource_root() / SHIPPED).read_text())
    if next(Draft202012Validator(schema()).iter_errors(document), None) is not None:
        raise DepthSettingsError(f"{SHIPPED} does not match schemas/assessment-depths.schema.yaml")
    return document["depths"]


def shipped(depth: str) -> dict:
    """The shipped values of ``depth``."""
    return copy.deepcopy(_shipped()[depth])


def effective(depth: str, *, organization: dict | None = None, scan: dict | None = None) -> tuple[dict, dict]:
    """``(values, origins)`` of ``depth``: the shipped file, then the organization's, then the team's ``depths``."""
    values = shipped(depth)
    origins = dict.fromkeys(values, "analyzer default")
    for layer, label in ((organization, "organization profile"), (scan, "scan profile")):
        for key, value in ((layer or {}).get(depth) or {}).items():
            values[key] = copy.deepcopy(value)
            origins[key] = label
    return values, origins


def organization_depths(org_profile: str | None, no_org_profile: bool, preset: str | None = None) -> dict:
    """The active organization profile's ``depths`` as the run resolves it; empty without one.

    An invalid profile yields nothing here, because the run refuses it before its first model call."""
    from appsec_analyzer.engine import initialize

    initialize()
    from runtime import resolve_org_profile

    effective, errors = resolve_org_profile.resolve(org_profile, preset, no_org_profile, None, resource_root())
    return {} if errors else effective.get("depths") or {}
