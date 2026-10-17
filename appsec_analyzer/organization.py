"""An explicit entry point for distributions with bundled organization defaults.

Only the organization's installed launcher selects a resource package. Nothing
is discovered in the assessed repository or through Python entry-point plugins.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator

from appsec_analyzer import ENGINE_VERSION, INTERFACE_VERSION, resource_root
from appsec_analyzer.profiles import DEPTHS, ProfileError, read_document, reject_source_paths, resolve_scan


@dataclass(frozen=True)
class Organization:
    root: Path
    command: str
    scan_profile: Path
    org_profile: Path
    identity: dict

    def describe(self) -> dict:
        return {
            "schema_version": 1,
            "engine_version": ENGINE_VERSION,
            "interface_version": INTERFACE_VERSION,
            "organization": self.identity,
            "defaults": {"profile": str(self.scan_profile), "org_profile": str(self.org_profile)},
            "defaults_overridable": True,
        }

    def apply(self, namespace) -> None:
        repositories = namespace.repo or [str(Path.cwd())]
        reject_source_paths([self.root], repositories)
        if namespace.profile is None and namespace.host is None:
            namespace.profile = str(self.scan_profile)
        if namespace.org_profile is None and not namespace.no_org_profile:
            namespace.org_profile = str(self.org_profile)


def _resource(root: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or "\\" in relative:
        raise ProfileError("organization resource paths must stay inside the installed package")
    selected = root.joinpath(*path.parts)
    if not selected.resolve().is_relative_to(root) or selected.resolve() != selected:
        raise ProfileError("organization resources must be regular files without symlinks")
    return selected


def load(package: str) -> Organization:
    """Validate the trusted launcher's data package before invoking any command."""
    try:
        root = files(package)
    except (ImportError, TypeError):
        raise ProfileError("organization resource package is unavailable") from None
    if not isinstance(root, Path):
        raise ProfileError("organization package must be installed as normal files")
    root = root.absolute()
    manifest = read_document(root / "organization.yaml")
    schema = yaml.safe_load((resource_root() / "schemas/organization-distribution.schema.yaml").read_text())
    if not Draft202012Validator(schema).is_valid(manifest):
        raise ProfileError("organization manifest is invalid; check organization-distribution.schema.yaml")
    if manifest["engine_version"] != ENGINE_VERSION or manifest["interface_version"] != INTERFACE_VERSION:
        raise ProfileError(
            "organization package requires a different engine or interface version; install matching wheels"
        )
    scan = _resource(root, manifest["scan_profile"])
    org = _resource(root, manifest["org_profile"])
    for depth in DEPTHS:
        resolve_scan(str(scan), depth=depth)
    document = read_document(org)
    from appsec_analyzer.cli import _engine_imports

    _engine_imports()
    from validators.validate_org_profile import validate

    if validate(document, org.parent, plugin_version=ENGINE_VERSION):
        raise ProfileError("bundled organization profile is invalid; check its files, fields and engine compatibility")
    # Advisor-only integration fields must not pretend to work in a distribution.
    unsupported = {"hooks", "mcp", "skills", "skill_toggles", "banner", "baseline", "security_coach", "llm_policy"}
    if unsupported.intersection(document):
        raise ProfileError("bundled organization profile contains unsupported Advisor integration fields")
    return Organization(root, manifest["command"], scan, org, document["organization"])


def main(package: str, argv: list[str] | None = None) -> int:
    """Call from an organization's console script: ``main('company_appsec')``."""
    try:
        organization = load(package)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"organization: error: {exc}", file=sys.stderr)
        return 2
    from appsec_analyzer.cli import main as analyzer_main

    return analyzer_main(argv, organization=organization)
