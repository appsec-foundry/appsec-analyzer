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
    from appsec_analyzer.engine import initialize as _engine_imports

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


# Public composition adapter, separate from installed distribution defaults.
CONFIG_CAPABILITY = {
    "available": True,
    "schema_version": 1,
    "commands": ["score"],
    "profile_fields": ["policy.disable_opus", "policy.url_allowlist", "presets.*.base_mode"],
}


def load_config(path: Path, *, repositories=()) -> dict:
    """Validate an engine-only projection without importing Advisor host settings."""
    import json

    # Score admits only the explicitly selected top-level checkout. Walking
    # to an ancestor Git marker here misclassifies missing or invalid sources
    # as profile errors and changes their public score status from 1 to 2.
    # A configuration inside the selected canonical source remains forbidden.
    for selection in repositories:
        if "://" not in selection and not selection.startswith("git@"):
            if path.expanduser().absolute().is_relative_to(Path(selection).expanduser().resolve()):
                raise ProfileError("organization configuration must be outside the selected source")
    document = read_document(path)
    schema = json.loads((resource_root() / "schemas/organization-config.schema.json").read_text())
    if not Draft202012Validator(schema).is_valid(document):
        raise ProfileError("invalid organization configuration envelope")
    if document["engine_version"] != ENGINE_VERSION:
        raise ProfileError("organization configuration requires a different pinned engine")
    profile = document["profile"]
    profile_schema = yaml.safe_load((resource_root() / "schemas/org-profile.schema.yaml").read_text())
    if not Draft202012Validator(profile_schema).is_valid(profile):
        raise ProfileError("invalid projected organization profile")
    allowed = {"api_version", "organization", "compatibility", "default_preset", "presets", "policy"}
    if set(profile) - allowed or any(set(preset) != {"base_mode"} for preset in profile["presets"].values()):
        raise ProfileError("organization configuration contains unsupported engine fields")
    from appsec_analyzer.engine import initialize

    initialize()
    from validators.validate_org_profile import validate

    if validate(profile, path.parent, plugin_version=document["advisor_core_version"]):
        raise ProfileError("projected organization profile is incompatible or invalid")
    return document


def config_command(namespace) -> int:
    """Inspect or run through the versioned public composition boundary."""
    import json

    from appsec_analyzer.cli import _parser
    from appsec_analyzer.cli import main as analyzer_main

    arguments = list(namespace.arguments)
    if arguments[:1] == ["--"]:
        arguments.pop(0)
    if namespace.config_action != "run" and arguments:
        raise ProfileError("organization inspection does not accept workflow arguments")
    if namespace.config_action == "run" and namespace.config_depth is not None:
        raise ProfileError("score does not accept an assessment-depth override")
    parsed = None
    repositories = []
    if namespace.config_action == "run":
        if not arguments or arguments[0] not in CONFIG_CAPABILITY["commands"]:
            raise ProfileError("organization-config supports only the declared score workflow")
        parsed = _parser().parse_args(arguments)
        repositories = [parsed.repo]
    document = load_config(Path(namespace.config), repositories=repositories)
    profile = document["profile"]
    preset = namespace.config_preset if namespace.config_preset is not None else profile["default_preset"]
    if preset not in profile["presets"]:
        raise ProfileError("organization preset is unavailable")
    if namespace.config_action != "run":
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "valid": True,
                    "organization": profile["organization"],
                    "preset": preset,
                    "defaults": {"assessment_depth": namespace.config_depth or profile["presets"][preset]["base_mode"]},
                    "policy": profile.get("policy", {}),
                    "supported_commands": CONFIG_CAPABILITY["commands"],
                    "score_uses_assessment_depth": False,
                },
                sort_keys=True,
            )
        )
        return 0
    from appsec_analyzer.engine import initialize

    initialize()
    from runtime.remote_repositories import parse_remote

    remote = parse_remote(parsed.repo)
    allowlist = profile.get("policy", {}).get("url_allowlist", [])
    if (
        remote is not None
        and allowlist
        and not any(remote.host == host.lower() or remote.host.endswith("." + host.lower()) for host in allowlist)
    ):
        raise ProfileError("Git destination is outside the organization allowlist")
    # Score has no model calls, report exports, or assessment depth. The only
    # applicable declared restriction is checked before Git or credentials.
    return analyzer_main(arguments)
