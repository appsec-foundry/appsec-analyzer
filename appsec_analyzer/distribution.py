"""Create an organization distribution and keep its engine pins aligned.

Both operations only read and write files in a directory the operator names.
They make no network requests and never build, install or publish anything.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from appsec_analyzer import ENGINE_VERSION, INTERFACE_VERSION, resource_root

TEMPLATE = "examples/organization-distribution"
NAME = re.compile(r"[a-z][a-z0-9]{1,29}")
# Longest names first, so the command and package names are not split by the generic ones.
_RENAMES = (
    ("nordlicht-appsec", "{name}-appsec"),
    ("nordlicht_appsec", "{name}_appsec"),
    ("NORDLICHT", "{upper}"),
    ("Nordlicht", "{title}"),
    ("nordlicht", "{name}"),
    (" (fictional example)", ""),
)
_README = """# {title} AppSec distribution

This repository ships the `{name}-appsec` command: the upstream Analyzer engine, unchanged, with this organization's profiles.

The profiles, context, abuse cases and requirements under `src/{name}_appsec/` are sample content. Replace them with your own before a release.

Build, install and release steps are in the Analyzer guide `docs/organization-distributions.md`. After installing a different engine, run `appsec-analyzer distribution update-engine .` here, rebuild both wheels and test them.
"""


class DistributionError(ValueError):
    """The request cannot be carried out without guessing or overwriting."""


def _regular(path: Path, root: Path) -> Path:
    """A real file that stays inside the organization repository, also through its directories."""
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise DistributionError(f"{path.name} must be a regular file inside the organization repository")
    return path


def _pin_patterns(manifest: Path) -> list[tuple[Path, str, re.Pattern]]:
    """Each place that names the engine, as (file, label, pattern capturing the version)."""
    root = manifest.parents[2]
    return [
        (root / "setup.cfg", "engine dependency", re.compile(r"^(\s*appsec-analyzer==)(\S+)$", re.M)),
        (root / "requirements.lock", "engine lock entry", re.compile(r"^(appsec-analyzer==)(\S+)$", re.M)),
        (manifest, "engine_version", re.compile(r"^(engine_version: )(\S+)$", re.M)),
        (manifest, "interface_version", re.compile(r"^(interface_version: )(\S+)$", re.M)),
    ]


def _find_manifest(repo: Path) -> Path:
    found = sorted(repo.glob("src/*/organization.yaml"))
    if len(found) != 1:
        raise DistributionError("expected exactly one src/<package>/organization.yaml in the organization repository")
    return _regular(found[0], repo)


def update_engine(repo: str) -> list[dict]:
    """Set every engine pin to the installed engine; change nothing if any pin is missing."""
    root = Path(repo).resolve()
    manifest = _find_manifest(root)
    targets = {"engine_version": ENGINE_VERSION, "interface_version": str(INTERFACE_VERSION)}
    pending: dict[Path, str] = {}
    changes = []
    for path, label, pattern in _pin_patterns(manifest):
        text = pending.get(path) or _regular(path, root).read_text(encoding="utf-8")
        if len(pattern.findall(text)) != 1:
            raise DistributionError(f"{path.name} must contain exactly one {label}; nothing was changed")
        old = pattern.search(text).group(2)
        new = targets.get(label, ENGINE_VERSION)
        pending[path] = pattern.sub(lambda match: match.group(1) + new, text)
        changes.append({"file": str(path.relative_to(root)), "pin": label, "old": old, "new": new})
    for path, text in pending.items():
        path.write_text(text, encoding="utf-8")
    return changes


def diverged(changes: list[dict]) -> bool:
    """True when the engine version was not the same in every file before the update."""
    return len({change["old"] for change in changes if change["pin"] != "interface_version"}) > 1


def init(name: str, target: str) -> Path:
    """Copy the example distribution into a new or empty directory under the organization's names."""
    if not NAME.fullmatch(name):
        raise DistributionError("NAME must be 2-30 lowercase letters and digits and start with a letter")
    destination = Path(target).absolute()
    if destination.is_symlink() or (destination.exists() and (not destination.is_dir() or any(destination.iterdir()))):
        raise DistributionError("the target must not exist or must be an empty directory; nothing is overwritten")
    template = resource_root() / TEMPLATE
    if not template.is_dir():
        raise DistributionError("the example distribution is not part of this installation")
    values = {"name": name, "upper": name.upper(), "title": name.capitalize()}
    renames = [(old, new.format(**values)) for old, new in _RENAMES]
    destination.mkdir(parents=True, exist_ok=True)
    for source in sorted(template.rglob("*")):
        relative = source.relative_to(template)
        if "__pycache__" in relative.parts or source.suffix == ".pyc" or source.is_dir() or source.is_symlink():
            continue
        if relative.name == "README.md" and len(relative.parts) == 1:
            continue
        text = source.read_text(encoding="utf-8")
        path = str(relative)
        for old, new in renames:
            text, path = text.replace(old, new), path.replace(old, new)
        selected = destination / path
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_text(text, encoding="utf-8")
        shutil.copymode(source, selected)
    (destination / "README.md").write_text(_README.format(**values), encoding="utf-8")
    update_engine(str(destination))
    return destination
