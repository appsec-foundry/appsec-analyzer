"""Build the single Analyzer runtime from its reviewed source tree."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent
RUNTIME_DIRS = ("scripts", "agents", "data", "schemas", "templates")
RUNTIME_ROOT_SCRIPTS = {"appsec-analyst-cli", "mermaid_validate.mjs"}
RETIRED_RUNTIME = {
    "plugin_meta.py",
    "plugin_read_gate.py",
    "plugin_write_gate.py",
    "appsec_status.py",
    "session_banner.py",
    "version_status.py",
}
RETIRED_ANALYZERS = {"security_steering.py"}
USER_DOCS = (
    "security-assessment.md",
    "threat-analyst.md",
    "configuration.md",
    "model-selection.md",
    "profiles.md",
    "providers.md",
    "headless-mode.md",
    "security-requirements-audit-skill.md",
    "threat-dragon-export.md",
    "local-release-preparation.md",
    "org-profiles.md",
    "organization-distributions.md",
)
_LOCAL_LINK = re.compile(r"\]\(([^)#]+)(?:#[^)]*)?\)")


def _ignore(directory: str, names: list[str]) -> set[str]:
    ignored = {
        name
        for name in names
        if name in {"__pycache__", ".pytest_cache", ".venv", ".git", "node_modules", "dist", "build", "wheelhouse"}
        or name.endswith((".pyc", ".pyo", ".egg-info"))
    }
    if Path(directory) == ROOT / "scripts":
        ignored.update(name for name in names if Path(directory, name).is_file() and name not in RUNTIME_ROOT_SCRIPTS)
    if Path(directory) == ROOT / "scripts" / "runtime":
        ignored.update(name for name in names if name in RETIRED_RUNTIME)
    if Path(directory) == ROOT / "scripts" / "analyzers":
        ignored.update(name for name in names if name in RETIRED_ANALYZERS)
    if Path(directory) == ROOT / "agents":
        ignored.add("appsec-stride-analyzer-v2.md")
    return ignored


def _copy_local_link_targets(source: Path, package: Path) -> None:
    for reference in _LOCAL_LINK.findall(source.read_text(encoding="utf-8")):
        if ":" in reference or reference.startswith(("/", "#")):
            continue
        path = source.parent / reference
        target = path.resolve()
        if not target.is_relative_to(ROOT) or not target.is_file() or path.is_symlink():
            raise ValueError(f"installed document has an invalid local link: {source.name}: {reference}")
        destination = package / target.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, destination)


class BuildAnalyzer(build_py):
    def run(self) -> None:
        package = Path(self.build_lib) / "appsec_analyzer"
        source_package = ROOT / "appsec_analyzer"
        if package.is_symlink() or package.resolve() == source_package.resolve():
            raise ValueError("build output must be a separate, non-symlinked package directory")
        if package.exists():
            shutil.rmtree(package)
        super().run()
        for name in RUNTIME_DIRS:
            shutil.copytree(ROOT / name, package / name, dirs_exist_ok=True, ignore=_ignore)
        for relative in (
            "appsec-analyzer/SKILL.md",
            "appsec-analyzer/business-context.md",
            "analyze-threats/references/analysis-contract.md",
            "audit-security-requirements/config.json",
        ):
            target = package / "skills" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            source = ROOT / "skills" / relative
            shutil.copy2(source, target)
            if source.suffix == ".md":
                _copy_local_link_targets(source, package)
        examples = package / "examples"
        examples.mkdir(exist_ok=True)
        shutil.copy2(ROOT / "examples" / "appsec-requirements-example.yaml", examples)
        for folder in ("profiles", "model-profiles"):
            shutil.copytree(ROOT / "examples" / folder, examples / folder, dirs_exist_ok=True)
        shutil.copytree(
            ROOT / "examples/organization-distribution",
            examples / "organization-distribution",
            dirs_exist_ok=True,
            ignore=_ignore,
        )
        docs = package / "docs"
        docs.mkdir(parents=True, exist_ok=True)
        for name in USER_DOCS:
            source = ROOT / "docs" / name
            shutil.copy2(source, docs / name)
            _copy_local_link_targets(source, package)
        shutil.copy2(ROOT / "engine.json", package / "engine.json")


setup(
    name="appsec-analyzer",
    version="0.1.0a0",
    description="Standalone deterministic AppSec scanning and assessment engine",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    url="https://github.com/appsec-foundry/appsec-analyzer",
    author="AppSec Foundry",
    license="Apache-2.0",
    python_requires=">=3.10",
    packages=find_packages(include=["appsec_analyzer", "appsec_analyzer.*"]),
    include_package_data=True,
    install_requires=["PyYAML>=6,<7", "jsonschema>=4.20,<5", "Jinja2>=3.1,<4"],
    extras_require={"requirements": ["requests>=2.32,<3", "beautifulsoup4>=4.12,<5"]},
    entry_points={"console_scripts": ["appsec-analyzer=appsec_analyzer.cli:main"]},
    cmdclass={"build_py": BuildAnalyzer},
)
