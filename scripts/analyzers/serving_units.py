"""Serving units: deployable code that answers requests or runs in a browser.

A component inventory that omits the unit serving a repository's routes, or
its client application, loses every finding, asset and flow behind it while
still looking complete. This scanner names those units from static signals so
inventory finalization can require a component for each of them.

Signals, per manifest root (the nearest directory holding a package or build
manifest, else the repository root):

* ``http-api``   route registrations from ``analyzers/route_inventory.py``;
  its entry files are the registering files, most routes first.
* ``client-app`` a ``package.json`` declaring a browser UI framework; its
  entry files are the runtime source files below that root.

Test, fixture, example, documentation, mock, vendored and build-output paths
never form or feed a unit. Languages without a route extractor (Go, Ruby,
PHP) yield no ``http-api`` unit; their coverage stays with discovery alone.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from shared._path_guard import is_safe_to_read

_MANIFESTS = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "requirements.txt",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "Gemfile",
        "composer.json",
    }
)
# Packages that only exist to render a browser UI. Meta-frameworks that also
# serve requests (Next.js, Nuxt) still declare one of these.
_CLIENT_FRAMEWORKS = ("@angular/core", "react-dom", "vue", "svelte", "solid-js", "preact")
_NON_RUNTIME_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "e2e",
        "cypress",
        "fixture",
        "fixtures",
        "testdata",
        "example",
        "examples",
        "sample",
        "samples",
        "doc",
        "docs",
        "mock",
        "mocks",
        "__mocks__",
        "stories",
        ".storybook",
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".git",
    }
)
_TEST_FILE_RE = re.compile(r"\.(?:spec|test|stories)\.[a-z]+$|(?:^|/)test_[^/]*\.py$|_test\.(?:py|go)$")
_TOOLING_FILE_RE = re.compile(r"\.config\.[a-z]+$|(?:^|/)(?:test-setup|setup-?tests?)\.[a-z]+$")
_CODE_EXTS = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".py", ".java", ".kt", ".cs"}
)
_ENTRY_NAME_RE = re.compile(r"(?:^|/)(?:main|index|app|server)\.[a-z]+$")
_MAX_MANIFEST_BYTES = 1_000_000
_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "schemas" / "architecture-serving-units.schema.json").read_text(
        encoding="utf-8"
    )
)
MAX_UNITS = _SCHEMA["properties"]["limits"]["properties"]["max_units"]["const"]
MAX_ENTRY_FILES = _SCHEMA["properties"]["limits"]["properties"]["max_entry_files"]["const"]


def is_runtime_path(rel: str) -> bool:
    """False for test, fixture, example, documentation, vendored or built files."""
    return not (set(rel.split("/")[:-1]) & _NON_RUNTIME_SEGMENTS or _TEST_FILE_RE.search(rel))


def _files(repo_root: Path) -> list[str]:
    found = []
    for directory, subdirectories, names in os.walk(repo_root):
        subdirectories[:] = sorted(d for d in subdirectories if d not in _NON_RUNTIME_SEGMENTS)
        base = Path(directory).relative_to(repo_root).as_posix()
        found.extend(name if base == "." else f"{base}/{name}" for name in names)
    return sorted(found)


def _manifest_root(rel: str, roots: list[str]) -> str:
    """The deepest manifest root holding ``rel``; ``""`` is the repository root."""
    return max((r for r in roots if r == "" or rel.startswith(r + "/")), key=len, default="")


def _client_framework(repo_root: Path, manifest: str) -> str | None:
    path = repo_root / manifest
    try:
        if not is_safe_to_read(path, repo_root) or path.stat().st_size > _MAX_MANIFEST_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    declared = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        if isinstance(data.get(key), dict):
            declared.update(data[key])
    return next((name for name in _CLIENT_FRAMEWORKS if name in declared), None)


def _package_sources(files: list[str], roots: list[str], root: str) -> list[str]:
    """Program files whose nearest manifest is `root`'s; nested packages and build tooling stay out."""
    return [
        f
        for f in files
        if Path(f).suffix in _CODE_EXTS and _manifest_root(f, roots) == root and not _TOOLING_FILE_RE.search(f)
    ]


def scan(repo_root: Path, routes: list[dict]) -> list[dict]:
    """Every serving unit with its complete entry-file list, in a stable order.

    ``routes`` are the rows of the route inventory of the same ``repo_root``.
    """
    repo_root = Path(repo_root)
    files = [f for f in _files(repo_root) if is_runtime_path(f)]
    manifests = [f for f in files if f.rsplit("/", 1)[-1] in _MANIFESTS]
    roots = sorted({m.rsplit("/", 1)[0] if "/" in m else "" for m in manifests})
    units = []
    registrations: dict[str, dict[str, int]] = {}
    frameworks: dict[str, set[str]] = {}
    for route in routes:
        rel = route.get("handler_file")
        if not isinstance(rel, str) or not is_runtime_path(rel):
            continue
        root = _manifest_root(rel, roots)
        counts = registrations.setdefault(root, {})
        counts[rel] = counts.get(rel, 0) + 1
        if route.get("framework"):
            frameworks.setdefault(root, set()).add(str(route["framework"]))
    for root, counts in sorted(registrations.items()):
        units.append(
            {
                "id": f"http-api:{root or '.'}",
                "kind": "http-api",
                "root": root,
                "framework": ", ".join(sorted(frameworks.get(root, ()))) or None,
                "entry_files": sorted(counts, key=lambda rel: (-counts[rel], rel)),
                # Not projected: the package's own program files, for `adopt`.
                "source_files": _package_sources(files, roots, root) if root else [],
            }
        )
    for manifest in manifests:
        if not manifest.endswith("package.json"):
            continue
        framework = _client_framework(repo_root, manifest)
        if framework is None:
            continue
        root = manifest.rsplit("/", 1)[0] if "/" in manifest else ""
        # A nested manifest root is its own unit, never this app's source.
        sources = _package_sources(files, roots, root)
        # Files beside the manifest are build tooling when the app has a source tree.
        depth = root.count("/") + 1 if root else 0
        if any(f.count("/") > depth for f in sources):
            sources = [f for f in sources if f.count("/") > depth]
        if not sources:
            continue
        sources.sort(key=lambda rel: (not _ENTRY_NAME_RE.search(rel), rel.count("/"), rel))
        units.append(
            {
                "id": f"client-app:{root or '.'}",
                "kind": "client-app",
                "root": root,
                "framework": framework,
                "entry_files": sources,
            }
        )
    return units


def project(units: list[dict]) -> dict:
    """The bounded, schema-checked view a model receives.

    Coverage during discovery needs one listed entry file. A path the contract
    rejects is left out, never shortened; a unit left without a listable entry
    file is omitted here and still enforced by component finalization.
    """
    from jsonschema import Draft202012Validator  # noqa: PLC0415

    item = _SCHEMA["properties"]["units"]["items"]["properties"]
    path_ok = Draft202012Validator(item["entry_files"]["items"]).is_valid
    shown = []
    for unit in units:
        files = [rel for rel in unit["entry_files"] if path_ok(rel)]
        if not files or len(unit["root"]) > item["root"]["maxLength"]:
            continue
        if len(shown) == MAX_UNITS:
            break
        shown.append(
            {
                **{key: unit[key] for key in ("id", "kind", "root", "framework")},
                "entry_files": files[:MAX_ENTRY_FILES],
                "omitted_entry_files": len(unit["entry_files"]) - min(len(files), MAX_ENTRY_FILES),
            }
        )
    projected = {
        "schema_version": 1,
        "limits": {
            "max_units": MAX_UNITS,
            "max_entry_files": MAX_ENTRY_FILES,
            "omitted_units": len(units) - len(shown),
        },
        "units": shown,
    }
    Draft202012Validator(_SCHEMA).validate(projected)
    return projected


# An http-api unit needs an application component; a client may be modelled as
# a client or, for server-rendered applications, as an application component.
_CARRIER_TIERS = {"http-api": {"application"}, "client-app": {"client", "application"}}


def _owns(component: dict, rel: str) -> bool:
    from orchestrator.build_stride_dispatch_manifest import _path_owns  # noqa: PLC0415

    paths = [p for p in component.get("paths") or [] if isinstance(p, str)]
    return rel in paths or _path_owns(paths, rel)


def carriers(unit: dict, components: list[dict]) -> list[dict]:
    """Components of an eligible tier that list one of the unit's entry files.

    A client app with its own root whose entry files no component lists is
    carried by the one client-tier component that lists runtime files below
    that root: the model modelled the app and left out only its entry file,
    which `adopt` then gives it. Two such components, an app at the repository
    root, or only an application component there (a server beside the app)
    stay uncovered, and an http-api unit always needs its entry file, because
    a data-access component below an API root serves no requests.
    """
    tiers = _CARRIER_TIERS[unit["kind"]]
    eligible = [c for c in components if c.get("tier") in tiers]
    exact = [c for c in eligible if any(_owns(c, rel) for rel in unit["entry_files"])]
    root = (unit.get("root") or "").strip("/")
    if exact or unit["kind"] != "client-app" or not root:
        return exact
    near = [
        c
        for c in eligible
        if c.get("tier") == "client"
        and any(
            isinstance(path, str) and path.startswith(root + "/") and is_runtime_path(path)
            for path in c.get("paths") or []
        )
    ]
    return near if len(near) == 1 else []


def uncovered(units: list[dict], components: list[dict]) -> list[dict]:
    return [unit for unit in units if not carriers(unit, components)]


def describe(units: list[dict]) -> str:
    """A bounded, controller-authored reason naming each uncovered unit."""
    rows = [
        f"{u['kind']} at {u['root'] or 'repository root'} (entry files: {', '.join(u['entry_files'][:3])})"
        for u in units[:MAX_UNITS]
    ]
    return "; ".join(rows)


def component_for(unit: dict, repo_root: Path, taken: set[str]) -> dict | None:
    """A component that carries `unit` when discovery modelled none, or None when it has no file.

    A client app takes the client tier and its source files; an API takes the
    application tier and its package's program files (its registration files
    at the repository root). The name comes from the package manifest.
    """
    client = unit["kind"] == "client-app"
    paths = [rel for rel in (unit["entry_files"] if client else unit.get("source_files") or unit["entry_files"])]
    paths = [rel for rel in paths if is_runtime_path(rel)]
    if not paths:
        return None
    root = unit.get("root") or ""
    label = (root.rsplit("/", 1)[-1] if root else repo_root.name) or "app"
    try:
        manifest = json.loads((repo_root / root / "package.json").read_text(encoding="utf-8"))
        label = str(manifest.get("name") or label) if isinstance(manifest, dict) else label
    except (OSError, ValueError):
        pass
    base = re.sub(r"[^a-z0-9]+", "-", f"{root or 'repository'}-{'client' if client else 'api'}".lower()).strip("-")
    cid = next(c for c in (base, *(f"{base}-{n}" for n in range(2, len(taken) + 3))) if c not in taken)
    where = root or "the repository root"
    return {
        "id": cid,
        "name": f"{label} {'client application' if client else 'API'}"[:80],
        "description": f"{'Client application' if client else 'HTTP API'} at {where}, "
        "added because discovery modelled no component for it.",
        "paths": paths,
        "tier": "client" if client else "application",
        "framework": unit.get("framework"),
        "complexity": "moderate",
        "deployment_zones": [],
        "handles_sensitive_data": False,
        "origin": "reconciliation",
    }


def _closest(found: list[dict], rel: str) -> dict:
    """The carrier whose listed files share the longest folder prefix with `rel`; the first on a tie."""

    def shared(path: str) -> int:
        common = 0
        for a, b in zip(path.split("/")[:-1], rel.split("/")[:-1], strict=False):
            if a != b:
                break
            common += 1
        return common

    return max(found, key=lambda c: max((shared(p) for p in c.get("paths") or [] if isinstance(p, str)), default=0))


def adopt(units: list[dict], components: list[dict], repo_root: Path, routes: list[dict]) -> int:
    """Give each unit's carrier the unit's code no eligible component lists; return additions.

    A client-app carrier receives the app's runtime source files. An http-api
    carrier receives its package's program files (route registrations,
    services, configuration; an API at the repository root has no package of
    its own and receives its registration files) and then the resolved
    handler module of every route registered there. Discovery lists only the
    files its model read, and a file no component lists is analysed by no
    job, so the package, not the reading, decides what the API comprises.
    With several carriers each file goes to the one listing files closest to
    it. Files another eligible component lists stay with it.
    """
    from analyzers.handler_resolver import HandlerResolver  # noqa: PLC0415

    eligible = [c for c in components if c.get("tier") in {"client", "application"}]
    added = 0

    def give(owner: dict, rel: str) -> None:
        nonlocal added
        if not is_runtime_path(rel) or any(_owns(c, rel) for c in eligible):
            return
        owner["paths"] = [*owner.get("paths", []), rel]
        added += 1

    resolver = None
    for unit in units:
        found = carriers(unit, components)
        if not found:
            continue
        if unit["kind"] == "client-app":
            for rel in unit["entry_files"]:
                give(found[0], rel)
            continue
        for rel in unit.get("source_files") or unit["entry_files"]:
            give(_closest(found, rel), rel)
        resolver = resolver or HandlerResolver(repo_root)
        for route in routes:
            registering = route.get("handler_file")
            owner = next((c for c in found if registering in unit["entry_files"] and _owns(c, registering)), None)
            if owner is None:
                continue
            module = resolver.handler_module(route)
            if module:
                give(owner, module)
    _adopt_workspace_packages(units, components, repo_root, give)
    return added


_JS_SPECIFIER_RE = re.compile(r"""(?:\bfrom\s*|\brequire\(\s*|\bimport\(\s*|^\s*import\s+)['"]([^'"\n]+)['"]""", re.M)


def _workspace_packages(repo_root: Path, files: list[str]) -> dict[str, str]:
    """Package name → folder of each named runtime manifest below the repository root."""
    packages = {}
    for rel in files:
        if not rel.endswith("/package.json"):
            continue
        try:
            name = json.loads((repo_root / rel).read_text(encoding="utf-8")).get("name")
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(name, str) and name:
            packages[name] = rel.rsplit("/", 1)[0]
    return packages


def _adopt_workspace_packages(units: list[dict], components: list[dict], repo_root: Path, give) -> None:
    """Give a carrier the program files of the workspace packages its code imports, transitively.

    A monorepo's shared packages (`@acme/shared`) run inside the app that
    imports them but belong to no unit of their own, so no component lists
    them. APIs adopt first: a package both an API and a client import runs on
    the server too, where its weaknesses matter most.
    """
    files = [f for f in _files(repo_root) if is_runtime_path(f)]
    packages = _workspace_packages(repo_root, files)
    if not packages:
        return
    roots = sorted({m.rsplit("/", 1)[0] if "/" in m else "" for m in files if m.rsplit("/", 1)[-1] in _MANIFESTS})
    sources = {root: _package_sources(files, roots, root) for root in packages.values()}

    def imported(rel: str) -> set[str]:
        try:
            text = (repo_root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return set()
        found = set()
        for spec in _JS_SPECIFIER_RE.findall(text):
            for name, root in packages.items():
                if spec == name or spec.startswith(name + "/"):
                    found.add(root)
        return found

    for kind in ("http-api", "client-app"):
        for unit in (u for u in units if u["kind"] == kind):
            found = carriers(unit, components)
            if not found:
                continue
            carrier = found[0]
            owned = lambda: {p for p in carrier.get("paths") or [] if isinstance(p, str)}  # noqa: E731
            pending = sorted(rel for rel in owned() if (repo_root / rel).is_file())
            scanned: set[str] = set()
            reached = {unit["root"]}
            while pending:
                rel = pending.pop()
                if rel in scanned:
                    continue
                scanned.add(rel)
                for root in sorted(imported(rel) - reached):
                    reached.add(root)
                    for source in sources[root]:
                        give(carrier, source)
                    # Only files the carrier now owns lead further; another owner's imports stay its own.
                    pending.extend(source for source in sources[root] if source in owned())
