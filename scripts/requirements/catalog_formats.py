"""Read a requirements catalog in a supported format as an Analyzer catalog.

Every consumer reads one shape: ``categories[].requirements[]`` (see
``schemas/requirements-catalog.schema.yaml``). A catalog in another format is
converted once, where it is loaded, so nothing after that point knows about
formats. Today the only other format is an OSCAL catalog in JSON or YAML.

The format is taken from the content: ``categories`` is an Analyzer catalog, an
OSCAL ``catalog`` with ``metadata.oscal-version`` is converted, and any other
OSCAL document (profile, system security plan, ...) is refused. Anything else
passes through unchanged so ``requirements_state.validate_catalog`` keeps
reporting its structural errors.

The input is untrusted. It is parsed with data-only loaders, and the walk is
bounded in depth, node count, control count and produced text, so a crafted
file cannot exhaust memory or the stack through nesting or YAML aliases.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import yaml

# JSON parses fast, so large OSCAL files are accepted in that form. YAML needs
# a lower limit: parsing it costs seconds per few megabytes.
MAX_RAW_BYTES = 16 * 1024 * 1024
MAX_YAML_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 16
MAX_NODES = 200_000
MAX_CONTROLS = 5_000
# Produced text, measured in characters before it is written out.
MAX_TEXT_CHARS = 2 * 1024 * 1024
MAX_PARAM_DEPTH = 3

FORMAT_ANALYZER = "analyzer"
FORMAT_OSCAL = "oscal-catalog"

_OSCAL_ROOTS = (
    "catalog",
    "profile",
    "system-security-plan",
    "component-definition",
    "assessment-plan",
    "assessment-results",
    "plan-of-action-and-milestones",
    "mapping-collection",
)
_INSERT = re.compile(r"\{\{\s*insert:\s*param,\s*([A-Za-z0-9_.\-]+)\s*\}\}")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class CatalogFormatError(ValueError):
    """The catalog is in a format Analyzer does not read, or exceeds a conversion limit."""


def normalize(body: bytes) -> tuple[bytes, dict]:
    """Return ``(body, info)``: an OSCAL catalog converted, anything else unchanged.

    ``info["source_sha256"]`` is always the checksum of the supplied bytes.
    """
    if len(body) > MAX_RAW_BYTES:
        raise CatalogFormatError(f"catalog is larger than {MAX_RAW_BYTES // 2**20} MiB")
    source = hashlib.sha256(body).hexdigest()
    analyzer = {"format": FORMAT_ANALYZER, "source_sha256": source}
    document = _parse(body)
    if document is None and len(body) > MAX_YAML_BYTES:
        raise CatalogFormatError(
            f"catalog is not JSON and larger than {MAX_YAML_BYTES // 2**20} MiB; supply it as JSON"
        )
    if not isinstance(document, dict):
        return body, analyzer
    roots = [r for r in _OSCAL_ROOTS if isinstance(document.get(r), dict) and _is_oscal(document[r])]
    if "categories" in document:
        if roots:
            raise CatalogFormatError("catalog has both `categories` and an OSCAL document; supply only one format")
        return body, analyzer
    if not roots:
        return body, analyzer
    if len(roots) != 1 or not set(document) <= {roots[0], "$schema"}:
        raise CatalogFormatError("OSCAL file holds more than one document")
    if roots[0] != "catalog":
        raise CatalogFormatError(
            f"an OSCAL {roots[0]} is not supported; supply an OSCAL catalog (resolve a profile to a catalog first)"
        )
    return _convert(document["catalog"], source)


def describe(info: dict) -> str | None:
    """One line for the console, or None for the Analyzer's own format."""
    if info.get("format") != FORMAT_OSCAL:
        return None
    return (
        f'OSCAL catalog "{info["title"]}" {info["version"]} (OSCAL {info["oscal_version"]}): '
        f"{info['requirements']} requirements, {info['withdrawn_left_out']} withdrawn left out; "
        "priority MUST assigned to every control (OSCAL has no obligation level)"
    )


def conversion_of(body: bytes) -> dict | None:
    """The conversion record a converted catalog carries, for a catalog read back from the cache."""
    document = _parse(body)
    record = document.get("conversion") if isinstance(document, dict) else None
    if not isinstance(record, dict) or record.get("format") != FORMAT_OSCAL:
        return None
    return _info(
        record.get("title"),
        record.get("version"),
        record.get("oscal_version"),
        str(record.get("source_sha256") or ""),
        record.get("requirements"),
        record.get("withdrawn_left_out"),
    )


def _parse(body: bytes) -> Any:
    """JSON first (fast), then YAML up to its own limit; None when neither applies."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        pass
    if len(body) > MAX_YAML_BYTES:
        return None
    try:
        return yaml.load(text, Loader=_YAML_LOADER)  # noqa: S506 - SafeLoader variant
    except (yaml.YAMLError, RecursionError, ValueError):
        return None


def _is_oscal(root: dict) -> bool:
    metadata = root.get("metadata")
    return isinstance(metadata, dict) and "oscal-version" in metadata


def _clean(value: Any, limit: int = 120) -> str:
    """Single-line text without control characters, for console and report fields."""
    return _CONTROL_CHARS.sub(" ", str(value if value is not None else "")).strip()[:limit]


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _info(title, version, oscal_version, source_sha256, requirements, withdrawn) -> dict:
    return {
        "format": FORMAT_OSCAL,
        "title": _clean(title),
        "version": _clean(version, 40),
        "oscal_version": _clean(oscal_version, 40),
        "source_sha256": source_sha256,
        "requirements": _count(requirements),
        "withdrawn_left_out": _count(withdrawn),
    }


def _items(node: dict, key: str) -> list[dict]:
    value = node.get(key)
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


class _State:
    def __init__(self) -> None:
        self.nodes = 0
        self.chars = 0
        self.controls = 0
        self.withdrawn = 0
        self.ids: set[str] = set()
        self.params: dict[str, dict] = {}
        self.categories: list[dict] = []
        self.category_ids: set[str] = set()

    def tick(self, depth: int, chars: int = 0) -> None:
        if depth > MAX_DEPTH:
            raise CatalogFormatError(f"OSCAL catalog is nested deeper than {MAX_DEPTH} levels")
        self.nodes += 1
        self.chars += chars
        if self.nodes > MAX_NODES or self.chars > MAX_TEXT_CHARS:
            raise CatalogFormatError("OSCAL catalog is too large to convert")


def _convert(catalog: dict, source_sha256: str) -> tuple[bytes, dict]:
    state = _State()
    _walk(catalog, [], 0, state)
    for category in state.categories:
        for requirement in category["requirements"]:
            requirement["text"] = _INSERT.sub(lambda m: _param_text(m.group(1), state, 0), requirement["text"])
    metadata = catalog.get("metadata") if isinstance(catalog.get("metadata"), dict) else {}
    count = sum(len(category["requirements"]) for category in state.categories)
    info = _info(
        metadata.get("title"),
        metadata.get("version"),
        metadata.get("oscal-version"),
        source_sha256,
        count,
        state.withdrawn,
    )
    converted: dict[str, Any] = {"source": FORMAT_OSCAL}
    if modified := _clean(metadata.get("last-modified") or ""):
        converted["generated"] = modified
    converted["description"] = (
        f"{info['title']} {info['version']} (OSCAL {info['oscal_version']}), converted by Analyzer; "
        "every control has priority MUST"
    )
    converted["categories"] = state.categories
    converted["conversion"] = dict(info)
    body = yaml.safe_dump(converted, sort_keys=False, allow_unicode=True, width=120).encode("utf-8")
    return body, info


def _walk(node: dict, titles: list[str], depth: int, state: _State) -> None:
    """Take ``node``'s own controls as one category, then recurse into its groups."""
    state.tick(depth)
    for param in _items(node, "params"):
        if isinstance(param.get("id"), str):
            state.params.setdefault(param["id"], param)
    requirements: list[dict] = []
    for control in _items(node, "controls"):
        _control(control, 0, state, requirements)
    if requirements:
        title = " / ".join(t for t in titles if t) or "Controls"
        base = _clean(node.get("id") or "") or _slug(title) or f"group-{len(state.categories) + 1}"
        state.categories.append({"id": _unique(base, state.category_ids), "title": title, "requirements": requirements})
    for group in _items(node, "groups"):
        label = _clean(group.get("title") or group.get("id") or "")
        _walk(group, [*titles, label], depth + 1, state)


def _control(control: dict, depth: int, state: _State, out: list[dict]) -> None:
    state.tick(depth)
    for param in _items(control, "params"):
        if isinstance(param.get("id"), str):
            state.params.setdefault(param["id"], param)
    state.controls += 1
    if state.controls > MAX_CONTROLS:
        raise CatalogFormatError(f"OSCAL catalog has more than {MAX_CONTROLS} controls")
    identifier = _clean(control.get("id") or "", 200)
    if not identifier:
        raise CatalogFormatError("an OSCAL control has no id")
    if identifier in state.ids:
        raise CatalogFormatError(f"OSCAL control id {identifier} appears more than once")
    state.ids.add(identifier)
    if any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in _items(control, "props")):
        state.withdrawn += 1
    else:
        title = _clean(control.get("title") or "", 300)
        statement = next((p for p in _items(control, "parts") if p.get("name") == "statement"), None)
        text = _part_text(statement, 0, state) if statement else ""
        out.append({"id": identifier, "title": title, "text": text or title, "priority": "MUST"})
    for child in _items(control, "controls"):
        _control(child, depth + 1, state, out)


def _part_text(part: dict, depth: int, state: _State) -> str:
    """Prose of a part and its items on one line, each item led by its label."""
    prose = part.get("prose")
    prose = " ".join(prose.split()) if isinstance(prose, str) else ""
    state.tick(depth, len(prose))
    pieces = [prose] if prose else []
    pieces += [t for t in (_part_text(child, depth + 1, state) for child in _items(part, "parts")) if t]
    text = " ".join(pieces)
    label = next((_clean(p.get("value"), 20) for p in _items(part, "props") if p.get("name") == "label"), "")
    return f"{label} {text}" if label and text and depth > 0 else text


def _param_text(parameter_id: str, state: _State, depth: int) -> str:
    """The parameter's value, or an open slot naming what has to be chosen or assigned."""
    param = state.params.get(parameter_id)
    values = param.get("values") if param else None
    select = param.get("select") if param else None
    choices = select.get("choice") if isinstance(select, dict) else None
    if param is None:
        text = f"[Assignment: {parameter_id}]"
    elif isinstance(values, list) and (given := [str(v) for v in values if isinstance(v, str | int | float)]):
        text = ", ".join(given)
    elif isinstance(choices, list) and (options := [" ".join(c.split()) for c in choices if isinstance(c, str)]):
        many = " (one or more)" if select.get("how-many") == "one-or-more" else ""
        text = f"[Selection{many}: {'; '.join(options)}]"
    else:
        text = f"[Assignment: {' '.join(str(param.get('label') or parameter_id).split())}]"
    # Parameters may refer to each other; every expansion is charged to the same budget as the walk.
    state.tick(0, len(text))
    if depth < MAX_PARAM_DEPTH:
        text = _INSERT.sub(lambda m: _param_text(m.group(1), state, depth + 1), text)
    return text


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def _unique(base: str, used: set[str]) -> str:
    candidate, number = base, 2
    while candidate in used:
        candidate = f"{base}-{number}"
        number += 1
    used.add(candidate)
    return candidate
