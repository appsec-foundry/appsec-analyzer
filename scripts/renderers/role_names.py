"""One name per legitimate role, shared by the report, the canonical YAML and the exports.

A regular role is "<project> User", or "<project> Visitor" when the code shows it
only without an account and self-registration is closed. A role whose access the
code does not establish is a User as well. A privileged role is "<project> Admin".
A combined assessment names no product, so its roles carry no prefix. A role the
owner declared keeps its declared name.

Privileged roles never share a card (RA-11). When there are several, each keeps
its authored name as a qualifier: "<project> Admin (Support)". Regular roles that
end with one name are one population and share one card, and the sender of a flow
without `from_entity` is the role "<project> User". Any other name that two cards
would share is numbered, so no two cards carry one name.

Names derive from access, project and declaration, and a qualifier is read back
from an earlier result, so applying the names twice changes nothing.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import collections
import re
from functools import cache
from pathlib import Path

import yaml

GENERIC_USER = "actor:user"
PRIVILEGED = "internet-priv-user"
# `external_entities[].name` in the output schema.
MAX_NAME = 80
_ADMIN_WORDS = frozenset({"admin", "admins", "administrator", "administrators"})
# Holders of a name that a further regular role joins instead of numbering it.
_SHAREABLE = ("regular", "declared")


@cache
def vocabulary() -> dict:
    """Role nouns and subtitles from the vocabulary the attacker labels use."""
    path = Path(__file__).resolve().parents[2] / "data/posture-actor-labels.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))["actors"]


def _meta(data) -> dict:
    return data.get("meta") if isinstance(data.get("meta"), dict) else {}


def project_name(data) -> str | None:
    meta = _meta(data)
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    legacy = (
        meta.get("project")
        if isinstance(meta.get("project"), str)
        else (meta.get("project") or {}).get("name")
        if isinstance(meta.get("project"), dict)
        else None
    )
    return project.get("name") or data.get("project_name") or meta.get("project_name") or legacy


def prefix(data) -> str:
    """The product name in front of a role, or "" when the system name covers several repositories.

    A combined assessment's system name ("Combined system (N repositories)" by
    default) names no user population.
    """
    sources = _meta(data).get("source_repositories")
    if isinstance(sources, list) and len(sources) > 1:
        return ""
    return " ".join(str(project_name(data) or "").split())


def _fit(text: str) -> str:
    return text if len(text) <= MAX_NAME else text[: MAX_NAME - 1].rstrip() + "…"


def _named(data, noun: str) -> str:
    return _fit(" ".join(part for part in (prefix(data), noun) if part))


def regular_name(data, access) -> str:
    """A regular role's name by its access class; a User when the code establishes none."""
    entry = vocabulary().get(access) or vocabulary()["internet-user"]
    noun = entry["legitimate_role_noun"]
    if access == "internet-anon" and _meta(data).get("open_user_registration") is True:
        noun = entry.get("open_registration_role_noun") or noun
    return _named(data, noun)


def regular_subtitle(data, access) -> str:
    """The card subtitle for regular roles that share one card."""
    if _meta(data).get("open_user_registration") is True and access in ("internet-anon", "internet-user", None):
        return vocabulary()["internet-anon"]["open_registration_role_subtitle"]
    return (vocabulary().get(access) or {}).get("legitimate_role_subtitle") or "legitimate client"


def _qualifier(name, base: str, project: str) -> str:
    """What sets one privileged role apart, from its authored name or an earlier result."""
    text = " ".join(str(name or "").split())
    earlier = re.fullmatch(rf"{re.escape(base)}(?: \((.+)\))?(?: \d+)?", text)
    if earlier:
        text = earlier.group(1) or ""
    elif project and text.casefold().startswith(project.casefold() + " "):
        text = text[len(project) + 1 :]
    return "" if text.casefold() in _ADMIN_WORDS else text


def _qualified(base: str, qualifier: str) -> str:
    if not qualifier:
        return base
    room = MAX_NAME - len(base) - 3
    if room < 2:
        return base
    if len(qualifier) > room:
        qualifier = qualifier[: room - 1].rstrip() + "…"
    return f"{base} ({qualifier})"


def _numbered(name: str, owner: dict, kind: str) -> str:
    """The first free numbered name; a regular role may share one that regular roles hold."""
    number = 2
    while True:
        suffix = f" {number}"
        candidate = name[: MAX_NAME - len(suffix)].rstrip() + suffix
        if candidate not in owner or (kind == "regular" and owner[candidate] in _SHAREABLE):
            return candidate
        number += 1


def role_entities(data) -> list[dict]:
    return [
        e
        for e in data.get("external_entities") or []
        if isinstance(e, dict) and isinstance(e.get("id"), str) and e["id"] and e.get("kind") == "legitimate-role"
    ]


def role_names(data) -> dict[str, str]:
    """The name of each legitimate role by id, and under GENERIC_USER that of the unnamed sender.

    Regular roles may share a name, which makes them one card; a declared regular
    role may host that card. Every other repeated name is numbered: declared names
    are the owner's decision and keep their spelling, so a derived name yields.
    """
    entries = role_entities(data)
    project = prefix(data)
    base = _named(data, vocabulary()[PRIVILEGED]["legitimate_role_noun"])
    admins = [e for e in entries if e.get("access") == PRIVILEGED and not e.get("declared")]
    wanted, kinds = {}, {}
    for entity in entries:
        key = entity["id"]
        privileged = entity.get("access") == PRIVILEGED
        if entity.get("declared"):
            wanted[key] = _fit(" ".join(str(entity.get("name") or key).split()))
            kinds[key] = "other" if privileged else "declared"
        elif privileged:
            qualifier = _qualifier(entity.get("name"), base, project) if len(admins) > 1 else ""
            wanted[key] = _qualified(base, qualifier)
            kinds[key] = "other"
        else:
            wanted[key] = regular_name(data, entity.get("access"))
            kinds[key] = "regular"
    wanted[GENERIC_USER], kinds[GENERIC_USER] = regular_name(data, None), "regular"
    order = [e["id"] for e in entries if e.get("declared")]
    order += [e["id"] for e in entries if not e.get("declared")] + [GENERIC_USER]
    names, owner = {}, {}
    for key in order:
        name, kind = wanted[key], kinds[key]
        held = owner.get(name)
        if held is not None and not (kind == "regular" and held in _SHAREABLE):
            name = _numbered(name, owner, kind)
        owner.setdefault(name, kind)
        names[key] = name
    return names


def apply_role_names(data) -> None:
    """Write each legitimate role's name into the model; identities stay as they are."""
    names = role_names(data)
    for entity in role_entities(data):
        entity["name"] = names[entity["id"]]


def card_aliases(data) -> dict[str, str]:
    """Regular role id → the id of the card that draws it, for roles that share a name.

    A declared role hosts the card it names; otherwise the smallest id does. The
    unnamed sender joins the card that carries its name under GENERIC_USER.
    """
    names = role_names(data)
    groups = collections.defaultdict(list)
    for entity in role_entities(data):
        if entity.get("access") != PRIVILEGED:
            groups[names[entity["id"]]].append(entity)
    aliases = {}
    for name, rows in groups.items():
        declared = [row["id"] for row in rows if row.get("declared")]
        host = declared[0] if declared else min(row["id"] for row in rows)
        aliases.update({row["id"]: host for row in rows if row["id"] != host and not row.get("declared")})
        if name == names[GENERIC_USER]:
            aliases[GENERIC_USER] = host
    return aliases
