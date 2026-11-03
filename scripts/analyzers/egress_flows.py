"""Retain observed outbound calls the architecture model omitted.

The controller supplies complete scanner observations from its frozen source
scope. Existing authored destinations and reviewed internal connections take
precedence. No endpoint is fetched, and no authentication or activation is
inferred. Model context limits do not remove these source observations.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
from collections import defaultdict


def _anchor(evidence: dict) -> tuple:
    return evidence.get("repository_id"), evidence.get("file"), evidence.get("line")


def destination_key(row: dict, owner: str | None = None) -> str:
    identity = [row.get(key) for key in ("kind", "host", "scheme", "port", "destination_id", "transport")]
    if not row.get("host"):
        identity.append(owner)
        identity.append(sorted({e.get("repository_id", "") for e in row.get("evidence") or []}))
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:20]


def _owner(evidence: dict, components: list[dict]) -> str | None:
    owners = set()
    for component in components:
        for entry in component.get("paths") or []:
            path = entry if isinstance(entry, str) else entry.get("path", "")
            repository = None if isinstance(entry, str) else entry.get("repository_id")
            if repository == evidence.get("repository_id") and fnmatch.fnmatchcase(evidence["file"], path):
                owners.add(component["id"])
    if len(owners) > 1:
        raise ValueError("Outbound call has ambiguous component ownership")
    return next(iter(owners), None)


def _covering(row, owner, evidence, flows, entities, anchors):
    cited = {_anchor(e) for e in evidence}
    for flow in flows:
        if flow.get("from") != owner or not cited & {_anchor(e) for e in flow.get("evidence") or []}:
            continue
        if flow.get("to") != "external":
            if flow.get("connection_id") and all(len(anchors[a]) == 1 for a in cited):
                return flow
            continue
        entity = entities.get(flow.get("to_entity"))
        if entity and entity.get("kind") == "legitimate-role":
            continue
        if flow.get("to_entity") == "ext-outbound-" + destination_key(row, owner):
            return flow
        # One line can call several services. An arbitrary flow on that line cannot cover them all.
        shared = cited & {_anchor(e) for e in flow.get("evidence") or []}
        if all(len(anchors[a]) == 1 for a in shared):
            return flow
        name = (row.get("host") or "") + (f":{row['port']}" if row.get("port") else "")
        if row.get("host") and entity and name == entity.get("name"):
            return flow
    return None


def reconcile(components: list[dict], document: dict, destinations: list[dict]) -> dict:
    """Fill omitted source-observed destinations, preserving authored flows and evidence."""
    result = copy.deepcopy(document)
    entities = result.setdefault("external_entities", [])
    flows = result.setdefault("data_flows", [])
    by_id = {row["id"]: row for row in entities}
    anchors = defaultdict(set)
    for row in destinations:
        for evidence in row["evidence"]:
            anchors[_anchor(evidence)].add(destination_key(row))
    for row in destinations:
        owned = defaultdict(list)
        for evidence in row["evidence"]:
            if owner := _owner(evidence, components):
                owned[owner].append(evidence)
        for owner, evidence in sorted(owned.items()):
            existing = _covering(row, owner, evidence, flows, by_id, anchors)
            if existing and existing.get("to_entity"):
                continue
            if existing and existing.get("to") != "external":
                continue
            entity_id = "ext-outbound-" + destination_key(row, owner)
            if entity_id in by_id and by_id[entity_id].get("kind") != "external-service":
                raise ValueError("Outbound destination identifier conflicts with an authored entity")
            if entity_id not in by_id:
                host = row.get("host")
                name = (
                    (host + (f":{row['port']}" if row.get("port") else ""))
                    if host
                    else ("Configured service " if row["kind"] == "configured" else "Request-selected service ")
                    + destination_key(row)[:8]
                )
                entity = {
                    "id": entity_id,
                    "name": name[:80],
                    "kind": "external-service",
                    "description": "Outbound destination observed at a client call. Deployment activation, payload sensitivity and authentication require assessment.",
                    "evidence": copy.deepcopy(evidence[:8]),
                }
                entities.append(entity)
                by_id[entity_id] = entity
                if len(entities) > 64:
                    raise ValueError("Observed outbound destinations exceed the architecture contract's capacity")
            if existing:
                existing["to_entity"] = entity_id
                continue
            protocol = (
                row.get("scheme", "").upper()
                or {"http": "HTTP(S)", "websocket": "WebSocket", "rpc": "RPC"}[row["transport"]]
            )
            number = 1 + max((int(f["id"][3:]) for f in flows if str(f.get("id", ""))[3:].isdigit()), default=0)
            flows.append(
                {
                    "id": f"df-{number:03d}",
                    "from": owner,
                    "to": "external",
                    "to_entity": entity_id,
                    "label": "Outbound client request; deployment activation and payload sensitivity unverified",
                    "diagram_label": "Outbound request",
                    "protocol": protocol,
                    "data_classification": "Internal",
                    "direction": "request-response",
                    "evidence": copy.deepcopy(evidence[:8]),
                    "provenance": "recon",
                }
            )
            if len(flows) > 500:
                raise ValueError("Observed outbound destinations exceed the architecture contract's capacity")
    if len(entities) > 64 or len(flows) > 500:
        raise ValueError("Observed outbound destinations exceed the architecture contract's capacity")
    return result


def uncovered(destinations: list[dict], components: list[dict], document: dict) -> list[dict]:
    """Destinations without a matching owner's flow and call-site evidence, for legacy diagnostics."""
    flows = document.get("data_flows") or []
    by_id = {e["id"]: e for e in document.get("external_entities") or []}
    anchors = defaultdict(set)
    for row in destinations:
        for evidence in row.get("evidence") or []:
            anchors[_anchor(evidence)].add(destination_key(row))
    missing = []
    for row in destinations:
        owned = defaultdict(list)
        for evidence in row.get("evidence") or []:
            owner = _owner(evidence, components)
            owned[owner].append(evidence)
        for owner, evidence in owned.items():
            if owner is None or not _covering(row, owner, evidence, flows, by_id, anchors):
                missing.append({**row, "evidence": evidence, "component_id": owner})
    return missing
