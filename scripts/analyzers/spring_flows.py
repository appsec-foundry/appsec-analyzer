"""Preserve source-evidenced Spring authentication methods in architecture flows."""

from __future__ import annotations

import copy
import hashlib


def reconcile(components: list[dict], document: dict, inventories: dict, repositories: dict) -> dict:
    """Add omitted credential alternatives; preserve authored flows and admitted ownership."""
    result = copy.deepcopy(document)
    flows = result.setdefault("data_flows", [])
    entities = result.setdefault("external_entities", [])
    accesses = {}
    for component in components:
        owned = {(p["repository_id"], p["path"]) for p in component["paths"]}
        for rid, inventory in inventories.items():
            for route in inventory.get("routes", []):
                if route.get("framework") != "spring" or (rid, route.get("handler_file")) not in owned:
                    continue
                if route.get("authn_handler_signal") != "verified" or route.get("authn_signal") not in {
                    "present",
                    "middleware_present",
                    "decorator_present",
                }:
                    continue
                for method in route.get("authentication_methods") or []:
                    if method in {"basic", "cookie", "bearer", "password"}:
                        accesses.setdefault((rid, component["id"], method), route)
    for (rid, target, method), route in accesses.items():
        if any(f.get("to") == target and (f.get("authentication") or {}).get("scheme") == method for f in flows):
            continue
        sources = repositories.get(rid, {})
        refs = [
            {"file": route["handler_file"], "line": route["handler_line"]},
            *(route.get("authn_handler_evidence") or []),
        ]
        evidence = []
        for ref in refs:
            file, line = ref.get("file"), ref.get("line")
            if file not in sources or not isinstance(line, int) or not 1 <= line <= len(sources[file].splitlines()):
                continue
            qualified = {
                "repository_id": rid,
                "file": file,
                "line": line,
                "sha256": hashlib.sha256(sources[file]).hexdigest(),
            }
            if qualified not in evidence:
                evidence.append(qualified)
        # Both the handler and its configured enforcement must be admitted.
        if len(evidence) < 2 or evidence[0]["file"] != route["handler_file"]:
            continue
        identity = "ext-spring-client-" + hashlib.sha256(rid.encode()).hexdigest()[:12]
        existing = next((e for e in entities if e["id"] == identity), None)
        if existing is None:
            entities.append(
                {
                    "id": identity,
                    "kind": "legitimate-role",
                    "name": "User",
                    "description": "A caller presenting credentials to Spring Security; permissions remain specific to each route.",
                    "access": "internet-user",
                    "evidence": evidence[:8],
                }
            )
        flows.append(
            {
                "id": f"df-{len(flows) + 1:03d}",
                "from": "external",
                "from_entity": identity,
                "to": target,
                "label": f"{route['method']} {route['path']}; payload classification and deployment transport are unverified",
                "diagram_label": {
                    "basic": "HTTP Basic request",
                    "cookie": "Session request",
                    "bearer": "Bearer request",
                    "password": "Login credentials",
                }[method],
                "protocol": "HTTP",
                "direction": "request-response",
                "provenance": "route-extraction",
                "data_classification": "Internal",
                "evidence": evidence[:8],
                "authentication": {
                    "scheme": method,
                    "scope": route.get("authn_handler_scope")
                    or "The configured Spring Security chain requires an authenticated caller",
                    "evidence": evidence[1:8],
                },
            }
        )
    return result
