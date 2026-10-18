"""Lossless structured JSON projection for Codex's strict output schema.

Optional values carry explicit presence, and dynamic object members use entry
arrays. No JSON document is hidden inside an unconstrained output string.
Canonical validation remains with the assessment controller.
"""

from __future__ import annotations

import json

from jsonschema import Draft202012Validator


def _object(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def _entries(value):
    return {"type": "array", "items": _object({"key": {"type": "string"}, "value": value})}


class CodexSchema:
    def __init__(self, canonical):
        self.definitions, self.plans, self.memo, self.resources, self.nodes = {}, {}, {}, {}, []
        self._index(canonical)
        generic = {"$ref": "#/$defs/json_value"}
        self.definitions["json_value"] = {
            "anyOf": [
                {"type": ["string", "number", "boolean", "null"]},
                {"type": "array", "items": generic},
                _object({"entries": _entries(generic)}),
            ]
        }
        self.plans["json_value"] = ("generic", None)
        payload = self._compile(canonical, canonical)
        self.schema = {**_object({"payload": payload}), "$defs": self.definitions}
        Draft202012Validator.check_schema(self.schema)
        self.validator = Draft202012Validator(self.schema)

    def _index(self, node, depth=0):
        if depth > 64:
            raise ValueError("Codex schema exceeds depth limit")
        if isinstance(node, dict):
            if "$id" in node:
                self.resources[node["$id"]] = node
            for value in node.values():
                self._index(value, depth + 1)
        elif isinstance(node, list):
            for value in node:
                self._index(value, depth + 1)

    def _resolve(self, reference, resource):
        uri, _, fragment = reference.partition("#")
        target = self.resources.get(uri) if uri else resource
        if target is None or (fragment and not fragment.startswith("/")):
            raise ValueError("Unavailable Codex schema reference")
        value = target
        if fragment:
            for key in fragment[1:].split("/"):
                key = key.replace("~1", "/").replace("~0", "~")
                value = value[int(key)] if isinstance(value, list) else value[key]
        return value, target

    def _compile(self, node, resource, depth=0):
        if depth > 64 or len(self.definitions) > 5000:
            raise ValueError("Codex schema exceeds complexity limit")
        if node is False:
            raise ValueError("Unsatisfiable Codex schema")
        if node is True or not node:
            return {"$ref": "#/$defs/json_value"}
        if "$id" in node:
            resource = node
        key = (id(node), id(resource))
        if key in self.memo:
            return {"$ref": "#/$defs/" + self.memo[key]}
        name = f"n{len(self.memo)}"
        self.memo[key] = name
        self.nodes.append(node)  # Keep synthesized union nodes alive for memo identities.
        self.definitions[name] = {}
        ref = {"$ref": "#/$defs/" + name}
        if "$ref" in node:
            target, owner = self._resolve(node["$ref"], resource)
            child = self._compile(target, owner, depth + 1)
            wire, plan = child, ("alias", child)
        elif "anyOf" in node or "oneOf" in node:
            children = [self._compile(child, resource, depth + 1) for child in node.get("anyOf", node.get("oneOf"))]
            wire, plan = {"anyOf": children}, ("union", children)
        else:
            kind = node.get("type")
            if kind is None and "properties" in node:
                kind = "object"
            if kind is None and ("const" in node or "enum" in node):
                values = [node["const"]] if "const" in node else node["enum"]
                names = {
                    type(v): t
                    for v, t in [(None, "null"), (False, "boolean"), (0, "integer"), (0.0, "number"), ("", "string")]
                }
                kinds = {names.get(type(v)) for v in values}
                if None not in kinds:
                    kind = next(iter(kinds)) if len(kinds) == 1 else sorted(kinds)
            if isinstance(kind, list) and any(t in kind for t in ("object", "array")):
                children = [self._compile({**node, "type": t}, resource, depth + 1) for t in kind]
                wire, plan = {"anyOf": children}, ("union", children)
            elif kind == "object":
                properties, children = {}, {}
                required = set(node.get("required", ()))
                for field, child in node.get("properties", {}).items():
                    compiled = self._compile(child, resource, depth + 1)
                    optional = field not in required
                    properties[field] = (
                        {
                            "anyOf": [
                                _object({"present": {"type": "boolean", "enum": [False]}}),
                                _object({"present": {"type": "boolean", "enum": [True]}, "value": compiled}),
                            ]
                        }
                        if optional
                        else compiled
                    )
                    children[field] = (compiled, optional)
                extra = None
                if node.get("additionalProperties", True) is not False or node.get("patternProperties"):
                    extra = "__extra"
                    while extra in properties:
                        extra += "_"
                    additional = True if node.get("patternProperties") else node.get("additionalProperties", True)
                    compiled = self._compile(additional, resource, depth + 1)
                    properties[extra] = _entries(compiled)
                    extra = (extra, compiled)
                wire, plan = _object(properties), ("object", (children, extra))
            elif kind == "array":
                child = self._compile(node.get("items", True), resource, depth + 1)
                wire = {"type": "array", "items": child}
                wire.update({k: node[k] for k in ("minItems", "maxItems") if k in node})
                plan = ("array", child)
            elif kind is not None:
                wire = {
                    k: node[k]
                    for k in (
                        "type",
                        "enum",
                        "pattern",
                        "format",
                        "minLength",
                        "maxLength",
                        "minimum",
                        "maximum",
                        "multipleOf",
                    )
                    if k in node
                }
                wire["type"] = kind
                if "const" in node:
                    wire["enum"] = [node["const"]]
                plan = ("scalar", None)
            else:
                wire, plan = {"$ref": "#/$defs/json_value"}, ("generic", None)
        if "description" in node:
            wire = {**wire, "description": node["description"]}
        self.definitions[name], self.plans[name] = wire, plan
        return ref

    def decode(self, wire):
        if not self.validator.is_valid(wire):
            raise ValueError("Codex response violates its structured wire schema")
        return self._decode(self.schema["properties"]["payload"], wire["payload"])

    def _decode(self, ref, value, depth=0):
        if depth > 64:
            raise ValueError("Codex response exceeds nesting limit")
        kind, plan = self.plans[ref["$ref"].rsplit("/", 1)[1]]
        if kind == "scalar":
            return value
        if kind == "alias":
            return self._decode(plan, value, depth + 1)
        if kind == "array":
            return [self._decode(plan, v, depth + 1) for v in value]
        if kind == "union":
            candidates = []
            for child in plan:
                validator = Draft202012Validator({**child, "$defs": self.definitions})
                if validator.is_valid(value):
                    candidates.append(self._decode(child, value, depth + 1))
            if not candidates or len({json.dumps(v, sort_keys=True, allow_nan=False) for v in candidates}) != 1:
                raise ValueError("Ambiguous Codex wire union")
            return candidates[0]
        if kind == "generic":
            if isinstance(value, list):
                return [self._decode({"$ref": "#/$defs/json_value"}, v, depth + 1) for v in value]
            if not isinstance(value, dict):
                return value
            return self._decode_entries(value["entries"], {"$ref": "#/$defs/json_value"}, {}, depth)
        children, extra = plan
        decoded = {}
        for field, (child, optional) in children.items():
            member = value[field]
            if optional:
                if not member["present"]:
                    continue
                member = member["value"]
            decoded[field] = self._decode(child, member, depth + 1)
        if extra:
            field, child = extra
            if any(entry["key"] in children for entry in value[field]):
                raise ValueError("Duplicate Codex declared object member")
            return self._decode_entries(value[field], child, decoded, depth)
        return decoded

    def _decode_entries(self, entries, child, decoded, depth):
        for entry in entries:
            if entry["key"] in decoded:
                raise ValueError("Duplicate Codex object member")
            decoded[entry["key"]] = self._decode(child, entry["value"], depth + 1)
        return decoded
