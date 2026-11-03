#!/usr/bin/env python3
"""Find outbound HTTP, WebSocket and RPC calls without executing repository code.

Bounded lexical analysis follows local URL assignments and standard client
instances. Only destination arguments count; unused configuration, headers,
payloads and comments do not establish destinations. Observations do not
prove deployment activation, authentication or an exploitable weakness.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import argparse
import bisect
import hashlib
import json
import re
from itertools import islice
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from shared._source_lex import code_only, without_comments

from analyzers.recon_patterns import _walk_repo

_CODE_EXTS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".vue",
    ".svelte",
    ".py",
    ".go",
    ".rb",
    ".php",
    ".java",
    ".kt",
    ".cs",
}
_MAX_LINE_CHARS = 2000
_MAX_CALL_CHARS = 8192
_MAX_CALLS = 4096
_MAX_BINDINGS = 1024
_MAX_RESOLUTION_DEPTH = 4
_NAME = r"(?:(?:self|this)\.)?[A-Za-z_$][\w$]*"
_ASSIGN = re.compile(rf"(?<![\w$.])(?P<name>{_NAME})\s*(?::\s*[\w<>\[\]|.? ]{{1,80}})?\s*(?::=|=(?!=|>))")
_LITERAL = re.compile(r"""(?:[frbuFRBU]{0,2})(["'`])((?:\\.|(?!\1)[\s\S])*?)\1""")
_CONFIG = re.compile(
    r"\bprocess\.env(?:\[|\.(?!(?:REACT_APP|VUE_APP|NEXT_PUBLIC|NUXT_PUBLIC|VITE|GATSBY|EXPO_PUBLIC)_))"
    r"|\bos\.(?:environ|getenv|Getenv)\b|\bENV(?:\[|\.fetch\b)|\bgetenv\s*\("
    r"|\$_ENV\b|\bconfig(?:\.get\b|\[)|\bsettings\.[A-Z]"
    r"|\b(?:System\.getenv|Environment\.GetEnvironmentVariable)\s*\("
)
_REQUEST = re.compile(
    r"\b(?:req|request|ctx\.request)\.(?:body|query|params|args|form|values|json|GET|POST|get_json)\b|\$_(?:GET|POST|REQUEST)\b"
)
_LOCAL = re.compile(
    r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|host\.docker\.internal)$"
    r"|\.(?:local|localhost|test|invalid)$|(?:^|\.)example\.(?:com|org|net)$"
)
_CALLS = (
    (
        "rpc-provider",
        "rpc",
        r"\bnew\s+(?:ethers\.)?(?:providers\.)?(?:JsonRpc|WebSocket|Infura|Alchemy)Provider\s*\(",
        0,
    ),
    ("web3", "rpc", r"\bnew\s+Web3\s*\(", 0),
    ("websocket", "websocket", r"\bnew\s+WebSocket\s*\(|\bwebsockets?\.connect\s*\(", 0),
    ("fetch", "http", r"(?<![\w.$])fetch\s*\(", 0),
    ("axios", "http", r"\baxios(?:\.(?:get|post|put|patch|delete|head|options|request))?\s*\(", 0),
    ("got", "http", r"(?<![\w.$])got(?:\.(?:get|post|put|patch|delete))?\s*\(", 0),
    ("node-http", "http", r"(?<![\w.$])https?\.(?:get|request)\s*\(", 0),
    ("requests", "http", r"\brequests\.(?:get|post|put|patch|delete|head|options)\s*\(", 0),
    ("requests", "http", r"\brequests\.request\s*\(", 1),
    ("httpx", "http", r"\bhttpx\.(?:get|post|put|patch|delete)\s*\(", 0),
    ("httpx", "http", r"\bhttpx\.(?:request|stream)\s*\(", 1),
    ("urlopen", "http", r"\burlopen\s*\(", 0),
    ("go-http", "http", r"\bhttp\.(?:Get|Post|Head)\s*\(", 0),
    ("go-http", "http", r"\bhttp\.NewRequest\s*\(", 1),
    ("go-http", "http", r"\bhttp\.NewRequestWithContext\s*\(", 2),
    ("ruby-http", "http", r"\bNet::HTTP\.(?:get|get_response|post|post_form)\s*\(", 0),
    ("php-http", "http", r"\b(?:curl_init|file_get_contents)\s*\(", 0),
)
_CALL_RES = tuple((name, transport, re.compile(pattern), arg) for name, transport, pattern, arg in _CALLS)
_INSTANCE_CALL = re.compile(
    rf"(?<![\w$.])(?P<name>{_NAME})\s*\.\s*(?P<method>get|post|put|patch|delete|head|options|request|stream|"
    r"GetAsync|PostAsync|PutAsync|DeleteAsync|GetStringAsync|getForObject|getForEntity|postForObject|postForEntity)\s*\("
)


def _arguments(code: str, opening: int) -> list[tuple[int, int]]:
    """Argument offsets of a balanced, bounded call or object, with strings masked."""
    stack, spans, start = [code[opening]], [], opening + 1
    pairs = {")": "(", "]": "[", "}": "{"}
    for i in range(start, min(len(code), opening + _MAX_CALL_CHARS)):
        char = code[i]
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != pairs[char]:
                return []
            if not stack:
                return [*spans, (start, i)]
        elif char == "," and len(stack) == 1:
            spans.append((start, i))
            start = i + 1
    return []


def _expression_end(code: str, start: int) -> int:
    stack = []
    for i in range(start, min(len(code), start + _MAX_CALL_CHARS)):
        char = code[i]
        if not stack and char in ";\n,)}":
            return i
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack:
                return i
            stack.pop()
    return min(len(code), start + _MAX_CALL_CHARS)


def _field(expression: str, fields: tuple[str, ...]) -> str | None:
    masked = code_only(expression)
    opening = masked.find("{")
    if opening < 0:
        return None
    for start, end in _arguments(masked, opening):
        item = expression[start:end]
        match = re.match(r"\s*['\"]?(\w+)['\"]?\s*:\s*", item)
        if match and match[1] in fields:
            return item[match.end() :].strip()
    return None


class _Source:
    def __init__(self, text: str, suffix: str):
        self.text = without_comments(text, python=suffix in {".py", ".rb"})
        self.text = "\n".join(row if len(row) <= _MAX_LINE_CHARS else " " * len(row) for row in self.text.split("\n"))
        self.code = code_only(self.text)
        self.lines = [i for i, char in enumerate(self.text) if char == "\n"]
        self.scope_offsets, self.scope_ids, self.parents = [-1], [0], {0: None}
        stack = [0]
        self.scope_limit = len(self.code)
        for offset, char in enumerate(self.code):
            if char not in "{}":
                continue
            if len(self.parents) >= 8192:
                self.scope_limit = offset
                break
            if char == "{":
                scope = len(self.parents)
                self.parents[scope] = stack[-1]
                stack.append(scope)
            elif len(stack) > 1:
                stack.pop()
            self.scope_offsets.append(offset)
            self.scope_ids.append(stack[-1])
        self.bindings: dict[str, list[tuple[int, str]]] = {}
        self.types = {}
        for client, pattern in (
            ("angular-http", rf"\b(?P<name>{_NAME})\s*:\s*HttpClient\b"),
            ("spring-http", rf"\b(?:RestTemplate|RestOperations|WebClient)\s+(?P<name>{_NAME})\b"),
            ("dotnet-http", rf"\bHttpClient\s+(?P<name>{_NAME})\b"),
        ):
            for match in islice(re.finditer(pattern, self.code), _MAX_BINDINGS):
                self.types.setdefault(match["name"], []).append((match.start(), client))
        for count, match in enumerate(_ASSIGN.finditer(self.code)):
            if count >= _MAX_BINDINGS:
                break
            start = match.end()
            while start < len(self.text) and self.text[start].isspace():
                start += 1
            expression = self.text[start : _expression_end(self.code, start)].strip()
            if expression:
                self.bindings.setdefault(match["name"], []).append((match.start(), expression))

    def value(self, name: str, at: int) -> tuple[int, str] | None:
        return next(
            (row for row in reversed(self.bindings.get(name, [])) if row[0] < at and self.visible(row[0], at)), None
        )

    def visible(self, declared: int, at: int) -> bool:
        if max(declared, at) >= self.scope_limit:
            return False
        wanted = self.scope_ids[bisect.bisect_right(self.scope_offsets, declared) - 1]
        scope = self.scope_ids[bisect.bisect_right(self.scope_offsets, at) - 1]
        for _ in range(64):
            if scope == wanted:
                return True
            scope = self.parents[scope]
            if scope is None:
                return False
        return False

    def resolve(self, expression: str, at: int, depth: int = 0) -> str:
        expression = expression.strip()
        if depth >= _MAX_RESOLUTION_DEPTH or len(expression) > _MAX_CALL_CHARS:
            return expression
        name = re.match(rf"^(?:f?[\"'`]\$?\{{\s*)?(?P<name>{_NAME})(?![\w$])", expression)
        if name and (binding := self.value(name["name"], at)):
            offset, value = binding
            rest = expression[name.end() :]
            if not rest or re.match(r"\s*(?:\+|\}|$)", rest):
                return self.resolve(value, offset, depth + 1)
        wrapper = re.match(r"^(?:URI|URL|url\.URL|new\s+(?:URI|URL))\s*\(", expression)
        if wrapper:
            spans = _arguments(code_only(expression), wrapper.end() - 1)
            if spans:
                return self.resolve(expression[slice(*spans[0])], at, depth + 1)
        return expression

    def instance(self, name: str, at: int, depth: int = 0) -> tuple[str, str | None] | None:
        if depth >= _MAX_RESOLUTION_DEPTH:
            return None
        binding = self.value(name, at)
        if binding:
            offset, expression = binding
            patterns = (
                ("axios", r"axios\.create\s*\(", ("baseURL",)),
                ("requests", r"requests\.Session\s*\(", ()),
                ("httpx", r"httpx\.(?:AsyncClient|Client)\s*\(", ("base_url",)),
                ("spring-http", r"new\s+RestTemplate\s*\(|WebClient\.(?:create|builder)\s*\(", ("baseUrl",)),
                ("dotnet-http", r"new\s+HttpClient\s*\(", ()),
                ("php-http", r"new\s+(?:\\?GuzzleHttp\\)?Client\s*\(", ("base_uri",)),
            )
            for client, pattern, fields in patterns:
                if re.search(pattern, expression):
                    base = _field(expression, fields) if fields else None
                    if not base and client in {"httpx", "php-http"}:
                        keyword = re.search(r"\b(?:base_url|base_uri)\s*(?:=|=>)\s*([^,)]+)", expression)
                        base = keyword[1] if keyword else None
                    if not base and client == "spring-http":
                        literal = next(_LITERAL.finditer(expression), None)
                        base = literal[0] if literal else None
                    return client, self.resolve(base, offset) if base else None
            if re.fullmatch(_NAME, expression):
                return self.instance(expression, offset, depth + 1)
        for offset, client in reversed(self.types.get(name.removeprefix("this."), [])):
            if offset < at and self.visible(offset, at):
                return client, None
        return None


def _destination(expression: str, source: _Source, at: int, base: str | None = None, depth: int = 0) -> dict | None:
    if depth >= _MAX_RESOLUTION_DEPTH:
        return None
    resolved = source.resolve(expression, at)
    literal = _LITERAL.match(resolved)
    if literal:
        url = literal[2]
        if re.match(r"^(?:https?|wss?)://", url):
            try:
                parsed = urlsplit(re.split(r"\$\{|\{", url, maxsplit=1)[0])
                host = (parsed.hostname or "").lower()
                port = parsed.port
            except ValueError:
                return None
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host) or _LOCAL.search(host):
                return None
            if port is not None and not 1 <= port <= 65535:
                return None
            result = {"kind": "fixed-host", "host": host, "scheme": parsed.scheme}
            if port is not None:
                result["port"] = port
            return result
        if url.startswith("/") and not url.startswith("//"):
            return _destination(base, source, at) if base else None
    if _REQUEST.search(resolved):
        kind = "user-controlled"
    elif _CONFIG.search(resolved):
        kind = "configured"
    else:
        return None
    fallback = re.search(r"\|\||\bor\b|\?\?", resolved)
    if fallback and (default := _destination(resolved[fallback.end() :], source, at, depth=depth + 1)):
        return default
    if fallback and re.search(r"['\"]https?://(?:localhost|127\.|0\.0\.0\.0)", resolved[fallback.end() :]):
        return None
    identity = re.sub(r"\s+", "", resolved)
    return {"kind": kind, "host": None, "destination_id": hashlib.sha256(identity.encode()).hexdigest()[:20]}


def _observations(source: _Source):
    calls = []
    for client, transport, pattern, argument in _CALL_RES:
        calls.extend(
            (m.start(), m.end() - 1, client, transport, argument, None)
            for m in islice(pattern.finditer(source.code), _MAX_CALLS)
        )
    for match in islice(_INSTANCE_CALL.finditer(source.code), _MAX_CALLS):
        if instance := source.instance(match["name"], match.start()):
            client, base = instance
            argument = 1 if match["method"] in {"request", "stream"} and client in {"requests", "httpx"} else 0
            calls.append((match.start(), match.end() - 1, client, "http", argument, base))
    for match in re.finditer(rf"(?P<name>{_NAME})\.(?:get|post|put|delete|patch)\s*\(\s*\)\s*\.uri\s*\(", source.code):
        if (instance := source.instance(match["name"], match.start())) and instance[0] == "spring-http":
            calls.append((match.start(), match.end() - 1, "spring-http", "http", 0, instance[1]))
    seen = set()
    for at, opening, client, transport, argument, base in sorted(calls)[:_MAX_CALLS]:
        if opening in seen:
            continue
        seen.add(opening)
        if re.search(r"\b(?:function|def)\s*$", source.code[max(0, at - 40) : at]):
            continue
        spans = _arguments(source.code, opening)
        if len(spans) <= argument:
            continue
        if re.match(r"\s*(?:=>|\{)", source.code[spans[-1][1] + 1 :]):
            continue
        expression = source.text[slice(*spans[argument])].strip()
        expression = re.sub(r"^url\s*=\s*", "", expression)
        if expression.startswith("{"):
            expression = _field(expression, ("url", "uri")) or ""
        if destination := _destination(expression, source, at, base):
            yield client, transport, destination, bisect.bisect_left(source.lines, at) + 1


def scan(repo_root: Path) -> list[dict[str, Any]]:
    """Destination groups retain independent configured targets and every call-site anchor."""
    rows = {}
    for path in _walk_repo(repo_root):
        if path.suffix.lower() not in _CODE_EXTS:
            continue
        try:
            source = _Source(path.read_text(encoding="utf-8", errors="replace"), path.suffix.lower())
        except OSError:
            continue
        rel = path.relative_to(repo_root).as_posix()
        for client, transport, destination, line in _observations(source):
            key = (
                destination["kind"],
                destination["host"],
                destination.get("scheme"),
                destination.get("port"),
                destination.get("destination_id"),
                transport,
            )
            row = rows.setdefault(key, {**destination, "transport": transport, "clients": set(), "evidence": []})
            row["clients"].add(client)
            evidence = {"file": rel, "line": line}
            if evidence not in row["evidence"]:
                row["evidence"].append(evidence)
    return [
        {
            **row,
            "clients": sorted(row["clients"]),
            "evidence": sorted(row["evidence"], key=lambda e: (e["file"], e["line"])),
        }
        for row in sorted(
            rows.values(),
            key=lambda row: (
                row["kind"] != "user-controlled",
                row["kind"] == "configured",
                -len(row["evidence"]),
                row["host"] or "",
                row["transport"],
                row.get("destination_id", ""),
                row.get("scheme", ""),
                row.get("port", 0),
            ),
        )
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    if not repo_root.is_dir():
        print(f"egress_clients: not a directory: {repo_root}", file=_sys.stderr)
        return 2
    print(json.dumps({"destinations": scan(repo_root)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
