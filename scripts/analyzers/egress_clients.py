#!/usr/bin/env python3
"""Outbound client calls the repository code makes, grouped by destination.

Inspected signal: one source line that calls an HTTP, WebSocket, or RPC client
(``fetch``, ``axios``, ``got``, Node ``http(s).get/request``, ``requests``,
``httpx``, ``urlopen``, Go ``http.Get/NewRequest``, ``new WebSocket``,
``websockets.connect``, ethers or web3 providers).

Trigger: the call names a literal absolute URL to a non-local host, a URL taken
from the incoming request on that line or in an assignment shortly before it,
or a URL that starts with an environment or application setting, on that line
or through a name the file assigns from one. The first is a fixed external
service, the second lets the caller choose the destination, and the third is a
service the deployment selects.

False-positive exclusions: relative URLs (same-origin calls of a client to its
own backend), loopback, ``*.local``, reserved example domains, calls whose
destination is none of the above, settings read for anything but the
destination, settings of a client bundle (``REACT_APP_*``, ``NEXT_PUBLIC_*``,
``import.meta.env``), whose base URL is normally the client's own backend,
minified lines, and every path the shared scan-exclude policy removes (tests,
fixtures, vendored code).

Evidence: repository-relative file and line of each call. The result is a lead
for the architecture analyst, not a finding; CWE and severity stay with the
analysis that confirms what the call does.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from analyzers.recon_patterns import _walk_repo

_CODE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py", ".go", ".rb", ".php"}
_MAX_LINE_CHARS = 2000  # longer lines are minified bundles, not call sites
_LOOKBACK_LINES = 10  # how far an assignment may precede the call it feeds

# Each alternative names its client; the order decides the label of a line
# that matches more than one.
_CLIENTS: tuple[tuple[str, str, str], ...] = (
    ("rpc-provider", "rpc", r"\bnew\s+(?:ethers\.)?(?:providers\.)?(?:JsonRpc|WebSocket|Infura|Alchemy)Provider\s*\("),
    ("web3", "rpc", r"\bnew\s+Web3\s*\("),
    ("websocket", "websocket", r"\bnew\s+WebSocket\s*\(|\bwebsockets?\.connect\s*\("),
    ("fetch", "http", r"(?<![\w.$])fetch\s*\("),
    ("axios", "http", r"\baxios(?:\.(?:get|post|put|patch|delete|head|request))?\s*\("),
    ("got", "http", r"(?<![\w.$])got(?:\.(?:get|post|put|patch|delete))?\s*\("),
    ("node-http", "http", r"(?<![\w.$])https?\.(?:get|request)\s*\("),
    ("requests", "http", r"\brequests\.(?:get|post|put|patch|delete|head|request)\s*\("),
    ("httpx", "http", r"\bhttpx\.(?:get|post|put|patch|delete|request|stream)\s*\("),
    ("urlopen", "http", r"\burlopen\s*\("),
    ("go-http", "http", r"\bhttp\.(?:Get|Post|Head|NewRequest(?:WithContext)?)\s*\("),
)
_CLIENT_RES = tuple((name, transport, re.compile(pattern)) for name, transport, pattern in _CLIENTS)
_URL_LITERAL = re.compile(r"""["'`](?:https?|wss?)://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)""")
_REQUEST_SOURCE = re.compile(
    r"\b(?:req|request|ctx\.request)\.(?:body|query|params|args|form|values|json|GET|POST|get_json)\b"
    r"|\$_(?:GET|POST|REQUEST)\b"
)
_FIRST_ARG = re.compile(r"\(\s*([A-Za-z_$][\w$]*)\s*[,)]")
_CONFIG_SOURCE = re.compile(
    r"\bprocess\.env(?:\[|\.(?!(?:REACT_APP|VUE_APP|NEXT_PUBLIC|NUXT_PUBLIC|VITE|GATSBY|EXPO_PUBLIC)_))"
    r"|\bos\.(?:environ|getenv|Getenv)\b"
    r"|\bENV(?:\[|\.fetch\b)"
    r"|\bgetenv\s*\("
    r"|\$_ENV\b"
    r"|\bconfig(?:\.get\b|\[)"
    r"|\bsettings\.[A-Z]"
)
# The name before a setting: `url =`, `url: string =`, `url :=`. Searched only in
# the text just before the setting, so a long line costs no more than a short one.
_ASSIGNED_NAME = re.compile(r"([A-Za-z_$][\w$]*)\s*(?::[^=]{0,60})?:?=\s*(?:await\s+)?$")
_ASSIGNMENT_WINDOW = 100
_FIRST_ARG_TEXT = re.compile(r"\(\s*([^,)]*)")
# What decides the host is the start of the URL: `base`, `base + '/x'`, `${base}/x`, `f"{self.base}/x"`.
_LEADING_NAME = re.compile(r"""(?:f?["'`]\$?\{\s*)?(?:(?:self|this)\.)?([A-Za-z_$][\w$]*)""")
_LOCAL_HOST = re.compile(
    r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|host\.docker\.internal)$"
    r"|\.(?:local|localhost|test|invalid)$|(?:^|\.)example\.(?:com|org|net)$"
)


def _configured_names(lines: list[str]) -> set[str]:
    """The names a file assigns directly from a setting."""
    names = set()
    for line in lines:
        source = _CONFIG_SOURCE.search(line) if len(line) <= _MAX_LINE_CHARS else None
        if source:
            assigned = _ASSIGNED_NAME.search(line[max(0, source.start() - _ASSIGNMENT_WINDOW) : source.start()])
            if assigned:
                names.add(assigned.group(1))
    return names


def _destination(lines: list[str], index: int, call_at: int, configured: set[str]) -> tuple[str, str] | None:
    """``(kind, host)`` of the call on ``lines[index]``, or None when it names no external destination."""
    rest = lines[index][call_at:]
    literal = _URL_LITERAL.search(rest)
    if literal:
        host = literal.group("host").lower()
        return None if _LOCAL_HOST.search(host) else ("fixed-host", host)
    if _REQUEST_SOURCE.search(rest):
        return ("user-controlled", "")
    argument = _FIRST_ARG.match(rest[rest.find("(") :])
    if argument:
        assigned = re.compile(rf"\b{re.escape(argument.group(1))}\b[^=\n]*=[^=\n]*")
        for previous in lines[max(0, index - _LOOKBACK_LINES) : index]:
            match = assigned.search(previous)
            if match and _REQUEST_SOURCE.search(match.group(0)):
                return ("user-controlled", "")
    url = _FIRST_ARG_TEXT.match(rest[rest.find("(") :])
    if url:
        leading = _LEADING_NAME.match(url.group(1))
        if _CONFIG_SOURCE.search(url.group(1)) or (leading and leading.group(1) in configured):
            return ("configured", "")
    return None


def scan(repo_root: Path) -> list[dict[str, Any]]:
    """Every destination with its clients, transports and call sites, in a deterministic order."""
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for path in _walk_repo(repo_root):
        if path.suffix.lower() not in _CODE_EXTS:
            continue
        rel = path.relative_to(repo_root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        configured = _configured_names(lines)
        for index, line in enumerate(lines):
            if len(line) > _MAX_LINE_CHARS:
                continue
            for name, transport, pattern in _CLIENT_RES:
                call = pattern.search(line)
                if not call:
                    continue
                destination = _destination(lines, index, call.start(), configured)
                if destination is not None:
                    kind, host = destination
                    row = rows.setdefault(
                        (kind, host, transport),
                        {"kind": kind, "host": host or None, "transport": transport, "clients": set(), "evidence": []},
                    )
                    row["clients"].add(name)
                    row["evidence"].append({"file": rel, "line": index + 1})
                break
    ordered = sorted(
        rows.values(),
        key=lambda row: (row["kind"] != "user-controlled", -len(row["evidence"]), row["host"] or "", row["transport"]),
    )
    return [
        {
            **row,
            "clients": sorted(row["clients"]),
            "evidence": sorted(row["evidence"], key=lambda e: (e["file"], e["line"])),
        }
        for row in ordered
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    if not repo_root.is_dir():
        print(f"egress_clients: not a directory: {repo_root}", file=sys.stderr)
        return 2
    print(json.dumps({"destinations": scan(repo_root)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
