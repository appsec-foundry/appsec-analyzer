"""Retained HTTPS Git helper contract for direct internal scanner scripts."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from appsec_analyzer.engine import initialize

initialize()
from shared._url_guard import validate_target_url

CLONE_TIMEOUT_S = 60


def remote_url(value: str) -> str:
    """Validate and canonicalize an explicitly supplied HTTPS Git URL."""
    if any(char.isspace() or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("repository URL contains whitespace, control characters, or backslashes")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid repository URL: {exc}") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("repository URL must use HTTPS and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("repository URL must not contain credentials")
    if "?" in value or "#" in value:
        raise ValueError("repository URL must not contain a query or fragment")
    path = parsed.path.rstrip("/")
    if not path or path == "/":
        raise ValueError("repository URL must include a project path")
    if any(not part or unquote(part) in {".", ".."} for part in path.split("/")[1:]):
        raise ValueError("repository URL contains an ambiguous project path")
    host = parsed.hostname.lower()
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    url = urlunsplit(("https", authority, path, "", ""))
    verdict = validate_target_url(url, check_ip_safety=False)
    if not verdict.ok:
        raise ValueError(f"repository URL blocked: {verdict.reason}")
    return url


def clone(url: str, checkout: Path) -> None:
    """Create a temporary working tree without shell evaluation or redirects."""
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "http.followRedirects=false",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--quiet",
        "--",
        url,
        str(checkout),
    ]
    try:
        done = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_S,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"},
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("git clone timed out") from exc
    except OSError as exc:
        raise RuntimeError(f"git clone could not start: {exc}") from exc
    if done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip().splitlines()
        raise RuntimeError(f"git clone failed: {detail[-1] if detail else f'exit {done.returncode}'}")
    if not checkout.is_dir():
        raise RuntimeError("git clone succeeded without a working tree")
