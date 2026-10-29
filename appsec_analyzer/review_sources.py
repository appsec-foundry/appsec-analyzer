"""Read-only MR/PR resolution with pinned HTTPS and isolated Git object retrieval."""

from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit


class ReviewError(ValueError):
    """A credential-free remote review diagnostic."""


@dataclass(frozen=True)
class Review:
    kind: str
    url: str
    host: str
    project: str
    number: int

    @property
    def repository(self):
        return f"https://{self.host}/{self.project}.git"


def parse(value: str, kind: str) -> Review:
    try:
        if any(ord(c) <= 32 or 127 <= ord(c) <= 159 for c in value) or kind not in {"mr", "pr"}:
            raise ValueError
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.port not in (None, 443)
            or len(value) > 2048
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", url.hostname)
        ):
            raise ValueError
        pattern = (
            r"/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/([1-9][0-9]{0,9})/?"
            if kind == "pr"
            else r"/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)/-/merge_requests/([1-9][0-9]{0,9})/?"
        )
        match = re.fullmatch(pattern, url.path)
        if not match or any(p in {".", ".."} for p in match[1].split("/")):
            raise ValueError
        host = url.hostname.lower()
        return Review(kind, f"https://{host}{url.path.rstrip('/')}", host, match[1], int(match[2]))
    except ValueError:
        raise ReviewError(
            "Use a complete HTTPS GitLab MR or GitHub PR URL without credentials, query or fragment."
        ) from None


class _PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        from runtime.remote_repositories import Remote, _address

        address = _address(Remote(f"https://{self.host}", "https", self.host, 443, "review"))
        raw = socket.create_connection((address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _get(host: str, path: str, kind: str) -> dict:
    from runtime.remote_repositories import RemoteError, select_token

    try:
        selected = select_token(host)
    except RemoteError as exc:
        raise ReviewError(str(exc)) from None
    name, token = selected or ("APPSEC_GIT_TOKEN", "")
    if any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ReviewError(f"{name} must be a single printable token.")
    headers = {"Accept": "application/json", "User-Agent": "appsec-analyzer"}
    if token:
        headers["Authorization" if kind == "pr" else "PRIVATE-TOKEN"] = f"Bearer {token}" if kind == "pr" else token
    connection = _PinnedHTTPS(host, timeout=30, context=ssl.create_default_context())
    deadline = time.monotonic() + 30
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise ReviewError(
                f"Review API returned HTTP {response.status}; check URL and read access. Redirects are refused."
            )
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReviewError("Review API exceeded its 30-second time limit.")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(65536, 2_097_153 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > 2_097_152:
                raise ReviewError("Review API response exceeds 2 MiB.")
        result = json.loads(body)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (OSError, http.client.HTTPException, ValueError, RecursionError) as exc:
        if isinstance(exc, ReviewError):
            raise
        raise ReviewError("Review API could not be read; check HTTPS connectivity, URL and read access.") from None
    finally:
        connection.close()


def _sha(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", value):
        raise ReviewError("Review API did not return a complete immutable commit identity.")
    return value


def resolve(review: Review) -> dict:
    """Only use identities from API metadata; returned URLs never authorize destinations."""
    try:
        if review.kind == "pr":
            host = "api.github.com" if review.host == "github.com" else review.host
            prefix = "" if review.host == "github.com" else "/api/v3"
            endpoint = f"{prefix}/repos/{review.project}"
            data = _get(host, f"{endpoint}/pulls/{review.number}", "pr")
            if data["number"] != review.number or data["base"]["repo"]["full_name"].lower() != review.project.lower():
                raise ReviewError("Review API returned a different pull request or repository.")
            target, head = _sha(data["base"]["sha"]), _sha(data["head"]["sha"])
            comparison = _get(host, f"{endpoint}/compare/{target}...{head}?per_page=1", "pr")
            base = _sha(comparison["merge_base_commit"]["sha"])
        else:
            endpoint = f"/api/v4/projects/{quote(review.project, safe='')}/merge_requests/{review.number}"
            data = _get(review.host, endpoint, "mr")
            if data["iid"] != review.number or parse(data["web_url"], "mr") != review:
                raise ReviewError("Review API returned a different merge request or repository.")
            base, head = _sha(data["diff_refs"]["base_sha"]), _sha(data["diff_refs"]["head_sha"])
            target = _sha(data["diff_refs"]["start_sha"])
        return {"url": review.url, "base": base, "head": head, "target": target}
    except (KeyError, TypeError, AttributeError):
        raise ReviewError(
            "Review metadata is incomplete; retry when its diff is ready or use local --base and --head."
        ) from None


@contextmanager
def checkout(review: Review, metadata: dict):
    """Stable URL-derived identity permits resuming a job; checkout lifetime is one invocation."""
    from runtime.remote_repositories import SECRET_ENV, _git, _git_env, _private_directory, parse_remote

    parent = Path(tempfile.gettempdir()).resolve() / f"appsec-threat-reviews-{os.getuid()}"
    _private_directory(parent)
    workspace = parent / hashlib.sha256(review.url.encode()).hexdigest()
    _private_directory(workspace)
    guard = os.open(workspace / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    root = workspace / "repository"
    created = False
    try:
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ReviewError("Another analysis is preparing this review; retry when it finishes.") from None
        if root.exists() or root.is_symlink():
            raise ReviewError(
                "A stale review checkout remains after an unclean stop; inspect and remove it before retrying."
            )
        env = _git_env(parse_remote(review.repository), workspace)
        if "APPSEC_GIT_TOKEN" in env and "APPSEC_GIT_USERNAME" not in env:
            env["APPSEC_GIT_USERNAME"] = "x-access-token" if review.kind == "pr" else "oauth2"
        created = True
        _git(["init", "--quiet", "--template=", str(root)], root, env)
        _git(
            [
                "-C",
                str(root),
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--depth=1",
                "--",
                review.repository,
                *dict.fromkeys(_sha(metadata[k]) for k in ("base", "head", "target")),
            ],
            root,
            env,
        )
        clean = {k: v for k, v in env.items() if k not in SECRET_ENV}
        _git(["-C", str(root), "checkout", "--quiet", "--detach", metadata["head"]], root, clean)
        yield root
    finally:
        if created and root.exists():
            shutil.rmtree(root)
        os.close(guard)
