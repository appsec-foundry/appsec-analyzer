"""Read-only, host-pinned JSON access to a platform API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

MAX_BYTES = 1_048_576
TIMEOUT_SECONDS = 20
GITHUB_API_VERSION = "2026-03-10"


class TransportError(RuntimeError):
    """The platform could not be reached or answered unreadably."""


@dataclass(frozen=True)
class Response:
    status: int
    body: Any = None
    rate_limited: bool = False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ARG002
        return None


class ApiClient:
    """GET requests to one API base. A token is only ever sent to that base."""

    def __init__(self, base_url: str, headers: dict[str, str], token_header: tuple[str, str] | None):
        self._base = base_url.rstrip("/")
        self._headers = {**headers, "Accept": "application/json", "User-Agent": "appsec-analyzer"}
        if token_header:
            self._headers[token_header[0]] = token_header[1]
        self._opener = urllib.request.build_opener(_NoRedirect)

    def get(self, path: str) -> Response:
        request = urllib.request.Request(self._base + path, headers=self._headers, method="GET")
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as reply:
                return self._read(reply.status, reply)
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400:
                # A redirect could carry the token to another host: refuse it.
                raise TransportError("the platform redirected the request") from None
            return self._read(error.code, error)
        except (urllib.error.URLError, OSError, TimeoutError):
            raise TransportError("the platform could not be reached") from None

    @staticmethod
    def _read(status: int, reply) -> Response:
        limited = reply.headers.get("x-ratelimit-remaining") == "0" or status == 429
        raw = reply.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise TransportError("the platform answer is too large")
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = None
        return Response(status, body, limited)


def github_client(token: str | None) -> ApiClient:
    return ApiClient(
        "https://api.github.com",
        {"X-GitHub-Api-Version": GITHUB_API_VERSION},
        ("Authorization", f"Bearer {token}") if token else None,
    )


def gitlab_client(token: str | None) -> ApiClient:
    return ApiClient("https://gitlab.com/api/v4", {}, ("PRIVATE-TOKEN", token) if token else None)
