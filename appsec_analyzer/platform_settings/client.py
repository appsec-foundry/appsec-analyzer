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


class _SelfHosted(urllib.request.HTTPSHandler):
    """Reaches a self-hosted instance like its Git host: at a checked address, or through the operator's proxy."""

    def __init__(self, host: str):
        super().__init__()
        self._host = host

    def https_open(self, req):
        from runtime.remote_repositories import Remote, RemoteError, _address, _check_allowlist, _PinnedHTTPS, _proxy

        remote = Remote(f"https://{self._host}", "https", self._host, 443, "platform")
        try:
            if _proxy(remote):
                _check_allowlist(remote)
                return super().https_open(req)
            address = _address(remote)
        except RemoteError as exc:
            raise TransportError(str(exc)) from None
        return self.do_open(lambda *_, **__: _PinnedHTTPS(remote, address), req)


class ApiClient:
    """GET requests to one API base. A token is only ever sent to that base."""

    def __init__(
        self,
        base_url: str,
        headers: dict[str, str],
        token_header: tuple[str, str] | None,
        *handlers: urllib.request.BaseHandler,
    ):
        self._base = base_url.rstrip("/")
        self._headers = {**headers, "Accept": "application/json", "User-Agent": "appsec-analyzer"}
        if token_header:
            self._headers[token_header[0]] = token_header[1]
        self._opener = urllib.request.build_opener(_NoRedirect, *handlers)

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


def gitlab_client(token: str | None, host: str = "gitlab.com") -> ApiClient:
    handlers = () if host == "gitlab.com" else (_SelfHosted(host),)
    return ApiClient(f"https://{host}/api/v4", {}, ("PRIVATE-TOKEN", token) if token else None, *handlers)
