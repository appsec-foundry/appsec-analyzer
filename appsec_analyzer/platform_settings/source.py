"""Admission of a GitHub or GitLab repository URL for platform setting checks."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

HOSTS = {"github.com": "github", "gitlab.com": "gitlab"}
_HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}")
_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}")
_FORMS = (
    re.compile(r"https://(?P<host>[^/@:]+)/(?P<path>[^?#]+)"),
    re.compile(r"ssh://git@(?P<host>[^/@:]+)/(?P<path>[^?#]+)"),
    re.compile(r"git@(?P<host>[^/@:]+):(?P<path>[^?#]+)"),
)


class SourceError(ValueError):
    """The selection is not a supported platform repository URL."""


@dataclass(frozen=True)
class Repository:
    platform: str
    host: str
    path: str

    @property
    def label(self) -> str:
        return f"{self.host}/{self.path}"


def _platform(host: str) -> str | None:
    """The platform of a host. Only the operator's GITLAB_HOST adds a host, never repository content."""
    if host in HOSTS:
        return HOSTS[host]
    from appsec_analyzer.engine import initialize

    initialize()
    from runtime.remote_repositories import _gitlab_host

    return "gitlab" if _HOST.fullmatch(host) and _gitlab_host(host) else None


def parse_repository(url: str) -> Repository:
    """Return the platform and repository path; never derive them from repository content."""
    for form in _FORMS:
        match = form.fullmatch(url.strip())
        if match:
            break
    else:
        raise SourceError("expected an HTTPS or SSH URL of a GitHub or GitLab repository")
    host = match["host"].lower()
    platform = _platform(host)
    if platform is None:
        raise SourceError(
            "only github.com and gitlab.com repositories are supported; "
            "set GITLAB_HOST to the host of a self-hosted GitLab"
        )
    path = match["path"].rstrip("/").removesuffix(".git")
    segments = path.split("/")
    limit = 2 if platform == "github" else 20
    if not 2 <= len(segments) <= limit or not all(_SEGMENT.fullmatch(s) and s not in (".", "..") for s in segments):
        raise SourceError("the URL does not name a repository")
    return Repository(platform, host, path)


def platform_hosts(sources: Iterable[str]) -> list[str]:
    """The distinct platform hosts of the selections; local paths and unsupported URLs have none."""
    hosts = set()
    for source in sources:
        try:
            hosts.add(parse_repository(source).host)
        except SourceError:
            continue
    return sorted(hosts)
