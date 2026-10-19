"""Admission of a GitHub or GitLab repository URL for platform setting checks."""

from __future__ import annotations

import re
from dataclasses import dataclass

HOSTS = {"github.com": "github", "gitlab.com": "gitlab"}
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


def parse_repository(url: str) -> Repository:
    """Return the platform and repository path; never derive them from repository content."""
    for form in _FORMS:
        match = form.fullmatch(url.strip())
        if match:
            break
    else:
        raise SourceError("expected an HTTPS or SSH URL of a GitHub or GitLab repository")
    host = match["host"].lower()
    if host not in HOSTS:
        raise SourceError("only github.com and gitlab.com repositories are supported")
    path = match["path"].rstrip("/").removesuffix(".git")
    segments = path.split("/")
    limit = 2 if HOSTS[host] == "github" else 20
    if not 2 <= len(segments) <= limit or not all(_SEGMENT.fullmatch(s) and s not in (".", "..") for s in segments):
        raise SourceError("the URL does not name a repository")
    return Repository(HOSTS[host], host, path)
