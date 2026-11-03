"""Run the platform security setting checks for one repository URL."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable

from appsec_analyzer.platform_settings import checks
from appsec_analyzer.platform_settings.client import ApiClient, TransportError, github_client, gitlab_client
from appsec_analyzer.platform_settings.source import Repository, parse_repository

SCHEMA_VERSION = 1
LIMITS = (
    "The settings describe the platform at check time, not the examined source revision. "
    "set means configured, not effective. This is not an assessment of the code or a release approval."
)


class PlatformSettingsError(ValueError):
    """The check could not run for this repository."""


def _inferred_gitlab(repo: Repository, token: str | None, make: Callable) -> tuple[checks.GitLab, checks.Context]:
    """Try the selected host anonymously; only an explicit platform token can add access."""
    runner = checks.GitLab(make(repo, None), repo, False)
    try:
        context = runner.context()
    except LookupError as exc:
        # A private GitLab project can be invisible anonymously. The operator's
        # explicit platform token authorizes access to this selected host only.
        if not token or not exc.args or exc.args[0].status not in (401, 403, 404):
            raise
    else:
        _require_gitlab_project(runner, repo)
        if not token:
            return runner, context
    runner = checks.GitLab(make(repo, token), repo, True)
    context = runner.context()
    _require_gitlab_project(runner, repo)
    return runner, context


def _require_gitlab_project(runner: checks.GitLab, repo: Repository) -> None:
    project = runner.project
    if type(project.get("id")) is not int or project["id"] <= 0 or project.get("path_with_namespace") != repo.path:
        raise PlatformSettingsError("the host could not be identified as GitLab from its project API")


def check_platform_settings(
    url: str,
    token: str | None = None,
    *,
    client_factory: Callable[[Repository, str | None], ApiClient] | None = None,
    now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
) -> dict:
    """Return the validated result; the token is used for requests only and never stored."""
    repo = parse_repository(url)
    make = client_factory or (lambda r, t: github_client(t) if r.platform == "github" else gitlab_client(t, r.host))
    try:
        if repo.inferred:
            runner, context = _inferred_gitlab(repo, token, make)
        else:
            client = make(repo, token)
            runner = (checks.GitHub if repo.platform == "github" else checks.GitLab)(client, repo, bool(token))
            context = runner.context()
        outcomes = runner.evaluate(context)
    except LookupError as exc:
        status = exc.args[0].status if exc.args else 0
        raise PlatformSettingsError(
            "the repository was not found or is not readable with this access"
            if status in (401, 403, 404)
            else "the platform did not return the repository"
        ) from None
    except TransportError as exc:
        raise PlatformSettingsError(str(exc)) from None
    rows = []
    for check_id, title in checks.CATALOG:
        outcome = outcomes[check_id]
        rows.append({"id": check_id, "title": title, "state": outcome.state, "reason": outcome.reason})
    summary = {
        state: sum(row["state"] == state for row in rows)
        for state in (checks.SET, checks.NOT_SET, checks.NOT_CHECKABLE)
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "platform": repo.platform,
        "host": repo.host,
        "repository": repo.path,
        "visibility": context.visibility,
        "access": "token" if token else "anonymous",
        "checked_at": now().replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "checks": rows,
        "summary": summary,
        "limits": LIMITS,
    }
