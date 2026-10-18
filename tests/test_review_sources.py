"""Read-only forge metadata and bounded checkout boundary; never contacts a live service."""

from __future__ import annotations

import os
import socket
import subprocess

import pytest

from appsec_analyzer import cli
from appsec_analyzer import review_sources as reviews

cli._engine_imports()

from runtime import remote_repositories as remote

from tests.test_threat_analysis_cli import project as project_fixture

project = project_fixture

A, B, C = "a" * 40, "b" * 40, "c" * 40


@pytest.mark.parametrize(
    "url,kind",
    [
        ("http://gitlab.example/a/b/-/merge_requests/1", "mr"),
        ("https://token@gitlab.example/a/b/-/merge_requests/1", "mr"),
        ("https://gitlab.example/a/../-/merge_requests/1", "mr"),
        ("https://gitlab.example/a/b/-/merge_requests/1?redirect=bad", "mr"),
        ("https://gitlab.example/a/b/-/merge_requests/1#token", "mr"),
        ("https://gitlab.example/a/b/-/merge_requests/0", "mr"),
        ("https://gitlab.example:8080/a/b/-/merge_requests/1", "mr"),
        ("https://gitlab.example/a/%2e%2e/-/merge_requests/1", "mr"),
        ("https://git\nlab.example/a/b/-/merge_requests/1", "mr"),
        ("https://github.com/a/b/pull/1", "mr"),
    ],
)
def test_invalid_review_urls_are_rejected_before_network(url, kind):
    with pytest.raises(reviews.ReviewError):
        reviews.parse(url, kind)


def test_gitlab_nested_project_and_immutable_diff_selection(monkeypatch):
    review = reviews.parse("https://gitlab.example/team/sub/app/-/merge_requests/42", "mr")
    calls = []

    def api(host, path, kind):
        calls.append((host, path, kind))
        return {
            "iid": 42,
            "web_url": review.url,
            "diff_refs": {"base_sha": A, "head_sha": B, "start_sha": C},
            "source_project": {"http_url_to_repo": "https://untrusted.invalid/steal"},
        }

    monkeypatch.setattr(reviews, "_get", api)
    assert reviews.resolve(review) == {"url": review.url, "base": A, "head": B, "target": C}
    assert calls == [("gitlab.example", "/api/v4/projects/team%2Fsub%2Fapp/merge_requests/42", "mr")]
    assert review.repository == "https://gitlab.example/team/sub/app.git"


def test_github_uses_only_known_api_destination_and_sha_comparison(monkeypatch):
    review = reviews.parse("https://github.com/team/app/pull/8", "pr")
    calls = []

    def api(host, path, kind):
        calls.append((host, path, kind))
        if "/pulls/" in path:
            return {
                "number": 8,
                "base": {"sha": C, "repo": {"full_name": "team/app"}},
                "head": {"sha": B},
                "url": "https://untrusted.invalid",
            }
        return {"merge_base_commit": {"sha": A}}

    monkeypatch.setattr(reviews, "_get", api)
    assert reviews.resolve(review)["base"] == A
    assert calls == [
        ("api.github.com", "/repos/team/app/pulls/8", "pr"),
        ("api.github.com", f"/repos/team/app/compare/{C}...{B}?per_page=1", "pr"),
    ]


@pytest.mark.parametrize("bad", [None, "main", "--upload-pack=bad", "a" * 39, "g" * 40])
def test_api_cannot_supply_ref_options_or_mutable_branches(monkeypatch, bad):
    review = reviews.parse("https://gitlab.example/team/app/-/merge_requests/1", "mr")
    monkeypatch.setattr(
        reviews,
        "_get",
        lambda *a: {"iid": 1, "web_url": review.url, "diff_refs": {"base_sha": bad, "head_sha": B, "start_sha": C}},
    )
    with pytest.raises(reviews.ReviewError):
        reviews.resolve(review)


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1"])
def test_pinned_https_rejects_prohibited_destinations_before_connect(monkeypatch, address):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (address, 443))]
    )
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **kw: pytest.fail("Prohibited address must never connect")
    )
    connection = reviews._PinnedHTTPS("gitlab.example")
    with pytest.raises(remote.RemoteError):
        connection.connect()


def test_https_pins_resolved_address_but_checks_original_tls_hostname(monkeypatch):
    monkeypatch.setattr(remote, "_address", lambda remote: "203.0.113.5")
    calls = []
    raw = object()
    monkeypatch.setattr(socket, "create_connection", lambda destination, **kw: (calls.append(destination), raw)[1])

    class TLS:
        def wrap_socket(self, sock, *, server_hostname):
            assert sock is raw and server_hostname == "gitlab.example"
            return "tls-socket"

    connection = reviews._PinnedHTTPS("gitlab.example")
    connection._context = TLS()
    connection.connect()
    assert calls == [("203.0.113.5", 443)] and connection.sock == "tls-socket"


@pytest.mark.parametrize(
    "status,body", [(302, b"redirect"), (401, b"sensitive server error"), (200, b"x" * 2097153), (200, b"not json")]
)
def test_redirects_oversized_and_invalid_api_responses_fail_closed(monkeypatch, status, body):
    calls = []

    class Reply:
        position = 0

        def read1(self, limit):
            chunk = body[self.position : self.position + limit]
            self.position += len(chunk)
            return chunk

    reply = Reply()
    reply.status = status

    class Connection:
        sock = None

        def __init__(self, *a, **kw):
            pass

        def request(self, method, path, headers):
            calls.append((method, path, headers))

        def getresponse(self):
            return reply

        def close(self):
            pass

    monkeypatch.setattr(reviews, "_PinnedHTTPS", Connection)
    monkeypatch.setenv("APPSEC_GIT_TOKEN", "isolated-test-token")
    with pytest.raises(reviews.ReviewError) as error:
        reviews._get("gitlab.example", "/api/v4/projects/p", "mr")
    assert len(calls) == 1 and calls[0][0] == "GET"
    assert "isolated-test-token" not in str(error.value) and "sensitive server error" not in str(error.value)


def test_token_header_injection_is_rejected_before_connection(monkeypatch):
    monkeypatch.setenv("APPSEC_GIT_TOKEN", "bad\r\nHeader: value")
    monkeypatch.setattr(reviews, "_PinnedHTTPS", lambda *a, **kw: pytest.fail("No connection"))
    with pytest.raises(reviews.ReviewError, match="token"):
        reviews._get("gitlab.example", "/api/v4/projects/p", "mr")


def test_checkout_uses_exact_objects_without_mutating_caller_repository(project, tmp_path, monkeypatch):
    before = subprocess.check_output(["git", "-C", str(project), "status", "--porcelain"])
    sha = subprocess.check_output(["git", "-C", str(project), "rev-parse", "HEAD"]).decode().strip()
    review = reviews.parse("https://gitlab.example/team/app/-/merge_requests/1", "mr")
    monkeypatch.setattr(reviews.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(
        remote, "_git_env", lambda *a: {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    )
    seen = []

    def git_command(command, root, env):
        seen.append(command)
        # Only transport is substituted; real init, fetch, checkout and cleanup execute.
        command = [str(project) if arg == review.repository else arg for arg in command]
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *command], env=env, check=True, capture_output=True)

    monkeypatch.setattr(remote, "_git", git_command)
    with reviews.checkout(review, {"base": sha, "head": sha, "target": sha}) as root:
        assert root != project and (root / "api.py").read_text() == (project / "api.py").read_text()
        assert root.parent.stat().st_mode & 0o777 == 0o700
    assert not root.exists()
    assert subprocess.check_output(["git", "-C", str(project), "status", "--porcelain"]) == before
    assert next(c for c in seen if "fetch" in c)[-1] == sha
    assert "--no-recurse-submodules" in next(c for c in seen if "fetch" in c)
