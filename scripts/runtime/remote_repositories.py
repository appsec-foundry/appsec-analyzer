"""Provision operator-selected Git URLs for the Analyzer CLI.

Only CLI selections authorize network access; repository content cannot add
destinations. Private, stable temporary paths preserve the controller's source
identities across retries. Checkouts are ephemeral; output stays caller-owned.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import http.client
import ipaddress
import itertools
import os
import re
import shlex
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_REPOSITORIES = 16
FETCH_SECONDS = 120
PREFLIGHT_TIMEOUT = 30
MAX_BYTES = 536_870_912
MAX_ENTRIES = 100_000
STDERR_BYTES = 8192
SECRET_ENV = ("APPSEC_GIT_TOKEN", "APPSEC_GIT_USERNAME", "APPSEC_GIT_SSH_KEY_FILE")
# The first variable set wins unless TOKEN_NAME_ENV (or --git-token-env) names another one.
# GITLAB_TOKEN goes only to GitLab hosts, so an ambient token never reaches an arbitrary Git URL.
TOKEN_ENV = ("APPSEC_GIT_TOKEN", "GIT_TOKEN", "GITLAB_TOKEN")
TOKEN_NAME_ENV = "APPSEC_GIT_TOKEN_ENV"
# A temporary checkout of a directory without Git lies in a slot with this prefix.
DIRECTORY_SLOT = "directory-"
# Git, curl and OpenSSH wording in the C locale; the first match wins. Only the class leaves this
# module, so no text from Git or the host reaches a message.
_FAILURES = (
    ("proxy", r"from proxy after CONNECT|Proxy CONNECT aborted|CONNECT tunnel failed|Could not resolve proxy"),
    ("name", r"Could not resolve host"),
    (
        "certificate",
        r"SSL certificate problem|server certificate verification failed"
        r"|SSL: (?:certificate subject name|no alternative certificate)",
    ),
    ("host_key", r"Host key verification failed|host key is known|REMOTE HOST IDENTIFICATION HAS CHANGED"),
    ("ssh_login", r"Permission denied \("),
    ("token", r"Authentication failed for"),
    ("login", r"could not read (?:Username|Password) for"),
    (
        "connection",
        r"Failed to connect to|Could not connect|Connection (?:refused|timed out|reset)|Network is unreachable"
        r"|No route to host|Operation timed out|Empty reply from server"
        r"|GnuTLS recv error|gnutls_handshake|SSL_ERROR_SYSCALL",
    ),
    ("not_found", r"repository '.*' not found|does not appear to be a git repository|returned error: 404"),
    ("forbidden", r"returned error: 403"),
    ("redirect", r"returned error: 30\d"),
    ("rate_limited", r"returned error: 429"),
    ("server", r"returned error: 5\d\d"),
)
_EXPLANATIONS = {
    "proxy": "the proxy refused the connection to {host}; check HTTPS_PROXY and whether the proxy allows this host",
    "name": "the host name {host} could not be resolved; check the URL and DNS",
    "certificate": (
        "the TLS certificate of {host} was not accepted; check the host name and the certificates this system trusts"
    ),
    "host_key": "the SSH host key of {host} is unknown or has changed; verify it and add it to known_hosts",
    "ssh_login": "{host} refused the SSH login; load the key into the SSH agent or set APPSEC_GIT_SSH_KEY_FILE",
    "connection": "{route} could not be reached; check the URL and network access",
    "rate_limited": "{host} is limiting requests (HTTP 429); try again later",
    "server": "{host} reported a server error; try again later",
}
# The answers a different path can change. Another try after a rejected token only adds a failed login.
_SUFFIX_CAN_HELP = {"redirect", "not_found", "login", "forbidden", "unknown"}


class RemoteError(ValueError):
    """A safe, credential-free diagnostic for the operator."""


class _GitFailed(RemoteError):
    """Git exited with an error. ``kind`` names a class of ``_FAILURES`` or ``unknown``."""

    def __init__(self, message: str, kind: str):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Remote:
    url: str
    scheme: str
    host: str
    port: int
    name: str


def parse_remote(value: str) -> Remote | None:
    """Recognize URLs without treating absolute or explicit relative paths as URLs."""
    if value.startswith(("/", "./", "../")) or ":" not in value:
        return None
    if len(value) > 4096 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise RemoteError("Invalid Git URL")
    scp = "://" not in value
    if scp:
        match = re.fullmatch(r"([\w.-]+@)?([A-Za-z0-9.-]+):([A-Za-z0-9._~/-]+)", value)
        if not match:
            raise RemoteError("Use an HTTPS URL, SSH URL or user@host:path")
        user, host, path = match.groups()
        scp_path = path.rstrip("/")
        value = f"ssh://{user or ''}{host}/{path.lstrip('/')}"
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 22)
    except ValueError:
        raise RemoteError("Invalid Git URL") from None
    if parsed.scheme not in {"https", "ssh"}:
        raise RemoteError("Remote repositories require HTTPS or SSH")
    if parsed.password is not None or (parsed.scheme == "https" and parsed.username is not None):
        raise RemoteError("Keep Git credentials out of URLs; use APPSEC_GIT_TOKEN or a credential helper")
    if not host or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", host) or not 1 <= port <= 65535:
        raise RemoteError("Invalid Git host or port")
    if parsed.username and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", parsed.username):
        raise RemoteError("Invalid SSH username")
    path = parsed.path.rstrip("/")
    if (
        parsed.query
        or parsed.fragment
        or not re.fullmatch(r"/[A-Za-z0-9._~/-]+", path)
        or any(p in {"", ".", ".."} for p in path.split("/")[1:])
    ):
        raise RemoteError("Git URL must name an unambiguous repository path without query or fragment")
    authority = f"[{host.lower()}]" if ":" in host else host.lower()
    if parsed.username:
        authority = parsed.username + "@" + authority
    if port != (443 if parsed.scheme == "https" else 22):
        authority += f":{port}"
    url = urlunsplit((parsed.scheme, authority, path, "", ""))
    if scp:
        # Git distinguishes a home-relative SCP path from an absolute ssh://
        # path. Preserve it for hosted services and self-hosted Git alike.
        url = f"{authority}:{scp_path}"
    name = path.rsplit("/", 1)[-1].removesuffix(".git")
    if not name or name in {".", "..", "~"}:
        raise RemoteError("Git URL must name a repository")
    return Remote(url, parsed.scheme, host.lower(), port, name[:80])


def _check_allowlist(remote: Remote) -> None:
    allowed = os.environ.get("APPSEC_URL_ALLOWLIST", "")
    if allowed and remote.host not in {h.strip().lower() for h in allowed.split(",")}:
        raise RemoteError("Git host is not in APPSEC_URL_ALLOWLIST")


def _proxy(remote: Remote) -> str | None:
    """Operator proxy for an HTTPS remote from ``https_proxy`` and ``no_proxy``.

    Only the operator's environment selects it; repository content never does. The proxy
    resolves and reaches the Git host, so the local address pinning does not apply.
    """
    if remote.scheme != "https":
        return None
    url = urllib.request.getproxies_environment().get("https")
    if not url or urllib.request.proxy_bypass_environment(remote.host):
        return None
    try:
        parsed = urlsplit(url)
        parsed.port  # noqa: B018 - rejects an invalid port
        usable = parsed.scheme in {"http", "https", "socks5", "socks5h"} and bool(parsed.hostname)
    except ValueError:
        usable = False
    if not usable or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise RemoteError("HTTPS_PROXY must be an http, https or socks5 URL with a host")
    return url


def describe_route(remote: Remote) -> str:
    """Destination for progress output; never includes proxy credentials."""
    proxy = _proxy(remote)
    if not proxy:
        return remote.host
    parsed = urlsplit(proxy)
    host = f"[{parsed.hostname}]" if ":" in (parsed.hostname or "") else parsed.hostname
    return f"{remote.host} via proxy {host}" + (f":{parsed.port}" if parsed.port else "")


def _address(remote: Remote) -> str:
    """Pin the explicit destination; private hosts are legitimate operator inputs."""
    _check_allowlist(remote)
    try:
        addresses = [
            ipaddress.ip_address(row[4][0])
            for row in socket.getaddrinfo(remote.host, remote.port, type=socket.SOCK_STREAM)
        ]
    except (OSError, ValueError):
        raise RemoteError("Git host could not be resolved") from None
    if not addresses or any(
        a.is_loopback
        or a.is_link_local
        or a.is_multicast
        or a.is_reserved
        or a.is_unspecified
        or (getattr(a, "ipv4_mapped", None) is not None)
        for a in addresses
    ):
        raise RemoteError("Git destination resolves to a prohibited network address")
    return str(addresses[0])


def _gitlab_host(host: str) -> bool:
    configured = re.sub(r"^[a-z][a-z0-9+.-]*://", "", os.environ.get("GITLAB_HOST", "").strip().lower())
    return host == "gitlab.com" or (bool(configured) and host == configured.split("/")[0].rsplit(":", 1)[0])


def select_token(host: str) -> tuple[str, str] | None:
    """Return (variable, token) for an HTTPS host, or None when no token variable applies.

    A variable named by ``APPSEC_GIT_TOKEN_ENV`` must be set and is used for every host.
    """
    named = os.environ.get(TOKEN_NAME_ENV, "")
    if named:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", named):
            raise RemoteError("--git-token-env takes the name of one environment variable")
        if named not in os.environ:
            raise RemoteError(f"{named} is not set; --git-token-env must name a variable that holds a Git token")
        return named, os.environ[named]
    for name in TOKEN_ENV:
        value = os.environ.get(name)
        if value is None or (name != "APPSEC_GIT_TOKEN" and not value):
            continue
        if name == "GITLAB_TOKEN" and not _gitlab_host(host):
            continue
        return name, value
    return None


class _PinnedHTTPS(http.client.HTTPSConnection):
    """One HTTPS request to the address Analyzer already checked, never to a redirect target."""

    def __init__(self, remote: Remote, address: str):
        super().__init__(remote.host, remote.port, timeout=10, context=ssl.create_default_context())
        self._address = address

    def connect(self):
        raw = socket.create_connection((self._address, self.port), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _redirect_target(remote: Remote) -> str | None:
    """Where the host sends a Git client that asks for this URL, or None when that is unknown.

    Only a redirect that Git reported calls this, to explain why Analyzer refused to follow it.
    It sends one request with the token Git would use, does not follow the answer, and reports
    only a valid repository URL on the same host.
    """
    connection = None
    try:
        if _proxy(remote):
            return None
        headers = {"User-Agent": "appsec-analyzer", "Accept": "*/*"}
        selected = select_token(remote.host)
        if selected:
            login = f"{os.environ.get('APPSEC_GIT_USERNAME', 'git')}:{selected[1]}"
            headers["Authorization"] = "Basic " + base64.b64encode(login.encode()).decode()
        connection = _PinnedHTTPS(remote, _address(remote))
        base = urlsplit(remote.url)
        connection.request("GET", f"{base.path}/info/refs?service=git-upload-pack", headers=headers)
        response = connection.getresponse()
        location = response.getheader("Location")
        if response.status not in {301, 302, 303, 307, 308} or not location:
            return None
        target = urlsplit(urljoin(f"{remote.url}/info/refs", location))
        if target.scheme != "https" or not target.path.endswith("/info/refs"):
            return None
        repository = parse_remote(urlunsplit(("https", base.netloc, target.path.removesuffix("/info/refs"), "", "")))
        if repository is None or target.hostname != remote.host or (target.port or 443) != remote.port:
            return None
        return repository.url if repository.url != remote.url else None
    except (OSError, http.client.HTTPException, ValueError):
        return None
    finally:
        if connection is not None:
            connection.close()


def credential_hint(remote: Remote) -> str:
    """Name the variables a failed access needed, without exposing any value."""
    if remote.scheme == "ssh":
        return "load the key into the SSH agent or set APPSEC_GIT_SSH_KEY_FILE, and trust the host key in known_hosts"
    selected = select_token(remote.host)
    if selected:
        hint = f"the token from {selected[0]} was not accepted; check its value, expiry, scope and APPSEC_GIT_USERNAME"
    elif os.environ.get("GITLAB_TOKEN"):
        hint = (
            f"GITLAB_TOKEN is set but is sent only to gitlab.com and GITLAB_HOST; for {remote.host} "
            f"set GITLAB_HOST={remote.host} or pass --git-token-env GITLAB_TOKEN"
        )
    else:
        hint = (
            "set APPSEC_GIT_TOKEN, GIT_TOKEN or GITLAB_TOKEN (GitLab hosts only: gitlab.com or GITLAB_HOST), "
            "name another variable with --git-token-env NAME, or configure a Git credential helper"
        )
    return hint


def _explanation(remote: Remote, kind: str) -> str | None:
    """The cause of a failure class for this remote, or None when Git named no known cause."""
    if kind in _EXPLANATIONS:
        return _EXPLANATIONS[kind].format(host=remote.host, route=describe_route(remote))
    if kind == "redirect":
        target = _redirect_target(remote)
        if target:
            return f"the host redirects this URL to {target}, which Analyzer does not follow; use that URL"
        return f"{remote.host} redirects this URL, which Analyzer does not follow; check the repository's current URL"
    selected = select_token(remote.host) if remote.scheme == "https" else None
    if kind == "token":
        if selected:
            return credential_hint(remote)
        return (
            f"{remote.host} rejected the login from your Git credential helper; renew it, or {credential_hint(remote)}"
        )
    if kind == "login":
        return f"{remote.host} asks for a login, which a private or a missing repository can cause: " + credential_hint(
            remote
        )
    if kind in {"not_found", "forbidden"}:
        problem = "reports no repository at this URL" if kind == "not_found" else "refused access (HTTP 403)"
        if selected:
            return f"{remote.host} {problem}; check the URL and whether the token from {selected[0]} may read it"
        return f"{remote.host} {problem}; check the URL, and for a private repository: {credential_hint(remote)}"
    return None


def _base_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k not in {"SSH_ASKPASS", "DISPLAY"}}


def _credentials(remote: Remote, directory: Path) -> list[tuple[str, str]]:
    """Read only credential configuration, outside any selected repository."""
    env = {**_base_env(), "GIT_CEILING_DIRECTORIES": str(directory)}
    for key in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM"):
        if key in os.environ:
            env[key] = os.environ[key]
    proc = subprocess.run(
        ["git", "config", "--null", "--get-urlmatch", "credential", remote.url],
        cwd=directory,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if proc.returncode not in {0, 1} or len(proc.stdout) > 65_536:
        raise RemoteError("Git credential configuration could not be read")
    result = []
    for row in proc.stdout.decode("utf-8").split("\0"):
        key, _, value = row.partition("\n")
        if key.lower() in {"credential.helper", "credential.username", "credential.usehttppath"}:
            result.append((key, value))
    return result


def _git_env(remote: Remote, directory: Path) -> dict[str, str]:
    proxy = _proxy(remote)
    if proxy:
        _check_allowlist(remote)
    address = None if proxy else _address(remote)
    env = _base_env()
    for name in (*TOKEN_ENV, os.environ.get(TOKEN_NAME_ENV)):
        env.pop(name, None)
    config = [
        ("core.hooksPath", os.devnull),
        ("core.fsmonitor", "false"),
        ("protocol.allow", "never"),
        (f"protocol.{remote.scheme}.allow", "always"),
        ("http.followRedirects", "false"),
        ("http.sslVerify", "true"),
        ("http.proxy", proxy or ""),
        ("credential.interactive", "false"),
    ]
    if remote.scheme == "https":
        config.extend(_credentials(remote, directory))
        if address:
            pinned = f"[{address}]" if ":" in address else address
            config.append(("http.curloptResolve", f"{remote.host}:{remote.port}:{pinned}"))
        selected = select_token(remote.host)
        if selected:
            for value in (selected[1], os.environ.get("APPSEC_GIT_USERNAME", "git")):
                if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
                    raise RemoteError("Git credential environment values must be nonempty single lines")
            # The helper reads this name, whichever variable supplied the token.
            env["APPSEC_GIT_TOKEN"] = selected[1]
            helper = "!" + shlex.join([sys.executable, str(Path(__file__).resolve()), "--credential"])
            config.extend([("credential.helper", ""), ("credential.helper", helper)])
    else:
        ssh = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "CanonicalizeHostname=no",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            f"Hostname={address}",
            "-o",
            f"HostKeyAlias={remote.host if remote.port == 22 else f'[{remote.host}]:{remote.port}'}",
            "-o",
            "ConnectTimeout=20",
        ]
        key = os.environ.get("APPSEC_GIT_SSH_KEY_FILE")
        if key:
            path = Path(key).expanduser().resolve(strict=True)
            if not path.is_file():
                raise RemoteError("APPSEC_GIT_SSH_KEY_FILE must name an existing key file")
            ssh.extend(["-o", "IdentitiesOnly=yes", "-i", str(path)])
        env["GIT_SSH_COMMAND"] = shlex.join(ssh)
        env["GIT_SSH_VARIANT"] = "ssh"
        env.pop("APPSEC_GIT_TOKEN", None)
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_ASKPASS="false",
        SSH_ASKPASS="false",
        GCM_INTERACTIVE="never",
        GIT_LFS_SKIP_SMUDGE="1",
        GIT_CONFIG_COUNT=str(len(config)),
        # _FAILURES matches Git's untranslated wording.
        LC_ALL="C",
    )
    for i, (key, value) in enumerate(config):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


def _within_limits(root: Path) -> None:
    size = count = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        count += len(dirs) + len(files)
        for name in files:
            try:
                size += (Path(parent) / name).lstat().st_size
            except FileNotFoundError:
                pass
        if count > MAX_ENTRIES or size > MAX_BYTES:
            raise RemoteError("Remote checkout exceeded its byte or entry limit")


def _stop(proc: subprocess.Popen) -> None:
    """Stop the whole child group before releasing or deleting its checkouts."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    except ProcessLookupError:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait()


class _Stderr(threading.Thread):
    """The end of a child's stderr, where Git states the failure.

    Reading to the end keeps a talkative host from stalling the child; keeping only the end bounds memory.
    """

    def __init__(self, stream):
        super().__init__(daemon=True)
        self._stream = stream
        self._end = b""
        self.start()

    def run(self):
        with self._stream:
            for chunk in iter(lambda: self._stream.read1(4096), b""):
                self._end = (self._end + chunk)[-STDERR_BYTES:]

    def kind(self) -> str:
        """The failure class Git stated. A host's own ``remote:`` lines cannot choose it."""
        self.join(1)
        lines = self._end.decode("utf-8", "replace").splitlines()
        text = "\n".join(line for line in lines if not line.startswith("remote:"))
        return next((kind for kind, pattern in _FAILURES if re.search(pattern, text)), "unknown")


def _git(command: list[str], root: Path, env: dict[str, str], hint="", scheme: str = "ssh") -> None:
    deadline = time.monotonic() + FETCH_SECONDS
    proc = subprocess.Popen(
        ["git", *command],
        cwd=root.parent,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    stderr = _Stderr(proc.stderr)
    try:
        while proc.poll() is None:
            _within_limits(root)
            if time.monotonic() > deadline:
                raise RemoteError("Remote checkout timed out")
            time.sleep(0.1)
        _within_limits(root)
        if proc.returncode:
            checks = "credentials and trusted SSH host keys" if scheme == "ssh" else "and credentials"
            detail = hint() if callable(hint) else hint
            raise _GitFailed(
                f"Git checkout failed; check repository access, {checks}" + (f": {detail}" if detail else ""),
                stderr.kind(),
            )
    finally:
        _stop(proc)


def _require_git_version() -> None:
    version = subprocess.run(
        ["git", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    match = re.search(rb"git version (\d+)\.(\d+)", version.stdout)
    if version.returncode or not match or tuple(map(int, match.groups())) < (2, 34):
        raise RemoteError("Git URL provisioning requires Git 2.34 or newer")


def _with_git_suffix(remote: Remote) -> Remote | None:
    """The same path with .git. HTTPS only: over SSH, Git finds such a repository by itself."""
    if remote.scheme != "https" or remote.url.endswith(".git"):
        return None
    return parse_remote(remote.url + ".git")


def _explained(failed: _GitFailed, remote: Remote, failure: str) -> RemoteError:
    detail = _explanation(remote, failed.kind)
    return RemoteError(f"{failure}: {detail}") if detail else failed


def _attempt(action, remote: Remote, failure: str) -> str | None:
    """Run ``action`` on the selected URL and, when the suffix can help, once more with .git.

    Each attempt builds its own Git environment, so it passes the destination checks and refuses
    redirects. Returns the URL that worked when it is not the selected one. A failed second attempt
    is the one reported: a first redirect says little about what the host holds at the .git URL.
    """
    try:
        action(remote)
        return None
    except _GitFailed as failed:
        second = _with_git_suffix(remote) if failed.kind in _SUFFIX_CAN_HELP else None
        if second is None:
            raise _explained(failed, remote, failure) from None
    try:
        action(second)
    except _GitFailed as failed:
        raise _explained(failed, second, failure) from None
    return second.url


def clone(remote: Remote, root: Path) -> str | None:
    """Check out the repository. Returns the URL used when it is not the selected one."""
    _require_git_version()
    env: dict[str, str] = {}

    def fetch(target: Remote) -> None:
        nonlocal env
        env = _git_env(target, root.parent)
        _git(
            [
                "clone",
                "--quiet",
                "--depth=1",
                "--single-branch",
                "--no-tags",
                "--no-checkout",
                "--template=",
                "--",
                target.url,
                str(root),
            ],
            root,
            env,
            lambda: credential_hint(target),
            target.scheme,
        )

    used = _attempt(fetch, remote, "Git checkout failed")
    # No global filters, hooks or repository-supplied submodule commands run.
    clean = {k: v for k, v in env.items() if k not in SECRET_ENV}
    _git(["-C", str(root), "checkout", "--quiet", "--detach", "HEAD"], root, clean)
    return used


def check_access(remote: Remote) -> str | None:
    """Check read access without downloading objects or retaining remote output.

    Returns the URL that worked when it is not the selected one.
    """
    try:
        _require_git_version()
    except (OSError, subprocess.SubprocessError):
        raise RemoteError("Git preflight could not check the installed Git version") from None
    return _attempt(_read_head, remote, "Git preflight failed")


def _read_head(remote: Remote) -> None:
    with tempfile.TemporaryDirectory(prefix="appsec-git-check-") as work:
        directory = Path(work)
        try:
            env = _git_env(remote, directory)
        except (OSError, subprocess.SubprocessError, UnicodeError):
            raise RemoteError("Git preflight could not prepare credentials or trusted SSH configuration") from None
        proc = None
        try:
            proc = subprocess.Popen(
                ["git", "ls-remote", "--quiet", "--exit-code", "--", remote.url, "HEAD"],
                cwd=directory,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            stderr = _Stderr(proc.stderr)
            code = proc.wait(timeout=PREFLIGHT_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RemoteError(
                f"Git preflight timed out after {PREFLIGHT_TIMEOUT} s reaching {describe_route(remote)}; "
                "check network access, or set HTTPS_PROXY if a proxy is required, and retry"
            ) from None
        except OSError:
            raise RemoteError("Git preflight could not start; check Git and credential-helper installation") from None
        finally:
            if proc is not None:
                _stop(proc)
        if code == 2:
            raise RemoteError("Git preflight found no HEAD; select a repository with a default-branch commit")
        if code:
            checks = "credentials and trusted SSH host keys" if remote.scheme == "ssh" else "and credentials"
            raise _GitFailed(
                f"Git preflight failed; check repository URL, read permission, {checks}: " + credential_hint(remote),
                stderr.kind(),
            )


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise RemoteError("Temporary checkout directory must be private and owned by this user")
    finally:
        os.close(fd)


def temporary_area() -> Path:
    return Path(tempfile.gettempdir()).resolve() / f"appsec-remotes-{os.getuid()}"


def _row(symbol: str, status: str, label: str, message: str) -> None:
    """A progress row in the layout of the ``Preflight`` rows."""
    from renderers.term_style import Style

    style = Style.for_stream(sys.stderr)
    print(f"  {style(symbol, status)} {style(f'{label:<12}', 'muted')}{message}", file=sys.stderr, flush=True)


def _check_directories(directories: list[Path], output: Path) -> None:
    """Make the checks admission can no longer make once a copy stands in for each directory."""
    for directory in directories:
        if output == directory or directory in output.parents or output in directory.parents:
            raise RemoteError("Output must be outside the selected directory")
    for first, second in itertools.combinations(directories, 2):
        if first == second or first in second.parents or second in first.parents:
            raise RemoteError("Duplicate or overlapping repository selections")


@contextmanager
def checkout_arguments(argv: list[str], on_clone=None):
    """Resolve URLs and directories without Git atomically; never mutate caller-owned local roots.

    ``on_clone(number, total, remote)`` runs after each completed clone.
    """
    # Imported here: this file also runs as a credential helper, without the engine on its path.
    from runtime.multi_repo_scope import ScopeError
    from runtime.plain_directory import copy_to_checkout, no_git_directory

    indexes = [i + 1 for i, a in enumerate(argv) if a == "--repo" and i + 1 < len(argv)]
    remotes = {i: remote for i in indexes if (remote := parse_remote(argv[i])) is not None}
    directories = {i: root for i in indexes if i not in remotes and (root := no_git_directory(argv[i])) is not None}
    if not remotes and not directories:
        yield argv
        return
    if len(indexes) > MAX_REPOSITORIES or len({r.url for r in remotes.values()}) != len(remotes):
        raise RemoteError("Select at most 16 distinct repositories")
    outputs = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--output"]
    if len(outputs) != 1 or not outputs[0] or outputs[0].startswith("--"):
        raise RemoteError("Git URLs and directories without Git require an explicit --output")
    output = Path(outputs[0]).resolve()
    _check_directories(list(directories.values()), output)
    parent = temporary_area()
    if output == parent or parent in output.parents or output in parent.parents:
        raise RemoteError("Output must be outside the temporary checkout area")
    _private_directory(parent)
    workspace = parent / hashlib.sha256(os.fsencode(output)).hexdigest()
    _private_directory(workspace)
    guard = os.open(workspace / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    created: list[Path] = []
    try:
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RemoteError("Another assessment is using this output directory") from None
        result = argv.copy()
        quiet = "--quiet" in argv
        for number, (index, remote) in enumerate(remotes.items(), start=1):
            slot = workspace / hashlib.sha256(remote.url.encode()).hexdigest()
            _private_directory(slot)
            root = slot / remote.name
            if root.exists() or root.is_symlink():
                raise RemoteError("A stale temporary checkout remains after an unclean stop; remove it before retrying")
            created.append(root)
            label = "Repository" if len(remotes) == 1 else f"Repo {number}/{len(remotes)}"
            if not quiet:
                _row("·", "muted", label, f"cloning {remote.name} from {describe_route(remote)}, latest commit only")
            started = time.monotonic()
            used = clone(remote, root)
            if not quiet:
                _row("✓", "ok", label, f"cloned in {time.monotonic() - started:.0f} s")
            # Shown with --quiet too: it decides what reaches a model.
            if used:
                _row("·", "muted", label, f"used {used}, because the URL without .git failed")
            if on_clone:
                on_clone(number, len(remotes), remote)
            result[index] = str(root)
        for number, (index, source) in enumerate(directories.items(), start=1):
            slot = workspace / (DIRECTORY_SLOT + hashlib.sha256(os.fsencode(source)).hexdigest())
            _private_directory(slot)
            root = slot / source.name
            if root.exists() or root.is_symlink():
                raise RemoteError("A stale temporary checkout remains after an unclean stop; remove it before retrying")
            created.append(root)
            label = "Repository" if len(directories) == 1 else f"Directory {number}/{len(directories)}"
            try:
                copy_to_checkout(source, root)
            except ScopeError as exc:
                raise RemoteError(str(exc)) from None
            if not quiet:
                _row("✓", "ok", label, f"copied {source.name} into a temporary directory, removed after the run")
            # Shown with --quiet too: it decides what reaches a model.
            if not (source / ".gitignore").is_file():
                _row(
                    "⚠", "warn", label, f"no .gitignore in {source.name}: build output and dependencies count as source"
                )
            result[index] = str(root)
        yield result
    finally:
        for root in reversed(created):
            if root.is_symlink():
                root.unlink()
            elif root.exists():
                shutil.rmtree(root)
        os.close(guard)


def _credential() -> int:
    """Git's private helper pipe, never the runner's output or an on-disk file."""
    if sys.argv[-1] != "get":
        return 0
    # Git supplies the canonical destination; redirects and rewrites are disabled.
    request = dict(line.split("=", 1) for line in sys.stdin.read(8192).splitlines() if "=" in line)
    if request.get("protocol") != "https":
        return 1
    token = os.environ.get("APPSEC_GIT_TOKEN", "")
    if not token:
        return 1
    print("username=" + os.environ.get("APPSEC_GIT_USERNAME", "git"))
    print("password=" + token)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["--credential"]:
        return _credential()
    print("Remote repository provisioning is internal; use appsec-analyzer assess --repo URL", file=sys.stderr)
    return 2


def _wait(proc: subprocess.Popen) -> int:
    code = proc.wait()
    return code if code >= 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
