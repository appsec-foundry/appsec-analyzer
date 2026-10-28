"""Provision operator-selected Git URLs for the Analyzer CLI.

Only CLI selections authorize network access; repository content cannot add
destinations. Private, stable temporary paths preserve the controller's source
identities across retries. Checkouts are ephemeral; output stays caller-owned.
"""

from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

MAX_REPOSITORIES = 16
FETCH_SECONDS = 120
PREFLIGHT_TIMEOUT = 30
MAX_BYTES = 536_870_912
MAX_ENTRIES = 100_000
SECRET_ENV = ("APPSEC_GIT_TOKEN", "APPSEC_GIT_USERNAME", "APPSEC_GIT_SSH_KEY_FILE")


class RemoteError(ValueError):
    """A safe, credential-free diagnostic for the operator."""


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
        if "APPSEC_GIT_TOKEN" in os.environ:
            for key in ("APPSEC_GIT_TOKEN", "APPSEC_GIT_USERNAME"):
                value = os.environ.get(key, "git")
                if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
                    raise RemoteError("Git credential environment values must be nonempty single lines")
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


def _git(command: list[str], root: Path, env: dict[str, str]) -> None:
    deadline = time.monotonic() + FETCH_SECONDS
    proc = subprocess.Popen(
        ["git", *command],
        cwd=root.parent,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        while proc.poll() is None:
            _within_limits(root)
            if time.monotonic() > deadline:
                raise RemoteError("Remote checkout timed out")
            time.sleep(0.1)
        _within_limits(root)
        if proc.returncode:
            raise RemoteError("Git checkout failed; check repository access, credentials and trusted SSH host keys")
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


def clone(remote: Remote, root: Path) -> None:
    _require_git_version()
    env = _git_env(remote, root.parent)
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
            remote.url,
            str(root),
        ],
        root,
        env,
    )
    # No global filters, hooks or repository-supplied submodule commands run.
    clean = {k: v for k, v in env.items() if k not in SECRET_ENV}
    _git(["-C", str(root), "checkout", "--quiet", "--detach", "HEAD"], root, clean)


def check_access(remote: Remote) -> None:
    """Check read access without downloading objects or retaining remote output."""
    try:
        _require_git_version()
    except (OSError, subprocess.SubprocessError):
        raise RemoteError("Git preflight could not check the installed Git version") from None
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
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
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
            raise RemoteError(
                "Git preflight failed; check repository URL, read permission, credentials and trusted SSH host keys"
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


@contextmanager
def checkout_arguments(argv: list[str], on_clone=None):
    """Resolve all URL selections atomically; never mutate caller-owned local roots.

    ``on_clone(number, total, remote)`` runs after each completed clone.
    """
    indexes = [i + 1 for i, a in enumerate(argv) if a == "--repo" and i + 1 < len(argv)]
    remotes = {i: remote for i in indexes if (remote := parse_remote(argv[i])) is not None}
    if not remotes:
        yield argv
        return
    if len(indexes) > MAX_REPOSITORIES or len({r.url for r in remotes.values()}) != len(remotes):
        raise RemoteError("Select at most 16 distinct repositories")
    outputs = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--output"]
    if len(outputs) != 1 or not outputs[0] or outputs[0].startswith("--"):
        raise RemoteError("Git URLs require an explicit --output outside the temporary checkouts")
    output = Path(outputs[0]).resolve()
    parent = Path(tempfile.gettempdir()).resolve() / f"appsec-remotes-{os.getuid()}"
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
            raise RemoteError("Another remote assessment is using this output directory") from None
        result = argv.copy()
        for number, (index, remote) in enumerate(remotes.items(), start=1):
            slot = workspace / hashlib.sha256(remote.url.encode()).hexdigest()
            _private_directory(slot)
            root = slot / remote.name
            if root.exists() or root.is_symlink():
                raise RemoteError("A stale temporary checkout remains after an unclean stop; remove it before retrying")
            created.append(root)
            quiet = "--quiet" in argv
            if not quiet:
                print(
                    f"Cloning {remote.name} {number}/{len(remotes)} from {describe_route(remote)} "
                    f"({remote.scheme.upper()}, latest commit only)",
                    file=sys.stderr,
                    flush=True,
                )
            started = time.monotonic()
            clone(remote, root)
            if not quiet:
                print(f"Cloned {remote.name} in {time.monotonic() - started:.0f} s", file=sys.stderr, flush=True)
            if on_clone:
                on_clone(number, len(remotes), remote)
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
