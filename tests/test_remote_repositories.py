"""Remote provisioning exercises real Git with an offline SSH transport fixture."""

from __future__ import annotations

import io
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime import remote_repositories as remote

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch):
    for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)


def git(*args, cwd=None, env=None, input=None):
    return subprocess.run(["git", *args], cwd=cwd, env=env, input=input, text=True, capture_output=True, check=True)


@pytest.fixture
def transport(tmp_path, monkeypatch):
    """Keep Git's clone and checkout real; replace only the network transport."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(remote.tempfile, "gettempdir", lambda: str(scratch))
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.delenv("APPSEC_GIT_TOKEN", raising=False)
    monkeypatch.delenv("APPSEC_GIT_SSH_KEY_FILE", raising=False)
    cfg = tmp_path / "operator.gitconfig"
    cfg.write_text("")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    sources = {}
    for name in ("storefront", "ledger"):
        root = tmp_path / name
        root.mkdir()
        git("init", "-q", cwd=root)
        git("config", "user.name", "Fixture", cwd=root)
        git("config", "user.email", "fixture@example.invalid", cwd=root)
        (root / "source.txt").write_text(f"source for {name}\n")
        (root / ".gitattributes").write_text("*.txt filter=untrusted\n")
        git("add", ".", cwd=root)
        git("commit", "-qm", "fixture", cwd=root)
        sources[f"team/{name}.git"] = str(root)
        sources[f"/team/{name}.git"] = str(root)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ssh = bin_dir / "ssh"
    ssh.write_text(
        f"#!{sys.executable}\nimport os, sys, json, shlex\n"
        "command = shlex.split(sys.argv[-1])\n"
        "assert command[0] == 'git-upload-pack'\n"
        "source = json.loads(os.environ['FIXTURE_SOURCES'])[command[1]]\n"
        "os.execvp('git-upload-pack', ['git-upload-pack', source])\n"
    )
    ssh.chmod(0o700)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("FIXTURE_SOURCES", json.dumps(sources))
    return scratch


@pytest.mark.parametrize(
    "url",
    [
        "https://git.example/team/storefront.git",
        "ssh://git@git.example/team/ledger.git",
        "git@git.example:team/storefront.git",
        "ssh://git@git.example:2222/team/storefront.git",
        "ssh://git@[2001:db8::1]/team/storefront.git",
    ],
)
def test_supported_urls(url):
    selected = remote.parse_remote(url)
    assert selected.scheme in {"https", "ssh"}
    assert selected.name in {"storefront", "ledger"}
    if url.startswith("git@"):
        assert selected.url == url


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@git.example/team/a.git",
        "https://secret@git.example/team/a.git",
        "ssh://git:secret@git.example/team/a.git",
        "file:///tmp/a",
        "git://git.example/a",
        "ext::sh -c bad",
        "ssh://-option/a",
        "ssh://git@git.example/a/../b",
        "https://git.example/%2e%2e/a",
        "https://git.example/a?token=secret",
        "https://git.example/a#secret",
        "https://git.example/a\nforged",
        "git@git.example:team/$(bad)",
        "ssh://git@git.example:0/a",
        "https://git.example:99999/a",
    ],
)
def test_malformed_or_credential_urls_fail_without_echo(url):
    with pytest.raises(remote.RemoteError) as error:
        remote.parse_remote(url)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("url", ["git@git.example:team/storefront.git", "ssh://git@git.example/team/ledger.git"])
def test_real_checkout_and_cleanup_with_stable_identity(transport, tmp_path, url):
    args = ["--repo", url, "--output", str(tmp_path / "reports"), "--full"]
    paths = []
    for _ in range(2):
        with remote.checkout_arguments(args) as resolved:
            root = Path(resolved[1])
            paths.append(root)
            assert (root / "source.txt").read_text().startswith("source for ")
            assert len(git("rev-parse", "HEAD", cwd=root).stdout.strip()) == 40
            output = Path(resolved[3])
            output.mkdir(exist_ok=True)
            (output / "state.json").write_text("preserved")
        assert not root.exists()
        assert (output / "state.json").read_text() == "preserved"
    assert paths[0] == paths[1]


def test_multiple_urls_and_local_paths_share_one_invocation(transport, tmp_path, monkeypatch):
    local = tmp_path / "local"
    local.mkdir()
    git("init", "-q", cwd=local)
    args = [
        "--repo",
        "git@git.example:team/storefront.git",
        "--repo",
        str(local),
        "--repo",
        "ssh://git@git.example/team/ledger.git",
        "--output",
        str(tmp_path / "report"),
    ]
    reported = []
    clone = remote.clone
    cloned = []
    monkeypatch.setattr(
        remote, "clone", lambda selected, root: (clone(selected, root), cloned.append(selected.name))[0]
    )
    on_clone = lambda number, total, selected: reported.append((number, total, selected.name, list(cloned)))  # noqa: E731
    with remote.checkout_arguments(args, on_clone=on_clone) as result:
        roots = [Path(result[i]) for i in (1, 3, 5)]
    # Reported after each completed clone, never for a local path.
    assert reported == [(1, 2, "storefront", ["storefront"]), (2, 2, "ledger", ["storefront", "ledger"])]
    assert not roots[0].exists() and not roots[2].exists()
    with remote.checkout_arguments(args) as result:
        roots = [Path(result[i]) for i in (1, 3, 5)]
        assert all(root.is_dir() for root in roots)
        assert result[3] == str(local)
    assert local.is_dir()
    assert not roots[0].exists() and not roots[2].exists()


def test_concurrent_output_is_refused_and_existing_checkout_preserved(transport, tmp_path):
    args = ["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "report")]
    with remote.checkout_arguments(args) as result:
        with pytest.raises(remote.RemoteError, match="Another assessment"):
            with remote.checkout_arguments(args):
                pass
        assert (Path(result[1]) / "source.txt").is_file()


def test_local_only_does_not_clone_or_require_output(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "clone", lambda *_: pytest.fail("local checkout must not be cloned"))
    args = ["--repo", str(tmp_path / "local")]
    with remote.checkout_arguments(args) as result:
        assert result == args


def test_checkout_failure_cleans_earlier_and_partial_roots(transport, tmp_path, monkeypatch):
    original = remote.clone
    roots = []

    def fail_second(selected, root):
        roots.append(root)
        if len(roots) == 2:
            root.mkdir()
            raise remote.RemoteError("fixture failure")
        original(selected, root)

    monkeypatch.setattr(remote, "clone", fail_second)
    args = [
        "--repo",
        "git@git.example:team/storefront.git",
        "--repo",
        "git@git.example:team/ledger.git",
        "--output",
        str(tmp_path / "report"),
    ]
    with pytest.raises(remote.RemoteError, match="fixture failure"):
        with remote.checkout_arguments(args):
            pass
    assert len(roots) == 2 and all(not r.exists() for r in roots)
    assert not (tmp_path / "report").exists()


@pytest.mark.parametrize(
    "args",
    [
        ["--repo", "https://git.example/a"],
        ["--repo", "https://git.example/a", "--repo", "https://git.example/a", "--output", "reports"],
        ["--repo", "https://git.example/a"] * 17 + ["--output", "reports"],
    ],
)
def test_admission_precedes_network(args, monkeypatch):
    monkeypatch.setattr(remote, "clone", lambda *_: pytest.fail("must reject before cloning"))
    with pytest.raises(remote.RemoteError):
        with remote.checkout_arguments(args):
            pass


def config(env):
    return [(env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"]) for i in range(int(env["GIT_CONFIG_COUNT"]))]


def test_environment_token_reaches_git_helper_without_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.setenv("APPSEC_GIT_TOKEN", "synthetic-test-token")
    monkeypatch.setenv("APPSEC_GIT_USERNAME", "fixture-user")
    selected = remote.parse_remote("https://git.example/team/source.git")
    env = remote._git_env(selected, tmp_path)
    result = git(
        "credential", "fill", cwd=tmp_path, env=env, input="protocol=https\nhost=git.example\npath=team/source.git\n\n"
    )
    assert "password=synthetic-test-token" in result.stdout
    assert "username=fixture-user" in result.stdout
    assert all("synthetic-test-token" not in v for _, v in config(env))
    assert not list(tmp_path.iterdir())


def test_operator_helper_and_username_configuration_is_preserved(tmp_path, monkeypatch):
    cfg = tmp_path / "operator.gitconfig"
    cfg.write_text('[credential "https://git.example"]\n helper = cache\n username = fixture\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    result = remote._credentials(remote.parse_remote("https://git.example/team/a.git"), tmp_path)
    assert ("credential.helper", "cache") in result
    assert ("credential.username", "fixture") in result


def test_transport_pinning_authentication_and_configuration_isolation(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.delenv("APPSEC_GIT_TOKEN", raising=False)
    monkeypatch.setenv("GIT_SSL_NO_VERIFY", "true")
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=no")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/fixture/agent.sock")
    key = tmp_path / "key with spaces"
    key.write_text("synthetic, not a private key")
    monkeypatch.setenv("APPSEC_GIT_SSH_KEY_FILE", str(key))
    env = remote._git_env(remote.parse_remote("ssh://git@git.example:2222/team/a.git"), tmp_path)
    command = shlex.split(env["GIT_SSH_COMMAND"])
    assert "BatchMode=yes" in command and "StrictHostKeyChecking=yes" in command
    assert "Hostname=192.0.2.10" in command and "HostKeyAlias=[git.example]:2222" in command
    assert "ProxyCommand=none" in command and "ControlPath=none" in command
    assert command[-1] == str(key) and env["SSH_AUTH_SOCK"] == "/fixture/agent.sock"
    assert "GIT_SSL_NO_VERIFY" not in env
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    https = remote._git_env(remote.parse_remote("https://git.example/team/a.git"), tmp_path)
    cfg = dict(config(https))
    assert cfg["http.curloptResolve"] == "git.example:443:192.0.2.10"
    assert cfg["http.followRedirects"] == "false" and cfg["http.sslVerify"] == "true"
    assert cfg["protocol.allow"] == "never" and cfg["core.hooksPath"] == os.devnull


def test_https_proxy_from_environment_is_used_without_local_resolution(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.setattr(remote, "_address", lambda _: pytest.fail("the proxy resolves the Git host"))
    monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@proxy.example:3128")
    target = remote.parse_remote("https://git.example/team/a.git")
    cfg = dict(config(remote._git_env(target, tmp_path)))
    assert cfg["http.proxy"] == "http://user:secret@proxy.example:3128"
    assert "http.curloptResolve" not in cfg
    assert cfg["http.followRedirects"] == "false" and cfg["http.sslVerify"] == "true"
    assert remote.describe_route(target) == "git.example via proxy proxy.example:3128"
    assert "secret" not in remote.describe_route(target)


def test_proxy_keeps_the_host_allowlist_and_honours_no_proxy(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("APPSEC_URL_ALLOWLIST", "git.example")
    with pytest.raises(remote.RemoteError, match="ALLOWLIST"):
        remote._git_env(remote.parse_remote("https://other.example/team/a.git"), tmp_path)
    monkeypatch.setenv("NO_PROXY", "git.example")
    direct = dict(config(remote._git_env(remote.parse_remote("https://git.example/team/a.git"), tmp_path)))
    assert direct["http.proxy"] == "" and direct["http.curloptResolve"] == "git.example:443:192.0.2.10"


@pytest.mark.parametrize("value", ["file:///tmp/p", "proxy.example:3128", "http://", "http://p.example:99999"])
def test_unusable_proxy_is_rejected(value, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", value)
    with pytest.raises(remote.RemoteError, match="HTTPS_PROXY"):
        remote._proxy(remote.parse_remote("https://git.example/team/a.git"))


def test_ssh_remote_ignores_http_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    assert remote._proxy(remote.parse_remote("git@git.example:team/a.git")) is None


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1"])
def test_prohibited_network_destinations_fail_before_transport(monkeypatch, address):
    monkeypatch.delenv("APPSEC_URL_ALLOWLIST", raising=False)
    monkeypatch.setattr(remote.socket, "getaddrinfo", lambda *_a, **_k: [(0, 0, 0, "", (address, 443))])
    with pytest.raises(remote.RemoteError, match="prohibited"):
        remote._address(remote.parse_remote("https://git.example/team/a.git"))


def test_private_operator_destination_and_host_allowlist(monkeypatch):
    monkeypatch.setenv("APPSEC_URL_ALLOWLIST", "git.example")
    monkeypatch.setattr(remote.socket, "getaddrinfo", lambda *_a, **_k: [(0, 0, 0, "", ("10.2.3.4", 443))])
    assert remote._address(remote.parse_remote("https://git.example/team/a.git")) == "10.2.3.4"
    with pytest.raises(remote.RemoteError, match="allowlist|ALLOWLIST"):
        remote._address(remote.parse_remote("https://other.example/team/a.git"))


def test_oversized_checkout_fails_and_cleans(transport, tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "MAX_BYTES", 1)
    with pytest.raises(remote.RemoteError, match="limit"):
        with remote.checkout_arguments(
            ["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "reports")]
        ):
            pass
    assert not list(transport.rglob("source.txt"))


def test_insecure_or_symlinked_temporary_directory_is_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o755)
    with pytest.raises(remote.RemoteError, match="private"):
        remote._private_directory(target)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        remote._private_directory(link)


def test_headless_routes_urls_before_authentication_and_preserves_argv(tmp_path):
    plugin = tmp_path / "plugin"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / ".claude-plugin/plugin.json").write_text("{}")
    scripts = plugin / "scripts/runtime"
    scripts.mkdir(parents=True)
    (scripts / "remote_repositories.py").write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n")
    args = ["--repo", "git@git.example:team/a.git", "--repo", "/local with spaces", "--output", "/reports with spaces"]
    proc = subprocess.run(
        [str(ROOT / "scripts/run-headless.sh"), *args],
        env={**os.environ, "CLAUDE_PLUGIN_DIR": str(plugin)},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == args


@pytest.mark.parametrize("exit_code", [0, 7, -15])
def test_runner_exit_cleanup_and_secret_removal(transport, tmp_path, monkeypatch, exit_code):
    scripts = tmp_path / "plugin/scripts"
    (scripts / "runtime").mkdir(parents=True)
    monkeypatch.setattr(remote, "__file__", str(scripts / "runtime/remote_repositories.py"))
    runner = scripts / "run-headless.sh"
    runner.write_text(
        f"#!{sys.executable}\nimport json, os, sys, pathlib, signal\n"
        f"pathlib.Path({str(tmp_path / 'received.json')!r}).write_text(json.dumps([sys.argv[1:], 'APPSEC_GIT_TOKEN' in os.environ]))\n"
        + ("os.kill(os.getpid(), signal.SIGTERM)\n" if exit_code < 0 else f"sys.exit({exit_code})\n")
    )
    runner.chmod(0o700)
    monkeypatch.setenv("APPSEC_GIT_TOKEN", "synthetic-test-token")
    result = remote.main(["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "reports")])
    assert result == (3 if exit_code < 0 else exit_code)
    args, token_present = json.loads((tmp_path / "received.json").read_text())
    assert not token_present and not Path(args[1]).exists()


def test_fetch_timeout_kills_transport_and_cleans(transport, tmp_path, monkeypatch):
    ssh = tmp_path / "bin/ssh"
    ssh.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(60)\n")
    monkeypatch.setattr(remote, "FETCH_SECONDS", 0.05)
    start = time.monotonic()
    with pytest.raises(remote.RemoteError, match="timed out"):
        with remote.checkout_arguments(
            ["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "reports")]
        ):
            pass
    assert time.monotonic() - start < 10
    assert not list(transport.rglob("storefront"))


def test_sigterm_stops_runner_and_removes_checkouts(transport, tmp_path):
    scripts = tmp_path / "plugin/scripts"
    (scripts / "runtime").mkdir(parents=True)
    ready = tmp_path / "ready"
    runner = scripts / "run-headless.sh"
    runner.write_text(
        f"#!{sys.executable}\nimport pathlib,time,sys\npathlib.Path({str(ready)!r}).write_text(sys.argv[2])\ntime.sleep(60)\n"
    )
    runner.chmod(0o700)
    harness = (
        f"import sys; sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
        "from runtime import remote_repositories as r\n"
        "r._address = lambda _: '192.0.2.10'\n"
        f"r.__file__ = {str(scripts / 'runtime/remote_repositories.py')!r}\n"
        f"raise SystemExit(r.main(['--repo','git@git.example:team/storefront.git','--output',{str(tmp_path / 'reports')!r}]))\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", harness], env={**os.environ, "TMPDIR": str(transport)})
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.exists()
        checkout = Path(ready.read_text())
        assert checkout.exists()
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 3
        assert not checkout.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def test_clone_does_not_execute_operator_filters_or_hooks(transport, tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\n")
    hook.chmod(0o700)
    cfg = tmp_path / "operator.gitconfig"
    cfg.write_text(f'[core]\n hooksPath = {hooks}\n[filter "untrusted"]\n smudge = touch {marker}\n required = true\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    with remote.checkout_arguments(
        ["--repo", "git@git.example:team/storefront.git", "--output", str(tmp_path / "report")]
    ) as args:
        assert (Path(args[1]) / "source.txt").is_file()
    assert not marker.exists()


@pytest.mark.parametrize("token", ["", "synthetic\npassword=injected"])
def test_empty_or_multiline_token_is_rejected(tmp_path, monkeypatch, token):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.setenv("APPSEC_GIT_TOKEN", token)
    with pytest.raises(remote.RemoteError, match="single lines"):
        remote._git_env(remote.parse_remote("https://git.example/team/a.git"), tmp_path)


def test_missing_credentials_fail_without_prompting(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    monkeypatch.delenv("APPSEC_GIT_TOKEN", raising=False)
    env = remote._git_env(remote.parse_remote("https://git.example/team/a.git"), tmp_path)
    proc = subprocess.run(
        ["git", "credential", "fill"],
        cwd=tmp_path,
        env=env,
        input="protocol=https\nhost=git.example\n\n",
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert proc.returncode != 0 and "password=" not in proc.stdout


def test_preflight_reads_remote_head_without_checkout(transport, capsys):
    before = sorted(str(path) for path in transport.rglob("*"))
    remote.check_access(remote.parse_remote("git@git.example:team/storefront.git"))
    assert sorted(str(path) for path in transport.rglob("*")) == before
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_preflight_git_failure_is_safe(transport):
    with pytest.raises(remote.RemoteError, match="Git preflight failed") as caught:
        remote.check_access(remote.parse_remote("git@git.example:team/nonexistent.git"))
    assert "nonexistent" not in str(caught.value)


def test_preflight_rejects_empty_repository(transport, tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    git("init", "-q", str(empty))
    monkeypatch.setenv("FIXTURE_SOURCES", json.dumps({"team/empty.git": str(empty)}))
    with pytest.raises(remote.RemoteError, match="no HEAD"):
        remote.check_access(remote.parse_remote("git@git.example:team/empty.git"))


def test_preflight_timeout_stops_child_group(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_require_git_version", lambda: None)
    monkeypatch.setattr(remote, "_git_env", lambda *a: {})
    stopped = []

    class Process:
        stderr = io.BytesIO()

        def __init__(self, args, **kwargs):
            assert args[:4] == ["git", "ls-remote", "--quiet", "--exit-code"]
            assert kwargs["stdout"] == subprocess.DEVNULL and kwargs["stderr"] == subprocess.PIPE
            assert kwargs["stdin"] == subprocess.DEVNULL and kwargs["start_new_session"]

        def wait(self, timeout):
            assert timeout == 30
            raise subprocess.TimeoutExpired("git", timeout)

    monkeypatch.setattr(remote.subprocess, "Popen", Process)
    monkeypatch.setattr(remote, "_stop", lambda proc: stopped.append(proc))
    with pytest.raises(remote.RemoteError, match=r"preflight timed out after 30 s reaching git\.example"):
        remote.check_access(remote.parse_remote("git@git.example:team/storefront.git"))
    assert len(stopped) == 1


def test_preflight_dns_denial_prevents_git_connection(monkeypatch):
    monkeypatch.setattr(remote, "_require_git_version", lambda: None)
    monkeypatch.setattr(remote.socket, "getaddrinfo", lambda *a, **kw: [(None, None, None, None, ("127.0.0.1", 22))])
    monkeypatch.setattr(remote.subprocess, "Popen", lambda *a, **kw: pytest.fail("no connection to denied address"))
    with pytest.raises(remote.RemoteError, match="prohibited"):
        remote.check_access(remote.parse_remote("git@git.example:team/storefront.git"))


def test_git_failure_is_redacted_and_partial_clone_is_removed(transport, tmp_path, capsys):
    code = remote.main(["--repo", "git@git.example:team/nonexistent.git", "--output", str(tmp_path / "reports")])
    assert code == 1
    diagnostic = capsys.readouterr().err
    assert "Git checkout failed" in diagnostic
    assert "Traceback" not in diagnostic and "nonexistent.git" not in diagnostic
    assert not list(transport.rglob("nonexistent"))


def test_clone_progress_names_the_host_route_and_completion(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setattr(remote, "clone", lambda target, root: root.mkdir())
    monkeypatch.setattr(remote.tempfile, "gettempdir", lambda: str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    argv = ["--repo", "https://git.example/team/a.git", "--output", str(tmp_path / "out")]
    with remote.checkout_arguments(argv):
        pass
    err = capsys.readouterr().err.splitlines()
    assert err[0] == "  · Repository  cloning a from git.example via proxy proxy.example:3128, latest commit only"
    assert err[1].startswith("  ✓ Repository  cloned in ")
    with remote.checkout_arguments([*argv, "--quiet"]):
        pass
    assert capsys.readouterr().err == ""


@pytest.fixture
def no_token_env(monkeypatch):
    for name in (*remote.TOKEN_ENV, remote.TOKEN_NAME_ENV, "GITLAB_HOST", "APPSEC_GIT_USERNAME", "CUSTOM_CI_PAT"):
        monkeypatch.delenv(name, raising=False)


def _https_env(tmp_path, monkeypatch, url="https://git.example/team/a.git"):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    return remote._git_env(remote.parse_remote(url), tmp_path)


def _filled(env, tmp_path, host):
    proc = subprocess.run(
        ["git", "credential", "fill"],
        cwd=tmp_path,
        env=env,
        input=f"protocol=https\nhost={host}\n\n",
        text=True,
        capture_output=True,
        timeout=5,
    )
    return proc.stdout


def test_token_variables_are_tried_in_order(tmp_path, monkeypatch, no_token_env):
    monkeypatch.setenv("GITLAB_TOKEN", "from-gitlab")
    monkeypatch.setenv("GIT_TOKEN", "from-git")
    assert "password=from-git" in _filled(_https_env(tmp_path, monkeypatch), tmp_path, "git.example")
    monkeypatch.setenv("APPSEC_GIT_TOKEN", "from-appsec")
    assert "password=from-appsec" in _filled(_https_env(tmp_path, monkeypatch), tmp_path, "git.example")
    monkeypatch.setenv("CUSTOM_CI_PAT", "from-custom")
    monkeypatch.setenv(remote.TOKEN_NAME_ENV, "CUSTOM_CI_PAT")
    env = _https_env(tmp_path, monkeypatch)
    assert "password=from-custom" in _filled(env, tmp_path, "git.example")
    assert not {"GIT_TOKEN", "GITLAB_TOKEN", "CUSTOM_CI_PAT"} & set(env)


def test_gitlab_token_reaches_only_gitlab_hosts(tmp_path, monkeypatch, no_token_env):
    monkeypatch.setenv("GITLAB_TOKEN", "from-gitlab")
    assert "password" not in _filled(_https_env(tmp_path, monkeypatch), tmp_path, "git.example")
    com = _https_env(tmp_path, monkeypatch, "https://gitlab.com/team/a.git")
    assert "password=from-gitlab" in _filled(com, tmp_path, "gitlab.com")
    monkeypatch.setenv("GITLAB_HOST", "https://git.example/")
    assert "password=from-gitlab" in _filled(_https_env(tmp_path, monkeypatch), tmp_path, "git.example")


def test_named_variable_must_be_set_is_validated_and_ignores_the_host_rule(tmp_path, monkeypatch, no_token_env):
    monkeypatch.setenv(remote.TOKEN_NAME_ENV, "CUSTOM_CI_PAT")
    with pytest.raises(remote.RemoteError, match="CUSTOM_CI_PAT is not set"):
        remote.select_token("git.example")
    monkeypatch.setenv(remote.TOKEN_NAME_ENV, "GITLAB_TOKEN")
    monkeypatch.setenv("GITLAB_TOKEN", "explicit")
    assert remote.select_token("git.example") == ("GITLAB_TOKEN", "explicit")
    monkeypatch.setenv(remote.TOKEN_NAME_ENV, "a b")
    with pytest.raises(remote.RemoteError, match="name of one environment variable"):
        remote.select_token("git.example")


def test_failure_hint_names_tried_variables_or_the_one_that_failed(monkeypatch, no_token_env):
    https = remote.parse_remote("https://git.example/team/a.git")
    hint = remote.credential_hint(https)
    assert all(n in hint for n in ("APPSEC_GIT_TOKEN", "GIT_TOKEN", "GITLAB_TOKEN", "--git-token-env"))
    monkeypatch.setenv("GITLAB_TOKEN", "ambient-secret")
    skipped = remote.credential_hint(https)
    assert "was not accepted" not in skipped and "ambient-secret" not in skipped
    assert "GITLAB_TOKEN is set but" in skipped and "GITLAB_HOST=git.example" in skipped
    assert "GITLAB_TOKEN is set but" not in remote.credential_hint(remote.parse_remote("https://gitlab.com/t/a.git"))
    monkeypatch.setenv("GIT_TOKEN", "ambient-secret")
    failed = remote.credential_hint(https)
    assert "token from GIT_TOKEN was not accepted" in failed and "ambient-secret" not in failed
    assert "SSH agent" in remote.credential_hint(remote.parse_remote("git@git.example:team/a.git"))
    bare = remote.credential_hint(remote.parse_remote("https://git.example/team/a"))
    assert "GIT_TOKEN was not accepted" in bare and "team/a" not in bare and ".git" not in bare
    with pytest.raises(remote.RemoteError) as raised:
        remote._git(["no-such-subcommand"], Path("/nonexistent-root"), dict(os.environ), failed, "https")
    assert "GIT_TOKEN was not accepted" in str(raised.value) and "SSH host keys" not in str(raised.value)
    with pytest.raises(remote.RemoteError, match="trusted SSH host keys"):
        remote._git(["no-such-subcommand"], Path("/nonexistent-root"), dict(os.environ))


def test_cli_option_names_the_token_variable_for_every_url_command(monkeypatch, no_token_env):
    from appsec_analyzer import cli

    for argv in (
        ["assess", "--repo", "https://git.example/a.git", "--git-token-env", "CUSTOM_CI_PAT"],
        ["preflight", "--git-token-env", "CUSTOM_CI_PAT"],
        ["scan-sources", "--repo", "https://git.example/a.git", "--git-token-env", "CUSTOM_CI_PAT"],
        ["score", "https://git.example/a.git", "--git-token-env", "CUSTOM_CI_PAT"],
        [
            "audit-requirements",
            "--repo",
            "https://git.example/a.git",
            "--output",
            "out",
            "--host",
            "claude-cli",
            "--demo",
            "--git-token-env",
            "CUSTOM_CI_PAT",
        ],
        ["analyze-threats", "--mr", "https://gitlab.com/g/p/-/merge_requests/1", "--git-token-env", "CUSTOM_CI_PAT"],
    ):
        ns = cli._parser().parse_args(argv)
        assert ns.git_token_env == "CUSTOM_CI_PAT", argv
    monkeypatch.setenv(remote.TOKEN_NAME_ENV, "placeholder")  # restored at teardown
    cli._use_git_token_variable(ns)
    assert os.environ[remote.TOKEN_NAME_ENV] == "CUSTOM_CI_PAT"


class _FakeConnection:
    """Records one request and answers with a fixed status and Location header."""

    status = 301
    location = "https://git.example/team/a.git/info/refs?service=git-upload-pack"
    seen: list = []

    def __init__(self, remote_, address):
        type(self).seen = [address]

    def request(self, method, path, headers):
        type(self).seen += [method, path, headers]

    def getresponse(self):
        outer = type(self)

        class Reply:
            status = outer.status

            @staticmethod
            def getheader(name):
                return outer.location

        return Reply()

    def close(self):
        pass


@pytest.fixture
def probe(monkeypatch, no_token_env):
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_proxy", lambda _: None)
    monkeypatch.setattr(remote, "_PinnedHTTPS", _FakeConnection)
    _FakeConnection.seen = []
    _FakeConnection.status = 301
    _FakeConnection.location = "https://git.example/team/a.git/info/refs?service=git-upload-pack"
    return _FakeConnection


def test_redirect_to_the_git_suffix_is_reported_and_never_followed(probe, monkeypatch):
    monkeypatch.setenv("GITLAB_HOST", "git.example")
    monkeypatch.setenv("GITLAB_TOKEN", "probe-secret")
    bare = remote.parse_remote("https://git.example/team/a")
    assert remote._redirect_target(bare) == "https://git.example/team/a.git"
    address, method, path, headers = probe.seen
    assert (address, method, path) == ("192.0.2.10", "GET", "/team/a/info/refs?service=git-upload-pack")
    assert headers["Authorization"].startswith("Basic ")
    hint = remote._explanation(bare, "redirect")
    assert "redirects this URL to https://git.example/team/a.git" in hint and "probe-secret" not in hint
    assert "was not accepted" not in hint


@pytest.mark.parametrize(
    ("status", "location"),
    [
        (301, "https://elsewhere.example/team/a.git/info/refs?service=git-upload-pack"),
        (301, "http://git.example/team/a.git/info/refs?service=git-upload-pack"),
        (301, "https://git.example/other/path"),
        (301, "https://git.example:8443/team/a.git/info/refs"),
        (301, "https://git.example/team/a/info/refs"),
        (401, "https://git.example/team/a.git/info/refs"),
        (200, None),
    ],
)
def test_only_a_same_host_repository_redirect_is_reported(probe, status, location):
    probe.status, probe.location = status, location
    assert remote._redirect_target(remote.parse_remote("https://git.example/team/a")) is None


def test_no_probe_through_a_proxy_or_after_a_network_error(probe, monkeypatch):
    bare = remote.parse_remote("https://git.example/team/a")
    monkeypatch.setattr(remote, "_proxy", lambda _: "http://proxy.example:3128")
    assert remote._redirect_target(bare) is None
    assert probe.seen == []
    monkeypatch.setattr(remote, "_proxy", lambda _: None)

    def refuse(*_):
        raise ConnectionRefusedError

    monkeypatch.setattr(remote, "_PinnedHTTPS", refuse)
    assert remote._redirect_target(bare) is None


def test_only_a_redirect_that_git_reported_is_probed(probe):
    moved = remote.parse_remote("https://git.example/old/a.git")
    for kind in ("token", "login", "not_found", "forbidden", "connection", "unknown"):
        remote._explanation(moved, kind)
    assert "redirects this URL" not in remote.credential_hint(moved)
    assert probe.seen == []
    probe.location = "https://git.example/new/a.git/info/refs?service=git-upload-pack"
    assert "redirects this URL to https://git.example/new/a.git" in remote._explanation(moved, "redirect")


def test_a_redirect_without_a_known_target_says_so(probe, monkeypatch):
    monkeypatch.setattr(remote, "_proxy", lambda _: "http://proxy.example:3128")
    message = remote._explanation(remote.parse_remote("https://git.example/team/a.git"), "redirect")
    assert "git.example redirects this URL" in message and "use that URL" not in message
    assert probe.seen == []


BARE = "https://git.example/team/a"
SUFFIX = f"{BARE}.git"
# Output of Git, curl and OpenSSH in the C locale. The first eight classes were recorded from real runs;
# 403, 429 and 503 follow the recorded wording of 301, and the two SSH texts are OpenSSH's standard ones.
GIT_OUTPUT = {
    "login": (
        "error: unable to read askpass response from 'false'\n"
        "fatal: could not read Username for 'https://gitlab.com': terminal prompts disabled\n"
    ),
    "token": (
        "remote: HTTP Basic: Access denied. If a password was provided for Git authentication, the password was "
        "incorrect or you're required to use a token instead of a password.\n"
        "fatal: Authentication failed for 'https://gitlab.com/team/a.git/'\n"
    ),
    "not_found": "remote: Not found.\nfatal: repository 'https://codeberg.org/team/a.git/' not found\n",
    "redirect": "fatal: unable to access 'https://gitlab.com/team/a/': The requested URL returned error: 301\n",
    "certificate": (
        "fatal: unable to access 'https://expired.badssl.com/x.git/': "
        "server certificate verification failed. CAfile: none CRLfile: none\n"
    ),
    "proxy": "fatal: unable to access 'https://x.example/a.git/': Received HTTP code 403 from proxy after CONNECT\n",
    "name": "fatal: unable to access 'https://x.example/a.git/': Could not resolve host: x.example\n",
    "connection": (
        "fatal: unable to access 'https://127.0.0.1:9/x.git/': "
        "Failed to connect to 127.0.0.1 port 9 after 0 ms: Connection refused\n"
    ),
    "forbidden": "fatal: unable to access 'https://x.example/a.git/': The requested URL returned error: 403\n",
    "rate_limited": "fatal: unable to access 'https://x.example/a.git/': The requested URL returned error: 429\n",
    "server": "fatal: unable to access 'https://x.example/a.git/': The requested URL returned error: 503\n",
    "host_key": (
        "No ED25519 host key is known for x.example and you have requested strict checking.\n"
        "Host key verification failed.\nfatal: Could not read from remote repository.\n"
    ),
    "ssh_login": "git@x.example: Permission denied (publickey).\nfatal: Could not read from remote repository.\n",
}


@pytest.mark.parametrize(
    ("kind", "output"),
    [
        *GIT_OUTPUT.items(),
        ("certificate", "fatal: ...: SSL: certificate subject name (*.x.example) does not match target host name\n"),
        ("connection", "ssh: connect to host 127.0.0.1 port 9: Connection refused\n"),
        ("connection", "fatal: ...: GnuTLS recv error (-110): The TLS connection was non-properly terminated.\n"),
        ("name", "ssh: Could not resolve hostname x.example: Temporary failure in name resolution\n"),
        ("proxy", "fatal: unable to access 'https://x.example/a.git/': Proxy CONNECT aborted\n"),
        ("unknown", "fatal: Could not read from remote repository.\n"),
        ("unknown", ""),
    ],
)
def test_each_git_failure_maps_to_one_cause(kind, output):
    assert remote._Stderr(io.BytesIO(output.encode())).kind() == kind


def test_each_cause_has_its_own_message(monkeypatch, no_token_env):
    https = remote.parse_remote(SUFFIX)
    expected = {
        "name": "the host name git.example could not be resolved",
        "connection": "git.example could not be reached",
        "proxy": "the proxy refused the connection to git.example",
        "certificate": "the TLS certificate of git.example was not accepted",
        "host_key": "the SSH host key of git.example is unknown or has changed",
        "ssh_login": "git.example refused the SSH login",
        "rate_limited": "git.example is limiting requests",
        "server": "git.example reported a server error",
        "login": "git.example asks for a login, which a private or a missing repository can cause",
        "not_found": "git.example reports no repository at this URL",
        "forbidden": "git.example refused access",
        "token": "git.example rejected the login from your Git credential helper",
    }
    assert set(expected) == set(GIT_OUTPUT) - {"redirect"}
    for kind, text in expected.items():
        assert text in remote._explanation(https, kind)
    assert remote._explanation(https, "unknown") is None
    for kind in ("name", "connection", "proxy", "certificate", "rate_limited", "server"):
        assert "TOKEN" not in remote._explanation(https, kind)
    assert "APPSEC_GIT_TOKEN" in remote._explanation(https, "login")
    monkeypatch.setenv("GIT_TOKEN", "ambient-secret")
    messages = {kind: remote._explanation(https, kind) for kind in expected}
    assert "the token from GIT_TOKEN was not accepted" in messages["token"]
    assert "whether the token from GIT_TOKEN may read it" in messages["not_found"]
    assert "whether the token from GIT_TOKEN may read it" in messages["forbidden"]
    assert "ambient-secret" not in str(messages)
    assert "SSH agent" in remote._explanation(remote.parse_remote("git@git.example:team/a.git"), "login")


class _FakeGit:
    def __init__(self, directory):
        self.directory = directory
        self.answers = {}

    def answer(self, url, output):
        self.answers[url] = output
        (self.directory / "answers.json").write_text(json.dumps(self.answers))

    def urls(self):
        log = self.directory / "urls"
        return log.read_text().split() if log.exists() else []


@pytest.fixture
def fake_git(tmp_path, monkeypatch, no_token_env):
    """A real child process that answers each URL with recorded output; all of Analyzer stays real."""
    directory = tmp_path / "fake-git"
    directory.mkdir()
    script = directory / "git"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['--version']:\n"
        "    print('git version 2.40.0')\n"
        "    raise SystemExit\n"
        "if '--' not in args:\n"
        "    raise SystemExit\n"
        "here = pathlib.Path(__file__).parent\n"
        "url = args[args.index('--') + 1]\n"
        "with open(here / 'urls', 'a') as urls:\n"
        "    urls.write(url + '\\n')\n"
        "answers = here / 'answers.json'\n"
        "output = json.loads(answers.read_text()).get(url, '') if answers.exists() else ''\n"
        "sys.stderr.write(output)\n"
        "sys.exit(2 if output == 'no HEAD' else 128 if output else 0)\n"
    )
    script.chmod(0o700)
    monkeypatch.setenv("PATH", str(directory) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(remote, "_address", lambda _: "192.0.2.10")
    monkeypatch.setattr(remote, "_credentials", lambda *_: [])
    return _FakeGit(directory)


def test_preflight_and_clone_report_the_cause_git_stated(fake_git, tmp_path):
    fake_git.answer(SUFFIX, GIT_OUTPUT["connection"])
    target = remote.parse_remote(SUFFIX)
    with pytest.raises(remote.RemoteError, match="^Git preflight failed: git.example could not be reached") as caught:
        remote.check_access(target)
    assert "TOKEN" not in str(caught.value)
    with pytest.raises(remote.RemoteError, match="^Git checkout failed: git.example could not be reached"):
        remote.clone(target, tmp_path / "checkout")


def test_a_failure_without_a_known_cause_keeps_the_general_message(fake_git):
    fake_git.answer(SUFFIX, "fatal: Could not read from remote repository.\n")
    with pytest.raises(remote.RemoteError, match="^Git preflight failed; check repository URL") as caught:
        remote.check_access(remote.parse_remote(SUFFIX))
    assert "APPSEC_GIT_TOKEN" in str(caught.value)


def test_host_text_cannot_choose_the_cause_or_reach_the_message(fake_git):
    fake_git.answer(SUFFIX, "remote: fatal: Authentication failed for 'https://evil.example/' host-supplied-text\n")
    with pytest.raises(remote.RemoteError, match="^Git preflight failed; check repository URL") as caught:
        remote.check_access(remote.parse_remote(SUFFIX))
    assert "host-supplied-text" not in str(caught.value) and "evil.example" not in str(caught.value)


def test_long_git_output_neither_stalls_nor_reaches_the_message(fake_git):
    fake_git.answer(SUFFIX, "remote: host-supplied-text\n" * 50_000 + GIT_OUTPUT["not_found"])
    with pytest.raises(remote.RemoteError, match="reports no repository at this URL") as caught:
        remote.check_access(remote.parse_remote(SUFFIX))
    assert "host-supplied-text" not in str(caught.value)
    stderr = remote._Stderr(io.BytesIO(b"x" * 1_000_000))
    stderr.join()
    assert stderr.kind() == "unknown" and len(stderr._end) == remote.STDERR_BYTES


def test_git_output_stays_in_the_matched_language(fake_git, tmp_path):
    assert remote._git_env(remote.parse_remote(SUFFIX), tmp_path)["LC_ALL"] == "C"


@pytest.mark.parametrize("kind", ["redirect", "not_found", "login", "forbidden"])
def test_preflight_tries_the_git_suffix_and_names_the_url_that_worked(fake_git, kind):
    fake_git.answer(BARE, GIT_OUTPUT[kind])
    assert remote.check_access(remote.parse_remote(BARE)) == SUFFIX
    assert fake_git.urls() == [BARE, SUFFIX]


def test_only_a_failed_https_url_without_the_suffix_gets_a_second_attempt(fake_git):
    assert remote.check_access(remote.parse_remote(BARE)) is None
    assert fake_git.urls() == [BARE]
    fake_git.answer(SUFFIX, GIT_OUTPUT["redirect"])
    with pytest.raises(remote.RemoteError):
        remote.check_access(remote.parse_remote(SUFFIX))
    assert fake_git.urls() == [BARE, SUFFIX]
    ssh = "git@git.example:team/a"
    fake_git.answer(ssh, GIT_OUTPUT["not_found"])
    with pytest.raises(remote.RemoteError):
        remote.check_access(remote.parse_remote(ssh))
    assert fake_git.urls() == [BARE, SUFFIX, ssh]


@pytest.mark.parametrize("kind", ["name", "connection", "proxy", "certificate", "token", "rate_limited", "server"])
def test_no_second_attempt_when_the_suffix_cannot_help(fake_git, kind):
    fake_git.answer(BARE, GIT_OUTPUT[kind])
    with pytest.raises(remote.RemoteError, match="^Git preflight failed: "):
        remote.check_access(remote.parse_remote(BARE))
    assert fake_git.urls() == [BARE]


def test_an_empty_repository_gets_no_second_attempt(fake_git):
    fake_git.answer(BARE, "no HEAD")
    with pytest.raises(remote.RemoteError, match="no HEAD"):
        remote.check_access(remote.parse_remote(BARE))
    assert fake_git.urls() == [BARE]


def test_second_failure_is_the_one_reported(fake_git):
    fake_git.answer(BARE, GIT_OUTPUT["redirect"])
    fake_git.answer(SUFFIX, GIT_OUTPUT["login"])
    with pytest.raises(remote.RemoteError) as caught:
        remote.check_access(remote.parse_remote(BARE))
    message = str(caught.value)
    assert "asks for a login" in message and "APPSEC_GIT_TOKEN" in message and "use that URL" not in message
    assert fake_git.urls() == [BARE, SUFFIX]


def test_suffix_attempt_repeats_the_destination_checks(fake_git, tmp_path, monkeypatch):
    environments, destinations = [], []
    build = remote._git_env

    def checked(target, directory):
        env = build(target, directory)
        environments.append((target.url, dict(config(env))["http.followRedirects"]))
        return env

    def address(target):
        destinations.append((target.host, target.port))
        return "192.0.2.10"

    monkeypatch.setattr(remote, "_git_env", checked)
    monkeypatch.setattr(remote, "_address", address)
    fake_git.answer(BARE, GIT_OUTPUT["redirect"])
    remote.check_access(remote.parse_remote(BARE))
    assert environments == [(BARE, "false"), (SUFFIX, "false")]
    assert destinations == [("git.example", 443), ("git.example", 443)]


def test_clone_tries_the_git_suffix_and_always_names_the_url(fake_git, tmp_path, monkeypatch, capsys):
    (tmp_path / "tmp").mkdir()
    monkeypatch.setattr(remote.tempfile, "gettempdir", lambda: str(tmp_path / "tmp"))
    fake_git.answer(BARE, GIT_OUTPUT["redirect"])
    with remote.checkout_arguments(["--repo", BARE, "--output", str(tmp_path / "out"), "--quiet"]) as local:
        assert Path(local[1]).name == "a"
    assert fake_git.urls() == [BARE, SUFFIX]
    assert f"used {SUFFIX}" in capsys.readouterr().err


def test_a_failed_checkout_step_is_not_mistaken_for_a_failed_url(fake_git, tmp_path, monkeypatch):
    run = remote._git

    def fail_checkout(command, *rest):
        if "checkout" in command:
            raise remote._GitFailed("Git checkout failed", "unknown")
        run(command, *rest)

    monkeypatch.setattr(remote, "_git", fail_checkout)
    with pytest.raises(remote.RemoteError, match="Git checkout failed"):
        remote.clone(remote.parse_remote(BARE), tmp_path / "checkout")
    assert fake_git.urls() == [BARE]
