"""Bundled defaults must work from installed wheels and fail closed on bad data."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from appsec_analyzer import cli, organization
from appsec_analyzer.profiles import ProfileError

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/organization-distribution"


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    root = tmp_path / "org-package"
    shutil.copytree(EXAMPLE / "src/nordlicht_appsec", root)
    monkeypatch.setattr(organization, "files", lambda package: root)
    return root


def change(path, **updates):
    document = yaml.safe_load(path.read_text())
    document.update(updates)
    path.write_text(yaml.safe_dump(document))


def test_bundled_defaults_apply_before_assessment_without_environment_or_cwd_lookup(bundle, tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path / "application")], check=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APPSEC_ADVISOR_ORG_PROFILE", "/not-the-bundled-profile.yaml")
    seen = []
    monkeypatch.setattr(cli, "_assess", lambda ns: seen.append(ns) or 0)
    assert organization.main("nordlicht_appsec", ["scan", "--repo", str(tmp_path / "application")]) == 0
    assert seen[0].org_profile == str(bundle / "org-profile.yaml")
    assert seen[0].run_profile["settings"]["budget"] == 20
    assert seen[0].run_profile["settings"]["outputs"] == ["markdown", "yaml", "sarif"]
    assert seen[0].run_profile["models"]["stride_analyzer"]["model"] == "sonnet"


@pytest.mark.parametrize("override", ["--org-profile=/operator/profile.yaml", "--no-org-profile"])
def test_explicit_operator_choices_override_distribution_defaults(bundle, monkeypatch, override):
    seen = []
    monkeypatch.setattr(cli, "_assess", lambda ns: seen.append(ns) or 0)
    assert organization.main("nordlicht_appsec", ["scan", "--profile=claude", "--budget=5", override]) == 0
    assert seen[0].run_profile["settings"]["budget"] == 5
    assert seen[0].org_profile == (None if override == "--no-org-profile" else "/operator/profile.yaml")
    assert seen[0].no_org_profile == (override == "--no-org-profile")


def test_show_and_validate_do_not_start_assessment(bundle, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_assess", lambda ns: pytest.fail("Offline inspection cannot call a model"))
    assert organization.main("nordlicht_appsec", ["organization", "validate"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] and result["organization"]["id"] == "nordlicht"
    assert result["defaults_overridable"] is True


@pytest.mark.parametrize("field,value", [("engine_version", "999.0.0"), ("interface_version", 99), ("extra", True)])
def test_incompatible_or_unknown_manifest_fields_fail_before_dispatch(bundle, monkeypatch, capsys, field, value):
    change(bundle / "organization.yaml", **{field: value})
    monkeypatch.setattr(cli, "main", lambda *a, **kw: pytest.fail("Invalid package cannot reach the CLI"))
    assert organization.main("nordlicht_appsec", ["scan"]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("relative", ["../outside.yaml", "/outside.yaml", "profiles/../../outside.yaml"])
def test_manifest_cannot_escape_package(bundle, relative):
    change(bundle / "organization.yaml", scan_profile=relative)
    with pytest.raises(ProfileError, match="inside"):
        organization.load("nordlicht_appsec")


@pytest.mark.parametrize(
    "resource", ["organization.yaml", "org-profile.yaml", "profiles/standard.yaml", "model-profiles/nordlicht.yaml"]
)
def test_missing_bundled_resources_stop_without_fallback(bundle, resource):
    (bundle / resource).unlink()
    with pytest.raises(ProfileError):
        organization.load("nordlicht_appsec")


def test_symlinked_resource_is_rejected(bundle, tmp_path):
    resource = bundle / "org-profile.yaml"
    external = tmp_path / "external.yaml"
    resource.rename(external)
    resource.symlink_to(external)
    with pytest.raises(ProfileError, match="symlink"):
        organization.load("nordlicht_appsec")


@pytest.mark.parametrize(
    "content", ["!!python/object/apply:os.system ['touch forbidden']", "schema_version: 1\nschema_version: 2"]
)
def test_unsafe_or_ambiguous_manifest_is_rejected(bundle, content):
    (bundle / "organization.yaml").write_text(content)
    with pytest.raises(ProfileError):
        organization.load("nordlicht_appsec")
    assert not (bundle / "forbidden").exists()


def test_invalid_context_and_advisor_only_integration_are_rejected(bundle):
    context = bundle / "context/organization.md"
    context.unlink()
    with pytest.raises(ProfileError, match="organization profile is invalid"):
        organization.load("nordlicht_appsec")
    context.write_text("Fictional context")
    change(bundle / "org-profile.yaml", skill_toggles={"appsec-analyzer": True})
    with pytest.raises(ProfileError, match="unsupported Advisor"):
        organization.load("nordlicht_appsec")


def test_distribution_cannot_be_selected_from_assessed_sources(bundle, monkeypatch):
    monkeypatch.setattr(cli, "_assess", lambda ns: pytest.fail("Source-owned defaults cannot reach a host"))
    assert organization.main("nordlicht_appsec", ["scan", "--repo", str(bundle)]) == 2


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    root = tmp_path_factory.mktemp("org-installed")
    subprocess.run(["git", "init", "-q", str(root / "project")], check=True)
    source = root / "engine"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "build", "dist", "__pycache__", "*.egg-info", ".pytest_cache", ".coverage-data"
        ),
    )
    dist = root / "dist"
    for cwd in (source, source / "examples/organization-distribution"):
        command = (
            [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist), str(cwd)]
            if cwd == source
            else [sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(dist), "sdist", "--dist-dir", str(dist)]
        )
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=90,
        )
        assert result.returncode == 0, result.stderr
    venv = root / "venv"
    result = subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(venv)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    result = subprocess.run(
        [
            str(venv / "bin/python"),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            *map(str, dist.glob("*.whl")),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("APPSEC_", "PYTHONPATH"))}
    environment["APPSEC_CLAUDE_EXECUTABLE"] = "/nonexistent/provider"
    environment["PATH"] = str(venv / "bin") + os.pathsep + environment["PATH"]
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        environment.pop(key, None)
    # Neither checkout nor the runtime's current directory supplies defaults.
    shutil.rmtree(source)
    return root, venv, environment, dist


def run_installed(installed, *args):
    root, venv, environment, _ = installed
    return subprocess.run(
        [str(venv / "bin/nordlicht-appsec"), *args],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=45,
    )


def test_installed_wheel_uses_bundled_defaults_after_source_checkout_is_removed(installed):
    result = run_installed(installed, "organization", "validate")
    assert result.returncode == 0, result.stderr
    doc = json.loads(result.stdout)
    assert doc["valid"] and doc["organization"]["id"] == "nordlicht"
    assert "/site-packages/nordlicht_appsec/" in doc["defaults"]["org_profile"]
    result = run_installed(installed, "version")
    assert json.loads(result.stdout)["organization"]["profile_version"] == "1.0.0"


def test_installed_profiles_reach_actual_runtime_resolution(installed):
    root, venv, environment, _ = installed
    result = subprocess.run(
        [
            str(venv / "bin/python"),
            "-c",
            "\n".join(
                [
                    "from appsec_analyzer import cli, resource_root",
                    "from appsec_analyzer.organization import load",
                    "bundle = load('nordlicht_appsec')",
                    "ns = cli._parser(organization=bundle).parse_args(['scan','--repo',"
                    + repr(str(root / "project"))
                    + "])",
                    "bundle.apply(ns)",
                    "cli._prepare_profile(ns)",
                    "cli._engine_imports()",
                    "from runtime.resolve_config import resolve",
                    "cfg = resolve(['--org-profile', ns.org_profile, '--output',"
                    + repr(str(root / "assessment"))
                    + "], resource_root())",
                    "assert cfg['org_profile']['id'] == 'nordlicht'",
                    "assert cfg['preset']['name'] == 'standard'",
                    "assert cfg['org_profile_context_documents'][0]['loaded'] is True",
                    "assert ns.run_profile['settings']['budget'] == 20",
                    "print('resolved')",
                ]
            ),
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "resolved"


def test_installed_source_scan_needs_no_provider(installed):
    root, _, _, _ = installed
    repo = root / "source-scan"
    repo.mkdir()
    (repo / "app.py").write_text("def example(value):\n    return value\n")
    for command in (
        ["git", "init", "-q", str(repo)],
        ["git", "-C", str(repo), "add", "app.py"],
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        ],
    ):
        subprocess.run(command, check=True, capture_output=True)
    result = run_installed(installed, "scan-sources", "--repo", str(repo), "--json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["assessment_status"] == "not_run"


def test_wheel_and_source_archive_include_organization_data_and_ci_example(installed):
    _, _, _, dist = installed
    with zipfile.ZipFile(next(dist.glob("nordlicht_appsec-*.whl"))) as archive:
        names = set(archive.namelist())
    for name in (
        "organization.yaml",
        "org-profile.yaml",
        "profiles/standard.yaml",
        "model-profiles/nordlicht.yaml",
        "abuse-cases/orders.yaml",
        "context/organization.md",
        "requirements/orders.yaml",
    ):
        assert "nordlicht_appsec/" + name in names
    with tarfile.open(next(dist.glob("nordlicht-appsec-*.tar.gz"))) as archive:
        names = {"/".join(name.split("/")[1:]) for name in archive.getnames()}
    assert "ci/assess.sh" in names and "requirements.lock" in names
    assert "ci/gitlab-ci.yml.example" in names


def test_installed_command_fails_closed_when_its_org_profile_is_missing(installed):
    result = run_installed(installed, "organization", "show")
    assert result.returncode == 0, result.stderr
    path = Path(json.loads(result.stdout)["defaults"]["org_profile"])
    backup = path.with_suffix(".backup")
    path.rename(backup)
    try:
        result = run_installed(installed, "scan", "--repo", "/does-not-exist")
        assert result.returncode == 2
        assert "profile is missing" in result.stderr
        assert "Model budget" not in result.stderr
    finally:
        backup.rename(path)


@pytest.mark.parametrize("code", [0, 1, 2, 3, 20, 130])
def test_ci_script_preserves_assessment_exit_code(tmp_path, code):
    fake = tmp_path / "nordlicht-appsec"
    fake.write_text(
        '#!/bin/sh\nif [ "$1" = organization ]; then exit 0; fi\ncase " $* " in *" --non-interactive "*) ;; *) exit 99 ;; esac\nexit '
        + str(code)
        + "\n"
    )
    fake.chmod(0o700)
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "ASSESSMENT_REPO": "/work/source",
        "ASSESSMENT_OUTPUT": "/private/output",
    }
    result = subprocess.run(["sh", str(EXAMPLE / "ci/assess.sh")], env=env, capture_output=True, text=True)
    assert result.returncode == code


def test_gitlab_example_has_protected_manual_execution_and_valid_shell():
    document = yaml.safe_load((EXAMPLE / "ci/gitlab-ci.yml.example").read_text())
    job = document["appsec-assessment"]
    assert job["allow_failure"] is False
    assert job["rules"][0]["when"] == "manual" and job["rules"][1] == {"when": "never"}
    assert 'CI_COMMIT_REF_PROTECTED == "true"' in job["rules"][0]["if"]
    assert 'CI_PIPELINE_SOURCE != "merge_request_event"' in job["rules"][0]["if"]
    assert job["artifacts"]["when"] == "always" and job["artifacts"]["access"] == "maintainer"
    for field in ("before_script", "script", "after_script"):
        for shell in job[field]:
            result = subprocess.run(["sh", "-n"], input=shell, text=True, capture_output=True)
            assert result.returncode == 0, result.stderr


def test_demo_launcher_reports_missing_engine_support_without_traceback(monkeypatch, capsys):
    launcher = runpy.run_path(str(EXAMPLE / "src/nordlicht_appsec/cli.py"))
    monkeypatch.setitem(sys.modules, "appsec_analyzer.organization", None)
    assert launcher["main"]() == 2
    error = capsys.readouterr().err
    assert "matching approved engine" in error and "Traceback" not in error


def _composition_config(tmp_path):
    document = {
        "schema_version": 1,
        "engine_version": "0.1.0a0",
        "advisor_core_version": "1.4.0",
        "profile": {
            "api_version": "appsec-advisor.org-profile/v2",
            "organization": {"id": "sample", "name": "Sample", "profile_version": "1"},
            "compatibility": {"core": ">=1 <2"},
            "default_preset": "daily",
            "presets": {"daily": {"base_mode": "standard"}, "release": {"base_mode": "thorough"}},
            "policy": {"disable_opus": True, "url_allowlist": ["git.example.org"]},
        },
    }
    path = tmp_path / "engine-config.yaml"
    path.write_text(json.dumps(document))
    return path, document


@pytest.mark.parametrize(
    "preset,depth,expected", [(None, None, "standard"), ("release", None, "thorough"), ("release", "quick", "quick")]
)
def test_composition_config_preserves_defaults_and_mandatory_policy(tmp_path, capsys, preset, depth, expected):
    path, document = _composition_config(tmp_path)
    args = ["organization-config", "show", "--config", str(path)]
    if preset:
        args += ["--preset", preset]
    if depth:
        args += ["--assessment-depth", depth]
    assert cli.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["defaults"]["assessment_depth"] == expected
    assert result["policy"] == document["profile"]["policy"]
    assert result["score_uses_assessment_depth"] is False
    assert result["supported_commands"] == ["score"]


@pytest.mark.parametrize(
    "case",
    ["host", "data-policy", "guardrail", "engine-version", "core-version", "preset", "host-format", "missing-preset"],
)
def test_composition_config_rejects_unsupported_fields_and_destinations(tmp_path, monkeypatch, capsys, case):
    path, document = _composition_config(tmp_path)
    args = ["organization-config", "run", "--config", str(path)]
    if case == "host":
        document["profile"]["hooks"] = {}
    elif case == "data-policy":
        document["profile"]["llm_policy"] = {"approval_required_actions": ["publish"]}
    elif case == "guardrail":
        document["profile"]["presets"]["daily"]["guardrails"] = {"soft_budget_usd": 10}
    elif case == "engine-version":
        document["engine_version"] = "99.0"
    elif case == "core-version":
        document["advisor_core_version"] = "3.0"
    elif case == "preset":
        args += ["--preset", "absent"]
    elif case == "host-format":
        document["profile"]["policy"]["url_allowlist"] = ["https://git.example.org"]
    elif case == "missing-preset":
        document["profile"]["default_preset"] = "absent"
    path.write_text(json.dumps(document))
    monkeypatch.setattr(cli, "_score", lambda ns: pytest.fail("Rejected policy must precede score and Git"))
    assert cli.main([*args, "--", "score", "https://unlisted.example.net/project.git"]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "selection,permitted",
    [
        ("/local/project", True),
        ("https://git.example.org/team/project.git", True),
        ("git@sub.git.example.org:team/other.git", True),
        ("https://git.example.org.attacker.net/team/project.git", False),
        ("git@elsewhere.example.net:team/other.git", False),
    ],
)
def test_composition_allowlist_is_checked_before_score_or_credentials(tmp_path, monkeypatch, selection, permitted):
    path, _ = _composition_config(tmp_path)
    seen = []
    monkeypatch.setattr(cli, "_score", lambda ns: seen.append(ns.repo) or 7)
    assert cli.main(["organization-config", "run", "--config", str(path), "--", "score", selection]) == (
        7 if permitted else 2
    )
    assert seen == ([selection] if permitted else [])


@pytest.mark.parametrize(
    "content",
    [
        "!!python/object/apply:os.system ['touch forbidden']",
        "schema_version: 1\nschema_version: 1",
        "profile: &x {}\ncopy: *x",
        "{}",
    ],
)
def test_composition_config_rejects_unsafe_or_missing_data(tmp_path, content):
    path = tmp_path / "bad.yaml"
    path.write_text(content)
    assert cli.main(["organization-config", "validate", "--config", str(path)]) == 2
    assert not (tmp_path / "forbidden").exists()


def test_composition_config_rejects_source_owned_profile_and_unsupported_workflow(tmp_path, monkeypatch):
    path, _ = _composition_config(tmp_path)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.setattr(cli, "_score", lambda ns: pytest.fail("Source-owned config must fail"))
    assert cli.main(["organization-config", "run", "--config", str(path), "--", "score", str(tmp_path)]) == 2
    assert cli.main(["organization-config", "run", "--config", str(path), "--", "assess"]) == 2


@pytest.mark.parametrize(
    "arguments", [["show", "--", "ignored"], ["run", "--assessment-depth", "quick", "--", "score", "/local/project"]]
)
def test_composition_config_does_not_ignore_inapplicable_arguments(tmp_path, arguments):
    path, _ = _composition_config(tmp_path)
    assert cli.main(["organization-config", arguments[0], "--config", str(path), *arguments[1:]]) == 2


def test_composition_config_empty_preset_is_an_error(tmp_path):
    path, _ = _composition_config(tmp_path)
    assert cli.main(["organization-config", "show", "--config", str(path), "--preset", ""]) == 2


def test_composition_config_rejects_invalid_advisor_version_identifier(tmp_path):
    path, document = _composition_config(tmp_path)
    document["advisor_core_version"] = "invalid-version"
    path.write_text(json.dumps(document))
    assert cli.main(["organization-config", "validate", "--config", str(path)]) == 2


@pytest.mark.parametrize("missing,marker", [("missing-service", "directory"), ("absent-api", "file")])
def test_composition_missing_source_retains_operational_exit_with_ancestor_git_marker(
    tmp_path, monkeypatch, missing, marker
):
    path, _ = _composition_config(tmp_path)
    if marker == "directory":
        (tmp_path / ".git").mkdir()
    else:
        (tmp_path / ".git").write_text("gitdir: elsewhere")
    observed = []
    monkeypatch.setattr(cli, "_score", lambda ns: observed.append(ns.repo) or 1)
    source = str(tmp_path / missing)
    assert cli.main(["organization-config", "run", "--config", str(path), "--", "score", source]) == 1
    assert observed == [source]
