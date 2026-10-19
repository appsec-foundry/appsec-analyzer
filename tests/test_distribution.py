"""Organization distribution scaffolding: init and update-engine."""

import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_analyzer import ENGINE_VERSION, INTERFACE_VERSION, cli, distribution


@pytest.fixture
def created(tmp_path):
    return distribution.init("acme", str(tmp_path / "acme-appsec"))


def _text(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def test_init_creates_a_distribution_the_engine_accepts(created):
    # Load in a fresh interpreter so the package name cannot clash with another test.
    code = (
        "import sys; from appsec_analyzer.organization import load; "
        "o = load('acme_appsec'); print(o.command, o.identity['id'])"
    )
    done = subprocess.run(
        [sys.executable, "-c", code],
        env={"PYTHONPATH": f"{created / 'src'}:{Path(distribution.__file__).parents[1]}"},
        cwd=created,
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.split() == ["acme-appsec", "acme"]


def test_init_uses_the_organization_name_everywhere(created):
    files = _text(created)
    assert not [p for p in files if "nordlicht" in p.lower()]
    assert not [p for p, text in files.items() if "nordlicht" in text.lower()]
    assert "fictional example" not in files["src/acme_appsec/org-profile.yaml"]
    assert "acme-appsec = acme_appsec.cli:main" in files["setup.cfg"]


def test_init_pins_the_installed_engine(created):
    manifest = (created / "src/acme_appsec/organization.yaml").read_text()
    assert f"engine_version: {ENGINE_VERSION}" in manifest
    assert f"interface_version: {INTERFACE_VERSION}" in manifest
    assert f"appsec-analyzer=={ENGINE_VERSION}" in (created / "setup.cfg").read_text()
    assert f"appsec-analyzer=={ENGINE_VERSION}" in (created / "requirements.lock").read_text()


def test_init_copies_no_credentials_results_or_caches(created):
    names = {p.name for p in created.rglob("*")}
    assert not {"__pycache__", ".env"} & names
    assert not [p for p in created.rglob("*") if p.suffix in {".pyc", ".pem", ".key"}]


def test_init_makes_no_network_connection(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("distribution init must not use the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    distribution.init("acme", str(tmp_path / "x"))


@pytest.mark.parametrize("name", ["", "A", "Acme", "a", "1acme", "ac-me", "ac_me", "../x", "a" * 31])
def test_init_rejects_names_that_are_not_safe_identifiers(tmp_path, name):
    with pytest.raises(distribution.DistributionError):
        distribution.init(name, str(tmp_path / "x"))
    assert not (tmp_path / "x").exists()


def test_init_never_overwrites_a_non_empty_target(tmp_path):
    target = tmp_path / "existing"
    target.mkdir()
    (target / "setup.cfg").write_text("mine")
    with pytest.raises(distribution.DistributionError):
        distribution.init("acme", str(target))
    assert _text(target) == {"setup.cfg": "mine"}


def test_init_accepts_an_existing_empty_directory(tmp_path):
    (tmp_path / "empty").mkdir()
    assert distribution.init("acme", str(tmp_path / "empty")).is_dir()


def test_init_refuses_a_symlinked_target(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(distribution.DistributionError):
        distribution.init("acme", str(tmp_path / "link"))
    assert not list(real.iterdir())


def _set_old_pins(root: Path, version: str = "0.0.1") -> None:
    for relative in ("setup.cfg", "requirements.lock", "src/acme_appsec/organization.yaml"):
        path = root / relative
        path.write_text(path.read_text().replace(ENGINE_VERSION, version))
    manifest = root / "src/acme_appsec/organization.yaml"
    manifest.write_text(manifest.read_text().replace(f"interface_version: {INTERFACE_VERSION}", "interface_version: 0"))


def test_update_engine_sets_every_pin_to_the_installed_engine(created):
    _set_old_pins(created)
    changes = distribution.update_engine(str(created))
    assert {c["pin"] for c in changes} == {
        "engine dependency",
        "engine lock entry",
        "engine_version",
        "interface_version",
    }
    assert all(c["new"] in (ENGINE_VERSION, str(INTERFACE_VERSION)) for c in changes)
    assert f"engine_version: {ENGINE_VERSION}" in (created / "src/acme_appsec/organization.yaml").read_text()
    assert f"interface_version: {INTERFACE_VERSION}" in (created / "src/acme_appsec/organization.yaml").read_text()
    assert f"=={ENGINE_VERSION}" in (created / "setup.cfg").read_text()
    assert not distribution.diverged(distribution.update_engine(str(created)))


def test_update_engine_reports_pins_that_had_drifted_apart(created):
    path = created / "setup.cfg"
    path.write_text(path.read_text().replace(f"appsec-analyzer=={ENGINE_VERSION}", "appsec-analyzer==0.0.1"))
    assert distribution.diverged(distribution.update_engine(str(created)))


def test_update_engine_changes_nothing_when_a_pin_is_missing(created):
    _set_old_pins(created)
    lock = created / "requirements.lock"
    lock.write_text("\n".join(line for line in lock.read_text().splitlines() if "appsec-analyzer" not in line))
    before = _text(created)
    with pytest.raises(distribution.DistributionError, match="nothing was changed"):
        distribution.update_engine(str(created))
    assert _text(created) == before


def test_update_engine_changes_nothing_when_a_pin_is_ambiguous(created):
    path = created / "requirements.lock"
    path.write_text(path.read_text() + f"appsec-analyzer=={ENGINE_VERSION}\n")
    before = _text(created)
    with pytest.raises(distribution.DistributionError):
        distribution.update_engine(str(created))
    assert _text(created) == before


def test_update_engine_refuses_a_symlinked_file_and_does_not_write_through_it(created, tmp_path):
    outside = tmp_path / "outside.lock"
    outside.write_text("appsec-analyzer==0.0.1\n")
    (created / "requirements.lock").unlink()
    (created / "requirements.lock").symlink_to(outside)
    with pytest.raises(distribution.DistributionError):
        distribution.update_engine(str(created))
    assert outside.read_text() == "appsec-analyzer==0.0.1\n"


def test_update_engine_refuses_a_package_directory_that_leaves_the_repository(created, tmp_path):
    outside = tmp_path / "elsewhere"
    (created / "src/acme_appsec").rename(outside)
    (created / "src/acme_appsec").symlink_to(outside)
    before = _text(outside)
    with pytest.raises(distribution.DistributionError, match="inside the organization repository"):
        distribution.update_engine(str(created))
    assert _text(outside) == before


def test_update_engine_needs_exactly_one_organization_package(tmp_path, created):
    with pytest.raises(distribution.DistributionError):
        distribution.update_engine(str(tmp_path / "missing"))
    second = created / "src/other_appsec"
    second.mkdir()
    (second / "organization.yaml").write_text("engine_version: 0.0.1\n")
    with pytest.raises(distribution.DistributionError):
        distribution.update_engine(str(created))


def test_cli_init_and_update_engine_report_and_exit_zero(tmp_path, capsys):
    assert cli.main(["distribution", "init", "acme", str(tmp_path / "acme-appsec")]) == 0
    assert cli.main(["distribution", "update-engine", str(tmp_path / "acme-appsec")]) == 0
    assert "engine_version" in capsys.readouterr().out


def test_cli_errors_exit_two_without_a_traceback(tmp_path, capsys):
    assert cli.main(["distribution", "init", "Bad Name", str(tmp_path / "x")]) == 2
    assert cli.main(["distribution", "update-engine", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err


def test_the_installed_organization_command_does_not_offer_distribution():
    with pytest.raises(SystemExit):
        cli.main(["distribution", "init", "acme"], organization=SimpleNamespace(command="acme-appsec"))
