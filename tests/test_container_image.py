"""The container image pins its inputs and runs without privileges or built-in credentials."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
_SPEC = importlib.util.spec_from_file_location("check_pins", ROOT / "container" / "check_pins.py")
check_pins = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_pins)
JOB_PATH = ROOT / "examples" / "openshift" / "assessment-job.yaml"
SECRET_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL", re.IGNORECASE)


def _instructions(text: str) -> list[tuple[str, str]]:
    """Dockerfile instructions with continuation lines joined; comments dropped."""
    joined = re.sub(r"\\\n", " ", "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#")))
    return [(line.split(None, 1)[0].upper(), line.split(None, 1)[1]) for line in joined.splitlines() if line.strip()]


def _unpinned_images(text: str) -> list[str]:
    stages = {args.split()[-1] for op, args in _instructions(text) if op == "FROM" and " AS " in args.upper()}
    images = [args.split()[0] for op, args in _instructions(text) if op == "FROM"]
    return [image for image in images if image not in stages and not re.search(r"@sha256:[0-9a-f]{64}$", image)]


def _unpinned_apt_packages(text: str) -> list[str]:
    unpinned = []
    for op, args in _instructions(text):
        for install in re.findall(r"apt-get install ([^&]*)", args) if op == "RUN" else ():
            unpinned += [word for word in install.split() if not word.startswith("-") and "=" not in word]
    return unpinned


def _secret_settings(text: str) -> list[str]:
    names = []
    for op, args in _instructions(text):
        if op in {"ENV", "ARG"}:
            names += [name for name in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", args) if SECRET_NAME.search(name)]
    return names


def _requirements(path: Path) -> dict[str, list[str]]:
    text = re.sub(r"\\\n", " ", path.read_text(encoding="utf-8"))
    pins = {}
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            name, rest = line.split("==", 1)
            pins[name.strip().lower().replace("_", "-")] = re.findall(r"--hash=sha256:([0-9a-f]{64})", rest)
    return pins


def test_every_base_image_is_pinned_by_digest():
    assert _unpinned_images(DOCKERFILE) == []


def test_every_debian_package_is_pinned():
    assert _unpinned_apt_packages(DOCKERFILE) == []


def _run_commands(text: str) -> str:
    return " ".join(args for op, args in _instructions(text) if op == "RUN")


def test_python_packages_are_installed_only_with_hashes():
    commands = re.findall(r"pip install [^&]*", _run_commands(DOCKERFILE))
    assert commands
    for command in commands:
        # --no-index installs only the wheel built from this checkout in the same build.
        assert "--require-hashes" in command or "--no-index" in command, command
    for name in ("requirements.txt", "build-requirements.txt"):
        pins = _requirements(ROOT / "container" / name)
        assert pins and all(pins.values()), name


def test_runtime_requirements_cover_the_package_dependencies():
    pins = _requirements(ROOT / "container" / "requirements.txt")
    setup = (ROOT / "setup.py").read_text(encoding="utf-8")
    declared = re.search(r"install_requires=\[([^\]]*)\]", setup).group(1)
    for requirement in re.findall(r'"([A-Za-z0-9_.-]+)', declared):
        assert requirement.lower() in pins, requirement


def test_claude_cli_is_checked_against_a_pinned_hash():
    hashes = re.findall(r"^ARG CLAUDE_CLI_SHA512_[A-Z0-9]+=([0-9a-f]+)$", DOCKERFILE, re.MULTILINE)
    assert len(hashes) == 2 and all(len(value) == 128 for value in hashes)
    assert re.search(r"^ARG CLAUDE_CLI_VERSION=\d+\.\d+\.\d+$", DOCKERFILE, re.MULTILINE)
    assert "sha512sum --check --strict" in _run_commands(DOCKERFILE)
    assert not re.search(r"\bnpm (install|ci|exec)\b|\bnpx\b", _run_commands(DOCKERFILE))


def test_image_runs_as_non_root_without_built_in_credentials():
    instructions = _instructions(DOCKERFILE)
    final_stage = instructions[max(index for index, (op, _) in enumerate(instructions) if op == "FROM") :]
    users = [args.strip() for op, args in final_stage if op == "USER"]
    assert users and users[-1].isdigit() and int(users[-1]) != 0
    assert _secret_settings(DOCKERFILE) == []
    assert [args for op, args in final_stage if op == "EXPOSE"] == []
    assert re.search(r'^ENTRYPOINT \["appsec-analyzer"\]$', DOCKERFILE, re.MULTILINE)


def test_build_context_keeps_git_for_the_version_stamp():
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert ".git" not in ignored and ".git/" not in ignored


def _wheel_from_tracked_files(text: str) -> bool:
    """The build copies the checkout, removes what Git does not track, then builds the wheel."""
    steps = _instructions(text)

    def first(op: str, word: str) -> int:
        return next((index for index, (name, args) in enumerate(steps) if name == op and word in args), -1)

    copy, clean, wheel = first("COPY", ". /src"), first("RUN", "git -C /src clean -ffdx"), first("RUN", "pip wheel")
    return -1 < copy < clean < wheel


@pytest.mark.parametrize(
    ("dockerfile", "expected"),
    [
        (DOCKERFILE, True),
        ("FROM x\nCOPY . /src\nRUN pip wheel /src\n", False),
        ("FROM x\nRUN git -C /src clean -ffdx\nCOPY . /src\nRUN pip wheel /src\n", False),
    ],
)
def test_wheel_contains_only_files_git_tracks(dockerfile, expected):
    # setup.py copies whole runtime directories; ignored files such as local reports must not reach the image.
    assert _wheel_from_tracked_files(dockerfile) is expected


def test_build_stops_without_readable_git_data():
    assert re.search(
        r"git -C /src rev-parse --git-dir >/dev/null\s+\|\|\s+\{[^}]*exit 1; \}", _run_commands(DOCKERFILE)
    )


def test_docker_examples_drop_rights():
    guide = re.sub(r"\\\n", " ", (ROOT / "docs" / "container.md").read_text(encoding="utf-8"))
    runs = [line for line in guide.splitlines() if line.strip().startswith("docker run")]
    assert runs
    for run in runs:
        assert "--cap-drop ALL" in run and "--security-opt no-new-privileges" in run, run


@pytest.mark.parametrize(
    ("check", "dockerfile", "found"),
    [
        (_unpinned_images, "FROM python:3.12-slim AS base\nFROM base\n", ["python:3.12-slim"]),
        (_unpinned_apt_packages, "FROM x\nRUN apt-get update && apt-get install --yes git curl=1\n", ["git"]),
        (
            _secret_settings,
            "FROM x\nENV ANTHROPIC_API_KEY=placeholder\nARG GIT_TOKEN=\n",
            ["ANTHROPIC_API_KEY", "GIT_TOKEN"],
        ),
    ],
)
def test_checks_reject_unsafe_dockerfiles(check, dockerfile, found):
    assert check(dockerfile) == found


def _job_and_pod() -> tuple[dict, dict]:
    documents = list(yaml.safe_load_all(JOB_PATH.read_text(encoding="utf-8")))
    job = next(document for document in documents if document["kind"] == "Job")
    return job, job["spec"]["template"]["spec"]


def test_openshift_job_runs_once_with_least_privilege():
    job, pod = _job_and_pod()
    assert job["spec"]["backoffLimit"] == 0
    assert pod["restartPolicy"] == "Never"
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    (container,) = pod["containers"]
    context = container["securityContext"]
    assert context["allowPrivilegeEscalation"] is False
    assert context["readOnlyRootFilesystem"] is True
    assert context["capabilities"]["drop"] == ["ALL"]
    assert "ports" not in container
    assert {"--non-interactive", "--budget", "--output", "--profile"} <= set(container["args"])


def test_openshift_job_pins_its_image_and_bounds_its_resources():
    job, pod = _job_and_pod()
    (container,) = pod["containers"]
    assert "@sha256:" in container["image"]
    assert job["spec"]["activeDeadlineSeconds"] > 0
    assert {"memory", "ephemeral-storage"} <= set(container["resources"]["limits"])


def test_openshift_job_takes_credentials_only_from_a_secret():
    _, pod = _job_and_pod()
    (container,) = pod["containers"]
    credentials = [item for item in container["env"] if SECRET_NAME.search(item["name"])]
    assert credentials
    for item in credentials:
        assert "value" not in item and "secretKeyRef" in item["valueFrom"], item["name"]
    assert not any("@" in arg for arg in container["args"] if arg.startswith("https://"))


def test_pin_check_reads_every_pin_in_the_dockerfile():
    base, claude, packages = check_pins.pins(DOCKERFILE)
    assert re.search(r"@sha256:[0-9a-f]{64}$", base)
    assert re.search(r"ARG CLAUDE_CLI_VERSION=" + re.escape(claude) + "$", DOCKERFILE, re.MULTILINE)
    installs = re.findall(r"apt-get install ([^&]*)", _run_commands(DOCKERFILE))
    expected = [word for command in installs for word in command.split() if "=" in word]
    assert expected and sorted(f"{name}={version}" for name, version in packages.items()) == sorted(expected)


def test_pin_check_reports_newer_debian_packages():
    policy = (
        "git:\n  Installed: (none)\n  Candidate: 1:2.47.3-0+deb13u2\n  Version table:\n"
        "pandoc:\n  Installed: (none)\n  Candidate: 3.1.11.1+ds-2\n"
    )
    available = check_pins.candidates(policy)
    assert available == {"git": "1:2.47.3-0+deb13u2", "pandoc": "3.1.11.1+ds-2"}
    pinned = {"git": "1:2.47.3-0+deb13u1", "pandoc": "3.1.11.1+ds-2"}
    assert check_pins.outdated(pinned, available) == ["git=1:2.47.3-0+deb13u2 (pinned 1:2.47.3-0+deb13u1)"]


@pytest.mark.parametrize(
    "dockerfile",
    [
        "FROM python:3.12 AS base\nARG CLAUDE_CLI_VERSION=1.0.0\nRUN apt-get install git=1\n",
        "FROM base\n",
    ],
)
def test_pin_check_fails_closed_on_unreadable_pins(dockerfile):
    with pytest.raises(ValueError):
        check_pins.pins(dockerfile)


def test_pin_check_fails_closed_when_apt_lacks_a_package():
    with pytest.raises(ValueError, match="curl"):
        check_pins.outdated({"curl": "1", "git": "2"}, {"git": "2"})
