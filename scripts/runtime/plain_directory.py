"""Give a local directory without Git the private checkout the analysis expects.

The analysis steps work on a Git checkout. A temporary copy with one commit gives
them that, so nothing is written into the selected directory. Git lists the files
from a private Git directory, so `.gitignore` applies as in a checkout. Everything
that is not copied leaves a stand-in, so admission records the same exclusions.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from runtime.multi_repo_scope import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    GitCommandFailed,
    OversizedBinary,
    OversizedText,
    ScopeError,
    _git,
    _omission,
    _read,
    _relative,
    sensitive_name,
)

TOO_LARGE = "The directory exceeds the source limits; add a .gitignore that leaves out build output and dependencies"
# A fixed identity and time: the same content yields the same commit, which --resume compares.
COMMIT_SETTINGS = ("user.name=AppSec Analyzer", "user.email=analyzer@invalid", "gc.auto=0", "maintenance.auto=false")
COMMIT_TIME = {"GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z"}
# Git does not look up the commit of a nested repository, so any value serves.
NESTED_COMMIT = "1" * 40


def no_git_directory(value: str) -> Path | None:
    """The directory ``value`` names if it lies in no Git repository, else None.

    An empty ``.git`` counts as none, because a sandbox can leave one behind. A
    ``.git`` with content stays a repository, even a damaged one: treating it as
    a plain directory would silently change which files reach a model.
    """
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        return None
    try:
        root = Path(value).resolve(strict=True)
        marker = root / ".git"
        if not root.is_dir() or (os.path.lexists(marker) and not _empty_directory(marker)):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    try:
        # Also answers inside a bare repository or a .git directory, unlike --show-toplevel.
        _git(root, "rev-parse", "--git-dir")
    except GitCommandFailed:
        return root
    return None


def _empty_directory(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink() and not any(path.iterdir())


def _listed(source: Path) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="appsec-listing-") as private:
        git_dir = Path(private)
        try:
            _git(git_dir, "init", "--quiet", "--bare", "--template=")
            listed = _git(source, "ls-files", "--others", "--exclude-standard", "-z", git_dir=git_dir)
        except ScopeError:
            raise ScopeError(
                "The directory cannot be listed; check read permissions, or add a .gitignore if it holds many files"
            ) from None
    try:
        names = [raw.decode("utf-8") for raw in listed.split(b"\0") if raw]
    except UnicodeError:
        raise ScopeError("Source paths must be valid UTF-8") from None
    if len(names) > MAX_FILES:
        raise ScopeError(TOO_LARGE)
    return names


def _nested_root(source: Path, parts: tuple[str, ...]) -> tuple[str, ...]:
    for end in range(1, len(parts) + 1):
        if os.path.lexists(source.joinpath(*parts[:end], ".git")):
            return parts[:end]
    raise ScopeError("Source changed during capture")


def _stand_in(target: Path, prefix: bytes) -> None:
    """A file too large for admission whose first bytes keep the original's classification."""
    with target.open("xb") as handle:
        handle.write(prefix)
        handle.truncate(MAX_FILE_BYTES + 1)


def _copy_file(source: Path, relative: str, target: Path) -> int:
    """Copy one file without following links; an oversized one leaves only a stand-in."""
    try:
        data = _read(source, relative)
    except OversizedBinary:
        _stand_in(target, b"\0")
        return 0
    except OversizedText:
        _stand_in(target, b" " * 8192)
        return 0
    target.write_bytes(data)
    return len(data)


def copy_to_checkout(source: Path, root: Path) -> None:
    """Create ``root`` as a one-commit checkout of what Git sees in ``source``."""
    names = _listed(source)
    root.mkdir(mode=0o700)
    _git(root, "init", "--quiet", "--template=")
    nested: set[tuple[str, ...]] = set()
    remaining = MAX_TOTAL_BYTES
    for name in names:
        parts = _relative(name.rstrip("/"))
        reason = _omission(source, parts, None)
        if reason == "nested-repository":
            nested.add(_nested_root(source, parts))
            continue
        if reason not in (None, "symlink"):
            continue
        target = root.joinpath(*parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if reason == "symlink":
            try:
                os.symlink(os.readlink(source.joinpath(*parts)), target)
            except OSError:
                raise ScopeError("Source changed during capture") from None
        elif sensitive_name(parts[-1]):
            target.touch(mode=0o600)
        else:
            remaining -= _copy_file(source, "/".join(parts), target)
            if remaining < 0:
                raise ScopeError(TOO_LARGE)
    _git(root, "add", "--all", overrides=COMMIT_SETTINGS)
    for parts in sorted(nested):
        root.joinpath(*parts).mkdir(mode=0o700, parents=True)
        _git(root, "update-index", "--add", "--cacheinfo", f"160000,{NESTED_COMMIT},{'/'.join(parts)}")
    _git(
        root,
        "commit",
        "--quiet",
        "--allow-empty",
        "--no-gpg-sign",
        "--message",
        "Directory without Git",
        overrides=COMMIT_SETTINGS,
        environment=COMMIT_TIME,
    )
