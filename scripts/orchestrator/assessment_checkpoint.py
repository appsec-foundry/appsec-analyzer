"""Private, immutable pre-summary state of the existing assessment controller.

The lifecycle still admits sources, settings and accounting. A snapshot only
skips already accepted computation under exactly the same runtime and run.
Its manifest hash is anchored in lifecycle state, outside model output.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath

from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import MAX_ARTIFACT_BYTES, digest
from runtime.assessment_state import MAX_DELIVERABLE_BYTES, _real_directory
from shared._atomic_io import atomic_write_json

MAX_ENTRIES = 8192
MAX_TOTAL_BYTES = 256 * 1024 * 1024


class _CheckpointLimit(ExchangeError):
    """A valid report may exceed the optional optimization's storage limits."""


def _read(path: Path, *, limit: int | None = None) -> bytes:
    limit = MAX_DELIVERABLE_BYTES if limit is None else limit
    if not os.path.lexists(path.parent):
        raise FileNotFoundError
    _real_directory(path.parent)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        if path.is_symlink():
            raise ExchangeError("Render checkpoint contains a link") from None
        raise
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ExchangeError("Render checkpoint input must be a bounded regular file without links")
        if info.st_size > limit:
            raise _CheckpointLimit("Render checkpoint input exceeds its byte limit")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise _CheckpointLimit("Render checkpoint input exceeds its byte limit")
    return data


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _files(directory: Path) -> dict[str, bytes]:
    if not os.path.lexists(directory):
        raise FileNotFoundError
    _real_directory(directory)
    result, total, entries = {}, 0, 0
    for root, directories, files in os.walk(directory, followlinks=False):
        entries += len(directories) + len(files)
        if entries > MAX_ENTRIES or len(Path(root).relative_to(directory).parts) > 64:
            raise _CheckpointLimit("Render checkpoint exceeds its entry limit")
        for name in directories:
            _real_directory(Path(root) / name)
        for name in sorted(files):
            path = Path(root) / name
            data = _read(path)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise _CheckpointLimit("Render checkpoint exceeds its total byte limit")
            result[path.relative_to(directory).as_posix()] = data
    return result


def _job_files(directory: Path) -> tuple[dict[str, str], list[dict]]:
    """Check all accepted artifacts, including jobs completed after the snapshot."""
    _real_directory(directory)
    hashes, receipts = {}, []
    for path in sorted(directory.glob("*.receipt.json")):
        if not re.fullmatch(r"job-[0-9a-f]{24}\.receipt\.json", path.name):
            raise ExchangeError("Render checkpoint contains an invalid job name")
        receipt_bytes = _read(path, limit=MAX_ARTIFACT_BYTES)
        receipt = json.loads(receipt_bytes)
        artifact = directory / (receipt["job_id"] + ".json")
        if not os.path.lexists(artifact):
            raise FileNotFoundError
        artifact_bytes = _read(artifact, limit=MAX_ARTIFACT_BYTES)
        if digest(json.loads(artifact_bytes)) != receipt["artifact_sha256"]:
            raise ExchangeError("Assessment job artifact changed after acceptance")
        hashes[path.name], hashes[artifact.name] = _hash(receipt_bytes), _hash(artifact_bytes)
        receipts.append(receipt)
    return hashes, receipts


def save(state, jobs, workspace: Path, data: dict, *, inputs=None) -> bool:
    """Publish the snapshot completely before referencing it from owned state."""
    try:
        files = _files(workspace)
    except _CheckpointLimit:
        return False
    job_files, _ = _job_files(jobs.directory)
    manifest = {
        "version": 1,
        "run_id": state.state["run_id"],
        "identity": state.identity,
        "inputs_sha256": digest(inputs),
        "files": {name: _hash(content) for name, content in files.items()},
        "jobs": job_files,
        "data": data,
        "job_state": {name: getattr(jobs, name) for name in ("infos", "notes", "gaps", "accepted_results")},
    }
    if len(json.dumps(manifest).encode()) > MAX_DELIVERABLE_BYTES:
        return False
    fingerprint = digest(manifest)
    destination = state.directory / ("render-checkpoint-" + fingerprint)
    with tempfile.TemporaryDirectory(prefix=".render-checkpoint-", dir=state.directory) as temporary:
        temporary = Path(temporary)
        for name, content in files.items():
            path = temporary / "workspace" / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o600)
        atomic_write_json(temporary / "manifest.json", manifest)
        if not os.path.lexists(destination):
            os.replace(temporary, destination)
        else:
            _real_directory(destination)
    state.state["render_checkpoint"] = fingerprint
    state.checkpoint()
    return True


def restore(state, jobs, workspace: Path, *, inputs=None) -> dict | None:
    """A missing snapshot falls back to replay; changed or linked input stops."""
    fingerprint = state.state.get("render_checkpoint")
    if not state.resume or state.runtime_changed or state.state["status"] == "complete" or not fingerprint:
        return None
    directory = state.directory / ("render-checkpoint-" + fingerprint)
    try:
        manifest = json.loads(_read(directory / "manifest.json"))
        if digest(manifest) != fingerprint:
            raise ExchangeError("Render checkpoint manifest changed after acceptance")
        if manifest["version"] != 1 or manifest["run_id"] != state.state["run_id"]:
            raise ExchangeError("Render checkpoint belongs to another run")
        if manifest["identity"] != state.identity:
            return None
        if manifest["inputs_sha256"] != digest(inputs):
            return None
        files = _files(directory / "workspace")
        if any(_hash(content) != manifest["files"].get(name) for name, content in files.items()):
            raise ExchangeError("Render checkpoint artifact changed after acceptance")
        if set(manifest["files"]) - set(files):
            return None
        hashes, receipts = _job_files(jobs.directory)
        if set(manifest["jobs"]) - set(hashes):
            return None
        if any(hashes[name] != expected for name, expected in manifest["jobs"].items()):
            raise ExchangeError("Render checkpoint accepted job changed")
    except FileNotFoundError:
        return None
    except ExchangeError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise ExchangeError("Render checkpoint is unreadable or malformed") from None

    # Validate everything before replacing the mutable rendering workspace.
    if os.path.lexists(workspace):
        _real_directory(workspace)
        shutil.rmtree(workspace)
    workspace.mkdir(mode=0o700)
    for name, content in files.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ExchangeError("Render checkpoint contains an invalid artifact path")
        path = workspace / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o600)
    for name, value in manifest["job_state"].items():
        if name in ("infos", "notes", "gaps", "accepted_results"):
            setattr(jobs, name, value)
    for receipt in receipts:
        if receipt["job_id"] + ".receipt.json" in manifest["jobs"]:
            jobs._record(receipt["role"])
            jobs.budget.accepted(receipt["job_id"], receipt["role"], receipt["usd"])
    if jobs.on_reused is not None:
        jobs.on_reused()
    if jobs.diagnostics:
        jobs.diagnostics.emit("render_checkpoint_reused", jobs=jobs.reused)
        for selector, accepted in jobs.accepted_results.items():
            jobs.diagnostics.job(accepted["role"], selector).emit("job_reused", checkpoint=True)
    return manifest["data"]


def discard(directory: Path) -> None:
    """Drop private snapshot copies after completion unless runtime files were requested."""
    for path in directory.glob("render-checkpoint-*"):
        if re.fullmatch(r"render-checkpoint-[0-9a-f]{64}", path.name):
            shutil.rmtree(path, ignore_errors=True)
