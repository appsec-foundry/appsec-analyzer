"""Bounded reads and exclusive publication of private result artifacts."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def read_bounded(path: Path, limit: int) -> bytes:
    """Read a regular, singly linked owned artifact without following links."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError("assessment artifact is not a bounded regular file")
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError("assessment artifact exceeds its size limit")
        return data
    finally:
        os.close(fd)


def publish_exclusive(path: Path, body: bytes) -> None:
    """Publish a complete 0600 artifact only when this run owns its name."""
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = f".{path.name}.{os.getpid()}.tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.fsync(directory)
        finally:
            os.unlink(temporary, dir_fd=directory)
    finally:
        os.close(directory)
