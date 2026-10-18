"""Bounded requirements catalog admission shared by analysis workflows."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import yaml

from appsec_analyzer.engine import initialize

MAX_CATALOG_BYTES = 1_048_576


def read_catalog(path: Path) -> tuple[bytes, dict]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_CATALOG_BYTES:
            raise ValueError("requirements catalog must be a bounded regular file")
        body = os.read(fd, MAX_CATALOG_BYTES + 1)
        if len(body) > MAX_CATALOG_BYTES:
            raise ValueError("requirements catalog exceeds its size limit")
    finally:
        os.close(fd)
    initialize()
    from requirements.requirements_state import validate_catalog

    errors, _warnings = validate_catalog(body)
    if errors:
        raise ValueError("requirements catalog violates its schema")
    catalog = yaml.safe_load(body)
    return body, catalog
