"""Bounded requirements catalog admission shared by analysis workflows."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import yaml

from appsec_analyzer.engine import initialize

MAX_CATALOG_BYTES = 1_048_576


def read_catalog(path: Path) -> tuple[bytes, dict, dict]:
    """Read a catalog; return its Analyzer-format bytes, the parsed catalog and what was read.

    The third value names the format and holds the checksum of the file as supplied.
    """
    initialize()
    from requirements.catalog_formats import MAX_RAW_BYTES, CatalogFormatError, normalize
    from requirements.requirements_state import validate_catalog

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_RAW_BYTES:
            raise ValueError("requirements catalog must be a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(MAX_RAW_BYTES + 1)
    finally:
        os.close(fd)
    try:
        body, source = normalize(raw)
    except CatalogFormatError as exc:
        raise ValueError(f"requirements catalog cannot be read: {exc}") from None
    if len(body) > MAX_CATALOG_BYTES:
        raise ValueError("requirements catalog exceeds its size limit")
    errors, _warnings = validate_catalog(body)
    if errors:
        raise ValueError("requirements catalog violates its schema")
    catalog = yaml.safe_load(body)
    return body, catalog, source
