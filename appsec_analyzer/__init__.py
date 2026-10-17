"""Standalone AppSec Analyzer command and resource boundary."""

from __future__ import annotations

from pathlib import Path

INTERFACE_VERSION = 1
ENGINE_VERSION = "0.1.0a0"


def resource_root() -> Path:
    """Locate the source tree or the wheel's private copy of engine resources."""
    package = Path(__file__).resolve().parent
    if (package / "scripts").is_dir():
        return package
    source = package.parent
    if (source / "scripts").is_dir() and (source / "schemas").is_dir():
        return source
    raise RuntimeError("AppSec Analyzer runtime resources are missing")
