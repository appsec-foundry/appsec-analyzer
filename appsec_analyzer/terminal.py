"""Shared terminal field formatting for public commands."""

import re
import traceback
from pathlib import Path


def field(value: object) -> str:
    """Keep repository-controlled names and scanner text on one terminal line."""
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))).strip()[:240]


def code_location(error: BaseException) -> str:
    """The function and line of Analyzer's own code where an exception arose, or "" when none of it is involved.

    The path is relative to the installation, so it names the place without the user's home directory.
    """
    package = Path(__file__).resolve().parent
    for frame in reversed(traceback.extract_tb(error.__traceback__)):
        path = Path(frame.filename).resolve()
        if path.is_relative_to(package) or path.is_relative_to(package.parent / "scripts"):
            return f"{frame.name} ({path.relative_to(package.parent).as_posix()}:{frame.lineno})"
    return ""


def error_summary(error: BaseException) -> str:
    """An unexpected exception on one terminal line: its type, its message and where it arose."""
    message, where = field(error), code_location(error)
    return type(error).__name__ + (f": {message}" if message else "") + (f" in {where}" if where else "")
