"""Shared terminal field formatting for public commands."""

import re


def field(value: object) -> str:
    """Keep repository-controlled names and scanner text on one terminal line."""
    return re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))).strip()[:240]
