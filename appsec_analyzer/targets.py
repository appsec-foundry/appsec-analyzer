"""Validation of operator-selected export targets."""

import argparse
from urllib.parse import urlsplit


def pentest_target(value: str) -> str:
    if any(char.isspace() or ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise argparse.ArgumentTypeError("must be an HTTP or HTTPS URL without control characters")
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in ("http", "https") and bool(parsed.hostname) and not parsed.username and not parsed.password
        )
        _ = parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError("must be an HTTP or HTTPS URL without embedded credentials")
    return value
