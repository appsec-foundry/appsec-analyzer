"""Structured progress emitted by the scoring workflow."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScoreEvent:
    step: str
    scanner: str | None = None
    status: str | None = None
