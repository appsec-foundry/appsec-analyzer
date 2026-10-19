"""Structured assessment invocation after public command-line validation."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass, fields


@dataclass(frozen=True)
class AssessmentOptions:
    repo: tuple[str, ...]
    output: str | None = None
    full: bool = False
    resume: bool = False
    rebuild: bool = False
    migrate_legacy: bool = False
    ignore_legacy: bool = False
    soft_budget: float | None = None
    hard_budget: float | None = None
    interactive_launch: bool = False
    max_calls: int | None = None
    max_duration: int | None = None
    max_parallel: int | None = None
    test_cases: bool = False
    pause_after: int | None = None
    model: str | None = None
    project: str | None = None
    trust_mode: str = "untrusted"
    fail_on: str | None = None
    quiet: bool = False
    non_interactive: bool = False
    verbose: bool = False
    json: bool = False
    width: int | None = None
    progress_file: str | None = None
    # Completed start checks as (symbol, label, message), shown under the run summary.
    preflight_checks: tuple[tuple[str, str, str], ...] = ()
    # The selections as given, for display: a Git URL instead of its temporary checkout.
    repo_sources: tuple[str, ...] = ()
    # Name of the environment variable that holds a read-only platform token, never the token itself.
    platform_token_env: str | None = None

    def __post_init__(self):
        from appsec_analyzer.execution_limits import validate_max_parallel

        if not self.repo or any(not isinstance(root, str) or not root for root in self.repo):
            raise ValueError("an assessment requires selected repositories")
        if self.trust_mode not in ("untrusted", "trusted"):
            raise ValueError("invalid repository trust mode")
        if self.width is not None and (type(self.width) is not int or self.width < 60):
            raise ValueError("console width must be at least 60")
        if self.max_parallel is not None:
            validate_max_parallel(self.max_parallel)
        if self.fail_on not in (None, "critical", "high", "medium"):
            raise ValueError("invalid assessment gate severity")


# The retained resolver still receives its own configuration arguments. The
# public CLI has already validated these tokens; splitting does not parse them
# again or change their spelling, ordering or resume identity.
_FLAGS_WITH_VALUE = frozenset(
    {
        "--repo",
        "--output",
        "--soft-budget",
        "--max-cost",
        "--hard-budget",
        "--max-budget",
        "--max-calls",
        "--max-duration",
        "--max-parallel",
        "--pause-after",
        "--model",
        "--project",
        "--trust-mode",
        "--fail-on",
        "--width",
        "--progress-file",
    }
)
_FLAGS = frozenset(
    {
        "--full",
        "--resume",
        "--rebuild",
        "--migrate-legacy",
        "--ignore-legacy",
        "--interactive-launch",
        "--quiet",
        "--non-interactive",
        "--verbose",
        "--json",
        "--test-cases",
    }
)


@dataclass(frozen=True)
class AssessmentRequest(Sequence[str]):
    """Options plus original arguments for legacy configuration and provenance.

    Sequence access preserves internal script adapters while the controller
    consumes the structured options directly.
    """

    options: AssessmentOptions
    arguments: tuple[str, ...]
    configuration: tuple[str, ...]

    def __len__(self):
        return len(self.arguments)

    def __getitem__(self, key):
        return self.arguments[key]

    def namespace(self) -> argparse.Namespace:
        values = {field.name: getattr(self.options, field.name) for field in fields(self.options)}
        values["repo"] = list(self.options.repo)
        return argparse.Namespace(**values)

    @classmethod
    def from_cli(cls, namespace, arguments: list[str]) -> AssessmentRequest:
        selected = {
            field.name: getattr(namespace, field.name)
            for field in fields(AssessmentOptions)
            if hasattr(namespace, field.name)
        }
        selected["repo"] = tuple(arguments[i + 1] for i, arg in enumerate(arguments[:-1]) if arg == "--repo")
        sources = tuple(getattr(namespace, "repo", None) or ())
        selected["repo_sources"] = sources if len(sources) == len(selected["repo"]) else ()
        # These are host-specific effective values, as admitted by the CLI.
        selected["max_calls"] = namespace.run_profile["settings"]["max_calls"] if "--max-calls" in arguments else None
        selected["hard_budget"] = namespace.hard_budget if "--hard-budget" in arguments else None
        remainder = []
        tokens = iter(arguments)
        for token in tokens:
            flag, equals, _ = token.partition("=")
            if flag in _FLAGS_WITH_VALUE:
                if not equals:
                    next(tokens)
            elif flag not in _FLAGS:
                remainder.append(token)
        return cls(AssessmentOptions(**selected), tuple(arguments), tuple(remainder))
