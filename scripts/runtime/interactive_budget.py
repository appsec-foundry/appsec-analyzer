"""Explicit terminal approval of a higher assessment spending limit."""

from __future__ import annotations

import os
import re
import select
import sys

from runtime.analyst_host import HostCancelled

_CI_MARKERS = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "JENKINS_URL",
    "BUILD_BUILDID",
    "BUILDKITE",
    "CIRCLECI",
    "TEAMCITY_VERSION",
)


def can_prompt(*, non_interactive=False, quiet=False, json_output=False) -> bool:
    if non_interactive or quiet or json_output:
        return False
    if any(os.environ.get(key, "").strip().lower() not in {"", "0", "false", "no"} for key in _CI_MARKERS):
        return False
    return sys.stdin.isatty() and sys.stderr.isatty()


class BudgetPrompt:
    def __init__(self, state, *, report, pause, role_labels):
        self.state = state
        self.budget = state.budget
        self.report, self.pause, self.role_labels = report, pause, role_labels
        self.declined = False

    def _readline(self, should_stop):
        while True:
            if should_stop():
                raise HostCancelled("Assessment cancelled while awaiting budget approval")
            self.budget.remaining_seconds()
            ready, _, _ = select.select([sys.stdin], [], [], 0.5)
            if ready:
                return sys.stdin.readline(128)

    def __call__(self, should_stop):
        if self.declined or len(self.state.state.get("budget_authorizations", [])) >= 16:
            return
        previous = self.budget.max_usd
        _, role, optional = getattr(self.budget._local, "job", (None, None, False))
        label = self.role_labels.get(role, "model analysis")
        consequence = "continue with unchecked work" if optional else "stop with incomplete results"
        self.pause(True)
        try:
            self.report(
                f"Budget approval needed: USD {self.budget.spent_usd:.2f} spent of {previous:.2f}; "
                f"{label} cannot fit after required reservations. Running model calls have finished. "
                "More budget does not guarantee completion."
            )
            for _ in range(3):
                sys.stderr.write(f"New TOTAL budget in USD (greater than {previous:.2f}), or Enter to {consequence}: ")
                sys.stderr.flush()
                line = self._readline(should_stop)
                if not line.strip() or len(line) >= 128:
                    break
                if re.fullmatch(r"[0-9]{1,9}(?:\.[0-9]{1,2})?", line.strip()):
                    amount = float(line.strip())
                    if amount > previous:
                        if should_stop():
                            raise HostCancelled("Assessment cancelled")
                        self.state.approve_budget_increase(amount)
                        self.report(
                            f"Budget increase authorized: USD {previous:.2f} -> {amount:.2f} total for this run."
                        )
                        return
                sys.stderr.write("Enter a higher total USD amount using a decimal point, or press Enter to decline.\n")
            self.declined = True
            self.report(f"Budget unchanged at USD {previous:.2f}; no further budget prompts in this process.")
        finally:
            self.pause(False)
