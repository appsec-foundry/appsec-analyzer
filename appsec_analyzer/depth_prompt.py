"""Ask which assessment depth to run when the user named none and a person is at the terminal (REQ-002)."""

from __future__ import annotations

import sys

_RELATIVE = {
    "quick": "lowest cost, shortest runtime",
    "standard": "medium cost and runtime",
    "thorough": "highest cost, longest runtime",
}


def _coverage(values: dict) -> str:
    if not values["verify"]:
        return "survey only, no verification"
    parts = [f"survey and verification of {len(values['verify'])} security aspects"]
    if values["abuse_cases"]:
        parts.append(f"up to {values['abuse_cases']} business rules")
    if values["architect_review"]:
        parts.append("architect review")
    return ", ".join(parts)


def choose(profiles: dict[str, dict]) -> str:
    """Return the depth the user picks; `profiles` maps each depth to its resolved scan profile.

    Enter picks standard. Nothing the user types is echoed, and an unreadable or invalid answer
    cancels, so no assessment starts without a deliberate choice.
    """
    depths = tuple(profiles)
    sys.stderr.write(
        "No --assessment-depth given. Each depth makes model calls; the limit is the most a run may cost.\n"
    )
    for number, depth in enumerate(depths, 1):
        settings = profiles[depth]["settings"]
        sys.stderr.write(
            f"  {number}) {depth:<9} {_RELATIVE[depth]}; limit USD {settings['budget']:g}; "
            f"{_coverage(settings['depth_settings'])}\n"
        )
    for _ in range(3):
        sys.stderr.write("Depth (1-3 or name, Enter for standard): ")
        sys.stderr.flush()
        line = sys.stdin.readline(128)
        if not line:
            break
        answer = line.strip().lower()
        if not answer:
            return "standard"
        if answer in depths:
            return answer
        if answer.isdecimal() and 1 <= int(answer) <= len(depths):
            return depths[int(answer) - 1]
    raise ValueError("no assessment depth chosen; nothing was started. Use --assessment-depth quick|standard|thorough")
