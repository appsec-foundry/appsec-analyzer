"""Ask which assessment depth to run when the user named none and a person is at the terminal (REQ-002)."""

from __future__ import annotations

import sys

_RELATIVE = {
    "quick": "lowest, shortest",
    "standard": "medium",
    "thorough": "highest, longest",
}


def _coverage(values: dict, depth: str = "standard") -> str:
    survey = "survey of every program file" if depth == "thorough" else "survey"
    if not values["verify"]:
        return f"{survey} only, no verification"
    parts = [f"{survey}, verification of {len(values['verify'])} security aspects"]
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
    from appsec_analyzer.assessment.console import usd_at_api_prices

    depths = tuple(profiles)
    priced = usd_at_api_prices(profiles[depths[0]].get("adapter"))
    meaning = (
        "the most subscription usage a run may take, valued at API prices" if priced else "the most a run may cost"
    )
    settings = [profiles[depth]["settings"] for depth in depths]
    limits = [f"USD {s['budget']:g}" if s["budget"] is not None else f"{s['max_calls']} calls" for s in settings]
    if len(set(limits)) == 1:
        # One limit for every depth, such as one from --budget, is named once instead of in each row.
        key = "budget" if settings[0]["budget"] is not None else "max_calls"
        flag = key.replace("_", "-")
        source = f" from --{flag}" if profiles[depths[0]]["origins"]["settings"].get(key) == "CLI" else ""
        limit_line = f"Limit: {limits[0]}{source} for every depth, {meaning}."
        columns = [""] * (len(depths) + 1)
    else:
        limit_line = f"Limit: {meaning}."
        width = max(len("Limit"), *map(len, limits))
        columns = [f"{text:<{width}}  " for text in ("Limit", *limits)]
    sys.stderr.write(f"No --assessment-depth given. Every depth makes model calls.\n{limit_line}\n\n")
    sys.stderr.write(f"     {'Depth':<9} {columns[0]}{'Cost, runtime':<16}  Covers\n")
    for number, (depth, column) in enumerate(zip(depths, columns[1:]), 1):
        sys.stderr.write(
            f"  {number}) {depth:<9} {column}{_RELATIVE[depth]:<16}  "
            f"{_coverage(profiles[depth]['settings']['depth_settings'], depth)}\n"
        )
    sys.stderr.write("\n")
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
