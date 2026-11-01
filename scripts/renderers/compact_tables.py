"""Building blocks of the report's compact tables (REQ-013).

Critical and High findings always stay visible. Only Medium and lower may collapse, and a collapsed
list keeps every entry, so nothing is lost. Cells hold Markdown links until a table becomes raw HTML;
`fixed_table` converts them, because Markdown is not processed inside an HTML block.
"""

from __future__ import annotations

import html
import re
from collections import Counter
from typing import Iterable

BADGES = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "informational": "⚪", "info": "⚪"}
_RANK = {"🔴": 0, "🟠": 1, "🟡": 2, "🟢": 3, "⚪": 4}
_NAMES = {"🟡": "Medium", "🟢": "Low", "⚪": "Info"}
_BADGE_RE = re.compile("[🔴🟠🟡🟢⚪]")
# A short list stays open: three lines cost less than a collapsed block and a click.
MIN_VISIBLE = 3
# Fixed tables must not stretch with the window: a wide window adds only empty space.
MAX_TABLE_WIDTH = "1240px"
_WRAP = "overflow-wrap:break-word"


def badge(severity: str | None) -> str:
    """The badge of a severity word, or an empty string for an unknown one."""
    return BADGES.get((severity or "").strip().lower(), "")


def token_count(count: int | None) -> str:
    """A token count for a table cell: ``850``, ``42k``, ``1.3M``, or a dash when it is unknown."""
    if count is None:
        return "–"
    if count < 1000:
        return str(count)
    return f"{count / 1000:.0f}k" if count < 1_000_000 else f"{count / 1_000_000:.1f}M"


def badge_of(entry: str) -> str:
    """The first severity badge in a table entry."""
    found = _BADGE_RE.search(entry)
    return found.group(0) if found else ""


def split_visible(entries: Iterable[str]) -> tuple[list[str], list[str]]:
    """Worst first: what stays visible, and what may collapse.

    Critical and High always stay. Lighter entries fill up to ``MIN_VISIBLE``, and one lone entry
    never collapses.
    """
    ordered = sorted(entries, key=lambda entry: _RANK.get(badge_of(entry), -1))
    shown = [entry for entry in ordered if badge_of(entry) not in _NAMES]
    rest = [entry for entry in ordered if badge_of(entry) in _NAMES]
    while len(shown) < MIN_VISIBLE and rest:
        shown.append(rest.pop(0))
    if len(rest) < 2:
        return shown + rest, []
    return shown, rest


def fold(entries: list[str]) -> str:
    """A collapsed block that names what it holds, or an empty string for no entries."""
    if not entries:
        return ""
    count = Counter(badge_of(entry) for entry in entries)
    label = " · ".join(f"{count[mark]} {_NAMES.get(mark, 'more')}" for mark in _RANK if mark in count)
    return f"<details><summary>{label}</summary>{'<br/>'.join(entries)}</details>"


def severity_tally(entries: list[str]) -> str:
    """One line that says how many findings of which severity remain open."""
    count = Counter(badge_of(entry) for entry in entries)
    names = {"🔴": "Critical", "🟠": "High", **_NAMES}
    said = " and ".join(f"{count[mark]} {names[mark]}" for mark in _RANK if mark in count)
    total = len(entries)
    return f"{said or total} finding{'' if total == 1 else 's'} remain{'s' if total == 1 else ''} open:"


def id_list(pairs: Iterable[tuple[str, str]]) -> str:
    """One badge per severity with its linked IDs behind it, one line each: a dot on every ID is only noise."""
    by_badge: dict[str, list[str]] = {}
    for mark, link in pairs:
        by_badge.setdefault(mark, []).append(f'<span style="white-space:nowrap">{link}</span>')
    # A finding without a known severity still stands in the list, after the rated ones.
    lines = [f"{mark}&nbsp;" + ", ".join(by_badge[mark]) for mark in _RANK if mark in by_badge]
    unrated = [link for mark, links in by_badge.items() if mark not in _RANK for link in links]
    return "<br/>".join(lines + ([", ".join(unrated)] if unrated else []))


def plain_text(value: object) -> str:
    """Model-authored text for a cell: it stays text and can form neither markup nor a link."""
    text = html.escape(" ".join(str(value).split()), quote=False)
    return re.sub(r"[`*_\[\]|\\]", lambda match: f"&#{ord(match.group(0))};", text)


def whole_sentences(text: str, limit: int) -> str:
    """Whole sentences up to the limit, so a text never ends inside a word."""
    kept = ""
    for sentence in re.split(r"(?<=[.!?])\s+", " ".join(str(text).split())):
        if kept and len(kept) + len(sentence) + 1 > limit:
            break
        kept = f"{kept} {sentence}".strip()
    return kept


def html_cell(cell: str) -> str:
    """Markdown of one table cell as HTML, with offered break points inside code."""
    cell = re.sub(r"\[([^\]]+)\]\((#[^)]+)\)", r'<a href="\2">\1</a>', cell)
    cell = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", cell)

    def code(match: re.Match[str]) -> str:
        # An HTML block is not Markdown, so a code span no longer protects its text. Code has no
        # spaces, so without break points the browser cuts it inside a word.
        text = match.group(1).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return "<code>" + re.sub(r"/(?=[\w-])|(?<=\w{4})\.(?=\w{4})", r"\g<0><wbr>", text) + "</code>"

    cell = re.sub(r"`([^`]+)`", code, cell)
    cell = cell.replace("</code>/<code>", "</code>/<wbr><code>")
    cell = re.sub(r"(?<!\w)_\((.+?)\)_", r"<em>(\1)</em>", cell)
    return re.sub(r"\\([\\`*_\[\]|$])", r"\1", cell)


def _table(head: Iterable[str], rows: Iterable[str], widths: Iterable[int]) -> str:
    cols = "".join(f'<col width="{share}%" style="width:{share}%">' for share in widths)
    ths = "".join(f"<th>{name}</th>" for name in head)
    body = "\n".join(rows)
    return (
        f'<table style="table-layout:fixed;width:100%;max-width:{MAX_TABLE_WIDTH}">\n'
        f"<colgroup>{cols}</colgroup>\n<thead><tr>{ths}</tr></thead>\n<tbody>\n{body}\n</tbody>\n</table>"
    )


def fixed_table(head: Iterable[str], rows: Iterable[Iterable[str]], widths: Iterable[int]) -> str:
    """A table with fixed column shares that wraps long cells between words."""
    lines = ("<tr>" + "".join(f'<td style="{_WRAP}">{html_cell(cell)}</td>' for cell in row) + "</tr>" for row in rows)
    return _table(head, lines, widths)


def spanned_table(head: Iterable[str], blocks: Iterable[tuple[str, list[list[str]]]], widths: Iterable[int]) -> str:
    """A fixed table whose first cell spans the rows of its block, so its text stands once.

    Each block is a first cell with its rows. Stripes follow rows and would cut through a spanning
    cell, so these cells set their own background.
    """
    style = f"{_WRAP};background:none"
    lines = []
    for first, rows in blocks:
        for index, row in enumerate(rows):
            span = "" if index else f'<td rowspan="{len(rows)}" style="{style}">{html_cell(first)}</td>'
            lines.append("<tr>" + span + "".join(f'<td style="{style}">{html_cell(c)}</td>' for c in row) + "</tr>")
    return _table(head, lines, widths)
