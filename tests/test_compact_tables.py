"""REQ-013: the building blocks of the report's compact tables."""

from __future__ import annotations

from renderers import compact_tables as tables


def _entries(*marks: str) -> list[str]:
    return [f"{mark} F-{number:03d}" for number, mark in enumerate(marks, 1)]


def test_critical_and_high_always_stay_visible_however_many_there_are() -> None:
    shown, rest = tables.split_visible(_entries(*"🟡" * 4, *"🟠" * 6, "🔴"))
    assert shown[0].startswith("🔴")
    assert [entry[0] for entry in shown] == ["🔴", *"🟠" * 6]
    assert [entry[0] for entry in rest] == ["🟡"] * 4


def test_light_entries_fill_a_short_list_and_one_lone_entry_never_collapses() -> None:
    shown, rest = tables.split_visible(_entries("🟠", "🟡", "🟡", "🟢"))
    assert len(shown) == 4 and not rest


def test_a_collapsed_block_names_what_it_holds_and_keeps_every_entry() -> None:
    entries = _entries("🟡", "🟡", "🟢")
    block = tables.fold(entries)
    assert "<summary>2 Medium · 1 Low</summary>" in block
    assert all(entry in block for entry in entries)
    assert tables.fold([]) == ""


def test_an_id_list_shows_one_badge_per_severity_worst_first() -> None:
    cell = tables.id_list([("🟡", "F-003"), ("🔴", "F-001"), ("🟡", "F-004")])
    lines = cell.split("<br/>")
    assert lines[0].startswith("🔴&nbsp;") and "F-001" in lines[0]
    assert lines[1].startswith("🟡&nbsp;") and "F-003" in lines[1] and "F-004" in lines[1]
    assert cell.count("🟡") == 1


def test_the_tally_says_what_remains_open() -> None:
    assert tables.severity_tally(_entries("🟠", "🟡", "🟡")) == "1 High and 2 Medium findings remain open:"
    assert tables.severity_tally(_entries("🔴")) == "1 Critical finding remains open:"
    assert tables.severity_tally(["F-001", "F-002"]) == "2 findings remain open:"


def test_a_token_count_is_short_and_an_unknown_one_stays_unknown() -> None:
    assert [tables.token_count(n) for n in (850, 42_400, 1_300_000)] == ["850", "42k", "1.3M"]
    assert tables.token_count(None) == "–"


def test_a_finding_without_a_severity_stays_in_an_id_list() -> None:
    assert "F-009" in tables.id_list([("", "F-009"), ("🔴", "F-001")]).split("<br/>")[1]


def test_a_fixed_table_turns_markdown_into_html_and_has_an_upper_width() -> None:
    table = tables.fixed_table(("A", "B"), [("[F-001](#f-001)", "**bold**")], (30, 70))
    assert '<a href="#f-001">F-001</a>' in table and "<strong>bold</strong>" in table
    assert "max-width:1240px" in table and 'style="width:30%"' in table


def test_code_in_an_html_cell_stays_escaped_text() -> None:
    """An HTML block is not Markdown, so a code span no longer protects its text."""
    cell = tables.html_cell("`<img src=x onerror=alert(1)>`")
    assert "<img" not in cell and "&lt;img" in cell


def test_code_offers_break_points_so_a_narrow_column_cuts_no_word() -> None:
    assert tables.html_cell("`security.isAuthorized()`") == "<code>security.<wbr>isAuthorized()</code>"
    assert tables.html_cell("`a`/`b`") == "<code>a</code>/<wbr><code>b</code>"
