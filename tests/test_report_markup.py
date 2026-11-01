"""REQ-013: text from an analyzed repository cannot run as markup in a report."""

from __future__ import annotations

import html
import re
import shutil
import subprocess

import pytest
from renderers.report_markup import keep_known_markup as clean

_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src=//evil></iframe>",
    "<video src=x onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<body onload=alert(1)>",
    "<math><mi xlink:href='javascript:alert(1)'>x</mi></math>",
    "<object data=javascript:alert(1)></object>",
    "<meta http-equiv=refresh content=0;url=//evil>",
    "<link rel=stylesheet href=//evil>",
    "<style>*{background:url(//evil)}</style>",
    "<form action=javascript:alert(1)><button>x</button></form>",
    "<base href=//evil>",
    "<pre><img src=x onerror=alert(1)></pre>",
]


def _rendered(md: str) -> str:
    """What the browser would get, the way the report's export builds it."""
    run = subprocess.run(["pandoc", "-f", "gfm", "-t", "html5"], input=md, text=True, capture_output=True, check=True)
    return run.stdout


def _active_markup(page: str) -> list[str]:
    """Anything in rendered HTML that could run, load, or navigate; text and comments are inert."""
    assert "--!>" not in page
    page = re.sub(r"<!--.*?-->", "", page, flags=re.S)
    page = re.sub(r"<code[^>]*>.*?</code>", "", page, flags=re.S)
    tags = re.findall(r"<[a-zA-Z][^>]*>", page)
    hits = [
        tag
        for tag in tags
        if re.match(r"<(?:script|iframe|svg|img|video|input|object|embed|meta|link|style|form|base|math)\b", tag)
        or re.search(r"\son[a-z]+\s*=", tag)
        or re.search(r"(?:href|src|action)\s*=\s*[\"']?\s*(?:javascript|data|vbscript):", html.unescape(tag), re.I)
        or re.search(r"style\s*=\s*[\"'][^\"']*(?:url|expression)", tag, re.I)
    ]
    return hits


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_unknown_tags_become_visible_text(payload):
    out = clean(f"Attacker sends {payload}.")
    assert "<" not in out and "alert" in out or "background" in out or "evil" in out


@pytest.mark.parametrize(
    "markup",
    [
        '<a href="javascript:alert(1)">x</a>',
        '<a href="JaVaScRiPt:alert(1)">x</a>',
        '<a href="java&#115;cript:alert(1)">x</a>',
        '<a href="data:text/html,<script>alert(1)</script>">x</a>',
        "<a href=javascript:alert(1)>x</a>",
        "<details ontoggle=alert(1) open>x</details>",
        '<span onmouseover="alert(1)">x</span>',
        "<td onclick=alert(1)>x</td>",
        '<span style="background:url(//evil)">x</span>',
        '<span style="width:expression(alert(1))">x</span>',
    ],
)
def test_allowed_tags_lose_every_unsafe_attribute(markup):
    assert _active_markup(clean(markup)) == []


def test_a_safe_attribute_survives_beside_a_dropped_one():
    assert clean('<a href="#f-001" onclick="x">F-001</a>') == '<a href="#f-001">F-001</a>'


def test_a_shortened_route_keeps_its_full_text_as_tooltip():
    route = '<code title="/a/very/long/route">/a/very/…</code>'
    assert clean(route) == route


def test_a_finding_link_keeps_its_title_as_tooltip():
    link = '<a href="#f-001" title="SQL &quot;injection&quot; &lt;login&gt;">F-001</a>'
    assert clean(link) == link


@pytest.mark.skipif(not shutil.which("pandoc"), reason="pandoc is not installed")
@pytest.mark.parametrize(
    "markdown",
    [
        "[x](javascript:alert(1))",
        "[x](JAVASCRIPT:alert(1))",
        "[x](java&#115;cript:alert(1))",
        "[x](javascript\\:alert(1))",
        "[x](<javascript:alert(1)>)",
        "[x](data:text/html,hello)",
        "[x](vbscript:msgbox(1))",
        "<javascript:alert(1)>",
        "[x]: javascript:alert(1)\n\n[x]",
    ],
)
def test_links_lead_nowhere_unsafe(markdown):
    assert _active_markup(_rendered(clean(markdown))) == []


def test_safe_links_stay():
    assert clean("[a](#f-001) [b](https://example.test/x) [c](report.md)") == (
        "[a](#f-001) [b](https://example.test/x) [c](report.md)"
    )


def test_a_code_span_protects_text_where_markdown_applies():
    assert clean("Payload `<img src=x onerror=alert(1)>` here.") == "Payload `<img src=x onerror=alert(1)>` here."


def test_a_code_span_protects_nothing_inside_an_html_block():
    """An HTML block is not Markdown: the backticks stay literal and the tag would run."""
    out = clean("<table><tr><td>`<img src=x onerror=alert(1)>`</td></tr></table>")
    assert "&lt;img" in out and "<img" not in out


def test_a_following_line_of_an_html_block_is_no_markdown_either():
    out = clean("<span>\n`<img src=x onerror=alert(1)>`\n</span>")
    assert "&lt;img" in out


def test_a_backslash_before_a_backtick_opens_no_code_span():
    assert "<img" not in clean("\\`<img src=x onerror=alert(1)>\\`")


def test_a_backtick_inside_an_attribute_opens_no_code_span():
    """Markdown reads the tag first, so the next tag is live though a regex could see a code span."""
    out = clean('<a href="`">x</a> <img src=x onerror=alert(1)> `')
    assert "<img" not in out


def test_a_tag_over_several_lines_stays_text():
    assert "<img" not in clean("text <img\nsrc=x\nonerror=alert(1)>")


def test_a_fence_inside_an_html_block_is_no_fence():
    out = clean("<details>\n```\n<img src=x onerror=alert(1)>\n```\n</details>")
    assert "<img" not in out


def test_fenced_code_stays_as_it_is():
    fence = "```html\n<script>alert(1)</script>\n```"
    assert clean(f"Before\n\n{fence}\n\nAfter") == f"Before\n\n{fence}\n\nAfter"


def test_a_deeply_indented_fence_marker_protects_nothing():
    """Four spaces cannot open a fence in a paragraph, so the next line is ordinary text."""
    assert "<img" not in clean("para\n    ```\n<img src=x onerror=alert(1)>\n    ```")


@pytest.mark.parametrize(
    "comment",
    [
        "<!-- x --!><img src=x onerror=alert(1)> -->",
        "<!--><img src=x onerror=alert(1)>",
        "<!---><img src=x onerror=alert(1)>",
    ],
)
def test_comment_spellings_a_browser_ends_early_stay_harmless(comment):
    assert _active_markup(clean(comment)) == []


def test_a_remote_image_becomes_a_link_so_opening_the_report_requests_nothing():
    assert clean("![x](https://evil.example/t.png)") == "[x](https://evil.example/t.png)"
    assert clean("![Diagram](other.svg)") == "![Diagram](other.svg)"


def test_placeholders_stay_readable_instead_of_being_swallowed_as_tags():
    assert clean("Use <other id> here.") == "Use &lt;other id&gt; here."


def test_a_lone_comparison_stays_as_written():
    assert clean("a < b and c > d") == "a < b and c > d"


def test_the_report_own_markup_passes_unchanged():
    report = (
        '<table style="table-layout:fixed;width:100%;max-width:1240px">\n'
        '<colgroup><col width="34%" style="width:34%"></colgroup>\n'
        "<thead><tr><th>Item</th></tr></thead>\n<tbody>\n"
        '<tr><td rowspan="2" style="overflow-wrap:break-word;background:none"><a href="#f-001">F-001</a></td></tr>\n'
        "</tbody>\n</table>\n\n"
        '<details><summary>2 Medium</summary><span style="white-space:nowrap">x</span><br/><wbr></details>\n\n'
        '<a id="t-001"></a>\n\n'
        '<blockquote style="border-left: 3px solid #dc2626; padding: 16px 20px; margin: 0;">x</blockquote>\n\n'
        "<!-- section:top -->\n<!-- several\nlines -->\n"
    )
    assert clean(report) == report


def test_a_tag_left_open_cannot_format_the_rest_of_the_report():
    """A bare `#{<code>}` once turned everything after it into code."""
    assert clean("Ruby uses #{<code>} here.") == "Ruby uses #{&lt;code&gt;} here."
    assert clean("Balanced <code>x</code> stays.") == "Balanced <code>x</code> stays."
    assert clean("In code `<em>` it stays, and <em>this</em> too.") == "In code `<em>` it stays, and <em>this</em> too."


def test_the_filter_is_idempotent():
    text = 'See <other id>, <a href="javascript:x">y</a>, [z](javascript:x) and `<b>`.\n<td onclick=x>`<img>`</td>'
    assert clean(clean(text)) == clean(text)


@pytest.mark.skipif(not shutil.which("pandoc"), reason="pandoc is not installed")
@pytest.mark.parametrize(
    "markdown",
    [
        *_PAYLOADS,
        "<details ontoggle=alert(1) open>x</details>",
        '<a href="javascript:alert(1)">x</a>',
        "[x](javascript:alert(1))",
        "[x](java&#115;cript:alert(1))",
        "<javascript:alert(1)>",
        "[x]: javascript:alert(1)\n\n[x]",
        "<table><tr><td>`<img src=x onerror=alert(1)>`</td></tr></table>",
        "<span>\n`<img src=x onerror=alert(1)>`\n</span>",
        "\\`<img src=x onerror=alert(1)>\\`",
        '<a href="`">x</a> <img src=x onerror=alert(1)> `',
        "text <img\nsrc=x\nonerror=alert(1)>",
        "<details>\n```\n<img src=x onerror=alert(1)>\n```\n</details>",
        "para\n    ```\n<img src=x onerror=alert(1)>\n    ```",
        "<!-- x --!><img src=x onerror=alert(1)> -->",
        "<!--><img src=x onerror=alert(1)>",
        "- <table><tr><td>`<img src=x onerror=alert(1)>`</td></tr></table>",
        "> <span>\n> `<img src=x onerror=alert(1)>`",
        "| a |\n|---|\n| <img src=x onerror=alert(1)> |",
        "<details><summary>x</summary><img src=x onerror=alert(1)></details>",
    ],
)
def test_nothing_runs_in_the_rendered_page(markdown):
    """The check that counts: the HTML a browser would get, built the way the export builds it."""
    assert _active_markup(_rendered(clean(markdown))) == [], clean(markdown)
