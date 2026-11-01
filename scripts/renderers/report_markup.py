"""Keep only known harmless markup in a report (REQ-013).

Text from an analyzed repository can reach the report through model output, and the HTML export
passes raw HTML on to the reader's browser. So markup is allowed by name: a tag or attribute that is
not listed turns into visible text, and a link may only lead to `#…` or `http(s)`.

The scan reads a line the way Markdown does, because a code span protects its text only where
Markdown applies. In a raw HTML block backticks mean nothing, so nothing there counts as code.
"""

from __future__ import annotations

import html
import re

ALLOWED_TAGS: dict[str, frozenset[str]] = {
    "a": frozenset({"href", "id", "title"}),
    "blockquote": frozenset({"style"}),
    "br": frozenset(),
    "code": frozenset({"title"}),
    "col": frozenset({"style", "width"}),
    "colgroup": frozenset(),
    "details": frozenset({"open"}),
    "em": frozenset(),
    "span": frozenset({"style"}),
    "strong": frozenset(),
    "summary": frozenset(),
    "table": frozenset({"style"}),
    "tbody": frozenset(),
    "td": frozenset({"colspan", "rowspan", "style"}),
    "th": frozenset({"colspan", "rowspan", "style"}),
    "thead": frozenset(),
    "tr": frozenset(),
    "wbr": frozenset(),
}

_TAG = r"""<(?P<close>/?)(?P<name>[a-zA-Z][a-zA-Z0-9:-]*)(?P<attrs>(?:[^<>"'`]|"[^"<]*"|'[^'<]*')*?)(?P<end>/?)>"""
_COMMENT = r"(?P<comment><!--(?:(?!-->).)*-->)"
_STRAY = r"(?P<stray><(?=[a-zA-Z/!?]))"
# A remote image would load when the report opens, so it becomes an ordinary link.
_REMOTE_IMAGE = r"(?P<image>!(?=\[[^\]\n]*\]\(\s*<?\s*[a-zA-Z][a-zA-Z0-9+.-]*:))"
_LINK = r"(?P<dest>\]\(\s*<?\s*)(?P<url>[^\s)>]+)"
# Alternatives run left to right like Markdown's inline parser, so whichever starts first wins: a
# backtick inside a tag's attribute opens no code span.
_CODE = r"(?<![\\`])(?P<ticks>`+)(?!`)(?:(?!(?P=ticks)(?!`)).)+?(?<!`)(?P=ticks)(?!`)"
_CODE_SPAN = re.compile(_CODE)
_INLINE_TAGS = ("code", "em", "span", "strong")
_MARKDOWN = re.compile("|".join((_COMMENT, f"(?P<code>{_CODE})", _TAG, _REMOTE_IMAGE, _LINK, _STRAY)))
_RAW_HTML = re.compile("|".join((_COMMENT, _TAG, _STRAY)))
_ATTR = re.compile(r"""([^\s=/"'<>]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?""")
_FENCE_OPEN = re.compile(r"^ {0,3}(?:(`{3,})[^`]*|(~{3,}).*)$")
_HTML_BLOCK = re.compile(r"^[ \t>*+\-\d.]*</?[a-zA-Z]")
_LINK_REFERENCE = re.compile(r"^( {0,3}\[[^\]\n]+\]:\s*<?\s*)(\S+?)(>?(?:\s.*)?)$")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_SAFE_STYLE = re.compile(r"^[a-zA-Z0-9\s:;%.,#()-]*$")


def _escaped(text: str) -> str:
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _safe_url(url: str) -> bool:
    """Whether a link target stays harmless once Markdown and the browser have decoded it."""
    plain = html.unescape(url).replace("\\", "").strip()
    return not _SCHEME.match(plain) or plain.lower().startswith(("http://", "https://"))


def _safe_value(attribute: str, value: str) -> bool:
    plain = html.unescape(value).strip()
    if attribute == "href":
        return plain.startswith("#") or plain.lower().startswith(("http://", "https://"))
    if attribute == "style":
        return bool(_SAFE_STYLE.match(plain)) and "url" not in plain.lower() and "expression" not in plain.lower()
    if attribute in ("rowspan", "colspan"):
        return plain.isdigit()
    return attribute != "width" or bool(re.fullmatch(r"\d{1,3}%?", plain))


def _tag(match: re.Match[str]) -> str:
    name = match.group("name").lower()
    if name not in ALLOWED_TAGS:
        return _escaped(match.group(0))
    if match.group("close"):
        return f"</{name}>"
    kept = []
    dropped = False
    for attribute, raw in _ATTR.findall(match.group("attrs")):
        lowered = attribute.lower()
        value = raw[1:-1] if raw[:1] in "\"'" and raw else raw
        if lowered in ALLOWED_TAGS[name] and _safe_value(lowered, value):
            kept.append(f'{lowered}="{value}"' if raw else lowered)
        else:
            dropped = True
    if not dropped:
        return match.group(0)
    return f"<{name}{''.join(' ' + part for part in kept)}{match.group('end')}>"


def _replace(match: re.Match[str]) -> str:
    groups = match.groupdict()
    if groups["stray"] is not None:
        return "&lt;"
    if groups["comment"] is not None or groups.get("code") is not None:
        return match.group(0)
    if groups.get("image") is not None:
        return ""
    if groups.get("dest") is not None:
        return groups["dest"] + (groups["url"] if _safe_url(groups["url"]) else "#")
    return _tag(match)


def _balanced(line: str) -> str:
    """Escape an inline tag without its partner: left open, it would format the rest of the report."""
    outside_code = _CODE_SPAN.sub("", line)
    for name in _INLINE_TAGS:
        opening = re.compile(rf"<{name}(?:\s[^<>]*)?>")
        tag = re.compile(rf"</?{name}(?:\s[^<>]*)?>")
        if len(opening.findall(outside_code)) != outside_code.count(f"</{name}>"):
            line = tag.sub(lambda match: _escaped(match.group(0)), line)
    return line


def _clean_line(line: str, *, markdown: bool) -> str:
    if not markdown:
        return _balanced(_RAW_HTML.sub(_replace, line))
    reference = _LINK_REFERENCE.match(line)
    if reference and not _safe_url(reference.group(2)):
        return f"{reference.group(1)}#{reference.group(3)}"
    return _balanced(_MARKDOWN.sub(_replace, line))


def _closes_fence(line: str, opener: str) -> bool:
    stripped = line.strip()
    return len(line) - len(line.lstrip(" ")) <= 3 and len(stripped) >= len(opener) and set(stripped) == {opener[0]}


def keep_known_markup(md: str) -> str:
    """Turn unknown markup into visible text. Idempotent, and fenced code stays as it is."""
    # A browser ends a comment at these spellings, while Markdown reads on to the next `-->`.
    md = md.replace("--!>", "-- !>").replace("<!--->", "<!-- -->").replace("<!-->", "<!-- -->")
    lines = []
    fence = ""
    in_block = False
    in_comment = False
    for line in md.split("\n"):
        if in_comment:
            lines.append(line)
            in_comment = "-->" not in line
            continue
        if fence:
            lines.append(line)
            fence = "" if _closes_fence(line, fence) else fence
            continue
        if in_block:
            in_block = bool(line.strip())
            lines.append(_clean_line(line, markdown=False))
            continue
        if line.lstrip().startswith("<!--") and "-->" not in line:
            in_comment = True
            lines.append(line)
            continue
        opened = _FENCE_OPEN.match(line)
        if opened:
            fence = opened.group(1) or opened.group(2)
            lines.append(line)
            continue
        if _HTML_BLOCK.match(line):
            in_block = True
            lines.append(_clean_line(line, markdown=False))
            continue
        lines.append(_clean_line(line, markdown=True))
    return "\n".join(lines)
