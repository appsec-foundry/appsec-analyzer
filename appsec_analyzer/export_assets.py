"""Reject active markup and resource references outside a frozen export bundle."""

from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from urllib.parse import urlsplit


def _css(value: str) -> None:
    # Generated diagrams use local paint servers; no imports, escapes or executable CSS.
    remainder = re.sub(r"url\(#[A-Za-z0-9_-]+\)", "", value, flags=re.I)
    if any(token in remainder.lower() for token in ("url", "@", "\\", "expression", "behavior")):
        raise ValueError("unsupported CSS in saved report")


def validate_svg(body: bytes) -> None:
    if b"<!" in body or len(body) > 16_777_216:
        raise ValueError("unsupported SVG declaration or size")
    root = ET.fromstring(body)
    if root.tag != "{http://www.w3.org/2000/svg}svg":
        raise ValueError("report image must be an SVG document")
    allowed = set(
        "svg g a defs path rect circle ellipse line polyline polygon text tspan title desc metadata marker clipPath mask pattern linearGradient radialGradient stop use style".split()
    )
    for index, node in enumerate(root.iter()):
        tag = node.tag.rsplit("}", 1)[-1]
        if index > 100_000 or tag not in allowed:
            raise ValueError("unsupported SVG content")
        if tag == "style":
            _css(node.text or "")
        for key, value in node.attrib.items():
            key = key.rsplit("}", 1)[-1].lower()
            if key.startswith("on") or key in ("src", "base"):
                raise ValueError("active SVG content is not supported")
            if key == "href" and not re.fullmatch(r"#[A-Za-z0-9_-]+", value):
                raise ValueError("external SVG resources are not supported")
            if key in {
                "style",
                "fill",
                "stroke",
                "filter",
                "clip-path",
                "mask",
                "cursor",
                "color-profile",
                "marker",
                "marker-start",
                "marker-mid",
                "marker-end",
            }:
                _css(value)


def validate_document(ast: dict, files: dict[str, bytes], markdown: str = "") -> None:
    """Validate Pandoc's actual parsed input before an embedding converter runs."""
    checked = set()

    def asset(value: str) -> None:
        if value in checked:
            return
        checked.add(value)
        if value.startswith("data:image/svg+xml;base64,"):
            validate_svg(base64.b64decode(value.split(",", 1)[1], validate=True))
            return
        if value not in files or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.(?:svg|png|jpg|jpeg)", value):
            raise ValueError("report resource is not a recorded local image")
        if value.endswith(".svg"):
            validate_svg(files[value])
        elif not (files[value].startswith(b"\x89PNG\r\n\x1a\n") or files[value].startswith(b"\xff\xd8\xff")):
            raise ValueError("invalid raster image")

    def link(value: str) -> None:
        if value.endswith(".svg") or value.startswith("data:"):
            asset(value)
        elif urlsplit(value).scheme.lower() not in ("", "http", "https", "mailto", "vscode"):
            raise ValueError("active report link is not supported")

    class Markup(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag not in set(
                "a p br hr table thead tbody tfoot tr th td caption colgroup col img picture source details summary div span h1 h2 h3 h4 h5 h6 ul ol li strong b em i code pre blockquote sub sup small".split()
            ):
                raise ValueError("active report markup is not supported")
            for key, value in attrs:
                if key not in set(
                    "align width height class id title style href src srcset media type alt colspan rowspan open scope".split()
                ):
                    raise ValueError("unsupported report attribute")
                value = value or ""
                if key == "style":
                    _css(value)
                elif key == "href":
                    link(value)
                elif key == "src":
                    asset(value)
                elif key == "srcset":
                    # Generated picture sources contain one sibling image per source.
                    asset(value)

        def handle_decl(self, decl):
            raise ValueError("report declarations are not supported")

        def handle_pi(self, data):
            raise ValueError("report processing instructions are not supported")

    # Legacy converters stage image references with a regex even inside code blocks.
    # Validate those references as well as the parsed document they will embed.
    from exporters.export_pdf import _MD_IMAGE_RE, DETAIL_LINK_RE

    for pattern in (_MD_IMAGE_RE, DETAIL_LINK_RE):
        for match in pattern.finditer(markdown):
            asset(match.group(1))

    pending = [ast]
    nodes = 0
    while pending:
        nodes += 1
        if nodes > 500_000:
            raise ValueError("report structure exceeds its limit")
        value = pending.pop()
        if isinstance(value, dict):
            kind, content = value.get("t"), value.get("c")
            if kind == "Image":
                asset(content[-1][0])
            elif kind == "Link":
                link(content[-1][0])
            elif kind in ("RawInline", "RawBlock"):
                if content[0] != "html":
                    raise ValueError("unsupported raw report format")
                parser = Markup(convert_charrefs=True)
                parser.feed(content[1])
                parser.close()
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
