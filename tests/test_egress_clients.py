"""Outbound client detection: fixed hosts, request-chosen and configured destinations."""

from __future__ import annotations

from pathlib import Path

import pytest
from analyzers.egress_clients import scan


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def _summary(rows):
    return [(r["kind"], r["host"], r["transport"], [(e["file"], e["line"]) for e in r["evidence"]]) for r in rows]


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (
            {
                "src/chain.ts": "const p = new WebSocketProvider(`wss://node.chainhost.net/v2/${key}`)\n",
                "src/upload.ts": "const target = req.body.pictureUrl\nconst body = '1'\nconst res = await fetch(target)\n",
            },
            [
                ("user-controlled", None, "http", [("src/upload.ts", 3)]),
                ("fixed-host", "node.chainhost.net", "rpc", [("src/chain.ts", 1)]),
            ],
        ),
        (
            # The same mechanism under other languages, clients and names.
            {
                "svc/proxy.py": "def go():\n    return requests.get(request.args.get('next'))\n",
                "svc/rates.go": 'resp, err := http.Get("https://rates.feedco.example2.org/today")\n',
            },
            [
                ("user-controlled", None, "http", [("svc/proxy.py", 2)]),
                ("fixed-host", "rates.feedco.example2.org", "http", [("svc/rates.go", 1)]),
            ],
        ),
    ],
    ids=["typescript", "python-and-go"],
)
def test_fixed_hosts_and_request_chosen_urls_are_destinations(tmp_path, files, expected):
    assert _summary(scan(_repo(tmp_path, files))) == expected


def test_one_host_called_from_two_files_is_one_destination(tmp_path):
    repo = _repo(
        tmp_path,
        {
            "a/wallet.ts": "const p = new JsonRpcProvider('https://rpc.ledgerco.io')\n",
            "b/mint.ts": "\nconst q = new JsonRpcProvider('https://rpc.ledgerco.io/x')\n",
        },
    )
    (row,) = scan(repo)
    assert row["clients"] == ["rpc-provider"]
    assert [(e["file"], e["line"]) for e in row["evidence"]] == [("a/wallet.ts", 1), ("b/mint.ts", 2)]


@pytest.mark.parametrize(
    "line",
    [
        "fetch('/api/orders')",  # same-origin call of a client to its own backend
        "fetch(`${base}/api/orders`)",  # configured, neither literal nor request-derived
        "fetch('http://localhost:3000/health')",
        "axios.get('https://api.example.com/v1')",  # reserved example domain
        "this.http.get('https://api.vendor.io')",  # framework client method, not Node http
        "const reply = 'see https://docs.vendor.io for details'",  # a URL without a client call
    ],
)
def test_calls_that_name_no_external_destination_are_ignored(tmp_path, line):
    assert scan(_repo(tmp_path, {"src/app.ts": line + "\n"})) == []


@pytest.mark.parametrize(
    ("rel", "text", "line"),
    [
        (
            "src/notify.ts",
            "export const send = async (id = 1, hook = process.env.ALERT_HOOK) => {\n"
            "  await fetch(hook, { method: 'POST' })\n}\n",
            2,
        ),
        ("src/direct.ts", "await axios.post(process.env.HOOK_URL, body)\n", 1),
        (
            # A module constant stands anywhere above its call, and a path may follow it.
            "src/pay.ts",
            "const API: string = config.get<string>('billing.url')\n" + "\n" * 20 + "await fetch(`${API}/charge`)\n",
            22,
        ),
        (
            "svc/rates.py",
            'BASE = os.environ["RATES_URL"]\n\ndef go():\n    return requests.get(f"{BASE}/today")\n',
            4,
        ),
        (
            "svc/client.py",
            "class C:\n    def __init__(self):\n"
            '        self.base = os.getenv("RATES_URL")\n\n'
            "    def go(self):\n"
            '        return httpx.get(self.base + "/x")\n',
            6,
        ),
        ("svc/rates.go", 'url := os.Getenv("RATES_URL")\nresp, err := http.Get(url)\n', 2),
    ],
    ids=["default-parameter", "on-the-call", "module-constant", "python-f-string", "python-attribute", "go"],
)
def test_a_destination_named_by_a_setting_is_configured(tmp_path, rel, text, line):
    (row,) = scan(_repo(tmp_path, {rel: text}))
    assert (row["kind"], row["host"], row["transport"]) == ("configured", None, "http")
    assert row["evidence"] == [{"file": rel, "line": line}]


@pytest.mark.parametrize(
    "text",
    [
        "fetch(url, { headers: { key: process.env.API_KEY } })\n",  # the setting is not the destination
        "fetch('/api/orders', { headers: { key: process.env.API_KEY } })\n",
        "const part = process.env.TENANT\nfetch(`/api/${part}`)\n",  # only a path segment
        "if (mode == process.env.MODE) fetch(mode)\n",  # a comparison assigns nothing
        "fetch(process.env.TARGET || 'http://localhost:3000')\n",  # a local default stays local
        # A client bundle's configured base URL is normally its own backend.
        "const base = process.env.REACT_APP_API_URL\nfetch(`${base}/orders`)\n",
        "const base = process.env.NEXT_PUBLIC_API\nfetch(`${base}/orders`)\n",
        "const base = process.env.VUE_APP_API\nfetch(`${base}/orders`)\n",
        "const base = import.meta.env.VITE_API_URL\nfetch(`${base}/orders`)\n",
        "const base = process.env.API_URL".ljust(2100) + "\nfetch(base)\n",  # minified line
    ],
)
def test_a_setting_that_does_not_name_the_destination_is_ignored(tmp_path, text):
    assert scan(_repo(tmp_path, {"src/app.ts": text})) == []


def test_a_literal_host_or_the_request_outranks_a_setting(tmp_path):
    repo = _repo(
        tmp_path,
        {
            "src/feed.ts": "fetch(process.env.FEED || 'https://feed.vendorhub.io/x')\n",
            "src/proxy.ts": "let next = process.env.NEXT_HOP\nnext = req.query.next\nfetch(next)\n",
        },
    )
    assert _summary(scan(repo)) == [
        ("user-controlled", None, "http", [("src/proxy.ts", 3)]),
        ("fixed-host", "feed.vendorhub.io", "http", [("src/feed.ts", 1)]),
    ]


def test_excluded_and_minified_code_is_not_scanned(tmp_path):
    repo = _repo(
        tmp_path,
        {
            "test/fixtures/call.ts": "fetch('https://api.vendor.io')\n",
            "node_modules/lib/index.js": "fetch('https://api.vendor.io')\n",
            "public/bundle.js": "x".ljust(2100, "x") + "fetch('https://api.vendor.io')\n",
        },
    )
    assert scan(repo) == []
