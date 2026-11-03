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


@pytest.mark.parametrize(
    ("rel", "source", "client"),
    [
        ("src/client.ts", "fetch(\n 'https://billing.vendorhub.io/orders'\n)\n", "fetch"),
        ("src/client.ts", "const BASE = 'https://billing.vendorhub.io'\nfetch(BASE + '/orders')\n", "fetch"),
        (
            "src/client.ts",
            "const BASE = 'https://billing.vendorhub.io'\nconst url = `${BASE}/orders`\nfetch(url)\n",
            "fetch",
        ),
        (
            "src/client.ts",
            "const api = axios.create({ baseURL: 'https://billing.vendorhub.io' })\napi.get('/orders')\n",
            "axios",
        ),
        ("src/client.ts", "const api = axios.create()\napi.get('https://billing.vendorhub.io/orders')\n", "axios"),
        (
            "src/client.ts",
            "axios.request({ headers: { link: 'https://docs.vendorhub.io' }, url: 'https://billing.vendorhub.io' })\n",
            "axios",
        ),
        (
            "svc/client.py",
            "session = requests.Session()\nsession.get('https://billing.vendorhub.io/orders')\n",
            "requests",
        ),
        (
            "svc/client.py",
            "client = httpx.Client(base_url='https://billing.vendorhub.io')\nclient.get('/orders')\n",
            "httpx",
        ),
        (
            "svc/client.py",
            "client = httpx.AsyncClient()\nawait client.get('https://billing.vendorhub.io/orders')\n",
            "httpx",
        ),
        (
            "src/client.ts",
            "class C { constructor(private http: HttpClient) {}\nload() { return this.http.get('https://billing.vendorhub.io/orders') } }\n",
            "angular-http",
        ),
        (
            "src/Client.java",
            'RestTemplate rest = new RestTemplate();\nrest.getForObject("https://billing.vendorhub.io/orders", String.class);\n',
            "spring-http",
        ),
        (
            "src/Client.java",
            'WebClient web = WebClient.create("https://billing.vendorhub.io");\nweb.get().uri("/orders").retrieve();\n',
            "spring-http",
        ),
        (
            "src/Client.cs",
            'HttpClient client = new HttpClient();\nawait client.GetStringAsync("https://billing.vendorhub.io/orders");\n',
            "dotnet-http",
        ),
        ("src/client.rb", "Net::HTTP.get(URI('https://billing.vendorhub.io/orders'))\n", "ruby-http"),
        (
            "src/client.php",
            "<?php\n$ch = curl_init('https://billing.vendorhub.io/orders');\ncurl_exec($ch);\n",
            "php-http",
        ),
        (
            "svc/client.go",
            'req, err := http.NewRequest("GET", "https://billing.vendorhub.io/orders", nil)\n',
            "go-http",
        ),
    ],
)
def test_rest_calls_retain_their_actual_destinations(tmp_path, rel, source, client):
    (row,) = scan(_repo(tmp_path, {rel: source}))
    assert row["host"] == "billing.vendorhub.io"
    assert row["clients"] == [client]
    assert row["scheme"] == "https"


@pytest.mark.parametrize(
    "source",
    [
        'http.NewRequest("GET", os.Getenv("BILLING_URL"), nil)',
        'http.NewRequestWithContext(ctx, "POST", os.Getenv("BILLING_URL"), nil)',
    ],
)
def test_go_request_method_is_not_mistaken_for_its_url(tmp_path, source):
    (row,) = scan(_repo(tmp_path, {"svc/client.go": source + "\n"}))
    assert row["kind"] == "configured" and row["host"] is None


def test_every_call_on_a_line_is_scanned_and_only_its_url_counts(tmp_path):
    rows = scan(
        _repo(
            tmp_path,
            {
                "src/client.ts": (
                    "fetch('/health'); axios.get('https://billing.vendorhub.io/orders'); "
                    "fetch('https://notify.vendorhub.io');\n"
                )
            },
        )
    )
    assert [(r["host"], r["clients"]) for r in rows] == [
        ("billing.vendorhub.io", ["axios"]),
        ("notify.vendorhub.io", ["fetch"]),
    ]


def test_a_header_url_cannot_replace_the_configured_destination(tmp_path):
    (row,) = scan(
        _repo(
            tmp_path,
            {
                "src/client.ts": (
                    "fetch(process.env.BILLING_URL, { headers: { 'X-Docs': 'https://docs.vendorhub.io' } })\n"
                )
            },
        )
    )
    assert row["kind"] == "configured" and row["host"] is None


def test_independent_settings_and_distinct_ports_do_not_collapse(tmp_path):
    rows = scan(
        _repo(
            tmp_path,
            {
                "src/client.ts": (
                    "fetch(process.env.BILLING_URL)\nfetch(process.env.NOTIFY_URL)\n"
                    "fetch('https://gateway.vendorhub.io:8443')\nfetch('https://gateway.vendorhub.io:9443')\n"
                )
            },
        )
    )
    assert len(rows) == 4
    assert len({r["destination_id"] for r in rows if r["kind"] == "configured"}) == 2
    assert {r["port"] for r in rows if r["kind"] == "fixed-host"} == {8443, 9443}


@pytest.mark.parametrize(
    "source",
    [
        "// fetch('https://billing.vendorhub.io')\n",
        "const doc = `fetch('https://billing.vendorhub.io')`\n",
        "const api = axios.create({ baseURL: 'https://billing.vendorhub.io' })\n",
        "const client = httpx.Client(base_url='https://billing.vendorhub.io')\n",
        "const api = { get: custom }\napi.get('https://billing.vendorhub.io')\n",
        "fetch('/orders', {body: 'https://billing.vendorhub.io'})\n",
        "fetch('/orders'); const doc = 'https://billing.vendorhub.io'\n",
        "const URL = 'http://localhost:8000'\nfetch(URL + '/orders')\n",
        "fetch(\n 'https://billing.vendorhub.io'\n",  # incomplete call
        "const a = b; const b = a; fetch(a)\n",  # cyclic unresolved names
        "function fetch(url = process.env.REMOTE) {}\n",
        "{ const target = 'https://billing.vendorhub.io' }\nfetch(target)\n",
    ],
)
def test_non_calls_and_unproven_destinations_stay_out(tmp_path, source):
    assert scan(_repo(tmp_path, {"src/client.ts": source})) == []


def test_a_later_assignment_does_not_change_an_earlier_call(tmp_path):
    (row,) = scan(
        _repo(
            tmp_path,
            {
                "src/client.ts": (
                    "const target = 'https://billing.vendorhub.io'\nfetch(target)\n"
                    "target = 'https://notify.vendorhub.io'\n"
                )
            },
        )
    )
    assert row["host"] == "billing.vendorhub.io"


def test_an_unrelated_function_binding_does_not_replace_the_callers_url(tmp_path):
    (row,) = scan(
        _repo(
            tmp_path,
            {
                "src/client.ts": (
                    "const url = 'https://billing.vendorhub.io'\n"
                    "function other() { const url = '/local' }\nfetch(url)\n"
                )
            },
        )
    )
    assert row["host"] == "billing.vendorhub.io"


def test_bounds_malformed_urls_and_credentials_do_not_expand_the_output(tmp_path):
    repo = _repo(
        tmp_path,
        {
            "src/client.ts": (
                "fetch('https://api.vendorhub.io:0')\n"
                "fetch('https://api.vendorhub.io:70000')\n"
                "fetch('https://bad_host.vendorhub.io')\n"
                "fetch(process.env.URL || " + "process.env.OTHER || " * 1200 + "'https://api.vendorhub.io')\n"
                "fetch('https://fixture-user:fixture-only@api.vendorhub.io/private?key=fixture-value')\n"
            )
        },
    )
    (row,) = scan(repo)
    assert row["host"] == "api.vendorhub.io"
    assert not any(value in str(row) for value in ("fixture-user", "fixture-only", "fixture-value", "private"))
