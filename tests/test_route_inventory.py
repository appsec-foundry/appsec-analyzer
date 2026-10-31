"""Tests for scripts/analyzers/route_inventory.py (arch.md §Route Inventory MVP)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "analyzers/route_inventory.py"
SCHEMA = json.loads((REPO_ROOT / "schemas" / "route-inventory.schema.json").read_text())


sys.path.insert(0, str(REPO_ROOT / "scripts"))
import analyzers.route_inventory as ri  # noqa: E402


def _run(repo_root: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo_root), "--stdout"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


# ---------------------------------------------------------------------------
# Per-framework extraction
# ---------------------------------------------------------------------------


def test_express_method_routes(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.get('/users', handler);\n"
        "app.post('/users', handler);\n"
        "app.delete('/users/:id', handler);\n"
    )
    inv = _run(tmp_path)
    methods_paths = {(r["method"], r["path"]) for r in inv["routes"]}
    assert ("GET", "/users") in methods_paths
    assert ("POST", "/users") in methods_paths
    assert ("DELETE", "/users/:id") in methods_paths
    assert "express" in inv["coverage"]["frameworks_detected"]


def test_fastapi_decorator(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app/routes.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "@router.get('/items/{id}')\n"
        "def get_item(id: int):\n"
        "    return {}\n"
        "@router.post('/items')\n"
        "def create(): return {}\n"
    )
    inv = _run(tmp_path)
    methods_paths = {(r["method"], r["path"]) for r in inv["routes"]}
    assert ("GET", "/items/{id}") in methods_paths
    assert ("POST", "/items") in methods_paths
    assert "fastapi" in inv["coverage"]["frameworks_detected"]


def test_flask_methods_kwarg(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/login', methods=['POST', 'GET'])\n"
        "def login(): return 'ok'\n"
    )
    inv = _run(tmp_path)
    methods = {r["method"] for r in inv["routes"] if r["path"] == "/login"}
    assert {"GET", "POST"}.issubset(methods)


def test_spring_get_mapping(tmp_path: Path) -> None:
    (tmp_path / "src/main/java/com/example").mkdir(parents=True)
    (tmp_path / "src/main/java/com/example/Api.java").write_text(
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class Api {\n"
        '  @GetMapping("/api/users")\n'
        '  public String users() { return "[]"; }\n'
        '  @DeleteMapping("/api/users/{id}")\n'
        "  public void delete(@PathVariable Long id) {}\n"
        "}\n"
    )
    inv = _run(tmp_path)
    methods_paths = {(r["method"], r["path"]) for r in inv["routes"]}
    assert ("GET", "/api/users") in methods_paths
    assert ("DELETE", "/api/users/{id}") in methods_paths
    assert "spring" in inv["coverage"]["frameworks_detected"]


def test_aspnet_minimal_apis(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/Program.cs").write_text(
        "var app = WebApplication.CreateBuilder(args).Build();\n"
        'app.MapGet("/items", () => "ok");\n'
        'app.MapPost("/items", (Item i) => i);\n'
    )
    inv = _run(tmp_path)
    methods_paths = {(r["method"], r["path"]) for r in inv["routes"]}
    assert ("GET", "/items") in methods_paths
    assert ("POST", "/items") in methods_paths
    assert "aspnet-minimal" in inv["coverage"]["frameworks_detected"]


def test_graphql_schema_operations_are_logical_entry_points(tmp_path: Path) -> None:
    (tmp_path / "schema.graphql").write_text(
        """
type Query {
  user(id: ID!): User @auth
  products: [Product]
}

type Mutation {
  updateUser(id: ID!, input: UserInput!): User
  login(email: String!, password: String!): AuthPayload
  grantRole(userId: ID!, role: Role!): User @hasRole(role: ADMIN)
}
""",
        encoding="utf-8",
    )

    inv = _run(tmp_path)
    jsonschema.validate(inv, SCHEMA)

    by_path = {r["path"]: r for r in inv["routes"]}
    assert by_path["Query user"]["method"] == "GRAPHQL"
    assert by_path["Query user"]["framework"] == "graphql"
    assert by_path["Query user"]["authn_signal"] == "decorator_present"
    assert by_path["Query user"]["missing_authz_suspect"] is True
    assert {"graphql-object-access", "missing-authz"} <= set(by_path["Query user"]["relevance_tags"])

    assert by_path["Mutation updateUser"]["missing_auth_suspect"] is True
    assert {"graphql-mutation", "graphql-object-access", "missing-auth"} <= set(
        by_path["Mutation updateUser"]["relevance_tags"]
    )

    assert by_path["Mutation login"]["missing_auth_suspect"] is False
    assert "graphql-mutation" in by_path["Mutation login"]["relevance_tags"]

    assert by_path["Mutation grantRole"]["authz_signal"] == "decorator_present"
    assert by_path["Mutation grantRole"]["missing_auth_suspect"] is False
    assert by_path["Mutation grantRole"]["missing_authz_suspect"] is False
    assert inv["coverage"]["frameworks_detected"] == ["graphql"]


def test_javascript_framework_detection_and_nestjs_decorators() -> None:
    fastify = ri._extract_javascript(
        Path("api.ts"), ["const fastify = require('fastify')();\n", "fastify.get('/fast', h);\n"]
    )
    koa = ri._extract_javascript(Path("api.ts"), ["import Router from 'koa-router';\n", "router.get('/koa', h);\n"])
    hapi = ri._extract_javascript(
        Path("api.ts"), ["const hapi = require('@hapi/hapi');\n", "server.get('/hapi', h);\n"]
    )
    nest = ri._extract_javascript(
        Path("controller.ts"),
        [
            "@Controller('/base')\n",
            "export class C {\n",
            "  @Get()\n",
            "  list() {}\n",
            "  @Post('/items')\n",
            "  create() {}\n",
            "}\n",
        ],
    )

    assert fastify[0].framework == "fastify"
    assert koa[0].framework == "koa"
    assert hapi[0].framework == "hapi"
    assert {(r.method, r.path, r.framework) for r in nest} == {
        ("GET", "/", "nestjs"),
        ("POST", "/items", "nestjs"),
    }


def test_python_django_and_default_route_methods() -> None:
    flask = ri._extract_python(
        Path("app.py"),
        ["from flask import Flask\n", "@app.route('/default')\n", "def default(): pass\n"],
    )
    django = ri._extract_python(
        Path("urls.py"),
        [
            "from django.urls import path\n",
            "urlpatterns = [\n",
            "  path('admin/', admin_view),\n",
            "  re_path('', empty_view),\n",
            "]\n",
        ],
    )

    assert flask[0].method == "GET"
    assert flask[0].path == "/default"
    assert django[0].framework == "django"
    assert django[0].method == "ANY"
    assert django[0].path == "admin/"


def test_java_jaxrs_path_and_http_method_lookahead() -> None:
    routes = ri._extract_java(
        Path("Api.java"),
        [
            "import javax.ws.rs.Path;\n",
            '@Path("/orders")\n',
            "@POST\n",
            "public Response create() { return ok(); }\n",
            '@Path("/status")\n',
            "public Response status() { return ok(); }\n",
        ],
    )

    by_path = {r.path: r for r in routes}
    assert by_path["/orders"].framework == "jaxrs"
    assert by_path["/orders"].method == "POST"
    assert by_path["/status"].method == "ANY"


def test_aspnet_map_methods_collapses_to_any() -> None:
    routes = ri._extract_aspnet(Path("Program.cs"), ['app.MapMethods("/bulk", new[] { "GET", "POST" }, h);\n'])
    assert routes[0].method == "ANY"


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


def test_management_surface_detected(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.get('/admin/users', h);\n"
        "app.get('/metrics', h);\n"
        "app.get('/api/items', h);\n"
        "app.get('/swagger', h);\n"
    )
    inv = _run(tmp_path)
    mgmt = {r["path"] for r in inv["routes"] if r["management_surface"]}
    not_mgmt = {r["path"] for r in inv["routes"] if not r["management_surface"]}
    assert "/admin/users" in mgmt
    assert "/metrics" in mgmt
    assert "/swagger" in mgmt
    assert "/api/items" in not_mgmt


def test_authn_signal_from_nearby_middleware(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text(
        "import express from 'express';\n"
        "const router = express.Router();\n"
        "router.use(requireAuth);\n"
        "router.get('/orders', h);\n"
    )
    inv = _run(tmp_path)
    orders = [r for r in inv["routes"] if r["path"] == "/orders"][0]
    assert orders["authn_signal"] == "middleware_present"


def test_authn_signal_defaults_to_unknown(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("import express from 'express';\nconst app = express();\napp.get('/public', h);\n")
    inv = _run(tmp_path)
    public = [r for r in inv["routes"] if r["path"] == "/public"][0]
    assert public["authn_signal"] == "unknown"
    assert public["authz_signal"] == "unknown"


def test_prefix_mounted_guard_marks_routes_protected(tmp_path: Path) -> None:
    """A prefix guard applies to later registrations on the same application."""
    (tmp_path / "server.ts").write_text(
        "app.use('/api/BasketItems', security.isAuthorized());\n"
        "app.get('/api/Users', security.isAuthorized());\n"
        "app.get('/api/BasketItems/:id', h);\n"
        "app.get('/api/Products', h);\n"
    )
    inv = _run(tmp_path)
    by_path = {r["path"]: r for r in inv["routes"]}
    assert by_path["/api/BasketItems/:id"]["authn_signal"] == "middleware_present"
    assert by_path["/api/Users"]["authn_signal"] == "middleware_present"
    assert by_path["/api/Products"]["authn_signal"] == "unknown"


@pytest.mark.parametrize(
    ("filename", "source", "expected"),
    [
        (
            "app.ts",
            "app.post('/a', security.isAuthorized(), h)\napp.post('/b', h)\napp.get('/c', requireAuth, h)\n",
            {("POST", "/a"): True, ("POST", "/b"): False, ("GET", "/c"): True},
        ),
        (
            "app.js",
            "router.put(\n  '/items/:id',\n  rateLimit({ max: 5 }),\n  // authenticate() is added later\n"
            "  update,\n)\nrouter.delete(\n  '/items/:id',\n  passport.authenticate('jwt'),\n  remove,\n)\n",
            {("PUT", "/items/:id"): False, ("DELETE", "/items/:id"): True},
        ),
        (
            "server.js",
            "fastify.get('/open', async () => 'ok')\n"
            "fastify.post('/secure', { preHandler: fastify.authenticate }, async () => 'ok')\n",
            {("GET", "/open"): False, ("POST", "/secure"): True},
        ),
        (
            "routes.ts",
            "router.get('/before', h)\nrouter.use(requireAuth)\nrouter.get('/after', h)\napi.get('/other', h)\n",
            {("GET", "/before"): False, ("GET", "/after"): True, ("GET", "/other"): False},
        ),
        (
            "urls.py",
            "from django.urls import path\nurlpatterns = [\n"
            "    path('account/', login_required(account)),\n    path('about/', about),  # login_required(x)\n]\n",
            {("ANY", "account/"): True, ("ANY", "about/"): False},
        ),
    ],
)
def test_a_guard_protects_only_its_own_registration(tmp_path: Path, filename, source, expected) -> None:
    (tmp_path / filename).write_text(source)
    inv = _run(tmp_path)
    signals = {(r["method"], r["path"]): r["authn_signal"] == "middleware_present" for r in inv["routes"]}
    assert signals == expected


def test_verb_guards_cover_their_method_and_path_while_use_covers_the_prefix(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "app.get('/api/users', security.isAuthorized())\n"
        "app.use('/api/orders', security.isAuthorized())\n"
        "app.all('/api/admin/*', requireAuth)\n"
        "app.get('/api/users', list)\napp.post('/api/users', create)\napp.get('/api/users/:id', show)\n"
        "app.delete('/api/orders/:id', cancel)\napp.post('/api/admin/reset', reset)\n"
    )
    inv = _run(tmp_path)
    guarded = {(r["method"], r["path"]) for r in inv["routes"] if r["authn_signal"] == "middleware_present"}
    assert ("GET", "/api/users") in guarded
    assert ("POST", "/api/users") not in guarded
    assert ("GET", "/api/users/:id") not in guarded
    assert ("DELETE", "/api/orders/:id") in guarded
    assert ("POST", "/api/admin/reset") in guarded
    suspects = {r["path"] for r in inv["routes"] if r["missing_auth_suspect"]}
    assert "/api/users" in suspects


def test_missing_auth_suspect_flags_sensitive_unguarded_routes(tmp_path: Path) -> None:
    """State-changing / management routes with no detected guard are flagged as
    advisory suspects — EXCEPT auth-flow/public-by-design endpoints."""
    # Space the routes apart so the ±6-line nearby-middleware window does not
    # bleed the guarded line's `isAuthorized` onto its neighbours.
    pad = "\n" * 12
    (tmp_path / "app.ts").write_text(
        "app.put('/rest/wallet/balance', h);\n"
        + pad  # sensitive write → suspect
        + "app.get('/rest/admin/config', h);\n"
        + pad  # management → suspect
        + "app.post('/rest/user/login', h);\n"
        + pad  # auth-flow → NOT a suspect
        + "app.post('/api/Orders', security.isAuthorized());\n"
        + pad  # guarded → NOT a suspect
        + "app.get('/rest/products', h);\n"  # GET read, not mgmt → NOT a suspect
    )
    inv = _run(tmp_path)
    susp = {r["path"] for r in inv["routes"] if r["missing_auth_suspect"]}
    assert "/rest/wallet/balance" in susp
    assert "/rest/admin/config" in susp
    assert "/rest/user/login" not in susp  # public by design
    assert "/api/Orders" not in susp  # guarded
    assert "/rest/products" not in susp  # GET, non-management
    assert inv["coverage"]["missing_auth_suspect_count"] >= 2


# ---------------------------------------------------------------------------
# relevance_tags — display signal for finding-free §5 rows
# ---------------------------------------------------------------------------


def test_relevance_tags_flag_auth_registration_and_suspect_routes(tmp_path: Path) -> None:
    """A finding-free route still earns §5 visibility when it sits on the
    auth / registration / management surface or is a missing-auth/authz suspect.
    A plain authenticated read with no id and no auth-flow path carries none."""
    pad = "\n" * 12
    (tmp_path / "app.ts").write_text(
        "app.post('/rest/user/login', h);\n"  # authentication
        + pad
        + "app.post('/api/Users/register', h);\n"  # registration (+ POST, but public-by-design login/register suppresses missing-auth)
        + pad
        + "app.get('/metrics', h);\n"  # management surface
        + pad
        + "app.put('/rest/wallet/balance', h);\n"  # state-changing, unguarded → missing-auth
        + pad
        + "app.get('/rest/products', h);\n"  # plain read, no relevance
    )
    inv = _run(tmp_path)
    tags = {r["path"]: set(r.get("relevance_tags") or []) for r in inv["routes"]}
    assert "authentication" in tags["/rest/user/login"]
    assert "registration" in tags["/api/Users/register"]
    assert "management" in tags["/metrics"]
    assert "missing-auth" in tags["/rest/wallet/balance"]
    assert tags["/rest/products"] == set()  # no relevance → may be collapsed in §5


def test_relevance_tags_validates_against_schema(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("app.post('/rest/user/login', h);\napp.get('/metrics', h);\n")
    inv = _run(tmp_path)
    jsonschema.validate(inv, SCHEMA)


# ---------------------------------------------------------------------------
# Excludes
# ---------------------------------------------------------------------------


def test_excludes_node_modules(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/x', h);")
    (tmp_path / "node_modules/express/lib").mkdir(parents=True)
    (tmp_path / "node_modules/express/lib/router.js").write_text("app.get('/should-not-appear', h);")
    inv = _run(tmp_path)
    paths = {r["path"] for r in inv["routes"]}
    assert "/x" in paths
    assert "/should-not-appear" not in paths


def test_excludes_build_output(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/keep', h);")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/bundle.js").write_text("app.get('/drop', h);")
    inv = _run(tmp_path)
    paths = {r["path"] for r in inv["routes"]}
    assert "/keep" in paths
    assert "/drop" not in paths


# ---------------------------------------------------------------------------
# Schema and contract
# ---------------------------------------------------------------------------


def test_route_inventory_validates_against_schema(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/a', h);\nrouter.post('/b', h);\n")
    inv = _run(tmp_path)
    jsonschema.validate(inv, SCHEMA)


def test_route_ids_are_unique_and_sequential(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/a', h);\napp.get('/b', h);\napp.get('/c', h);\n")
    inv = _run(tmp_path)
    ids = [r["route_id"] for r in inv["routes"]]
    assert ids == sorted(set(ids))
    assert all(rid.startswith("R-") for rid in ids)


def test_empty_repo_emits_empty_routes(tmp_path: Path) -> None:
    inv = _run(tmp_path)
    assert inv["version"] == 1
    assert inv["routes"] == []
    assert inv["coverage"]["route_count"] == 0


def test_exclude_fallback_and_source_walker_filters(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ri, "_scan_is_excluded", None)
    assert ri._is_excluded("node_modules/pkg/index.js") is True
    assert ri._is_excluded("src/app.ts") is False

    def boom(_rel):
        raise RuntimeError("bad scan-excludes")

    monkeypatch.setattr(ri, "_scan_is_excluded", boom)
    assert ri._is_excluded("vendor/lib/router.js") is True

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.ts").write_text("app.get('/x', h);\n", encoding="utf-8")
    (tmp_path / "src" / "notes.txt").write_text("app.get('/ignored', h);\n", encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("app.get('/ignored', h);\n", encoding="utf-8")

    files = [p.relative_to(tmp_path).as_posix() for p in ri._walk_sources(tmp_path)]
    assert files == ["src/app.ts"]


def test_read_lines_and_extract_file_handle_empty_and_unsupported_files(tmp_path: Path) -> None:
    missing = tmp_path / "missing.ts"
    assert ri._read_lines(missing) == []

    empty = tmp_path / "empty.ts"
    empty.write_text("", encoding="utf-8")
    assert ri._extract_file(tmp_path, empty) == []

    unsupported = tmp_path / "routes.txt"
    unsupported.write_text("app.get('/ignored', h);\n", encoding="utf-8")
    assert ri._extract_file(tmp_path, unsupported) == []


def test_route_inventory_writes_to_output_dir(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("app.get('/x', h);")
    out = tmp_path / "output"
    subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(tmp_path), "--output-dir", str(out)],
        capture_output=True,
        text=True,
        check=True,
    )
    target = out / ".route-inventory.json"
    assert target.is_file()
    data = json.loads(target.read_text())
    assert data["version"] == 1


def test_route_inventory_missing_repo_returns_error(tmp_path: Path, capsys) -> None:
    assert ri._main(["--repo-root", str(tmp_path / "missing"), "--stdout"]) == 1
    assert "repo-root not found" in capsys.readouterr().err


def test_build_inventory_tolerates_unreadable_source_and_dedupes_routes(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "app.ts"
    src.write_text("app.get('/x', h);\n", encoding="utf-8")

    def fake_walk(_repo_root):
        return iter([src])

    duplicate = ri.RouteCandidate(
        method="GET",
        path="/x",
        framework="express",
        handler_file="app.ts",
        handler_line=1,
    )

    monkeypatch.setattr(ri, "_walk_sources", fake_walk)
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unreadable")))
    monkeypatch.setattr(ri, "_extract_file", lambda *_args, **_kwargs: [duplicate, duplicate])

    inv = ri.build_inventory(tmp_path)

    assert inv["coverage"]["route_count"] == 1
    assert inv["routes"][0]["path"] == "/x"


# ---------------------------------------------------------------------------
# missing_authz_suspect (BOLA surface) + cross-file authZ lift
# ---------------------------------------------------------------------------


def _route(inv: dict, method: str, path: str) -> dict:
    hits = [r for r in inv["routes"] if r["method"] == method and r["path"] == path]
    assert hits, f"{method} {path} not in inventory"
    return hits[0]


def test_missing_authz_suspect_on_authenticated_object_route(tmp_path: Path) -> None:
    """Authenticated (central authN mount), object-addressing (:id), no authZ
    gate → BOLA suspect."""
    (tmp_path / "app.ts").write_text(
        "const app = express();\n"
        "app.use('/api/orders', security.isAuthorized());\n"
        "app.get('/api/orders/:id', getOrder);\n"
        "app.put('/api/orders/:id', updateOrder);\n"
    )
    inv = _run(tmp_path)
    assert _route(inv, "GET", "/api/orders/:id")["authn_signal"] == "middleware_present"
    assert _route(inv, "GET", "/api/orders/:id")["missing_authz_suspect"] is True
    assert _route(inv, "PUT", "/api/orders/:id")["missing_authz_suspect"] is True
    assert inv["coverage"]["missing_authz_suspect_count"] >= 2


def test_missing_authz_suspect_cleared_by_central_authz_mount(tmp_path: Path) -> None:
    """A centrally-mounted role guard lifts authz cross-file → not a suspect (P1b)."""
    (tmp_path / "app.ts").write_text(
        "const app = express();\n"
        "app.use('/api/orders', security.isAuthorized());\n"
        "app.use('/api/orders', requireRole('user'));\n"
        "app.get('/api/orders/:id', getOrder);\n"
    )
    inv = _run(tmp_path)
    r = _route(inv, "GET", "/api/orders/:id")
    assert r["authz_signal"] == "middleware_present"
    assert r["missing_authz_suspect"] is False


def test_missing_authz_suspect_not_on_unauthenticated_route(tmp_path: Path) -> None:
    """Public (no authN) object route is not a BOLA suspect — precision guard."""
    (tmp_path / "app.ts").write_text("const app = express();\napp.get('/api/products/:id', getProduct);\n")
    inv = _run(tmp_path)
    assert _route(inv, "GET", "/api/products/:id")["missing_authz_suspect"] is False


def test_missing_authz_suspect_not_on_collection_route(tmp_path: Path) -> None:
    """No path parameter → not object-addressing → not a suspect."""
    (tmp_path / "app.ts").write_text(
        "const app = express();\n"
        "app.use('/api/orders', security.isAuthorized());\n"
        "app.get('/api/orders', listOrders);\n"
    )
    inv = _run(tmp_path)
    assert _route(inv, "GET", "/api/orders")["missing_authz_suspect"] is False


def test_llm_tag_requires_both_a_model_path_and_a_declared_sdk(tmp_path: Path) -> None:
    """A chat route counts as an LLM surface only where a model SDK is declared."""
    (tmp_path / "app.ts").write_text("const app = express();\napp.post('/rest/chat', chatbot);\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"@ai-sdk/openai-compatible": "^2.0.35"}}')
    assert "llm" in _route(_run(tmp_path), "POST", "/rest/chat")["relevance_tags"]


def test_a_chat_route_without_a_model_dependency_is_not_tagged(tmp_path: Path) -> None:
    """False-positive guard: plenty of applications chat without a model."""
    (tmp_path / "app.ts").write_text("const app = express();\napp.post('/rest/chat', chatbot);\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.19.0"}}')
    assert "llm" not in _route(_run(tmp_path), "POST", "/rest/chat")["relevance_tags"]


def test_a_model_dependency_alone_tags_nothing(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("const app = express();\napp.get('/api/products', listProducts);\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"openai": "^4.0.0"}}')
    assert _route(_run(tmp_path), "GET", "/api/products")["relevance_tags"] == []


def test_llm_sdk_signal_covers_proxy_and_gateway_libraries(tmp_path: Path) -> None:
    """A route reaches a model through a proxy layer just as through a vendor SDK."""
    (tmp_path / "app.py").write_text("@app.post('/v1/completions')\ndef complete():\n    pass\n")
    (tmp_path / "requirements.txt").write_text("fastapi==0.115.0\nlitellm==1.52.0\n")
    assert "llm" in _route(_run(tmp_path), "POST", "/v1/completions")["relevance_tags"]


# ---------------------------------------------------------------------------
# A guard is code: literals, comments and handler bodies never count as one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/privacy-policy", "/docs/authorize-help", "/api/authenticate-info"],
)
def test_a_path_literal_is_not_a_guard(tmp_path: Path, path: str) -> None:
    (tmp_path / "app.js").write_text(f"app.post('{path}', saveItem)\n")
    (row,) = _run(tmp_path)["routes"]
    assert (row["authn_signal"], row["authz_signal"]) == ("unknown", "unknown")


def test_a_guard_call_still_counts_beside_a_literal(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("app.post('/privacy-policy', requireAuth, authorize('editor'), saveItem)\n")
    (row,) = _run(tmp_path)["routes"]
    assert (row["authn_signal"], row["authz_signal"]) == ("middleware_present", "middleware_present")


@pytest.mark.parametrize(
    ("annotation", "mapping"),
    [
        ('@Secured("ROLE_ADMIN")', '@DeleteMapping("/items/{id}")'),
        ('@RolesAllowed({"auditor"})', '@PutMapping("/ledgers/{ledgerId}")'),
        ("@PreAuthorize(\"hasRole('OPS')\")", '@PostMapping("/jobs")'),
    ],
)
def test_method_security_annotations_authenticate_and_authorize(tmp_path: Path, annotation: str, mapping: str) -> None:
    (tmp_path / "Ctrl.java").write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class Ctrl {\n"
        f"    {annotation}\n"
        f"    {mapping}\n"
        "    public void act() { service.run(); }\n"
        "}\n"
    )
    (row,) = _run(tmp_path)["routes"]
    assert row["authn_signal"] == "middleware_present"
    assert row["authz_signal"] == "decorator_present"


def test_a_mapping_without_method_security_stays_unknown(tmp_path: Path) -> None:
    (tmp_path / "Ctrl.java").write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class Ctrl {\n"
        '    @DeleteMapping("/items/{id}")\n'
        "    public void remove(Long id) { repo.deleteById(id); }\n"
        "}\n"
    )
    (row,) = _run(tmp_path)["routes"]
    assert (row["authn_signal"], row["authz_signal"]) == ("unknown", "unknown")


def test_a_bare_authorize_attribute_authenticates_and_roles_authorize() -> None:
    assert ri._scan_auth_text("[Authorize]\npublic IActionResult Get()") == ("middleware_present", "unknown")
    assert ri._scan_auth_text('[Authorize(Roles = "Admin")]') == ("middleware_present", "middleware_present")
    assert ri._scan_auth_text('[Authorize(Policy = "Billing")]') == ("middleware_present", "middleware_present")


@pytest.mark.parametrize(
    "commented",
    [
        "// app.put('/api/items/:id', requireAuth, updateItem)\n",
        "/* app.put('/api/items/:id', requireAuth, updateItem) */\n",
        "/*\n  app.put('/api/items/:id',\n    requireAuth, updateItem)\n*/\n",
    ],
)
def test_a_commented_out_registration_is_not_a_route_or_a_guard(tmp_path: Path, commented: str) -> None:
    (tmp_path / "server.js").write_text(commented + "app.get('/api/items/:id', showItem)\n")
    (tmp_path / "snippet.js").write_text("// app.use('/api/items', requireAuth)\n")
    inv = _run(tmp_path)
    assert [(r["method"], r["path"], r["authn_signal"]) for r in inv["routes"]] == [
        ("GET", "/api/items/:id", "unknown")
    ]


def test_a_url_inside_a_string_does_not_start_a_comment(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const docs = 'https://example.test'; app.post('/api/items', requireAuth, add)\n"
    )
    (row,) = _run(tmp_path)["routes"]
    assert row["authn_signal"] == "middleware_present"


@pytest.mark.parametrize(
    "example",
    [
        "const example = \"app.get('/example', handler)\";\n",
        "const example = `\napp.post('/example', handler)\n`;\n",
        "const example = \"app.route('/example').get(handler)\";\n",
    ],
)
def test_route_shaped_literal_examples_are_not_live_registrations(tmp_path: Path, example: str):
    (tmp_path / "server.js").write_text(example + "app.get('/actual', handler)\n")
    assert [(r["method"], r["path"]) for r in _run(tmp_path)["routes"]] == [("GET", "/actual")]


def test_a_quoted_guard_never_protects_an_actual_route(tmp_path: Path):
    (tmp_path / "server.js").write_text(
        "const express = require('express'); const app = express()\n"
        "const requireAuth = require('express-jwt')({secret: process.env.KEY})\n"
        "const example = \"app.use('/private', requireAuth)\"\n"
        "app.get('/private/data', (req,res) => res.json({value: 1}))\n"
    )
    (row,) = _run(tmp_path)["routes"]
    assert row["authn_signal"] not in {"present", "middleware_present"}
    assert row.get("guard_lines", []) == []


@pytest.mark.parametrize("execution", ["eval(example)", "new Function(example)()", "vm.runInNewContext(example)"])
def test_potentially_executed_string_routes_remain_candidates(tmp_path: Path, execution: str):
    (tmp_path / "server.js").write_text("const example = \"app.get('/dynamic', handler)\";\n" + execution)
    assert any(row["path"] == "/dynamic" for row in _run(tmp_path)["routes"])


def test_tutorial_directory_names_do_not_exclude_executable_routes(tmp_path: Path):
    (tmp_path / "tutorials").mkdir()
    (tmp_path / "tutorials/server.js").write_text("app.get('/actual', handler)\n")
    assert any(row["path"] == "/actual" for row in _run(tmp_path)["routes"])


@pytest.mark.parametrize(
    ("mount", "field"),
    [
        ("app.use('/api/items', rateLimit({ windowMs: 60000, max: f(10) }), requireAuth)\n", "authn_signal"),
        ("router.use('/api/items', cors({ origin: allow() }), requireRole('admin'))\n", "authz_signal"),
    ],
)
def test_a_mount_guard_after_a_nested_call_protects_the_prefix(tmp_path: Path, mount: str, field: str) -> None:
    receiver = mount.split(".", 1)[0]
    (tmp_path / "server.js").write_text(mount + f"{receiver}.delete('/api/items/:id', removeItem)\n")
    row = next(r for r in _run(tmp_path)["routes"] if r["path"] == "/api/items/:id")
    assert row[field] == "middleware_present"


@pytest.mark.parametrize(
    "mount",
    [
        "app.use('/api/items', serveDocs('requireAuth'))\n",
        "app.use('/api/items', (req, res, next) => { audit('requireRole'); next() })\n",
        "app.use('/api/items', function (req, res, next) { log(authorize); next() })\n",
    ],
)
def test_a_literal_or_handler_body_is_not_a_mount_guard(tmp_path: Path, mount: str) -> None:
    receiver = mount.split(".", 1)[0]
    (tmp_path / "server.js").write_text(mount + f"{receiver}.delete('/api/items/:id', removeItem)\n")
    row = next(r for r in _run(tmp_path)["routes"] if r["path"] == "/api/items/:id")
    assert (row["authn_signal"], row["authz_signal"]) == ("unknown", "unknown")


def test_a_commented_python_decorator_is_not_a_route(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "# @app.route('/admin/purge', methods=['POST'])\n"
        "@app.route('/items/<int:item_id>')\n"
        "def show(item_id):\n"
        "    return ''\n"
    )
    assert [r["path"] for r in _run(tmp_path)["routes"]] == ["/items/<int:item_id>"]


@pytest.mark.parametrize("name", ["records", "invoices"])
def test_decorators_do_not_authenticate_a_neighbour(tmp_path, name):
    (tmp_path / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.get('/private')\n@login_required\ndef private():\n    return 'ok'\n\n"
        f"@app.delete('/admin/{name}')\ndef remove():\n    return '', 204\n"
    )
    inventory = _run(tmp_path)
    assert _route(inventory, "GET", "/private")["authn_signal"] == "middleware_present"
    assert _route(inventory, "DELETE", "/admin/" + name)["authn_signal"] == "absent"


@pytest.mark.parametrize("name", ["records", "invoices"])
@pytest.mark.parametrize("placement", ["other-file", "other-object", "later", "before"])
def test_mount_guard_needs_the_same_object_and_precedes_the_handler(tmp_path, name, placement):
    header = "const app = express();\n"
    route = f"app.delete('/admin/{name}', (req, res) => {{ res.sendStatus(204); }});\n"
    guard = f"app.use('/admin/{name}', requireAuth);\n"
    if placement == "other-file":
        (tmp_path / "other.js").write_text(header + guard)
        source = header + route
    elif placement == "other-object":
        source = header + guard.replace("app.use", "other.use") + route
    else:
        source = header + (guard + route if placement == "before" else route + guard)
    (tmp_path / "api.js").write_text(source)
    row = _route(_run(tmp_path), "DELETE", "/admin/" + name)
    assert row["authn_signal"] == ("middleware_present" if placement == "before" else "absent")


@pytest.mark.parametrize("name", ["records", "invoices"])
def test_authenticated_action_without_object_id_still_needs_authorization_review(tmp_path, name):
    (tmp_path / "api.js").write_text(
        f"app.post('/{name}/export', requireAuth, exportData);\n"
        f"app.post('/{name}/approved', requireAuth, requireRole('exporter'), exportData);\n"
    )
    inventory = _run(tmp_path)
    assert "authorization-review-required" in _route(inventory, "POST", f"/{name}/export")["notes"]
    assert "authorization-review-required" not in _route(inventory, "POST", f"/{name}/approved")["notes"]


@pytest.mark.parametrize("resource", ["records", "invoices"])
@pytest.mark.parametrize("guarded", [True, False])
def test_local_scope_rejection_is_distinct_from_object_ownership(tmp_path, resource, guarded):
    guard = (
        f'    if "{resource}:write" not in claims.get("scope", "").split():\n        return "forbidden", 403\n'
        if guarded
        else ""
    )
    (tmp_path / "api.py").write_text(
        "from flask import Flask, request\nimport jwt\napp = Flask(__name__)\n"
        f'@app.post("/{resource}/<int:id>")\ndef change(id):\n'
        '    token = request.headers.get("Authorization", "").removeprefix("Bearer ")\n'
        '    try:\n        claims = jwt.decode(token, key, algorithms=["RS256"])\n'
        '    except jwt.InvalidTokenError:\n        return "unauthorized", 401\n'
        + guard
        + "    return repo.update(id)\n"
    )
    row = _route(_run(tmp_path), "POST", f"/{resource}/<int:id>")
    assert row["authn_signal"] == "present"
    assert ("authorization-review-required" in row["notes"]) == (not guarded)
    assert row["missing_authz_suspect"] is True


@pytest.mark.parametrize(
    "server,listed",
    [
        ("import { serveFiles } from './routes/files'\napp.use('/files/:name', serveFiles())\n", True),
        ("const { serveFiles } = require('./routes/files')\napp.use('/files/:name', serveFiles())\n", True),
        # A prefix mount without a path parameter stays a guard prefix.
        ("import { serveFiles } from './routes/files'\napp.use('/files', serveFiles())\n", False),
        # A deeper registration below the mount makes it a prefix, not a terminal handler.
        (
            "import { serveFiles } from './routes/files'\napp.use('/files/:name', serveFiles())\n"
            "app.get('/files/:name/meta', serveFiles())\n",
            False,
        ),
        # Guards and package middleware never become routes.
        ("import { isAuthorized } from './lib/auth'\napp.use('/files/:name', isAuthorized())\n", False),
        ("import * as security from './lib/auth'\napp.use('/files/:name', security.isAuthorized())\n", False),
        ("import express from 'express'\napp.use('/files/:name', express.static('files'))\n", False),
    ],
    ids=["import", "require", "prefix", "not-leaf", "named-guard", "member-guard", "package"],
)
def test_terminal_use_mount_is_a_route_with_its_handler_module(tmp_path: Path, server: str, listed: bool) -> None:
    """A `use` mount that ends the request at a repository handler is a route,
    so the handler module reaches the registering component's analysis."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "files.ts").write_text(
        "export function serveFiles () { return (req, res) => res.send('x') }\n"
    )
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "auth.ts").write_text("export function isAuthorized () { return (req, res, next) => next() }\n")
    (tmp_path / "server.ts").write_text("import express from 'express'\nconst app = express()\n" + server)
    mounts = [r for r in ri.build_inventory(tmp_path)["routes"] if r["method"] == "ALL" and r["path"] == "/files/:name"]
    assert bool(mounts) == listed
    if listed:
        assert mounts[0]["handler_module"] == "routes/files.ts"


# ---------------------------------------------------------------------------
# Router composition across `use` mounts
# ---------------------------------------------------------------------------

_REQUIRE_AUTH = (
    "export function requireAuth() {\n"
    "  return (req, res, next) => {\n"
    "    if (!req.session.user) {\n"
    "      return res.status(401).end();\n"
    "    }\n"
    "    next();\n"
    "  };\n"
    "}\n"
)


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")


@pytest.mark.parametrize(
    "files,expected",
    [
        (
            {
                "src/app.ts": "import express from 'express';\nimport routes from './routes';\n"
                "const app = express();\napp.use('/', routes);\n",
                "src/routes.ts": "import { Router } from 'express';\nimport usersRouter from './api/users';\n"
                "import { requireAuth } from './auth';\nconst router = Router();\n"
                "router.use('/api/v2/user', requireAuth(), usersRouter);\nexport default router;\n",
                "src/auth.ts": _REQUIRE_AUTH,
                "src/api/users.ts": "import { Router } from 'express';\nconst router = Router();\n"
                "router.get('/me', (req, res) => res.json(req.session.user));\nexport default router;\n",
            },
            ("GET", "/api/v2/user/me", "src/api/users.ts"),
        ),
        (
            {
                "server.js": "const express = require('express');\nconst { requireAuth } = require('./lib/auth');\n"
                "const { createOrdersRouter } = require('./orders/router');\nconst app = express();\n"
                "app.use('/shop/orders', requireAuth(), createOrdersRouter(db));\n",
                "lib/auth.js": _REQUIRE_AUTH.replace("export function", "function")
                + "module.exports = { requireAuth };\n",
                "orders/router.js": "const { Router } = require('express');\nfunction createOrdersRouter(db) {\n"
                "  const r = Router();\n  r.delete('/:orderId', (req, res) => res.sendStatus(204));\n  return r;\n}\n"
                "module.exports = { createOrdersRouter };\n",
            },
            ("DELETE", "/shop/orders/:orderId", "orders/router.js"),
        ),
    ],
    ids=["imported-router", "required-factory"],
)
def test_mounted_routers_take_the_full_path_and_the_mount_guard(tmp_path: Path, files, expected) -> None:
    _write(tmp_path, files)
    method, path, handler_file = expected
    route = _route(_run(tmp_path), method, path)
    assert route["handler_file"] == handler_file
    assert route["authn_signal"] == "middleware_present"
    assert route["authn_handler_signal"] == "verified"


def test_a_same_file_router_and_an_unguarded_mount_keep_their_own_signals(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app.ts": "import express from 'express';\nconst app = express();\nconst api = express.Router();\n"
            "api.get('/status', (req, res) => res.send('ok'));\napp.use('/api', api);\n",
        },
    )
    route = _route(_run(tmp_path), "GET", "/api/status")
    assert route["authn_signal"] == "absent"


def test_middleware_and_unmounted_routers_are_no_router_mounts(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app.ts": "import express from 'express';\nimport { audit } from './audit';\nconst app = express();\n"
            "app.use('/admin', audit);\n",
            "audit.ts": "import { Router } from 'express';\nexport const audit = (req, res, next) => next();\n"
            "const router = Router();\nrouter.get('/report', (req, res) => res.send('r'));\nexport default router;\n",
        },
    )
    paths = {(r["method"], r["path"]) for r in _run(tmp_path)["routes"]}
    assert ("GET", "/report") in paths and ("GET", "/admin/report") not in paths


_USERS_ROUTER = (
    "import { Router } from 'express';\nconst router = Router();\n"
    "router.get('/me', (req, res) => res.json({}));\nexport default router;\n"
)


@pytest.mark.parametrize(
    "setup,expected",
    [
        ("installSecurity(app);\n", "unknown"),
        ("configure(app, options);\n", "unknown"),
        ("http.createServer(app).listen(8080);\n", "absent"),
    ],
    ids=["helper", "helper-with-options", "server-only"],
)
def test_an_application_handed_to_a_helper_may_be_guarded_unseen(tmp_path: Path, setup: str, expected: str) -> None:
    _write(
        tmp_path,
        {
            "src/app.ts": "import express from 'express';\nimport http from 'http';\nimport usersRouter from './users';\n"
            "import { installSecurity, configure } from './security';\nconst app = express();\n"
            + setup
            + "app.use('/api/users', usersRouter);\n",
            "src/security.ts": "export function installSecurity(app) {}\nexport function configure(app, o) {}\n",
            "src/users.ts": _USERS_ROUTER,
        },
    )
    assert _route(_run(tmp_path), "GET", "/api/users/me")["authn_signal"] == expected


def test_two_mounts_on_one_line_keep_their_own_guards(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app.ts": "import express from 'express';\nimport aRouter from './a';\nimport bRouter from './b';\n"
            "import { requireAuth } from './auth';\nconst app = express();\n"
            "app.use('/a', aRouter); app.use('/b', requireAuth(), bRouter);\n",
            "auth.ts": _REQUIRE_AUTH,
            "a.ts": _USERS_ROUTER,
            "b.ts": _USERS_ROUTER,
        },
    )
    inventory = _run(tmp_path)
    assert _route(inventory, "GET", "/b/me")["authn_signal"] == "middleware_present"
    assert _route(inventory, "GET", "/a/me")["authn_signal"] == "absent"


def test_koa_router_nesting_through_routes_is_composed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app.js": "const Koa = require('koa');\nconst Router = require('@koa/router');\nconst app = new Koa();\n"
            "const api = new Router();\nconst router = new Router();\n"
            "router.get('/me', (ctx) => { ctx.body = {}; });\napi.use('/users', router.routes());\n"
            "app.use(api.routes());\n",
        },
    )
    assert _route(_run(tmp_path), "GET", "/users/me")["framework"] == "koa"


@pytest.mark.parametrize(
    "guards",
    [
        "router.use(requireAuth(), requireAdmin(), csrfProtection);\n",
        "const adminGuards = [requireAuth(), requireAdmin()];\nrouter.use(...adminGuards);\n",
    ],
)
def test_a_router_wide_admin_gate_authenticates_and_authorizes_later_routes(tmp_path: Path, guards: str) -> None:
    (tmp_path / "admin.ts").write_text(
        "import { Router } from 'express';\nconst router = Router();\n"
        + guards
        + "router.patch('/apps/:id/scope', h);\n"
    )
    (row,) = _run(tmp_path)["routes"]
    assert (row["authn_signal"], row["authz_signal"]) == ("middleware_present", "middleware_present")
    assert "authorization-review-required" not in row["notes"]


def test_a_spread_without_a_local_array_proves_no_guard(tmp_path: Path) -> None:
    (tmp_path / "admin.ts").write_text(
        "import { Router } from 'express';\nimport { guards } from './g';\nconst router = Router();\n"
        "router.use(...guards);\nrouter.patch('/apps/:id/scope', h);\n"
    )
    (row,) = _run(tmp_path)["routes"]
    assert row["authn_signal"] == "unknown"


def test_a_guarded_route_named_like_a_public_probe_is_not_public(tmp_path: Path) -> None:
    (tmp_path / "admin.ts").write_text(
        "import { Router } from 'express';\nconst router = Router();\n"
        "router.post('/backoffice/refresh', requireAuth(), h);\nrouter.post('/auth/refresh', h);\n"
        "router.get('/jobs/:id/status', h);\nrouter.get('/status', h);\n"
    )
    notes = {row["path"]: row["notes"] for row in _run(tmp_path)["routes"]}
    assert "public-by-design" not in notes["/backoffice/refresh"]
    assert "public-by-design" not in notes["/jobs/:id/status"]
    assert "public-by-design" in notes["/auth/refresh"]
    assert "public-by-design" in notes["/status"]


def test_a_route_with_a_configured_path_is_an_authentication_entry_point(tmp_path: Path) -> None:
    (tmp_path / "auth.ts").write_text(
        "import { Router } from 'express';\nconst router = Router();\nconst LOGIN_PATH = '/login';\n"
        "router.get(LOGIN_PATH, startLogin);\n"
        "router.get(config.oidc.callbackPath, async (req, res) => { await client.authorizationCodeGrant(cfg, url); });\n"
    )
    rows = {row["path"]: row for row in _run(tmp_path)["routes"]}
    assert set(rows) == {"/login", "/{config.oidc.callbackPath}"}
    callback = rows["/{config.oidc.callbackPath}"]
    assert {"path-from-configuration", "public-by-design"} <= set(callback["notes"])
    assert "authentication" in callback["relevance_tags"]


@pytest.mark.parametrize(
    "source",
    [
        "const api = axios.create();\napi.get(endpoint, { params });\n",
        "import express from 'express';\nconst app = express();\napp.get(settingName);\n",
    ],
)
def test_a_client_call_or_a_setting_read_is_no_route(tmp_path: Path, source: str) -> None:
    (tmp_path / "client.ts").write_text(source)
    assert _run(tmp_path)["routes"] == []


def test_each_method_of_a_route_chain_is_a_route_with_its_own_guard(tmp_path: Path) -> None:
    (tmp_path / "items.ts").write_text(
        "import { Router } from 'express';\nconst router = Router();\n"
        "router\n  .route('/items/:id')\n  .get(readItem)\n  .patch(requireAuth(), updateItem);\n"
    )
    rows = {(row["method"], row["path"]): row for row in _run(tmp_path)["routes"]}
    assert set(rows) == {("GET", "/items/:id"), ("PATCH", "/items/:id")}
    assert rows[("GET", "/items/:id")]["authn_signal"] == "unknown"
    assert rows[("PATCH", "/items/:id")]["authn_signal"] == "middleware_present"
    assert rows[("PATCH", "/items/:id")]["handler_line"] == 6
