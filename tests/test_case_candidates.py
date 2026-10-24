"""Applicability and starting candidates of test cases over a small web application (REQ-040)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from analyzers import authz_confirm
from analyzers.route_inventory import build_inventory
from model import case_candidates as cc
from model.case_outcomes import load_catalog

from tests.test_controller_fixture import FILES

# The controller fixture (an order route behind a verified JWT guard, a public
# login and a route behind an unresolvable guard) plus a guard that only
# decodes its token, one handler module with an ownership check, a check that
# exists only in a comment and no check at all, a role-guarded route, and a
# second component that serves the same resource.
SHOP = {
    **FILES,
    "server.js": FILES["server.js"].replace(
        "app.listen(3000)\n",
        "const { requireAuth } = require('./lib/decode')\n"
        "const invoices = require('./lib/invoices')\n"
        "app.get('/api/wallet/:id', requireAuth, (req, res) => res.json({ id: req.params.id }))\n"
        "app.get('/api/invoices/:id', authenticate, invoices.show())\n"
        "app.delete('/api/invoices/:id', authenticate, invoices.remove())\n"
        "app.get('/api/receipts/:id', authenticate, invoices.receipt())\n"
        "app.post('/api/users/:id/role', authenticate, requireRole('admin'), (req, res) => res.status(204).end())\n"
        "app.listen(3000)\n",
    ),
    "lib/decode.js": (
        "const jwt = require('jsonwebtoken')\n"
        "module.exports.requireAuth = (req, res, next) => {\n"
        "  const user = jwt.decode((req.headers.authorization || '').replace('Bearer ', ''))\n"
        "  if (!user) return res.status(401).end()\n"
        "  req.user = user\n"
        "  next()\n"
        "}\n"
    ),
    "lib/invoices.js": (
        "const Invoice = require('./model')\n"
        "module.exports.show = () => async (req, res) => {\n"
        "  const invoice = await Invoice.findById(req.params.id)\n"
        "  if (invoice.userId !== req.user.id) throw new Error('forbidden')\n"
        "  res.json(invoice)\n"
        "}\n"
        "module.exports.remove = () => async (req, res) => {\n"
        "  const invoice = await Invoice.findById(req.params.id)\n"
        "  // if (invoice.userId !== req.user.id) throw new Error('forbidden')\n"
        "  await invoice.destroy()\n"
        "  res.status(204).end()\n"
        "}\n"
        "module.exports.receipt = () => async (req, res) => {\n"
        "  const receipt = await Invoice.findById(req.params.id)\n"
        "  /* if (receipt.userId !== req.user.id) throw new Error('forbidden') */\n"
        "  res.json(receipt)\n"
        "}\n"
    ),
    "lib/model.js": "module.exports = { findById: async (id) => ({ id }) }\n",
    "admin/server.js": (
        "const express = require('express')\n"
        "const { authenticate } = require('../lib/auth')\n"
        "const Invoice = require('../lib/model')\n"
        "\n"
        "const app = express()\n"
        "\n"
        "app.get('/api/invoices/:id', authenticate, async (req, res) => {\n"
        "  const invoice = await Invoice.findById(req.params.id)\n"
        "  res.json(invoice)\n"
        "})\n"
    ),
}
COMPONENTS = {
    "api": ["server.js", "lib/auth.js", "lib/reports.js", "lib/decode.js", "lib/invoices.js", "lib/model.js"],
    "web": ["web/src/api.ts"],
    "admin": ["admin/server.js"],
}
CANDIDATE_ID = re.compile(r"pc-[0-9a-f]{16}")


def write_repo(root: Path, files: dict[str, str]) -> Path:
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")
    return root


def shop_facts(root: Path) -> tuple[dict, list[dict], dict]:
    """(facts, scanner findings, inventory) of the shop as the controller would build them."""
    write_repo(root, SHOP)
    inventory = build_inventory(root)
    findings = authz_confirm.build_document(root, inventory)["findings"]
    return cc.route_facts(root, inventory, findings, components=COMPONENTS), findings, inventory


def route_id(facts: dict, method: str, path: str, file: str = "server.js") -> str:
    return next(
        row["route_id"]
        for row in facts["routes"].values()
        if (row["method"], row["path"], row["handler_file"]) == (method, path, file)
    )


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


@pytest.fixture(scope="module")
def shop(tmp_path_factory):
    return shop_facts(tmp_path_factory.mktemp("shop"))


def _case(catalog, case_id):
    return next(case for case in catalog["test_cases"] if case["id"] == case_id)


# --- facts --------------------------------------------------------------------


def test_facts_record_route_authentication_and_handler_evidence(shop):
    facts, _, _ = shop
    orders = facts["routes"][route_id(facts, "GET", "/api/orders/:id")]
    assert (orders["authn_signal"], orders["authn_handler_signal"]) == ("middleware_present", "verified")
    assert orders["object_id"] and orders["handler_read"] and not orders["object_access"]
    login = facts["routes"][route_id(facts, "POST", "/rest/login")]
    assert (login["authn_signal"], login["object_id"]) == ("absent", False)
    wallet = facts["routes"][route_id(facts, "GET", "/api/wallet/:id")]
    assert wallet["authn_handler_signal"] == "decode_only"
    show = facts["routes"][route_id(facts, "GET", "/api/invoices/:id")]
    assert show["ownership_predicate"] and show["object_access"]
    assert ["lib/invoices.js", 2, 6] in show["chain"]
    # A check written only in a line or block comment is no ownership predicate.
    for path, method in (("/api/invoices/:id", "DELETE"), ("/api/receipts/:id", "GET")):
        row = facts["routes"][route_id(facts, method, path)]
        assert row["object_access"] and not row["ownership_predicate"]
        assert row["scanner_rules"] == ["AUTHZ-301"]


def test_facts_are_plain_data_without_absolute_paths(shop):
    facts, _, inventory = shop
    text = json.dumps(facts)
    assert json.loads(text) == facts
    assert inventory["repo_root"] not in text
    assert all(not path.startswith("/") for path in facts["files"])


def test_routes_belong_to_the_component_that_owns_their_handler(shop):
    facts, _, _ = shop
    components = facts["components"]
    assert route_id(facts, "GET", "/api/invoices/:id", "admin/server.js") in components["admin"]["route_ids"]
    assert components["web"]["route_ids"] == []
    api = set(components["api"]["route_ids"])
    assert {row["route_id"] for row in facts["routes"].values() if row["handler_file"] == "server.js"} == api


# --- applicability ------------------------------------------------------------


def test_signals_apply_per_component(catalog, shop):
    facts, _, _ = shop
    assert cc.applies(_case(catalog, "TC-AUTHN-01"), facts, "api") == (True, cc.APPLIES_REASONS["routes"])
    assert cc.applies(_case(catalog, "TC-AUTHZ-01"), facts, "api")[0]
    assert cc.applies(_case(catalog, "TC-AUTHN-02"), facts, "api") == (True, cc.APPLIES_REASONS["jwt_usage"])
    # The browser client registers no routes and handles no tokens.
    assert cc.applies(_case(catalog, "TC-AUTHN-01"), facts, "web") == (False, cc.NOT_APPLICABLE_REASON)
    assert cc.applies(_case(catalog, "TC-AUTHZ-01"), facts, "web")[0] is False
    assert cc.applies(_case(catalog, "TC-AUTHN-02"), facts, "web")[0] is False
    assert cc.applies(_case(catalog, "TC-DATA-02"), facts, "web") == (True, cc.APPLIES_REASONS["always"])
    # Without a component the whole repository counts.
    assert cc.applies(_case(catalog, "TC-AUTHN-02"), facts)[0]


def test_a_signal_without_an_evaluator_applies(catalog, shop):
    facts, _, _ = shop
    assert cc.applies(_case(catalog, "TC-INFRA-01"), facts, "web") == (True, cc.NO_EVALUATOR_REASON)
    assert cc.applies({"applies_when": [{"signal": "quantum_usage"}]}, facts, "web") == (True, cc.NO_EVALUATOR_REASON)
    assert cc.applies({"applies_when": []}, facts, "web") == (True, cc.NO_EVALUATOR_REASON)
    # One evaluated signal that is missing does not outweigh one that cannot be evaluated.
    mixed = {"applies_when": [{"signal": "jwt_usage"}, {"signal": "quantum_usage"}]}
    assert cc.applies(mixed, facts, "web") == (True, cc.NO_EVALUATOR_REASON)


def test_a_signal_mentioned_only_in_comments_or_test_files_does_not_apply(catalog, tmp_path):
    mentions = {
        "app.js": (
            "const express = require('express')\n"
            "// const jwt = require('jsonwebtoken')\n"
            "/* jwt.verify(token, key); app.get('/api/orders/:id', handler) */\n"
            "const app = express()\n"
            "// app.get('/api/orders/:id', (req, res) => res.json({}))\n"
        ),
        "worker.py": "# import jwt\n# subprocess.run(['ls'])\nprint('ready')\n",
        "test/auth.test.js": "const jwt = require('jsonwebtoken')\njwt.verify(token, key)\n",
        "src/auth.spec.ts": "import jwt from 'jsonwebtoken'\n",
        "tests/test_run.py": "import subprocess\nsubprocess.run(['ls'])\n",
    }
    root = write_repo(tmp_path / "mentions", mentions)
    facts = cc.route_facts(root, build_inventory(root), [], components={"app": list(mentions)})
    assert facts["routes"] == {}
    for case_id in ("TC-AUTHN-01", "TC-AUTHN-02", "TC-AUTHZ-01", "TC-INPUT-03"):
        assert cc.applies(_case(catalog, case_id), facts, "app") == (False, cc.NOT_APPLICABLE_REASON), case_id

    # The same code outside a comment applies.
    code = {
        "app.js": "const jwt = require('jsonwebtoken')\nconst express = require('express')\nconst app = express()\n"
        "app.get('/api/orders/:id', (req, res) => res.json({}))\n",
        "worker.py": "import subprocess\nsubprocess.run(['ls'])\n",
    }
    root = write_repo(tmp_path / "code", code)
    facts = cc.route_facts(root, build_inventory(root), [], components={"app": list(code)})
    for case_id in ("TC-AUTHN-01", "TC-AUTHN-02", "TC-AUTHZ-01", "TC-INPUT-03"):
        assert cc.applies(_case(catalog, case_id), facts, "app")[0], case_id


# --- starting candidates ------------------------------------------------------


def test_object_routes_and_scanner_hits_form_one_candidate_per_location(catalog, shop):
    facts, findings, _ = shop
    case = _case(catalog, "TC-AUTHZ-01")
    result = cc.starting_candidates(case, "api", facts, findings)
    candidates = result["candidates"]
    assert result["overflow"] == 0
    # Routes with an identifier in the path, and the login, whose body could carry one.
    expected = {
        route_id(facts, method, path)
        for method, path in (
            ("GET", "/api/orders/:id"),
            ("POST", "/rest/login"),
            ("GET", "/api/wallet/:id"),
            ("GET", "/api/invoices/:id"),
            ("DELETE", "/api/invoices/:id"),
            ("GET", "/api/receipts/:id"),
            ("POST", "/api/users/:id/role"),
        )
    }
    assert {row["route_id"] for row in candidates} == expected
    assert len(candidates) == len(expected)
    for row in candidates:
        assert CANDIDATE_ID.fullmatch(row["candidate_id"])
        assert row["origin"] == "pre-check"
        assert row["anchor"] == {
            "file": facts["routes"][row["route_id"]]["handler_file"],
            "line": facts["routes"][row["route_id"]]["handler_line"],
        }
    # The AUTHZ-301 hits sit at their routes' registrations and come first.
    flagged = [row for row in candidates if "rule_ids" in row]
    assert [row["rule_ids"] for row in flagged] == [["AUTHZ-301"], ["AUTHZ-301"]]
    assert candidates[: len(flagged)] == flagged
    # The admin component's hit on the same resource stays with the admin component.
    admin = cc.starting_candidates(case, "admin", facts, findings)["candidates"]
    assert [row["anchor"]["file"] for row in admin] == ["admin/server.js"]
    assert admin[0]["rule_ids"] == ["AUTHZ-301"]


def test_candidate_ids_are_stable_and_distinct_per_case_and_component(catalog, shop):
    facts, findings, _ = shop
    first = cc.starting_candidates(_case(catalog, "TC-AUTHZ-01"), "api", facts, findings)["candidates"]
    again = cc.starting_candidates(_case(catalog, "TC-AUTHZ-01"), "api", facts, findings)["candidates"]
    assert first == again
    ids = {row["candidate_id"] for row in first}
    assert len(ids) == len(first)
    other_case = cc.starting_candidates(_case(catalog, "TC-AUTHN-01"), "api", facts, findings)["candidates"]
    assert not ids & {row["candidate_id"] for row in other_case}


def test_route_facts_select_the_candidates_of_each_case(catalog, shop):
    facts, findings, _ = shop
    # Authentication covers every route of the component.
    authn = cc.starting_candidates(_case(catalog, "TC-AUTHN-01"), "api", facts, findings)["candidates"]
    assert {row["route_id"] for row in authn} == set(facts["components"]["api"]["route_ids"])
    routes = facts["components"]["api"]["route_ids"]
    # Privileged operations start from the missing-authorization suspects and every state-changing route,
    # whatever its guards: a guard known by name proves no role check.
    authz = cc.starting_candidates(_case(catalog, "TC-AUTHZ-02"), "api", facts, findings)["candidates"]
    changing = {"POST", "PUT", "PATCH", "DELETE", "ALL"}
    assert {row["route_id"] for row in authz} == {
        rid
        for rid in routes
        if facts["routes"][rid]["missing_authz_suspect"] or facts["routes"][rid]["method"].upper() in changing
    }
    # Privileged fields start from every route that accepts a request body.
    fields = cc.starting_candidates(_case(catalog, "TC-AUTHZ-03"), "api", facts, findings)["candidates"]
    assert fields and {row["route_id"] for row in fields} == {
        rid for rid in routes if facts["routes"][rid]["method"].upper() in {"POST", "PUT", "PATCH", "ALL"}
    }
    # A case without route facts starts from its rules only.
    assert cc.starting_candidates(_case(catalog, "TC-AUTHN-03"), "api", facts, [])["candidates"] == []
    # The browser client has no route candidates.
    assert cc.starting_candidates(_case(catalog, "TC-AUTHN-01"), "web", facts, findings)["candidates"] == []


def test_the_cap_keeps_scanner_hits_and_counts_the_rest(catalog, shop):
    facts, findings, _ = shop
    case = _case(catalog, "TC-AUTHZ-01")
    full = cc.starting_candidates(case, "api", facts, findings)["candidates"]
    capped = cc.starting_candidates(case, "api", facts, findings, cap=2)
    assert capped["candidates"] == full[:2]
    assert all("rule_ids" in row for row in capped["candidates"])
    assert capped["overflow"] == len(full) - 2
    assert cc.starting_candidates(case, "api", facts, findings, cap=0) == {"candidates": [], "overflow": len(full)}
    for cap in (-1, 2.5, True, "40"):
        with pytest.raises(ValueError):
            cc.starting_candidates(case, "api", facts, findings, cap=cap)


def test_owner_checks_also_start_from_routes_that_take_a_body(catalog, tmp_path):
    reviews = {
        "app.js": "const express = require('express')\nconst app = express()\n"
        "app.patch('/rest/reviews', (req, res) => res.json({ id: req.body.id }))\n"
        "app.get('/rest/status', (req, res) => res.json({}))\n",
    }
    root = write_repo(tmp_path / "reviews", reviews)
    facts = cc.route_facts(root, build_inventory(root), [], components={"app": list(reviews)})
    case = _case(catalog, "TC-AUTHZ-01")
    # The update takes the review's identifier from the body, not from the path.
    assert cc.applies(case, facts, "app") == (True, cc.APPLIES_REASONS["object_id_routes"])
    candidates = cc.starting_candidates(case, "app", facts, [])["candidates"]
    assert [facts["routes"][row["route_id"]]["path"] for row in candidates] == ["/rest/reviews"]
    # A component that only reads without an identifier gives the owner check nothing to start from.
    status = {"app.js": reviews["app.js"].replace("app.patch('/rest/reviews', ", "app.get('/rest/reviews', ")}
    root = write_repo(tmp_path / "status", status)
    facts = cc.route_facts(root, build_inventory(root), [], components={"app": list(status)})
    assert cc.applies(case, facts, "app") == (False, cc.NOT_APPLICABLE_REASON)


def test_role_checks_also_start_from_authenticated_reads_without_an_identifier(catalog, tmp_path):
    lists = {
        "server.js": "const express = require('express')\nconst { authenticate } = require('./lib/auth')\n"
        "const app = express()\n"
        "app.get('/rest/users', authenticate, (req, res) => res.json([]))\n"
        "app.get('/rest/products', (req, res) => res.json([]))\n",
        "lib/auth.js": FILES["lib/auth.js"],
    }
    root = write_repo(tmp_path, lists)
    facts = cc.route_facts(root, build_inventory(root), [], components={"api": list(lists)})
    users = facts["routes"][route_id(facts, "GET", "/rest/users")]
    # No inventory flag selects the user list; only its authentication does.
    assert not users["missing_authz_suspect"] and users["authn_signal"] == "middleware_present"
    candidates = cc.starting_candidates(_case(catalog, "TC-AUTHZ-02"), "api", facts, [])["candidates"]
    # The public catalog needs no role.
    assert [row["route_id"] for row in candidates] == [users["route_id"]]


def _at(name, line):
    return {"candidate_id": f"pc-{name}", "origin": "pre-check", "anchor": {"file": "server.js", "line": line}}


def test_batches_keep_each_location_in_one_job_and_give_the_first_job_every_test_case():
    precheck = {
        "TC-AUTHZ-01": [_at("a1", 1), _at("a2", 2)],
        "TC-AUTHZ-02": [_at("b1", 1), _at("b3", 3)],
        "TC-AUTHZ-03": [_at("c2", 2), _at("c4", 4)],
        "TC-AUTHZ-05": [],
    }
    # Lines 1 and 2 hold two candidates each and fill the first job; lines 3 and 4 follow.
    assert cc.batches(precheck, limit=4) == [
        {
            "TC-AUTHZ-01": [_at("a1", 1), _at("a2", 2)],
            "TC-AUTHZ-02": [_at("b1", 1)],
            "TC-AUTHZ-03": [_at("c2", 2)],
            "TC-AUTHZ-05": [],
        },
        {"TC-AUTHZ-02": [_at("b3", 3)], "TC-AUTHZ-03": [_at("c4", 4)]},
    ]
    # A location is never split, even when it alone exceeds the limit.
    tight = cc.batches(precheck, limit=1)
    assert len(tight) == 4 and tight[0] == {
        "TC-AUTHZ-01": [_at("a1", 1)],
        "TC-AUTHZ-02": [_at("b1", 1)],
        "TC-AUTHZ-03": [],
        "TC-AUTHZ-05": [],
    }
    # Within the limit, one job answers everything, as before batching.
    assert cc.batches(precheck) == [precheck]
    # A remainder under a quarter of the limit joins the job before it instead of paying a job's context.
    many = {"TC-AUTHZ-01": [_at(f"m{line}", line) for line in range(1, 10)]}
    assert [len(job["TC-AUTHZ-01"]) for job in cc.batches(many, limit=8)] == [9]
    # A remainder of a quarter or more keeps its own job.
    assert [len(job["TC-AUTHZ-01"]) for job in cc.batches(many, limit=4)] == [4, 4, 1]
    for limit in (0, -1, 2.5, True):
        with pytest.raises(ValueError):
            cc.batches(precheck, limit=limit)


def test_rule_candidates_stay_in_their_component_and_repository(catalog, shop):
    facts, _, _ = shop
    threats = [
        {"source_check_id": "AUTHZ-005", "evidence": {"file": "lib/auth.js", "line": 5}, "component_id": "api"},
        {"source_check_id": "AUTHZ-005", "evidence": {"file": "admin/server.js", "line": 2}, "component_id": "admin"},
        {"source_check_id": "AUTHZ-005", "evidence": {"file": "../outside.js", "line": 1}, "component_id": "api"},
        {"source_check_id": "INJ-001", "evidence": {"file": "lib/auth.js", "line": 3}, "component_id": "api"},
        {"check_id": "AUTHZ-006", "file": "lib/decode.js", "line": 3},
        {"check_id": "AUTHZ-006", "file": "web/src/api.ts", "line": 1},
        "not a finding",
        {"source_check_id": "AUTHZ-005", "evidence": {"file": "lib/auth.js", "line": "5"}},
    ]
    case = _case(catalog, "TC-AUTHN-02")
    candidates = cc.starting_candidates(case, "api", facts, threats)["candidates"]
    assert [(row["anchor"], row["rule_ids"]) for row in candidates] == [
        ({"file": "lib/auth.js", "line": 5}, ["AUTHZ-005"]),
        ({"file": "lib/decode.js", "line": 3}, ["AUTHZ-006"]),
    ]
    assert all("route_id" not in row for row in candidates)
    # The controller's findings keyed by component give the same result.
    keyed = {"api": threats[:1] + threats[2:4], "admin": threats[1:2]}
    assert cc.starting_candidates(case, "api", facts, keyed)["candidates"] == candidates[:1]
    # A hit at a route registration names the route even when no route fact selects it.
    role = route_id(facts, "POST", "/api/users/:id/role")
    row = facts["routes"][role]
    hit = {"source_check_id": "AUTHZ-005", "evidence": {"file": row["handler_file"], "line": row["handler_line"]}}
    tokens = cc.starting_candidates(_case(catalog, "TC-AUTHN-02"), "api", facts, [hit])["candidates"]
    assert [(entry["route_id"], entry["rule_ids"]) for entry in tokens] == [(role, ["AUTHZ-005"])]
    # Where a route fact selects the route too, the hit joins its candidate, which comes first.
    hit = {**hit, "source_check_id": "AUTHZ-003"}
    mass_assignment = cc.starting_candidates(_case(catalog, "TC-AUTHZ-03"), "api", facts, [hit])["candidates"]
    assert (mass_assignment[0]["route_id"], mass_assignment[0]["rule_ids"]) == (role, ["AUTHZ-003"])
    assert [entry["route_id"] for entry in mass_assignment].count(role) == 1


def test_component_scoped_calls_need_a_known_component(catalog, shop, tmp_path):
    facts, findings, inventory = shop
    case = _case(catalog, "TC-AUTHZ-01")
    with pytest.raises(ValueError):
        cc.starting_candidates(case, "billing", facts, findings)
    with pytest.raises(ValueError):
        cc.applies(case, facts, "billing")
    unassigned = cc.route_facts(write_repo(tmp_path, SHOP), inventory, findings)
    assert unassigned["components"] is None
    with pytest.raises(ValueError):
        cc.starting_candidates(case, "api", unassigned, findings)


# --- generated routes ---------------------------------------------------------

# finale-rest generates CRUD routes per model in a loop, behind a mount guard,
# a route chain, a registered delete, and a guard that is only a comment. One
# element states no plain name, one call limits its actions and update method,
# one builds its path from a value the file does not state, and an unrelated
# ``resource`` call is no generator.
GENERATED = {
    "server.js": (
        "const express = require('express')\n"
        "const finale = require('finale-rest')\n"
        "const { authenticate } = require('./lib/auth')\n"
        "const app = express()\n"
        "app.use('/api/Items/:id', authenticate)\n"
        "app.route('/api/Users/:id')\n"
        "  .get(authenticate)\n"
        "  .put(authenticate)\n"
        "// app.put('/api/Products/:id', authenticate)\n"
        "app.delete('/api/Products/:id', authenticate, (req, res) => res.status(204).end())\n"
        "const models = [\n"
        "  { name: 'User', exclude: ['password'] },\n"
        "  { name: 'Product' },\n"
        "  { name: 'Item' },\n"
        "  { name: 'bad name' },\n"
        "]\n"
        "for (const { name } of models) {\n"
        "  finale.resource({ model: name, endpoints: [`/api/${name}s`, `/api/${name}s/:id`] })\n"
        "}\n"
        "finale.resource({ endpoints: ['/api/Logs', '/api/Logs/:id'], actions: ['list', 'update'], updateMethod: 'patch' })\n"
        "finale.resource({ endpoints: [`/api/${kind}s`] })\n"
        "app.listen(3000)\n"
    ),
    "lib/auth.js": FILES["lib/auth.js"],
    "lib/store.js": "const store = { resource: () => {} }\nstore.resource({ endpoints: ['/api/Ghosts'] })\n",
}


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    root = write_repo(tmp_path_factory.mktemp("generated"), GENERATED)
    inventory = build_inventory(root)
    return cc.route_facts(root, inventory, [], components={"api": list(GENERATED)}), inventory


def test_generator_calls_add_the_routes_the_inventory_misses(generated):
    facts, inventory = generated
    rows = {(row["method"], row["path"]): row for row in facts["routes"].values() if row["generated"]}
    crud = [("GET", ""), ("POST", ""), ("GET", "/:id"), ("PUT", "/:id"), ("DELETE", "/:id")]
    expected = {(method, f"/api/{name}s{suffix}") for name in ("User", "Product", "Item") for method, suffix in crud}
    # The registered delete stays the inventory's route; the limited call adds only its list and patch.
    expected = expected - {("DELETE", "/api/Products/:id")} | {("GET", "/api/Logs"), ("PATCH", "/api/Logs/:id")}
    assert set(rows) == expected
    last = max(int(row["route_id"][2:]) for row in inventory["routes"])
    assert sorted(int(row["route_id"][2:]) for row in rows.values()) == list(range(last + 1, last + 1 + len(rows)))
    for (method, path), row in rows.items():
        assert (row["handler_file"], row["handler_line"]) == ("server.js", 20 if "Logs" in path else 18)
        assert row["object_id"] is path.endswith("/:id")
        assert not (row["handler_read"] or row["object_access"] or row["ownership_predicate"])
        assert row["route_id"] in facts["components"]["api"]["route_ids"]
    json.dumps(facts)


def test_a_generated_route_carries_the_registrations_that_run_before_it(generated):
    facts, _ = generated
    rows = {(row["method"], row["path"]): row for row in facts["routes"].values()}
    call = ["server.js", 18, 18]
    assert rows["PUT", "/api/Users/:id"]["chain"] == [["server.js", 6, 8], call]
    assert rows["GET", "/api/Items/:id"]["chain"] == [["server.js", 5, 5], call]
    assert rows["GET", "/api/Items"]["chain"] == [call]
    # A registration written only in a comment does not run.
    assert rows["PUT", "/api/Products/:id"]["chain"] == [call]
    # The inventory's own delete keeps its anchor and learns that the generator handles it next.
    delete = rows["DELETE", "/api/Products/:id"]
    assert not delete["generated"] and delete["handler_line"] == 10 and call in delete["chain"]


def test_commented_generators_and_guards_stay_out_after_a_regex_literal(tmp_path):
    # The quotes inside the regex literal end comment blanking for the rest of the file.
    notes = {
        "server.js": "const finale = require('finale-rest')\n"
        'const href = /a href="([^"]+?)"/gi\n'
        "// app.use('/api/Notes/:id', guard)\n"
        "finale.resource({ endpoints: ['/api/Notes/:id'] })\n"
        "// finale.resource({ endpoints: ['/api/Drafts'] })\n",
    }
    root = write_repo(tmp_path, notes)
    facts = cc.route_facts(root, build_inventory(root), [], components={"api": list(notes)})
    rows = {(row["method"], row["path"]): row for row in facts["routes"].values()}
    assert set(rows) == {("GET", "/api/Notes/:id"), ("PUT", "/api/Notes/:id"), ("DELETE", "/api/Notes/:id")}
    assert all(row["chain"] == [["server.js", 4, 4]] for row in rows.values())


def test_generator_detection_keeps_paths_plain_and_its_work_bounded(tmp_path, monkeypatch):
    calls = {
        "server.js": "const finale = require('finale-rest')\n"
        "finale.resource({ endpoints: ['/api/Ones', '/api/a b', 'api/relative'] })\n"
        "finale.resource({ endpoints: ['/api/Twos'] })\n"
        "finale.resource({ endpoints: ['/api/Threes'] })\n"
        "finale.resource({ endpoints: ['/api/Open'] \n",
    }
    root = write_repo(tmp_path, calls)
    inventory = build_inventory(root)

    def paths():
        facts = cc.route_facts(root, inventory, [], components={"api": list(calls)})
        return {row["path"] for row in facts["routes"].values() if row["generated"]}

    # Only plain absolute paths count, and a call that never closes registers nothing.
    assert paths() == {"/api/Ones", "/api/Twos", "/api/Threes"}
    monkeypatch.setattr(cc, "_MAX_GENERATOR_CALLS", 2)
    assert paths() == {"/api/Ones", "/api/Twos"}


def test_each_generated_route_is_its_own_candidate_at_the_shared_call(catalog, generated):
    facts, _ = generated
    candidates = cc.starting_candidates(_case(catalog, "TC-AUTHZ-02"), "api", facts, [])["candidates"]
    at_call = [row for row in candidates if row["anchor"] == {"file": "server.js", "line": 18}]
    changing = {
        row["route_id"]
        for row in facts["routes"].values()
        if row["generated"] and row["handler_line"] == 18 and row["method"] != "GET"
    }
    assert {row["route_id"] for row in at_call} == changing and len(at_call) == len(changing)
    assert len({row["candidate_id"] for row in candidates}) == len(candidates)
    # The routes of one call share their location, so batching keeps them in one job.
    jobs = cc.batches({"TC-AUTHZ-02": candidates}, limit=2)
    assert sum(any(row in job["TC-AUTHZ-02"] for row in at_call) for job in jobs) == 1


# A generator serves imported data models from a loop, behind a guard-only
# registration and a mount guard; one element's model comes from outside the
# repository, and one call names its model directly. CommonJS and ES modules
# import the same way.
SERVED = {
    "require": (
        "const express = require('express')\n"
        "const finale = require('finale-rest')\n"
        "const { requireLogin, denyAll } = require('./lib/guards')\n"
        "const { Order } = require('./models/order')\n"
        "const { Card } = require('../outside/card')\n"
        "const { Note } = require('./models/note')\n",
        "exports.requireLogin = () => (req, res, next) => {\n"
        "  if (!req.user) return res.sendStatus(401)\n"
        "  next()\n"
        "}\n"
        "exports.denyAll = () => (req, res, next) => res.sendStatus(403) && next()\n",
    ),
    "import": (
        "import express from 'express'\n"
        "import * as finale from 'finale-rest'\n"
        "import { requireLogin, denyAll } from './lib/guards'\n"
        "import { OrderModel as Order } from './models/order'\n"
        "import { Card } from '../outside/card'\n"
        "import { Note } from './models/note'\n",
        "export const requireLogin = () => (req, res, next) => {\n"
        "  if (!req.user) return res.sendStatus(401)\n"
        "  next()\n"
        "}\n"
        "export const denyAll = () => (req, res, next) => res.sendStatus(403) && next()\n",
    ),
}


def _served(root: Path, style: str) -> dict:
    header, guards = SERVED[style]
    ext = "js" if style == "require" else "ts"
    files = {
        f"repo/server.{ext}": header + "const app = express()\n"
        "app.get('/api/Orders', requireLogin())\n"
        "app.use('/api/Orders/:id', denyAll())\n"
        "const resources = [\n"
        "  { name: 'Order', model: Order },\n"
        "  { name: 'Card', model: Card },\n"
        "]\n"
        "for (const { name, model } of resources) {\n"
        "  finale.resource({ model, endpoints: [`/api/${name}s`, `/api/${name}s/:id`] })\n"
        "}\n"
        "finale.resource({ model: Note, endpoints: ['/api/Notes'] })\n",
        f"repo/lib/guards.{ext}": guards,
        f"repo/models/order.{ext}": "class Order extends Model {}\nOrder.init({ role: DataTypes.STRING })\n",
        f"repo/models/note.{ext}": "const x = 1\nconst Note = sequelize.define('note', { body: DataTypes.TEXT })\n",
        f"outside/card.{ext}": "export const Card = {}\n",
    }
    repo = write_repo(root, files) / "repo"
    owned = [path.removeprefix("repo/") for path in files if path.startswith("repo/")]
    return cc.route_facts(repo, build_inventory(repo), [], components={"api": owned}), ext


@pytest.mark.parametrize("style", ["require", "import"])
def test_generated_routes_name_their_guards_and_data_model(tmp_path, style):
    facts, ext = _served(tmp_path, style)
    server = f"server.{ext}"
    rows = {(row["method"], row["path"]): row for row in facts["routes"].values()}
    order = [f"models/order.{ext}", 1]
    # The guard-only registration stays the inventory's route and learns the model the generator serves there.
    listing = rows["GET", "/api/Orders"]
    assert not listing["generated"] and listing["data_model"] == order and listing["guards"] == []
    # A generated route lists the guards of the registrations that run for it, and its data model.
    for method in ("GET", "PUT", "DELETE"):
        row = rows[method, "/api/Orders/:id"]
        assert row["generated"] and row["data_model"] == order
        assert row["guards"] == [[f"lib/guards.{ext}", 5, 5]]
    created = rows["POST", "/api/Orders"]
    assert created["generated"] and created["guards"] == [] and created["data_model"] == order
    # A directly named model resolves to its definition in the same way.
    assert rows["GET", "/api/Notes"]["data_model"] == [f"models/note.{ext}", 2]
    # A model from outside the repository names no data model.
    assert rows["GET", "/api/Cards"]["generated"] and rows["GET", "/api/Cards"]["data_model"] is None
    assert all(row["data_model"] is None for row in facts["routes"].values() if row["handler_file"] != server)
    json.dumps(facts)


def test_a_string_model_option_names_no_data_model(generated):
    facts, _ = generated
    assert all(row["data_model"] is None for row in facts["routes"].values())


@pytest.mark.parametrize("allowed_model", [True, False])
def test_verification_preloads_a_generated_routes_guard_and_data_model(tmp_path, catalog, allowed_model):
    """A job reads the guard and model a generated route relies on without a further read call."""
    from orchestrator import assessment_test_cases as pilot
    from runtime.assessment_host import MAX_CONTEXT_BYTES
    from runtime.multi_repo_scope import AssessmentScope, RepositoryView

    facts, ext = _served(tmp_path, "import")
    repo = tmp_path / "repo"
    files = {path.relative_to(repo).as_posix(): path.read_bytes() for path in repo.rglob("*") if path.is_file()}
    view = RepositoryView("repo-" + "1" * 16, repo, "b" * 40, "c" * 64, files)
    scope = AssessmentScope((view,), tmp_path / "output")
    rid = view.repository_id
    case = _case(catalog, "TC-AUTHZ-02")
    candidates = cc.starting_candidates(case, "api", facts, [])["candidates"]
    route = route_id(facts, "DELETE", "/api/Orders/:id", f"server.{ext}")
    precheck = {case["id"]: [row for row in candidates if row.get("route_id") == route]}
    guard, model = f"lib/guards.{ext}", f"models/order.{ext}"
    allowed = {(rid, path) for path in files if path != model or allowed_model}
    envelope = {"incident": [], "adjacent": [], "allowed": frozenset(allowed), "job_allowed": frozenset(allowed)}
    architecture = {
        "route_inventories": {rid: build_inventory(repo)},
        "route_middleware": {rid: {}},
    }
    component = {"id": "api", "repository_ids": [rid], "paths": [{"repository_id": rid, "path": p} for p in files]}
    preload = pilot._preload(
        scope, {"existing_controls": []}, precheck, rid, facts, envelope, architecture, [component], MAX_CONTEXT_BYTES
    )
    order = [(key[1], key[2]) for key in preload]
    # Guard and model come before the candidate's own window, so a full packet still carries them;
    # the direct imports that fill leftover room would serve them only after it.
    window = order.index((f"server.{ext}", 1))
    assert order.index((guard, 5)) < window
    if allowed_model:
        assert order.index((model, 1)) < window
    else:
        # A model outside the job's sources stays unread: the preload never widens what a job may read.
        assert (model, 1) not in order
    assert all((rid, key[1]) in allowed for key in preload)


def test_every_job_of_a_component_and_aspect_names_all_its_test_cases_once():
    from orchestrator import assessment_test_cases as pilot

    entry = {
        "jobs": [{"TC-AUTHZ-01": [], "TC-AUTHZ-06": []}, {"TC-AUTHZ-01": [], "TC-AUTHZ-02": []}, {"TC-AUTHZ-02": []}]
    }
    assert pilot._entry_cases(entry) == ["TC-AUTHZ-01", "TC-AUTHZ-06", "TC-AUTHZ-02"]


def test_a_later_verification_job_starts_only_after_its_entrys_first_job_ended():
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    from orchestrator import assessment_test_cases as pilot

    a, b = {"name": "a"}, {"name": "b"}
    work = pilot._first_jobs_first([(a, 1), (a, 2), (a, 3), (b, 1), (b, 2)])
    assert work == [(a, 1), (b, 1), (a, 2), (a, 3), (b, 2)]
    events, lock = [], threading.Lock()

    def investigate(position, item, view):
        entry, number = item
        with lock:
            events.append(("start", entry["name"], number))
        time.sleep(0.05 if number == 1 else 0)
        with lock:
            events.append(("end", entry["name"], number))
        if entry is b and number == 1:
            raise RuntimeError("first job failed")
        return number

    run = pilot._after_first_jobs(work, investigate)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(run, position, item, None) for position, item in enumerate(work, 1)]
    for name, later in (("a", (2, 3)), ("b", (2,))):
        assert all(events.index(("start", name, n)) > events.index(("end", name, 1)) for n in later)
    # A failed first job still lets its later jobs run.
    assert isinstance(futures[1].exception(), RuntimeError) and futures[4].result() == 2


# --- code sites ---------------------------------------------------------------


def test_every_code_site_kind_marks_its_examples_and_only_those():
    kinds, model_file = cc.site_kinds()
    for kind, entry in kinds.items():
        if entry["pattern"] is None:
            assert entry["source"] == "egress_clients", kind
            continue
        for line in entry["matches"]:
            assert entry["pattern"].search(line), (kind, line)
        for line in entry["ignores"]:
            assert not entry["pattern"].search(line), (kind, line)
    assert model_file.search("const User = sequelize.define('User', {")


# A search route whose handler builds SQL, a query helper no route reaches, a
# route that fetches a URL from the body, a data model with a password field,
# a form that only names a password, and a query written only in a comment.
SITES = {
    "server.js": "const express = require('express')\n"
    "const { search } = require('./routes/search')\n"
    "const { preview } = require('./routes/preview')\n"
    "const app = express()\n"
    "app.get('/rest/search', search())\n"
    "app.post('/rest/preview', preview())\n"
    "app.get('/rest/status', (req, res) => res.json({}))\n",
    "routes/search.js": "module.exports.search = () => (req, res) => {\n"
    "  models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${req.query.q}%'`).then(r => res.json(r))\n"
    "}\n",
    "routes/preview.js": "module.exports.preview = () => async (req, res) => {\n"
    "  const page = await fetch(req.body.url)\n"
    "  res.json({ status: page.status })\n"
    "}\n",
    "lib/db.js": "module.exports.raw = (sql) => pool.query(sql)\n// pool.query('DROP TABLE users')\n",
    "models/user.js": "const User = sequelize.define('User', {\n  email: DataTypes.STRING,\n  password: DataTypes.STRING,\n})\n",
    "web/form.js": "const password = form.password\n",
}


@pytest.fixture(scope="module")
def sites(tmp_path_factory):
    root = write_repo(tmp_path_factory.mktemp("sites"), SITES)
    return cc.route_facts(root, build_inventory(root), [], components={"api": list(SITES)})


def test_code_sites_are_lines_of_code_their_patterns_mark(sites):
    found = sites["sites"]
    assert found["raw_query"] == [["lib/db.js", 1], ["routes/search.js", 2]]
    # A data model's field counts; a form that only names a password does not.
    assert found["sensitive_field"] == [["models/user.js", 3]]
    # Only a destination the request chooses makes an outbound call a site.
    assert found["outbound_request"] == [["routes/preview.js", 2]]
    json.dumps(sites)


def test_a_route_that_reaches_a_sink_is_the_candidate_and_names_the_sink(catalog, sites):
    candidates = cc.starting_candidates(_case(catalog, "TC-INPUT-01"), "api", sites, [])["candidates"]
    by_route = {row.get("route_id"): row for row in candidates}
    search = by_route[route_id(sites, "GET", "/rest/search")]
    assert search["anchor"] == {"file": "server.js", "line": 5}
    assert search["sinks"] == [{"file": "routes/search.js", "line": 2}]
    # The helper no route reaches is a candidate of its own; the status route reaches no sink.
    assert [row["anchor"] for row in candidates if "route_id" not in row] == [{"file": "lib/db.js", "line": 1}]
    assert route_id(sites, "GET", "/rest/status") not in by_route
    outbound = cc.starting_candidates(_case(catalog, "TC-INPUT-05"), "api", sites, [])["candidates"]
    assert [(row["route_id"], row["sinks"]) for row in outbound] == [
        (route_id(sites, "POST", "/rest/preview"), [{"file": "routes/preview.js", "line": 2}])
    ]


def test_responses_start_from_reads_of_stored_data(catalog, sites):
    candidates = cc.starting_candidates(_case(catalog, "TC-DATA-01"), "api", sites, [])["candidates"]
    assert [row["route_id"] for row in candidates] == [route_id(sites, "GET", "/rest/search")]


def test_responses_also_start_from_records_a_read_route_saves_and_from_configuration(catalog, tmp_path):
    root = write_repo(
        tmp_path,
        {
            "server.js": "const express = require('express')\n"
            "const config = require('config')\n"
            "const { Captcha } = require('./models')\n"
            "const app = express()\n"
            "app.get('/rest/config', (req, res) => res.json(config.util.toObject(config)))\n"
            "app.get('/rest/captcha', async (req, res) => {\n"
            "  const captcha = Captcha.build({ answer: 42 })\n"
            "  await captcha.save()\n"
            "  res.json(captcha)\n"
            "})\n"
            "app.get('/rest/ping', (req, res) => res.json({ ok: true }))\n",
        },
    )
    facts = cc.route_facts(root, build_inventory(root), [], components={"api": ["server.js"]})
    candidates = cc.starting_candidates(_case(catalog, "TC-DATA-01"), "api", facts, [])["candidates"]
    assert sorted(row["route_id"] for row in candidates) == sorted(
        route_id(facts, "GET", path) for path in ("/rest/config", "/rest/captcha")
    )


def test_a_credential_kept_in_browser_storage_starts_a_storage_check(catalog, tmp_path):
    root = write_repo(
        tmp_path,
        {
            "web/login.ts": "export function remember (auth: { token: string }, language: string) {\n"
            "  localStorage.setItem('language', language)\n"
            "  localStorage.setItem('token', auth.token)\n"
            "}\n",
        },
    )
    facts = cc.route_facts(root, build_inventory(root), [], components={"web": ["web/login.ts"]})
    assert facts["sites"]["client_storage"] == [["web/login.ts", 3]]
    candidates = cc.starting_candidates(_case(catalog, "TC-DATA-02"), "web", facts, [])["candidates"]
    assert [row["anchor"] for row in candidates] == [{"file": "web/login.ts", "line": 3}]


# A checkout route under a prefix guard whose handler writes the wallet of the caller the guard set,
# and a helper no route reaches.
REACHED = {
    "server.js": "const express = require('express')\n"
    "const { isAuthorized } = require('./lib/guards')\n"
    "const { checkout } = require('./routes/order')\n"
    "const app = express()\n"
    "app.use('/rest/basket', isAuthorized())\n"
    "app.post('/rest/basket/:id/checkout', checkout())\n",
    "lib/guards.js": "module.exports.isAuthorized = () => (req, res, next) => {\n"
    "  req.body.UserId = req.user.id\n"
    "  next()\n"
    "}\n",
    "routes/order.js": "module.exports.checkout = () => async (req, res) => {\n"
    "  await Wallet.decrement({ balance: 10 }, { where: { UserId: req.body.UserId } })\n"
    "  res.json({})\n"
    "}\n",
    "lib/unused.js": "module.exports.drain = (id) => Wallet.destroy({ where: { UserId: id } })\n",
}


def test_a_scanner_hit_inside_a_handler_gets_the_guards_of_the_routes_reaching_it(tmp_path, catalog):
    """The guard that sets the caller decides the hit, so the job reads it without a further call."""
    from orchestrator import assessment_test_cases as pilot
    from runtime.assessment_host import MAX_CONTEXT_BYTES
    from runtime.multi_repo_scope import AssessmentScope, RepositoryView

    repo = write_repo(tmp_path / "repo", REACHED)
    inventory = build_inventory(repo)
    hits = [
        {"source_check_id": "AUTHZ-001", "evidence": {"file": "routes/order.js", "line": 2}},
        {"source_check_id": "AUTHZ-001", "evidence": {"file": "lib/unused.js", "line": 1}},
    ]
    facts = cc.route_facts(repo, inventory, hits, components={"api": list(REACHED)})
    case = _case(catalog, "TC-AUTHZ-01")
    candidates = cc.starting_candidates(case, "api", facts, hits)["candidates"]
    checkout = route_id(facts, "POST", "/rest/basket/:id/checkout")
    located = {row["anchor"]["file"]: row for row in candidates if "route_id" not in row}
    assert located["routes/order.js"]["reached_by"] == [checkout]
    assert "reached_by" not in located["lib/unused.js"]

    files = {path: (repo / path).read_bytes() for path in REACHED}
    view = RepositoryView("repo-" + "1" * 16, repo, "b" * 40, "c" * 64, files)
    scope = AssessmentScope((view,), tmp_path / "output")
    rid = view.repository_id
    precheck = {case["id"]: [located["routes/order.js"]]}
    listed = pilot._context_candidates(precheck, rid, facts)[0]["candidates"]
    # The context names where the route and the prefix guard before it are registered, whatever room the
    # preload has left for their source.
    registered = [{"repository_id": rid, "file": "server.js", "line": line} for line in (5, 6)]
    assert listed[0]["reached_by"] == [
        {"route_id": checkout, "method": "POST", "path": "/rest/basket/:id/checkout", "registered_at": registered}
    ]
    allowed = frozenset((rid, path) for path in files)
    envelope = {"incident": [], "adjacent": [], "allowed": allowed, "job_allowed": allowed}
    architecture = {
        "route_inventories": {rid: inventory},
        "route_middleware": {rid: {checkout: [["lib/guards.js", 1, 4]]}},
    }
    component = {"id": "api", "repository_ids": [rid], "paths": [{"repository_id": rid, "path": p} for p in files]}
    preload = pilot._preload(
        scope, {"existing_controls": []}, precheck, rid, facts, envelope, architecture, [component], MAX_CONTEXT_BYTES
    )
    covered = lambda path, line: any(key[1] == path and key[2] <= line <= key[3] for key in preload)  # noqa: E731
    # The guard's definition, its prefix registration and the route's registration, beside the hit itself.
    assert covered("lib/guards.js", 2) and covered("server.js", 5) and covered("server.js", 6)
    assert covered("routes/order.js", 2)
