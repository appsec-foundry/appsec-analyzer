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
    expected = {
        route_id(facts, method, path)
        for method, path in (
            ("GET", "/api/orders/:id"),
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
