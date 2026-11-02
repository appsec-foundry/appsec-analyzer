"""Authentication methods survive from executable checks to Figure 1."""

import json
from pathlib import Path

import jsonschema
import pytest
from analyzers.client_api_flows import flows
from analyzers.flow_route_auth import route_outcome
from analyzers.route_inventory import build_inventory
from contexts.build_architecture_analysis_context import project_routes
from renderers.figure1_security import authentication_profile

ROOT = Path(__file__).resolve().parents[1]


def inventory(tmp_path, imports, body):
    (tmp_path / "app.js").write_text(
        "import express from 'express'\n" + imports + "\nconst app = express()\n"
        "app.post('/access', async (req, res) => {\n" + body + "\n})\n"
    )
    result = build_inventory(tmp_path)
    jsonschema.validate(result, json.loads((ROOT / "schemas/route-inventory.schema.json").read_text()))
    projected = project_routes(json.dumps(result).encode())
    assert len(projected["routes"]) == 1
    return projected["routes"][0]


@pytest.mark.parametrize(
    ("imports", "check"),
    [
        ("import passwords from 'bcrypt'", "await passwords.compare(req.body.password, user.passwordHash)"),
        ("import { compare as matches } from 'bcryptjs'", "await matches(req.body.password, user.hash)"),
        ("const bcrypt = require('bcryptjs')", "bcrypt.compareSync(req.body.password, user.hash)"),
        ("import * as argon from 'argon2'", "await argon.verify(user.passwordHash, req.body.password)"),
    ],
)
def test_password_libraries_need_a_checked_boolean_result(tmp_path, imports, check):
    row = inventory(
        tmp_path, imports, f"const valid = {check}\nif (!valid) {{ return res.status(401).end() }}\nres.json({{}})"
    )
    assert row["authn_handler_scheme"] == "password"
    assert route_outcome(row)[0] == "password"
    [flow] = flows("client", {0: [{"file": "client.js", "line": 1}]}, [row], lambda _: "api")
    assert authentication_profile(flow)["scheme"] == "password"


@pytest.mark.parametrize(
    ("imports", "body"),
    [
        (
            "import bcrypt from 'bcrypt'",
            "const valid = bcrypt.compare(req.body.password, user.hash)\nif (!valid) { return res.status(401).end() }",
        ),
        (
            "import bcrypt from 'bcrypt'",
            "const valid = await bcrypt.compare(req.body.password, user.hash)\nres.json(valid)",
        ),
        (
            "import bcrypt from 'bcrypt'",
            "const valid = await bcrypt.compare(req.body.password, req.body.hash)\nif (!valid) { return res.status(401).end() }",
        ),
        (
            "import bcrypt from 'custom-passwords'",
            "const valid = await bcrypt.compare(req.body.password, user.hash)\nif (!valid) { return res.status(401).end() }",
        ),
        ("import bcrypt from 'bcrypt'", "const hash = await bcrypt.hash(req.body.password, 12)\nres.json(hash)"),
        (
            "import argon from 'argon2'",
            "const valid = argon.verify(user.hash, req.body.password)\nif (!valid) { return res.status(401).end() }",
        ),
        (
            "import argon from 'unknown-library'",
            "const valid = await argon.verify(user.hash, req.body.password)\nif (!valid) { return res.status(401).end() }",
        ),
        (
            "import bcrypt from 'bcrypt'",
            "const sample = `const valid = await bcrypt.compare(req.body.password, user.hash)\nif (!valid) { return res.status(401).end() }`\nres.json(sample)",
        ),
    ],
    ids=[
        "unawaited-promise",
        "ignored-result",
        "caller-chosen-hash",
        "unknown-library",
        "hash-only",
        "unawaited-argon",
        "unknown-verifier",
        "string-only",
    ],
)
def test_password_names_or_unchecked_calls_do_not_establish_authentication(tmp_path, imports, body):
    assert inventory(tmp_path, imports, body)["authn_handler_signal"] != "verified"


SQL_LOGIN = """models.sequelize.query(`SELECT * FROM Accounts WHERE email = '${req.body.email || ''}' AND password = '${hash(req.body.password || '')}'`, { plain: true })
  .then((account) => {
    const user = toJson(account)
    if (user.data?.id) {
      res.json({ token: issue(user) })
    } else {
      res.status(401).end()
    }
  })"""


def test_password_lookup_with_a_rejected_missing_account_is_a_password_method(tmp_path):
    assert inventory(tmp_path, "", SQL_LOGIN)["authn_handler_scheme"] == "password"


@pytest.mark.parametrize(
    "body",
    [
        SQL_LOGIN.replace("AND password", "OR password"),
        SQL_LOGIN.replace("if (user.data?.id)", "if (true)"),
        SQL_LOGIN.replace("res.status(401).end()", "res.json({})"),
    ],
)
def test_password_lookup_needs_both_constraints_and_a_rejected_missing_account(tmp_path, body):
    assert inventory(tmp_path, "", body)["authn_handler_signal"] != "verified"


OTP = """const { totpToken } = req.body
const valid = check({ secret: user.totpSecret, token: totpToken }).valid
if (!valid) { return res.status(401).end() }
res.json({})"""


def test_totp_keeps_its_specific_scope_without_claiming_independent_factors(tmp_path):
    row = inventory(tmp_path, "import { verifySync as check } from 'otplib'", OTP)
    scheme, scope, evidence = route_outcome(row)
    assert scheme == "other" and "TOTP" in scope
    [flow] = flows("client", {0: [{"file": "client.js", "line": 1}]}, [row], lambda _: "api")
    profile = authentication_profile(flow)
    assert profile["scheme"] == "other" and "TOTP" in profile["description"]
    assert "factors" not in flow["authentication"]
    assert evidence == [{"file": "app.js", "line": 6}]


@pytest.mark.parametrize(
    "imports,body",
    [
        ("import { verifySync as check } from 'custom-otp'", OTP),
        ("import { verifySync as check } from 'otplib'", OTP.replace("if (!valid)", "if (valid)")),
        (
            "import { verifySync as check } from 'otplib'",
            OTP.replace("const { totpToken } = req.body", "const totpToken = 'example'"),
        ),
    ],
)
def test_otp_dependency_or_ignored_or_nonrequest_check_does_not_establish_authentication(tmp_path, imports, body):
    assert inventory(tmp_path, imports, body)["authn_handler_signal"] != "verified"


@pytest.mark.parametrize("credential,scheme", [("readToken(req)", "bearer"), ("req.cookies.token", "cookie")])
def test_failed_session_cache_lookup_rejects_the_caller(tmp_path, credential, scheme):
    row = inventory(
        tmp_path,
        "",
        "try {\nreq.body.UserId = sessions.tokenMap["
        + credential
        + "].data.id\nres.json({})\n} catch (err) {\nreturn res.status(401).end()\n}",
    )
    assert row["authn_handler_scheme"] == scheme


@pytest.mark.parametrize(
    "body",
    [
        "req.body.UserId = sessions.tokenMap[readToken(req)]?.data.id\nreturn res.status(401).end()",
        "req.body.UserId = sessions.tokenMap[readToken(req)].data.id\nreturn res.status(401).end()",
        "try { req.body.UserId = sessions.tokenMap[readToken(req)].data.id } catch (err) { res.json({}) }",
    ],
)
def test_a_session_cache_read_needs_its_own_rejecting_catch(tmp_path, body):
    assert inventory(tmp_path, "", body)["authn_handler_signal"] != "verified"


@pytest.mark.parametrize("reader", ["req.headers['x-api-key']", "req.get('x-api-key')", "req.header('x-api-key')"])
def test_explicit_api_key_comparison_names_the_method(tmp_path, reader):
    row = inventory(
        tmp_path,
        "",
        f"const key = {reader}\nif (key !== process.env.SERVICE_KEY) {{ return res.status(403).end() }}\nres.json({{}})",
    )
    assert row["authn_handler_scheme"] == "api-key"


def test_an_api_key_read_without_rejection_stays_unknown(tmp_path):
    row = inventory(tmp_path, "", "const key = req.get('x-api-key')\nres.json({ provided: !!key })")
    assert row["authn_handler_signal"] == "unresolved"


def test_basic_auth_middleware_keeps_its_method_through_both_schemas(tmp_path):
    (tmp_path / "app.js").write_text(
        "import express from 'express'\nimport basicAuth from 'express-basic-auth'\nconst app = express()\napp.get('/access', basicAuth({ users: configuredUsers }), (req, res) => res.json({}))\n"
    )
    result = build_inventory(tmp_path)
    jsonschema.validate(result, json.loads((ROOT / "schemas/route-inventory.schema.json").read_text()))
    [row] = project_routes(json.dumps(result).encode())["routes"]
    assert row["authn_handler_scheme"] == "basic"


@pytest.mark.parametrize("scheme", ["password", "basic", "api-key", "oauth2", "oidc", "saml"])
def test_existing_authentication_methods_are_not_lost_from_the_architecture_context(tmp_path, scheme):
    row = inventory(tmp_path, "", "res.json({})")
    row.update(authn_handler_signal="verified", authn_handler_scheme=scheme)
    result = {"version": 1, "routes": [row], "coverage": {}}
    projected = project_routes(json.dumps(result).encode())
    assert projected["routes"][0]["authn_handler_scheme"] == scheme
