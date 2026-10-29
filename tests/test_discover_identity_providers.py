"""Source-to-diagram coverage for generic external identity integrations."""

import copy
import json
from pathlib import Path

import analyzers.discover_identity_providers as discovery
import jsonschema
import pytest
import renderers.figure1_dfd as figure1_dfd
from validators.validate_fragment import repository_path_errors


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _components():
    return [
        {
            "id": "client",
            "name": "Web client",
            "tier": "client",
            "paths": ["src/**", "config/**"],
            "deployment_zones": ["client-device"],
        }
    ]


def _flows():
    return {"schema_version": 1, "component_inventory_fingerprint": "sha256:" + "a" * 64, "data_flows": []}


@pytest.mark.parametrize(
    "rel,source,role",
    [
        (
            "src/login.ts",
            'const issuerUrl = "https://id.example/oauth2/authorize";\nwindow.location.assign(`${issuerUrl}?client_id=${clientId}`);',
            "OAuth authorization",
        ),
        ("src/login.js", 'fetch("https://identity.example/oauth/token", {method:"POST"});', "OAuth token exchange"),
        ("src/profile.py", 'requests.get("https://identity.example/oidc/userinfo")', "OAuth profile request"),
        ("src/client.ts", 'new UserManager({authority: "https://login.example/realms/staff"});', "OIDC discovery"),
        (
            "src/client.py",
            'oauth.register(server_metadata_url="https://identity.example/.well-known/openid-configuration")',
            "OIDC discovery",
        ),
        ("src/client.ts", 'Issuer.discover("https://identity.example")', "OIDC discovery"),
        ("src/sso.js", 'new SAMLStrategy({entryPoint: "https://sso.example/signin"});', "SAML sign-in"),
        ("config/sso.yaml", "saml:\n  enabled: true\n  entryPoint: https://sso.example/signin\n", "SAML sign-in"),
        ("config/auth.json", '{"oidc":{"authority":"https://id.example"}}', "OIDC discovery"),
        (
            "config/application.yaml",
            "spring:\n  security:\n    oauth2:\n      client:\n        provider:\n          staff:\n            issuer-uri: https://sso.example/realms/staff\n",
            ("OIDC discovery", "OIDC sign-in"),
        ),
        (
            "config/application.properties",
            "spring.security.oauth2.client.provider.staff.issuer-uri=https://sso.example/realms/staff",
            ("OIDC discovery", "OIDC sign-in"),
        ),
        (
            "config/application.properties",
            "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://sso.example/realms/staff",
            "OIDC discovery",
        ),
        (
            "config/application.yaml",
            "spring.security.oauth2.resourceserver.jwt.issuer-uri: https://sso.example/realms/staff\n",
            "OIDC discovery",
        ),
    ],
)
def test_client_integrations_are_generic_and_evidenced(tmp_path, rel, source, role):
    # A client registration that discovers its provider also signs users in there.
    roles = [role] if isinstance(role, str) else list(role)
    _write(tmp_path, rel, source)
    candidates = discovery.discover(tmp_path)
    assert [c.role for c in candidates] == roles
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert len(result["external_entities"]) == 1 and len(result["data_flows"]) == len(roles)
    assert {f["from"] for f in result["data_flows"]} == {"client"}
    assert {f["to"] for f in result["data_flows"]} == {"external"}
    assert repository_path_errors("data-flows", result, tmp_path) == []
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(result, schema)
    assert discovery.reconcile(tmp_path, _components(), result) == result


@pytest.mark.parametrize(
    ("source", "scheme", "host"),
    [
        (
            "window.location.href = 'https://login.example.invalid/oauth2/authorize?response_type=code'",
            "oauth2",
            "login.example.invalid",
        ),
        (
            "const endpoint = 'https://identity.example.invalid/oauth2/authorize?scope=openid&response_type=code';\nwindow.location.href = endpoint;",
            "oidc",
            "identity.example.invalid",
        ),
        ("document.location =\n 'https://staff.example.invalid/saml/login';", "saml", "staff.example.invalid"),
        (
            "location.href = 'https://accounts.example.invalid/oauth/authorize?response_type=token'",
            "oauth2",
            "accounts.example.invalid",
        ),
    ],
)
def test_browser_location_assignments_reach_the_provider_and_figure(tmp_path, source, scheme, host):
    _write(tmp_path, "src/signin.ts", source)
    result = discovery.reconcile(tmp_path, _components(), _flows())
    [flow] = result["data_flows"]
    [provider] = result["external_entities"]
    assert flow["from"] == "client" and flow["to_entity"] == provider["id"]
    assert provider["kind"] == "identity-provider" and host in provider["name"]
    assert flow["authentication"]["scheme"] == scheme
    assert repository_path_errors("data-flows", result, tmp_path) == []
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(result, schema)
    assert discovery.reconcile(tmp_path, _components(), result) == result
    svg, state = figure1_dfd._build({**result, "components": _components()}, [], [])
    assert host in svg
    assert any(edge["src"] == "client" and edge["dst"] == provider["id"] for edge in state["edges"])


@pytest.mark.parametrize(
    "source",
    [
        "// window.location.href = 'https://id.example/oauth2/authorize'",
        "const sample = \"window.location.href = 'https://id.example/oauth2/authorize'\";",
        "const unused = 'https://id.example/oauth2/authorize'; window.location.href = dynamicUrl;",
        "const endpoint = 'https://id.example/oauth2/authorize'; endpoint = localUrl; window.location.href = endpoint;",
        "window.location.href === 'https://id.example/oauth2/authorize'",
        "settings.location.href = 'https://id.example/oauth2/authorize'",
        "window.location.href = 'https://id.example/oauth/token'",
        "window.location.href = 'https://user:password@id.example/oauth2/authorize'",
        "window.location.href = `https://${host}/oauth2/authorize`",
    ],
)
def test_non_redirects_do_not_create_identity_providers(tmp_path, source):
    _write(tmp_path, "src/signin.ts", source)
    assert discovery.reconcile(tmp_path, _components(), _flows()) == _flows()


@pytest.mark.parametrize(
    "rel,source",
    [
        ("docs/oauth.md", 'fetch("https://id.example/oauth/token")'),
        ("src/login.spec.ts", 'fetch("https://id.example/oauth/token")'),
        ("examples/login.ts", 'fetch("https://id.example/oauth/token")'),
        ("src/login.ts", '// fetch("https://id.example/oauth/token")'),
        ("src/login.py", '# requests.get("https://id.example/oauth/token")'),
        ("src/login.py", '"""requests.get("https://id.example/oauth/token")"""'),
        ("src/login.ts", "const docs = 'fetch(\"https://id.example/oauth/token\")';"),
        ("src/login.ts", 'const unused = "https://id.example/oauth/token"; console.log(unused);'),
        ("src/login.ts", 'import OAuth2 from "oauth2";'),
        ("src/login.ts", 'const url = "https://id.example/oauth/token"; url = localUrl; fetch(url);'),
        ("src/login.ts", 'const value = mapping.get("https://id.example/oauth/token");'),
        ("src/login.ts", 'text.replace("https://id.example/oauth/token", "");'),
        ("src/server.ts", 'app.get("/oauth/authorize", handler);'),
        ("config/server.yaml", "oauth:\n  server:\n    issuer: https://our-server.example\n"),
        ("config/client.yaml", "oidc:\n  enabled: false\n  authority: https://id.example\n"),
        ("config/client.yaml", "application:\n  url: https://id.example/oauth/token\n"),
        ("config/client.json", '{"dependencies":{"openid-client":"1"}}'),
        ("src/login.ts", "fetch(process.env.OIDC_ENDPOINT);"),
        ("src/login.ts", 'fetch("https://user:password@id.example/oauth/token");'),
    ],
)
def test_non_integrations_are_not_promoted(tmp_path, rel, source):
    _write(tmp_path, rel, source)
    assert discovery.discover(tmp_path) == []
    assert discovery.reconcile(tmp_path, _components(), _flows()) == _flows()


def test_multiple_providers_and_realms_are_not_merged(tmp_path):
    _write(
        tmp_path,
        "config/clients.json",
        json.dumps(
            {
                "oidc": {
                    "first": {"issuer": "https://id.example/realms/first"},
                    "second": {"issuer": "https://id.example/realms/second"},
                    "third": {"issuer": "https://other.example"},
                }
            }
        ),
    )
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert len(result["external_entities"]) == 3
    assert len(result["data_flows"]) == 3
    assert len({f["to_entity"] for f in result["data_flows"]}) == 3


def test_arbitrary_oidc_issuer_paths_are_distinct(tmp_path):
    _write(
        tmp_path,
        "config/clients.json",
        json.dumps(
            {
                "oidc": {
                    "first": {"issuer": "https://id.example/organization-a"},
                    "second": {"issuer": "https://id.example/organization-b"},
                }
            }
        ),
    )
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert len(result["external_entities"]) == 2
    assert discovery.reconcile(tmp_path, _components(), result) == result


def test_saml_nested_endpoint_and_metadata_are_not_called_oidc(tmp_path):
    _write(
        tmp_path,
        "config/sso.json",
        json.dumps(
            {
                "saml": {
                    "idp": {
                        "metadataUrl": "https://sso.example/metadata",
                        "singleSignOnService": {"url": "https://sso.example/signin"},
                    }
                }
            }
        ),
    )
    assert {c.role for c in discovery.discover(tmp_path)} == {"SAML sign-in", "SAML metadata"}
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert len(result["external_entities"]) == 1
    assert {f["label"] for f in result["data_flows"]} == {"Configured SAML sign-in", "Configured SAML metadata"}
    assert discovery.reconcile(tmp_path, _components(), result) == result


def test_reuses_authored_provider_with_unique_source_evidence(tmp_path):
    _write(tmp_path, "src/login.ts", 'fetch("https://id.example/oauth/token");')
    doc = _flows()
    doc["external_entities"] = [
        {
            "id": "ext-staff",
            "kind": "identity-provider",
            "name": "Staff sign-in",
            "description": "Company identity service",
            "evidence": [{"file": "src/login.ts", "line": 1}],
        }
    ]
    result = discovery.reconcile(tmp_path, _components(), doc)
    assert result["external_entities"] == doc["external_entities"]
    assert result["data_flows"][0]["to_entity"] == "ext-staff"


def test_ambiguous_owner_is_not_arbitrarily_chosen(tmp_path):
    _write(tmp_path, "src/auth.ts", 'fetch("https://id.example/oauth/token");')
    with pytest.raises(ValueError, match="unique component owner"):
        discovery.reconcile(tmp_path, _components() + [{"id": "other", "paths": ["src/**"]}], _flows())


def test_browser_navigation_uses_client_despite_narrower_functional_auth_paths(tmp_path):
    _write(tmp_path, "src/login.ts", 'window.location.assign("https://id.example/oauth/authorize");')
    components = _components() + [{"id": "auth-service", "tier": "application", "paths": ["src/login.ts"]}]
    result = discovery.reconcile(tmp_path, components, _flows())
    assert result["data_flows"][0]["from"] == "client"
    assert discovery.reconcile(tmp_path, components, result) == result


def test_browser_navigation_without_matching_client_fails_instead_of_inventing_server_flow(tmp_path):
    _write(tmp_path, "src/login.ts", 'window.location.assign("https://id.example/oauth/authorize");')
    with pytest.raises(ValueError, match="unique component owner"):
        discovery.reconcile(tmp_path, [{"id": "backend", "tier": "application", "paths": ["src/**"]}], _flows())


def test_saml_sdk_metadata_is_not_oidc_discovery(tmp_path):
    _write(tmp_path, "src/sso.ts", 'new SAMLStrategy({metadataUrl: "https://sso.example/metadata"});')
    assert discovery.discover(tmp_path)[0].role == "SAML metadata"


def test_entity_id_collision_does_not_reclassify_a_user_role(tmp_path):
    _write(tmp_path, "src/auth.ts", 'fetch("https://id.example/oauth/token");')
    result = discovery.reconcile(tmp_path, _components(), _flows())
    result["external_entities"][0]["kind"] = "legitimate-role"
    with pytest.raises(ValueError, match="collides"):
        discovery.reconcile(tmp_path, _components(), result)


def test_reconciles_existing_generic_flow_without_duplicate(tmp_path):
    _write(tmp_path, "src/login.ts", 'fetch("https://id.example/oauth/token");')
    doc = _flows()
    doc["data_flows"] = [
        {"id": "df-009", "from": "client", "to": "external", "evidence": [{"file": "src/login.ts", "line": 1}]}
    ]
    result = discovery.reconcile(tmp_path, _components(), doc)
    assert len(result["data_flows"]) == 1
    assert result["data_flows"][0]["id"] == "df-009"
    assert result["data_flows"][0]["to_entity"] == result["external_entities"][0]["id"]


@pytest.mark.parametrize("provenance", ["recon", "architecture", "repo-declared"])
def test_authored_flow_to_the_provider_is_not_duplicated_whatever_its_provenance(tmp_path, provenance):
    _write(
        tmp_path,
        "src/login.ts",
        'const authorize = "https://id.example/oauth2/authorize";\nwindow.location.assign(authorize);\n',
    )
    doc = _flows()
    doc["external_entities"] = [
        {
            "id": "ext-staff",
            "kind": "identity-provider",
            "name": "Staff sign-in",
            "description": "Company identity service",
            "evidence": [{"file": "src/login.ts", "line": 1}],
        }
    ]
    authored = {
        "id": "df-004",
        "from": "client",
        "to": "external",
        "to_entity": "ext-staff",
        "label": "Browser redirect to the staff sign-in page",
        "provenance": provenance,
        "evidence": [{"file": "src/login.ts", "line": 2}],
    }
    doc["data_flows"] = [authored]
    # Not duplicated; its unknown authentication is filled from the sign-in step (FE-14).
    flows = discovery.reconcile(tmp_path, _components(), doc)["data_flows"]
    assert [{k: v for k, v in f.items() if k != "authentication"} for f in flows] == [authored]
    assert flows[0]["authentication"]["scheme"] == "oauth2"

    generated_other_role = {**authored, "label": "OAuth token exchange", "provenance": "recon"}
    doc["data_flows"] = [generated_other_role]
    labels = [f["label"] for f in discovery.reconcile(tmp_path, _components(), doc)["data_flows"]]
    assert labels == ["OAuth token exchange", "OAuth authorization"]


_WRAPPER_SOURCES = {
    "typescript": (
        "src/services/account.ts",
        "export class AccountClient {\n"
        "  constructor (private readonly http: HttpClient) {}\n"
        "\n"
        "  fetchProfile (token: string) {\n"
        "    return this.http.get('https://accounts.example.net/oauth2/v3/userinfo?access_token=' + token)\n"
        "  }\n"
        "}\n",
        "src/pages/callback.ts",
        "export class CallbackPage {\n"
        "  init (): void {\n"
        "    this.accounts.fetchProfile(this.tokenFromHash()).subscribe({\n"
        "      next: (profile) => {\n"
        "        this.session.start(profile.email)\n"
        "      }\n"
        "    })\n"
        "  }\n"
        "}\n",
        5,
    ),
    "python": (
        "src/identity/gateway.py",
        "import requests\n"
        "\n"
        "\n"
        "def load_member(token):\n"
        '    reply = requests.get("https://login.example.org/oidc/userinfo", headers={"Authorization": token})\n'
        "    return reply.json()\n",
        "src/web/views.py",
        "from identity.gateway import load_member\n"
        "\n"
        "def dashboard(request):\n"
        '    member = load_member(request.session["token"])\n'
        "    return render(request, member)\n",
        4,
    ),
}


def _authored_profile_flow(caller, line, entity="ext-accounts"):
    return {
        "id": "df-003",
        "from": "client",
        "to": "external",
        "to_entity": entity,
        "label": "Profile lookup with the received access token",
        "provenance": "architecture",
        "evidence": [{"file": caller, "line": line}],
    }


def _entities(*ids):
    return [
        {
            "id": entity,
            "kind": "identity-provider",
            "name": f"Provider {entity}",
            "description": "Account provider",
            "evidence": [{"file": "src/pages/other.ts", "line": 1}],
        }
        for entity in ids
    ]


@pytest.mark.parametrize("language", sorted(_WRAPPER_SOURCES))
def test_request_modelled_at_its_wrapper_call_is_not_duplicated(tmp_path, language):
    wrapper, wrapper_text, caller, caller_text, line = _WRAPPER_SOURCES[language]
    _write(tmp_path, wrapper, wrapper_text)
    _write(tmp_path, caller, caller_text)
    _write(tmp_path, "src/pages/other.ts", "export {}\n")
    doc = _flows()
    doc["external_entities"] = _entities("ext-accounts")
    doc["data_flows"] = [_authored_profile_flow(caller, line)]
    result = discovery.reconcile(tmp_path, _components(), doc)
    assert [flow["id"] for flow in result["data_flows"]] == ["df-003"]
    assert [entity["id"] for entity in result["external_entities"]] == ["ext-accounts"]
    url_line = next(n for n, text in enumerate(wrapper_text.splitlines(), 1) if "userinfo" in text)
    assert {"file": wrapper, "line": url_line} in result["data_flows"][0]["evidence"]
    assert repository_path_errors("data-flows", result, tmp_path) == []


@pytest.mark.parametrize(
    "caller_text,entities",
    [
        # The authored flow cites code that never calls the wrapper.
        ("export class CallbackPage {\n  init (): void {\n    this.orders.load()\n  }\n}\n", ["ext-accounts"]),
        # Two providers claim the same call; neither representation is chosen.
        (_WRAPPER_SOURCES["typescript"][3], ["ext-accounts", "ext-backup"]),
    ],
)
def test_unrelated_or_ambiguous_callers_keep_the_generated_request(tmp_path, caller_text, entities):
    wrapper, wrapper_text, caller, _text, line = _WRAPPER_SOURCES["typescript"]
    _write(tmp_path, wrapper, wrapper_text)
    _write(tmp_path, caller, caller_text)
    _write(tmp_path, "src/pages/other.ts", "export {}\n")
    doc = _flows()
    doc["external_entities"] = _entities(*entities)
    doc["data_flows"] = [
        {**_authored_profile_flow(caller, line if "fetchProfile" in caller_text else 3, entity), "id": f"df-00{i}"}
        for i, entity in enumerate(entities, 3)
    ]
    authored = copy.deepcopy(doc["data_flows"])
    result = discovery.reconcile(tmp_path, _components(), doc)
    assert result["data_flows"][: len(authored)] == authored
    assert [flow["label"] for flow in result["data_flows"][len(authored) :]] == ["OAuth profile request"]


def test_every_discovered_role_is_recognised_as_generated(tmp_path):
    sources = {
        "src/a.ts": 'fetch("https://id.example/oauth/token")',
        "src/b.py": 'requests.get("https://id.example/oidc/userinfo")',
        "src/c.ts": 'new UserManager({authority: "https://login.example/realms/staff"})',
        "src/d.js": 'new SAMLStrategy({entryPoint: "https://sso.example/signin"})',
        "src/e.ts": 'new SAMLStrategy({metadataUrl: "https://sso.example/metadata"})',
        "src/f.ts": 'window.location.assign("https://id.example/oauth/authorize")',
    }
    for rel, text in sources.items():
        _write(tmp_path, rel, text)
    roles = {integration.role for integration in discovery.discover(tmp_path)}
    assert len(roles) == 6 and roles <= discovery._ROLES


def test_respects_evidenced_internal_identity_server(tmp_path):
    _write(tmp_path, "src/login.ts", 'fetch("https://id.example/oauth/token");')
    doc = _flows()
    doc["data_flows"] = [
        {"id": "df-009", "from": "client", "to": "identity-server", "evidence": [{"file": "src/login.ts", "line": 1}]}
    ]
    result = discovery.reconcile(tmp_path, _components() + [{"id": "identity-server", "paths": ["identity/**"]}], doc)
    assert result.get("external_entities", []) == []
    assert result["data_flows"] == doc["data_flows"]


def test_unowned_integration_fails_without_mutating_input(tmp_path):
    _write(tmp_path, "elsewhere/auth.ts", 'fetch("https://id.example/oauth/token");')
    original = _flows()
    with pytest.raises(ValueError, match="unique component owner"):
        discovery.reconcile(tmp_path, _components(), original)
    assert original == _flows()


def test_specific_component_path_wins_over_broad_application_path(tmp_path):
    _write(tmp_path, "src/client/auth.ts", 'fetch("https://id.example/oauth/token");')
    components = _components() + [{"id": "browser", "paths": ["src/client/**"]}]
    result = discovery.reconcile(tmp_path, components, _flows())
    assert result["data_flows"][0]["from"] == "browser"


def test_does_not_read_escaping_symlinks_or_oversize_files(tmp_path, monkeypatch):
    outside = _write(tmp_path, "outside.ts", 'fetch("https://id.example/oauth/token");')
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src/link.ts").symlink_to(outside)
    monkeypatch.setattr(discovery, "MAX_FILE_BYTES", 30)
    _write(repo, "src/large.ts", outside.read_text())
    assert discovery.discover(repo) == []


def test_scan_budget_fails_explicitly(tmp_path, monkeypatch):
    _write(tmp_path, "src/auth.ts", 'fetch("https://id.example/oauth/token");')
    monkeypatch.setattr(discovery, "MAX_BYTES", 1)
    with pytest.raises(ValueError, match="source budget"):
        discovery.discover(tmp_path)


def test_query_credentials_are_not_copied_to_model(tmp_path):
    _write(tmp_path, "src/auth.ts", 'fetch("https://id.example/oauth/token?client_secret=must-not-leak");')
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert "must-not-leak" not in json.dumps(result)


# ---------------------------------------------------------------------------
# Authentication of identity-provider steps (sign-in, profile, token, metadata)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "rel,source,expected",
    [
        (  # browser sign-in, implicit grant
            "src/login.ts",
            'const u = "https://id.example/o/oauth2/v2/auth";\n'
            "location.replace(`${u}?client_id=${id}&response_type=token&scope=email`);",
            {"scheme": "oauth2", "flow": "implicit", "transport": "protected"},
        ),
        (  # OIDC sign-in with PKCE
            "src/login.ts",
            'window.location.assign("https://id.example/oauth2/authorize?response_type=code&scope=openid&code_challenge=" + c);',
            {"scheme": "oidc", "flow": "authorization-code-pkce", "transport": "protected"},
        ),
        (  # sign-in without a stated grant
            "src/login.ts",
            'window.location.assign("https://id.example/oauth2/authorize");',
            {"scheme": "oauth2", "transport": "protected"},
        ),
        (  # SAML in code and in configuration
            "src/sso.js",
            'new SAMLStrategy({entryPoint: "https://sso.example/signin"});',
            {"scheme": "saml", "transport": "protected"},
        ),
        (
            "config/sso.yaml",
            "saml:\n  entryPoint: https://sso.example/signin\n",
            {"scheme": "saml", "transport": "protected"},
        ),
        (  # profile request with the user's access token
            "src/profile.py",
            'requests.get("https://identity.example/oidc/userinfo")',
            {"scheme": "bearer", "transport": "protected"},
        ),
        (  # token request: client secret, private_key_jwt, PKCE-only public client
            "src/token.py",
            'requests.post("https://id.example/oauth/token", data={"client_secret": secret, "code": code})',
            {"scheme": "client-secret", "transport": "protected"},
        ),
        (
            "src/token.py",
            'requests.post("https://id.example/oauth/token", data={"client_assertion": jwt})',
            {"scheme": "private-key", "transport": "protected"},
        ),
        (
            "src/token.ts",
            'fetch("https://id.example/oauth/token", {method: "POST", body: `code_verifier=${v}`});',
            {"scheme": "oauth2", "flow": "authorization-code-pkce", "transport": "protected"},
        ),
        (  # public metadata
            "src/client.ts",
            'Issuer.discover("https://identity.example")',
            {"scheme": "none", "public": True, "transport": "protected"},
        ),
    ],
)
def test_identity_provider_steps_carry_the_authentication_their_protocol_proves(tmp_path, rel, source, expected):
    _write(tmp_path, rel, source)
    result = discovery.reconcile(tmp_path, _components(), _flows())
    auth = result["data_flows"][0]["authentication"]
    assert {k: auth[k] for k in expected} == expected
    assert set(auth) - set(expected) == {"scope", "evidence"}
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(result, schema)
    assert result["external_entities"][0]["service_roles"][0]["evidence"] == result["data_flows"][0]["evidence"]


def test_an_unproven_client_authentication_stays_unknown(tmp_path):
    _write(tmp_path, "src/login.js", 'fetch("https://identity.example/oauth/token", {method:"POST"});')
    assert "authentication" not in discovery.reconcile(tmp_path, _components(), _flows())["data_flows"][0]


@pytest.mark.parametrize(
    "authored,filled",
    [
        (None, "oauth2"),
        ({"scheme": "unknown", "scope": "not determined", "evidence": [{"file": "src/login.ts", "line": 2}]}, "oauth2"),
        ({"scheme": "cookie", "scope": "authored", "evidence": [{"file": "src/login.ts", "line": 2}]}, "cookie"),
    ],
)
def test_only_an_unknown_authored_scheme_is_filled(tmp_path, authored, filled):
    _write(tmp_path, "src/login.ts", 'const a = "https://id.example/oauth2/authorize";\nwindow.location.assign(a);\n')
    doc = _flows()
    doc["external_entities"] = [
        {
            "id": "ext-staff",
            "kind": "identity-provider",
            "name": "Staff sign-in",
            "description": "IdP",
            "evidence": [{"file": "src/login.ts", "line": 1}],
        }
    ]
    flow = {
        "id": "df-001",
        "from": "client",
        "to": "external",
        "to_entity": "ext-staff",
        "label": "Sign-in",
        "provenance": "architecture",
        "evidence": [{"file": "src/login.ts", "line": 2}],
    }
    if authored:
        flow["authentication"] = authored
    doc["data_flows"] = [flow]
    assert discovery.reconcile(tmp_path, _components(), doc)["data_flows"][0]["authentication"]["scheme"] == filled


@pytest.mark.parametrize(
    "source,cited_line,errors",
    [
        ('const a = "https://id.example/oauth2/authorize";\nwindow.location.assign(a);\n', 2, 1),
        ('requests.get("https://identity.example/oidc/userinfo")\n', 1, 1),
        ('new SAMLStrategy({entryPoint: "https://sso.example/signin"});\n', 1, 1),
        ('Issuer.discover("https://identity.example")\n', 1, 0),  # public metadata may be unauthenticated
    ],
)
def test_self_check_rejects_none_on_a_step_where_the_provider_authenticates(tmp_path, source, cited_line, errors):
    _write(tmp_path, "src/login.ts", source)
    flow = {
        "id": "df-001",
        "from": "client",
        "to": "external",
        "to_entity": "ext-x",
        "label": "Step",
        "evidence": [{"file": "src/login.ts", "line": cited_line}],
        "authentication": {
            "scheme": "none",
            "scope": "authored",
            "evidence": [{"file": "src/login.ts", "line": cited_line}],
        },
    }
    assert len(discovery.identity_authentication_errors(tmp_path, [flow])) == errors


def test_identity_provider_pill_names_the_idp_and_machine_servers_keep_the_protocol_term():
    vocabulary = figure1_dfd._capability_vocabulary()[1]
    role = [{"role": "oauth-authorization-server", "evidence": [{"file": "a.ts", "line": 1}]}]
    idp = figure1_dfd._capability_rows(role, vocabulary, "role", "Staff sign-in", label_key="identity_provider_label")
    m2m = figure1_dfd._capability_rows(role, vocabulary, "role", "Token service")
    assert idp[0]["label"] == "IdP · OAuth 2.0" and m2m[0]["label"] == "OAuth authorization server"


def _sign_in_doc(providers=("ext-accounts",), group="social-login", back=None):
    doc = _flows()
    doc["external_entities"] = _entities(*providers)
    doc["data_flows"] = [
        {
            "id": f"df-00{index}",
            "from": "client",
            "to": "external",
            "to_entity": provider,
            "label": "Sign-in redirect",
            "protocol": "HTTPS",
            "data_classification": "Confidential",
            "direction": "request-response",
            "protocol_group": group,
            "provenance": "architecture",
            "evidence": [{"file": "src/pages/other.ts", "line": 1}],
            "authentication": {
                "scheme": "oauth2",
                "flow": "implicit",
                "scope": "The provider authenticates the user",
                "transport": "protected",
                "evidence": [{"file": "src/pages/other.ts", "line": 1}],
            },
        }
        for index, provider in enumerate(providers, 1)
    ]
    if back is not None:
        doc["data_flows"].append(
            {
                "id": "df-009",
                "from": "external",
                "from_entity": providers[0],
                "to": "client",
                "label": "Token delivery to the callback route",
                "protocol": "HTTPS",
                "data_classification": "Confidential",
                "direction": "request-response",
                "protocol_group": group,
                "provenance": "architecture",
                "evidence": [{"file": "src/pages/other.ts", "line": 1}],
                **({"authentication": back} if back else {}),
            }
        )
    return doc


@pytest.mark.parametrize(
    "source",
    [
        'requests.get("https://api.example/oauth2/v1/userinfo")\n',
        'fetch("https://profile.example/oidc/userinfo?alt=json")\n',
    ],
)
def test_profile_request_calls_the_provider_the_user_signed_in_at(tmp_path, source):
    _write(tmp_path, "src/profile.ts", source)
    _write(tmp_path, "src/pages/other.ts", "export {}\n")
    result = discovery.reconcile(tmp_path, _components(), _sign_in_doc())
    assert [e["id"] for e in result["external_entities"]] == ["ext-accounts"]
    profile = next(f for f in result["data_flows"] if f["label"] == "OAuth profile request")
    assert profile["to_entity"] == "ext-accounts" and profile["protocol_group"] == "social-login"
    assert profile["authentication"]["scheme"] == "bearer"
    roles = [r["role"] for r in result["external_entities"][0]["service_roles"]]
    assert roles == ["oauth-resource-server"]


def test_profile_request_keeps_its_own_party_when_several_providers_sign_users_in(tmp_path):
    _write(tmp_path, "src/profile.ts", 'requests.get("https://api.example/oauth2/v1/userinfo")\n')
    _write(tmp_path, "src/pages/other.ts", "export {}\n")
    result = discovery.reconcile(tmp_path, _components(), _sign_in_doc(("ext-accounts", "ext-staff")))
    profile = next(f for f in result["data_flows"] if f["label"] == "OAuth profile request")
    assert profile["to_entity"].startswith("ext-idp-") and "protocol_group" not in profile


@pytest.mark.parametrize(
    "back",
    [
        {},
        {"scheme": "none", "scope": "Redirect response", "evidence": [{"file": "src/pages/other.ts", "line": 1}]},
        {"scheme": "unknown", "scope": "not determined", "evidence": [{"file": "src/pages/other.ts", "line": 1}]},
    ],
)
def test_the_redirect_back_completes_the_sign_in_and_carries_its_protocol(tmp_path, back):
    result = discovery.reconcile(tmp_path, _components(), _sign_in_doc(back=back))
    auth = result["data_flows"][-1]["authentication"]
    assert (auth["scheme"], auth["flow"], auth["transport"]) == ("oauth2", "implicit", "protected")
    assert auth["evidence"] == [{"file": "src/pages/other.ts", "line": 1}]
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(result, schema)


def test_the_redirect_back_keeps_an_authored_scheme_and_needs_a_matching_sign_in(tmp_path):
    authored = {"scheme": "cookie", "scope": "authored", "evidence": [{"file": "src/pages/other.ts", "line": 1}]}
    kept = discovery.reconcile(tmp_path, _components(), _sign_in_doc(back=authored))
    assert kept["data_flows"][-1]["authentication"]["scheme"] == "cookie"
    other_group = _sign_in_doc(back={})
    other_group["data_flows"][-1]["protocol_group"] = "unrelated"
    assert "authentication" not in discovery.reconcile(tmp_path, _components(), other_group)["data_flows"][-1]


def _two_tier():
    return [
        {
            "id": "client",
            "name": "Web client",
            "tier": "client",
            "paths": ["web/**"],
            "deployment_zones": ["client-device"],
        },
        {
            "id": "server",
            "name": "Backend",
            "tier": "application",
            "paths": ["srv/**", "config/**"],
            "deployment_zones": ["dmz"],
        },
    ]


def _with_sign_in(doc=None):
    doc = doc or _sign_in_doc()
    for flow in doc["data_flows"]:
        flow["evidence"] = flow["authentication"]["evidence"] = [{"file": "web/login.ts", "line": 1}]
    for entity in doc["external_entities"]:
        entity["evidence"] = [{"file": "web/login.ts", "line": 1}]
    return doc


_CONFIDENTIAL_CLIENTS = {
    "passport": (
        "srv/auth.ts",
        "passport.use(new GoogleStrategy({\n  clientID: process.env.GOOGLE_ID,\n"
        "  clientSecret: process.env.GOOGLE_SECRET,\n  callbackURL: '/auth/callback',\n}, verify));\n",
        1,
    ),
    "authlib": (
        "srv/app.py",
        "oauth.register(\n    name='staff',\n    client_id=CONFIG['id'],\n    client_secret=CONFIG['secret'],\n"
        "    client_kwargs={'scope': 'openid email'},\n)\n",
        1,
    ),
    "spring-yaml": (
        "config/application.yml",
        "spring:\n  security:\n    oauth2:\n      client:\n        registration:\n          staff:\n"
        "            client-id: portal\n            client-secret: ${STAFF_SECRET}\n",
        8,
    ),
    "properties": (
        "config/application.properties",
        "spring.security.oauth2.client.registration.staff.client-id=portal\n"
        "spring.security.oauth2.client.registration.staff.client-secret=${STAFF_SECRET}\n",
        2,
    ),
    "json-sibling": (
        "config/auth.json",
        '{"google": {"clientID": "abc", "clientSecret": "from-vault", "callback": "/cb"}}',
        1,
    ),
}


@pytest.mark.parametrize("shape", sorted(_CONFIDENTIAL_CLIENTS))
def test_a_library_token_request_shows_the_client_secret_it_is_configured_with(tmp_path, shape):
    rel, source, line = _CONFIDENTIAL_CLIENTS[shape]
    _write(tmp_path, rel, source)
    _write(tmp_path, "web/login.ts", "export {}\n")
    result = discovery.reconcile(tmp_path, _two_tier(), _with_sign_in())
    token = [f for f in result["data_flows"] if f["label"] == "OAuth token exchange"]
    assert len(token) == 1
    assert (token[0]["from"], token[0]["to_entity"], token[0]["protocol_group"]) == (
        "server",
        "ext-accounts",
        "social-login",
    )
    auth = token[0]["authentication"]
    assert (auth["scheme"], auth["transport"], auth["evidence"]) == (
        "client-secret",
        "protected",
        [{"file": rel, "line": line}],
    )
    assert "secret" not in json.dumps(token[0]["evidence"]).lower().replace(rel.lower(), "")
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(result, schema)
    assert discovery.reconcile(tmp_path, _two_tier(), result) == result


@pytest.mark.parametrize(
    "variant", ["no-provider", "two-providers", "public-client", "token-url-already-drawn", "no-oauth-context"]
)
def test_no_token_request_is_invented_without_a_provider_or_secret(tmp_path, variant):
    rel, source, _line = _CONFIDENTIAL_CLIENTS["passport"]
    doc = _with_sign_in()
    if variant == "no-provider":
        doc = {**_flows(), "external_entities": [], "data_flows": []}
    elif variant == "two-providers":
        doc = _with_sign_in(_sign_in_doc(("ext-accounts", "ext-staff")))
    elif variant == "public-client":
        source = source.replace("  clientSecret: process.env.GOOGLE_SECRET,\n", "")
    elif variant == "token-url-already-drawn":
        source = (
            "const client = new OAuth2({clientId: ID, clientSecret: SECRET, "
            "tokenUrl: 'https://tokens.example/oauth/token'});\nclient.post('https://tokens.example/oauth/token');\n"
        )
    else:
        source = "app.register(cache, {clientId: 'x', clientSecret: 'y'});\n"
    _write(tmp_path, rel, source)
    _write(tmp_path, "web/login.ts", "export {}\n")
    result = discovery.reconcile(tmp_path, _two_tier(), doc)
    token = [f for f in result["data_flows"] if "token exchange" in f["label"]]
    if variant == "token-url-already-drawn":
        # Only the URL-derived requests remain; none is added towards the sign-in provider.
        assert token and all(f["to_entity"] != "ext-accounts" for f in token)
    else:
        assert token == []


# ---------------------------------------------------------------- OAuth / OpenID Connect flows (REQ-005)
def _spa_and_api():
    return [
        {"id": "web", "name": "Web client", "tier": "client", "paths": ["web/**"]},
        {"id": "api", "name": "API", "tier": "server", "paths": ["api/**"]},
    ]


def _steps(tmp_path, files, components=None):
    for rel, text in files.items():
        _write(tmp_path, rel, text)
    result = discovery.reconcile(tmp_path, components or _spa_and_api(), _flows())
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(result, schema)
    steps = set()
    for flow in result["data_flows"]:
        auth = flow.get("authentication") or {}
        steps.add((flow["from"], flow["label"].removeprefix("Configured "), auth.get("scheme"), auth.get("flow")))
    return result, steps


SPRING_CLIENT = (
    "spring:\n  security:\n    oauth2:\n      client:\n        registration:\n          corp:\n"
    "            client-id: app\n            client-secret: ${{SECRET}}\n{grant}"
    "        provider:\n          corp:\n            issuer-uri: https://sso.example/realms/corp\n"
)


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (  # openid-client 6: the library performs the sign-in and the token request
            {
                "api/auth.js": "const config = await client.discovery(new URL('https://sso.example/realms/corp'), "
                "process.env.CLIENT_ID, client.ClientSecretPost(process.env.CLIENT_SECRET))\n"
            },
            {
                ("api", "OIDC discovery", "none", None),
                ("api", "OIDC sign-in", "oidc", None),
                ("api", "OAuth token exchange", "client-secret", None),
            },
        ),
        (  # openid-client 5
            {
                "api/auth.js": "const issuer = await Issuer.discover('https://sso.example')\n"
                "const oidc = new issuer.Client({ client_id: id, client_secret: s, redirect_uris: [cb] })\n"
            },
            {
                ("api", "OIDC discovery", "none", None),
                ("api", "OIDC sign-in", "oidc", None),
                ("api", "OAuth token exchange", "client-secret", None),
            },
        ),
        (  # Spring Security oauth2Login
            {"api/src/main/resources/application.yml": SPRING_CLIENT.format(grant="")},
            {
                ("api", "OIDC discovery", "none", None),
                ("api", "OIDC sign-in", "oidc", None),
                ("api", "OAuth token exchange", "client-secret", None),
            },
        ),
        (  # Spring client credentials: a service client signs nobody in
            {
                "api/src/main/resources/application.yml": SPRING_CLIENT.format(
                    grant="            authorization-grant-type: client_credentials\n"
                )
            },
            {
                ("api", "OIDC discovery", "none", None),
                ("api", "OAuth token exchange", "client-secret", "client-credentials"),
            },
        ),
        (  # ASP.NET Core OpenID Connect handler
            {
                "api/Program.cs": "services.AddAuthentication().AddOpenIdConnect(o => {\n"
                '  o.Authority = "https://login.example/tenant";\n  o.ClientId = id;\n  o.ClientSecret = s;\n'
                '  o.ResponseType = "code";\n  o.UsePkce = true;\n});\n'
            },
            {
                ("api", "OIDC discovery", "none", None),
                ("api", "OIDC sign-in", "oidc", "authorization-code-pkce"),
                ("api", "OAuth token exchange", "client-secret", "authorization-code-pkce"),
            },
        ),
        (  # passport-oauth2 with explicit endpoints
            {
                "api/auth.js": "passport.use(new OAuth2Strategy({\n"
                "  authorizationURL: 'https://sso.example/oauth2/authorize',\n"
                "  tokenURL: 'https://sso.example/oauth2/token',\n"
                "  clientID: id, clientSecret: s, callbackURL: '/cb'\n}, verify))\n"
            },
            {("api", "OAuth authorization", "oauth2", None), ("api", "OAuth token exchange", "client-secret", None)},
        ),
        (  # Go golang.org/x/oauth2
            {
                "api/auth.go": "var conf = &oauth2.Config{\n\tClientID: id,\n\tClientSecret: s,\n"
                '\tEndpoint: oauth2.Endpoint{\n\t\tAuthURL: "https://sso.example/oauth2/auth",\n'
                '\t\tTokenURL: "https://sso.example/oauth2/token",\n\t},\n}\n'
            },
            {("api", "OAuth authorization", "oauth2", None), ("api", "OAuth token exchange", "client-secret", None)},
        ),
        (  # browser client: keycloak-js
            {
                "web/auth.ts": "const kc = new Keycloak({ url: 'https://sso.example', realm: 'corp', clientId: 'spa' })\n"
            },
            {("web", "OIDC discovery", "none", None), ("web", "OIDC sign-in", "oidc", None)},
        ),
        (  # browser client: oidc-client-ts
            {
                "web/auth.ts": "new UserManager({ authority: 'https://sso.example/realms/corp', client_id: 'spa', "
                "redirect_uri: cb, response_type: 'code' })\n"
            },
            {("web", "OIDC discovery", "none", None), ("web", "OIDC sign-in", "oidc", "authorization-code")},
        ),
        (  # browser client: a settings object passed by name (angular-oauth2-oidc)
            {
                "web/auth.config.ts": "export const authConfig: AuthConfig = { issuer: 'https://sso.example/realms/corp', "
                "clientId: 'spa', responseType: 'code', redirectUri: window.location.origin }\n"
            },
            {("web", "OIDC discovery", "none", None), ("web", "OIDC sign-in", "oidc", "authorization-code")},
        ),
        (  # browser client: nested settings (MSAL)
            {
                "web/msal.ts": "export const msalConfig = { auth: { clientId: 'spa', "
                "authority: 'https://login.example/tenant-id', redirectUri: '/' } }\n"
            },
            {("web", "OIDC discovery", "none", None), ("web", "OIDC sign-in", "oidc", None)},
        ),
        (  # Keycloak adapter file of a client
            {"api/keycloak.json": '{"realm": "corp", "auth-server-url": "https://sso.example/", "resource": "app"}'},
            {("api", "OIDC discovery", "none", None), ("api", "OIDC sign-in", "oidc", None)},
        ),
        (  # client credentials request written by hand
            {
                "api/svc.js": "await fetch('https://sso.example/oauth2/token', { method: 'POST', body: "
                "new URLSearchParams({ grant_type: 'client_credentials', client_id: id, client_secret: s }) })\n"
            },
            {("api", "OAuth token exchange", "client-secret", "client-credentials")},
        ),
        (  # legacy password grant
            {
                "api/login.js": "await fetch('https://sso.example/oauth2/token', { method: 'POST', body: "
                "new URLSearchParams({ grant_type: 'password', username: u, password: p }) })\n"
            },
            {("api", "OAuth token exchange", "password", "password")},
        ),
    ],
    ids=[
        "openid-client-6",
        "openid-client-5",
        "spring-login",
        "spring-client-credentials",
        "aspnet-oidc",
        "passport-oauth2",
        "go-oauth2",
        "keycloak-js",
        "oidc-client-ts",
        "settings-object",
        "msal-nested",
        "keycloak-adapter-file",
        "client-credentials",
        "password-grant",
    ],
)
def test_oauth_client_setups_draw_the_steps_their_code_evidences(tmp_path, files, expected):
    result, steps = _steps(tmp_path, files)
    assert steps == expected
    assert {e["kind"] for e in result["external_entities"]} == {"identity-provider"}
    assert discovery.reconcile(tmp_path, _spa_and_api(), result) == result


@pytest.mark.parametrize(
    "files",
    [
        {
            "api/application.yml": "spring:\n  security:\n    oauth2:\n      resourceserver:\n        jwt:\n"
            "          issuer-uri: https://sso.example/realms/corp\n"
        },
        {
            "api/Program.cs": 'services.AddAuthentication().AddJwtBearer(o => {\n  o.Authority = "https://login.example/t";\n'
            '  o.Audience = "api";\n});\n'
        },
        {"api/api.js": "const checkJwt = auth({ audience: 'api', issuerBaseURL: 'https://sso.example/' })\n"},
        {
            "api/keycloak.json": '{"realm": "corp", "auth-server-url": "https://sso.example/", "resource": "api", '
            '"bearer-only": true}'
        },
    ],
    ids=["spring-resource-server", "aspnet-jwt-bearer", "express-oauth2-jwt-bearer", "keycloak-bearer-only"],
)
def test_a_resource_server_discovers_its_provider_without_signing_anyone_in(tmp_path, files):
    _result, steps = _steps(tmp_path, files)
    assert steps == {("api", "OIDC discovery", "none", None)}


@pytest.mark.parametrize(
    "source",
    [
        "app.use(expressjwt({ secret: jwksRsa.expressJwtSecret({ jwksUri: 'https://sso.example/.well-known/jwks.json' }) }))\n",
        "const keys = createRemoteJWKSet(new URL('https://sso.example/oauth2/v1/keys'))\n",
        "const client = jwksClient({ jwksUri: 'https://sso.example/protocol/openid-connect/certs' })\n",
    ],
    ids=["jwks-rsa", "jose", "jwks-client"],
)
def test_a_remote_key_set_is_public_metadata_not_missing_authentication(tmp_path, source):
    result, steps = _steps(tmp_path, {"api/keys.js": source})
    assert steps == {("api", "OIDC signing keys", "none", None)}
    assert result["data_flows"][0]["authentication"]["public"] is True


@pytest.mark.parametrize(
    "files",
    [
        {"api/verify.js": "jwt.verify(token, publicKey, { issuer: 'https://sso.example/', audience: 'api' })\n"},
        {"api/sign.js": "jwt.sign(claims, key, { issuer: 'https://app.example/' })\n"},
        {"api/package.json": '{"dependencies": {"openid-client": "^6.0.0", "keycloak-connect": "^26.0.0"}}'},
        {"api/oidc.yml": "oidc:\n  enabled: false\n  issuer: https://sso.example/\n  client-id: app\n"},
    ],
    ids=["local-issuer-check", "own-token-issuer", "dependency-names", "disabled-config"],
)
def test_names_and_local_issuer_checks_add_no_protocol_step(tmp_path, files):
    result, steps = _steps(tmp_path, files)
    assert steps == set() and result.get("external_entities", []) == []


@pytest.mark.parametrize(
    "issuer",
    [
        "https://sso.example.com/realms/corp",
        "https://login.microsoftonline.com/0f1e2d3c/v2.0",
        "https://corp.okta.com/oauth2/default",
        "https://corp.eu.auth0.com/",
        "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Ab12",
        "https://accounts.google.com",
        "https://auth.example.com/application/o/app/",
    ],
)
def test_the_sign_in_is_drawn_alike_for_every_provider_product(tmp_path, issuer):
    _result, steps = _steps(
        tmp_path, {"web/auth.ts": f"new UserManager({{ authority: '{issuer}', client_id: 'spa', redirect_uri: cb }})\n"}
    )
    assert steps == {("web", "OIDC discovery", "none", None), ("web", "OIDC sign-in", "oidc", None)}


def test_a_provider_deployed_with_the_system_is_reached_as_its_component(tmp_path):
    components = [
        *_spa_and_api(),
        {"id": "sso", "name": "Identity server", "tier": "server", "paths": ["sso/**"], "workloads": ["keycloak"]},
    ]
    result, steps = _steps(
        tmp_path,
        {
            "web/auth.ts": "new UserManager({ authority: 'http://keycloak:8080/realms/corp', client_id: 'spa', redirect_uri: cb })\n"
        },
        components,
    )
    assert result.get("external_entities", []) == []
    assert {(f["from"], f["to"], f["label"]) for f in result["data_flows"]} == {
        ("web", "sso", "OIDC discovery"),
        ("web", "sso", "OIDC sign-in"),
    }
    assert ("web", "OIDC sign-in", "oidc", None) in steps
    assert discovery.reconcile(tmp_path, components, result) == result


def test_a_modelled_sign_in_makes_the_derived_one_unnecessary(tmp_path):
    _write(
        tmp_path,
        "web/auth.ts",
        "new UserManager({ authority: 'https://sso.example/realms/corp', client_id: 'spa', redirect_uri: cb })\n",
    )
    _write(
        tmp_path,
        "web/login.ts",
        "window.location.assign('https://sso.example/realms/corp/protocol/openid-connect/auth?scope=openid')\n",
    )
    result = discovery.reconcile(tmp_path, _spa_and_api(), _flows())
    assert sorted(f["label"] for f in result["data_flows"]) == ["OAuth authorization", "OIDC discovery"]


def _bearer(flow_id, check_file, receiver="api"):
    return {
        "id": flow_id,
        "from": "web",
        "to": receiver,
        "label": "API requests",
        "protocol": "HTTPS",
        "direction": "request-response",
        "data_classification": "Internal",
        "provenance": "route-extraction",
        "evidence": [{"file": "web/api.ts", "line": 1}],
        "authentication": {
            "scheme": "bearer",
            "scope": "the handler checks a bearer credential and rejects the request without it",
            "evidence": [{"file": check_file, "line": 3}],
        },
    }


def _resource_server(tmp_path, files):
    for rel, text in files.items():
        _write(tmp_path, rel, text)
    return discovery.reconcile(tmp_path, _spa_and_api(), _flows())


@pytest.mark.parametrize(
    ("files", "check_file"),
    [
        (
            {"api/auth.js": "const checkJwt = auth({ audience: 'api', issuerBaseURL: 'https://sso.example/' })\n"},
            "api/auth.js",
        ),
        (
            {
                "api/keycloak.json": '{"realm": "corp", "auth-server-url": "https://sso.example/", "resource": "api", "bearer-only": true}'
            },
            "api/routes.js",
        ),
    ],
    ids=["same-file", "component-configuration"],
)
def test_a_bearer_check_names_the_provider_whose_access_token_it_accepts(tmp_path, files, check_file):
    result = _resource_server(tmp_path, files)
    provider = result["external_entities"][0]
    flows = [*result["data_flows"], _bearer("df-090", check_file)]
    assert discovery.reconcile_token_issuers(flows, result["external_entities"], _spa_and_api()) == ["df-090"]
    auth = flows[-1]["authentication"]
    assert auth["issuer"] == provider["id"] and provider["name"] in auth["scope"]
    assert {"file": check_file, "line": 3} in auth["evidence"] and len(auth["evidence"]) == 2
    document = {**_flows(), "data_flows": flows, "external_entities": result["external_entities"]}
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(document, schema)


def test_a_bearer_check_without_a_code_link_stays_a_plain_bearer_token(tmp_path):
    single = _resource_server(
        tmp_path, {"api/auth.js": "const checkJwt = auth({ issuerBaseURL: 'https://sso.example/' })\n"}
    )
    elsewhere = [*copy.deepcopy(single["data_flows"]), _bearer("df-090", "api/routes.js")]
    assert discovery.reconcile_token_issuers(elsewhere, single["external_entities"], _spa_and_api()) == []
    _write(tmp_path, "api/other.js", "const second = auth({ issuerBaseURL: 'https://other.example/' })\n")
    both = discovery.reconcile(tmp_path, _spa_and_api(), _flows())
    flows = [*both["data_flows"], _bearer("df-090", "api/auth.js")]
    assert discovery.reconcile_token_issuers(flows, both["external_entities"], _spa_and_api()) == []  # two providers
    cookie = _bearer("df-091", "api/auth.js")
    cookie["authentication"]["scheme"] = "cookie"
    assert (
        discovery.reconcile_token_issuers([*single["data_flows"], cookie], single["external_entities"], _spa_and_api())
        == []
    )
    assert "issuer" not in flows[-1]["authentication"]


def test_an_issuer_must_name_an_identity_provider_or_component():
    from validators.validate_fragment import fragment_invariant_errors

    flow = _bearer("df-001", "api/auth.js")
    entity = {"id": "ext-mail", "name": "Mail", "kind": "external-service"}
    for issuer, expected in (("ext-mail", "must name an identity provider"), ("ghost", "must resolve")):
        flow["authentication"]["issuer"] = issuer
        document = {"data_flows": [flow], "external_entities": [entity], "components": _spa_and_api()}
        assert any(expected in error for error in fragment_invariant_errors("data-flows", document))
