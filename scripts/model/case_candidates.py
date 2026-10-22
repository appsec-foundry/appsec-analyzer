"""model/case_candidates.py: applicability and starting candidates of test cases (REQ-040).

``route_facts`` reads one repository snapshot once, after the scanners ran: the
route inventory rows, the resolved handler chain of each route
(``analyzers/handler_resolver.py``), the ownership predicate and object access
of each handler body (``analyzers/authz_confirm.py``), the scanner rules
anchored at each registration, and the files where each catalog
``applies_when`` signal shows in code. The result is plain JSON data, so the
model investigation and the post-checks (``model/case_postchecks.py``) can run
after the snapshot is gone.

``applies`` evaluates a test case's ``applies_when`` signals; a signal without
an evaluator applies, so a missing evaluator never hides a test case. A signal
counts only in code: a mention in a comment, in a test file, or in a file
outside the component never makes it apply.

``starting_candidates`` turns the pre-check results of one component into the
candidate locations a model investigation starts from: the component's routes
that the test case's route facts select, and the scanner findings of its
starting rules. One candidate stands for one location, so a scanner hit at a
route registration joins that route's candidate instead of counting twice.
Candidates beyond an optional cap are only counted.

``batches`` splits the candidates of one component and aspect into model jobs
of at most ``MAX_CANDIDATES``. The candidates of one location stay in one job,
so its code is read once for every test case that names it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from analyzers import authz_confirm
from analyzers.capability_signals import _TEST_PATH_RE
from analyzers.handler_resolver import HandlerResolver
from analyzers.route_inventory import _PATH_PARAM_RE, _is_excluded
from shared._path_guard import is_safe_to_read
from shared._source_lex import without_comments

#: Candidates one model call receives; a component and aspect with more get several calls.
MAX_CANDIDATES = 40
#: Larger files are generated or bundled code, not reviewed source.
_MAX_FILE_BYTES = 1_000_000

# Keys of a scanner finding that name its rule: the threat shape the controller
# holds, then the raw sidecar shape the scanners write.
_RULE_KEYS = ("source_check_id", "config_check_id", "check_id")

_CODE_EXTS = frozenset(
    {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".py",
        ".java",
        ".kt",
        ".scala",
        ".cs",
        ".vb",
        ".go",
        ".rb",
        ".php",
        ".swift",
        ".dart",
        ".rs",
        ".html",
        ".htm",
        ".vue",
        ".svelte",
    }
)
_HASH_COMMENT_EXTS = frozenset({".py", ".rb"})
_MARKUP_EXTS = frozenset({".html", ".htm", ".vue", ".svelte"})
_MARKUP_COMMENT_RE = re.compile(r"<!--[\s\S]*?(?:-->|\Z)")
_NOT_NEWLINE_RE = re.compile(r"[^\n]")

# Code patterns per applicability signal, matched against comment-blanked code
# of non-test files. A pattern names a call, an import or an API whose purpose
# is the signal; a signal that matches too broadly only costs a model call.
_SIGNAL_CODE: dict[str, re.Pattern] = {
    "jwt_usage": re.compile(
        r"\b(?:jwt|jws|jose|jsonwebtoken|Jwts)\s*\.\s*(?:sign|verify|decode|encode|parser|builder)\w*\s*\("
        r"|\b(?:require|import)\s*\(?\s*['\"](?:jsonwebtoken|jose|jws|jwt-decode|express-jwt|koa-jwt|passport-jwt"
        r"|express-oauth2-jwt-bearer|@nestjs/jwt)['\"]"
        r"|\bfrom\s+['\"](?:jsonwebtoken|jose|jws|jwt-decode|express-jwt|koa-jwt|passport-jwt|@nestjs/jwt)['\"]"
        r"|^[ \t]*(?:import\s+jwt\b|from\s+(?:jwt|jose|authlib\.jose|flask_jwt_extended)\b)"
        r"|\bio\.jsonwebtoken\b|\bcom\.auth0\.jwt\b|\bJwtSecurityTokenHandler\b|\bgolang-jwt/jwt\b|\bJWT::(?:encode|decode)\b",
        re.MULTILINE,
    ),
    "password_handling": re.compile(
        r"\b(?:bcrypt\w*|argon2\w*|scrypt\w*|pbkdf2\w*|hashpw|checkpw|password_hash|password_verify"
        r"|check_password(?:_hash)?|generate_password_hash|set_password|make_password|PasswordEncoder|PasswordHasher"
        r"|passlib)\b"
        r"|\b(?:body|form|data|params|credentials|user|json)\s*(?:\.|\[\s*['\"])\s*(?:password|passwd|pwd|newPassword"
        r"|new_password|currentPassword|current_password)\b"
    ),
    "session_handling": re.compile(
        r"\b(?:express-session|cookie-session|koa-session|flask_session|SessionMiddleware|HttpSession|session_start)\b"
        r"|\b(?:req|request|ctx)\s*\.\s*session\b"
        r"|\b(?:res|response|ctx)\s*\.\s*(?:cookie|cookies\s*\.\s*set|set_cookie)\s*\(|\bset_cookie\s*\("
        r"|\bdocument\s*\.\s*cookie\b|\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\("
        # Issuing a token is creating a session.
        r"|\b(?:jwt|jsonwebtoken|jws)\s*\.\s*(?:sign|encode)\s*\(|\bnew\s+SignJWT\s*\("
    ),
    "database_access": re.compile(
        r"\b(?:require|import)\s*\(?\s*['\"](?:sequelize|mongoose|mongodb|knex|typeorm|@prisma/client|pg|mysql2?"
        r"|sqlite3?|better-sqlite3|redis|ioredis|marsdb|nedb)['\"]"
        r"|\bfrom\s+['\"](?:sequelize|mongoose|mongodb|knex|typeorm|@prisma/client|pg|mysql2?|sqlite3?"
        r"|better-sqlite3)['\"]"
        r"|^[ \t]*(?:import|from)\s+(?:sqlite3|psycopg2?|pymysql|MySQLdb|sqlalchemy|pymongo|redis|django\.db|peewee"
        r"|tortoise)\b"
        r"|\.(?:query|execute|executemany|raw|rawQuery|findAll|findOne|findById|findByPk|findMany|findUnique|findFirst"
        r"|insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\("
        r"|\bobjects\s*\.\s*(?:get|filter|all|create|raw)\s*\("
        r"|\b(?:JdbcTemplate|EntityManager|PreparedStatement|SqlCommand|DbContext|JpaRepository|CrudRepository)\b"
        r"|\b(?:sql|gorm)\s*\.\s*Open\s*\(",
        re.MULTILINE,
    ),
    "command_execution": re.compile(
        r"\bchild_process\b|(?<![\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|eval)\s*\("
        r"|\bsubprocess\s*\.\s*\w+\s*\(|\bos\s*\.\s*(?:system|popen|exec\w*|spawn\w*)\s*\("
        r"|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\b|\bexec\s*\.\s*Command\w*\s*\("
        r"|(?<![\w$>.])(?:shell_exec|passthru|proc_open|popen|system)\s*\("
        r"|\bvm\s*\.\s*run\w*\s*\(|\bnew\s+Function\s*\(|\bsafeEval\s*\(|\bnotevil\b"
        r"|\b(?:pug|jade|ejs|handlebars|Handlebars|nunjucks|doT|_)\s*\.\s*(?:compile|template)\s*\("
        r"|\brender_template_string\s*\(|\.from_string\s*\("
    ),
    "outbound_requests": re.compile(
        r"(?<![\w$.])fetch\s*\(|\baxios\s*(?:\.\s*\w+\s*)?\("
        r"|\b(?:require|import)\s*\(?\s*['\"](?:request|request-promise\w*|got|node-fetch|axios|superagent|needle"
        r"|undici|cross-fetch)['\"]"
        r"|\bfrom\s+['\"](?:got|node-fetch|axios|superagent|needle|undici|cross-fetch)['\"]"
        r"|\bhttps?\s*\.\s*(?:get|request)\s*\("
        r"|\brequests\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\(|\burllib\d?\s*\.\s*request\b"
        r"|\burlopen\s*\(|\bhttpx\s*\.\s*\w+\s*\("
        r"|\b(?:RestTemplate|WebClient|OkHttpClient|HttpURLConnection|HttpClient)\b|\bcurl_(?:init|exec)\s*\("
        r"|\bhttp\s*\.\s*(?:Get|Post|NewRequest)\s*\("
    ),
    "file_access": re.compile(
        r"\bfs\s*\.\s*(?:promises\s*\.\s*)?(?:read\w*|write\w*|create(?:Read|Write)Stream|unlink\w*|open\w*|append\w*"
        r"|copy\w*|rename\w*|rm\w*|stat\w*|access\w*|exists\w*)\s*\("
        r"|\b(?:res|response|reply)\s*\.\s*(?:sendFile|sendfile|download)\s*\(|\bexpress\s*\.\s*static\s*\("
        r"|\bserveIndex\s*\(|(?<![\w$.])open\s*\(|\bsend_(?:file|from_directory)\s*\(|\bshutil\s*\.\s*\w+\s*\("
        r"|\bos\s*\.\s*(?:remove|unlink|listdir|makedirs|Open|ReadFile|WriteFile|Create)\s*\("
        r"|\bnew\s+File(?:InputStream|OutputStream|Reader|Writer)?\s*\("
        r"|\bFiles\s*\.\s*(?:read\w*|write\w*|new\w+|copy|move|delete\w*)\s*\("
        r"|\b(?:file_get_contents|file_put_contents|fopen|readfile)\s*\(|\bioutil\s*\.\s*\w+File\s*\("
        r"|\bFile\s*\.\s*(?:Read\w*|Write\w*|Open\w*|Delete)\s*\("
    ),
    "xml_or_deserialization": re.compile(
        r"\blibxml(?:js\d?)?\b|\bxml2js\b|\bfast-xml-parser\b|\bXMLParser\b|\bDOMParser\b|\bxmldom\b"
        r"|\bsax\s*\.\s*parser\s*\(|\b(?:etree|ElementTree|minidom|pulldom|xmltodict|lxml)\b"
        r"|\bDocumentBuilderFactory\b|\bSAXParser(?:Factory)?\b|\bXMLInputFactory\b|\bXmlDocument\b|\bXmlReader\b"
        r"|\bsimplexml_load_\w+\s*\(|\bDOMDocument\b"
        r"|\b(?:pickle|cPickle|marshal|dill)\s*\.\s*loads?\s*\(|\bshelve\s*\.\s*open\s*\(|\bjsonpickle\b"
        r"|\b(?:yaml|YAML|jsyaml|jsYaml)\s*\.\s*(?:load|loadAll|unsafe_load|full_load|safeLoad|safe_load)\s*\("
        r"|\bunserialize\s*\(|\bObjectInputStream\b|\bXMLDecoder\b|\bBinaryFormatter\b|\bnode-serialize\b"
        r"|\bserialize-javascript\b|\bMarshal\s*\.\s*load\s*\("
    ),
    "uploads_or_archives": re.compile(
        r"\bmulter\b|\bbusboy\b|\bformidable\b|\bexpress-fileupload\b|\bconnect-multiparty\b"
        r"|\bupload\s*\.\s*(?:single|array|fields|any)\s*\(|\brequest\s*\.\s*files\b"
        r"|\b(?:UploadFile|MultipartFile|IFormFile|FileStorage)\b|\$_FILES\b"
        r"|\b(?:unzipper|adm-zip|AdmZip|jszip|JSZip|yauzl|decompress|tar-stream)\b|\bunzip\w*\s*\("
        r"|\btar\s*\.\s*(?:x|extract)\s*\(|\b(?:zipfile|tarfile)\b|\bextractall\s*\("
        r"|\bZip(?:InputStream|Archive|File)\b|\bGZIPInputStream\b"
    ),
    "crypto_usage": re.compile(
        r"\b(?:require|import)\s*\(?\s*['\"](?:crypto|node:crypto|crypto-js|bcrypt\w*|node-forge|tweetnacl"
        r"|libsodium\w*)['\"]"
        r"|\bfrom\s+['\"](?:crypto|node:crypto|crypto-js|node-forge|tweetnacl)['\"]"
        r"|\bcrypto\s*\.\s*(?:create\w+|randomBytes|randomUUID|randomInt|pbkdf2\w*|scrypt\w*|subtle"
        r"|generateKeyPair\w*|publicEncrypt|privateDecrypt|sign|verify|timingSafeEqual)\b"
        r"|^[ \t]*(?:import|from)\s+(?:hashlib|hmac|secrets|cryptography|Crypto|nacl|bcrypt|passlib)\b"
        r"|\b(?:MessageDigest|Cipher|KeyGenerator|SecureRandom|Mac)\s*\.\s*getInstance\s*\(|\bSecretKeySpec\b"
        r"|\bjavax\.crypto\b|\bSystem\.Security\.Cryptography\b|\bcrypto/(?:aes|sha\d+|md5|rand|hmac|rsa|cipher)\b"
        r"|\b(?:openssl_\w+|hash_hmac|random_bytes|md5|sha1)\s*\(|\bCryptoJS\s*\.",
        re.MULTILINE,
    ),
    "frontend_code": re.compile(
        r"@Component\s*\(|\bfrom\s+['\"](?:react|react-dom(?:/client)?|vue|svelte|@angular/core|preact|solid-js)['\"]"
        r"|\brequire\s*\(\s*['\"](?:react|react-dom|vue)['\"]\s*\)"
        r"|\bdocument\s*\.\s*(?:getElementById|querySelector\w*|createElement|cookie|write)\b"
        r"|\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b"
        r"|\bwindow\s*\.\s*(?:location|localStorage|sessionStorage|postMessage|addEventListener)\b"
    ),
    "mobile_code": re.compile(
        r"^[ \t]*import\s+(?:android|androidx)\.|^[ \t]*import\s+(?:UIKit|SwiftUI)\b"
        r"|\b(?:from|require\s*\(\s*)\s*['\"]react-native['\"]|['\"]package:flutter/",
        re.MULTILINE,
    ),
    "llm_features": re.compile(
        r"\b(?:require|import)\s*\(?\s*['\"](?:openai|@anthropic-ai/sdk|@google/generative-ai|@google/genai"
        r"|langchain|@langchain/[\w-]+|ai|@ai-sdk/[\w-]+|ollama|cohere-ai|@mistralai/mistralai|groq-sdk)['\"]"
        r"|\bfrom\s+['\"](?:openai|@anthropic-ai/sdk|@google/generative-ai|@google/genai|langchain|@langchain/[\w-]+"
        r"|ai|@ai-sdk/[\w-]+|ollama|cohere-ai|@mistralai/mistralai|groq-sdk)['\"]"
        r"|^[ \t]*(?:import|from)\s+(?:openai|anthropic|langchain\w*|llama_index|litellm|ollama|cohere|mistralai"
        r"|google\.generativeai|google\.genai|groq|vertexai)\b"
        r"|\bchat\s*\.\s*completions\s*\.\s*create\s*\(|\bChatCompletion\s*\.\s*create\s*\(|\bgenerateContent\s*\(",
        re.MULTILINE,
    ),
    "tenant_identifier": re.compile(r"(?i)\btenant\w*|\b(?:org|organization|workspace)_?id\b"),
}
# Signals that a file's path alone shows; its content then is not needed.
_SIGNAL_PATHS: dict[str, re.Pattern] = {
    "frontend_code": re.compile(r"\.(?:html?|vue|svelte|jsx|tsx)$"),
    "mobile_code": re.compile(r"(?:^|/)(?:AndroidManifest\.xml|Info\.plist|pubspec\.yaml|Podfile)$|\.(?:swift|dart)$"),
}
# Signals the route rows decide rather than file content.
_ROUTE_SIGNALS = ("routes", "object_id_routes")

# One fixed reason per signal; the reason never repeats repository text.
APPLIES_REASONS = {
    "always": "the test case applies to every component",
    "routes": "the component registers routes",
    "object_id_routes": "the component registers routes with an object identifier",
    "jwt_usage": "the code issues, verifies or decodes JSON Web Tokens",
    "password_handling": "the code handles passwords",
    "session_handling": "the code creates or stores sessions or session tokens",
    "database_access": "the code accesses a database",
    "command_execution": "the code runs commands, evaluates code or compiles templates",
    "outbound_requests": "the code sends outbound requests",
    "file_access": "the code reads, writes or serves files",
    "xml_or_deserialization": "the code parses XML or deserializes data",
    "uploads_or_archives": "the code accepts uploads or extracts archives",
    "crypto_usage": "the code uses cryptographic primitives",
    "frontend_code": "the component contains browser code",
    "mobile_code": "the component contains mobile app code",
    "llm_features": "the code calls a language model",
    "tenant_identifier": "the code handles a tenant or organization identifier",
}
NO_EVALUATOR_REASON = "no evaluator exists for an applicability signal, so the test case applies"
NOT_APPLICABLE_REASON = "no applicability signal of the test case shows in the examined code"

# Methods that change state, and those that also carry a request body; ALL registers every method.
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE", "ALL"})
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "ALL"})
# Route facts a test case can name as starting points, with the routes each selects. A route that
# changes state is selected whatever its guards: a guard known only by name proves no role or field check.
_ROUTE_FACTS = {
    "route_inventory.authn_signal": lambda row: True,
    "route_inventory.missing_auth_suspect": lambda row: row["missing_auth_suspect"],
    "route_inventory.missing_authz_suspect": lambda row: row["missing_authz_suspect"],
    "route_inventory.state_changing": lambda row: row["method"].upper() in _STATE_CHANGING,
    "route_inventory.accepts_body": lambda row: row["method"].upper() in _BODY_METHODS,
}


def route_facts(
    repo_root: Path,
    inventory: Mapping[str, Any] | list[dict],
    scanner_findings: Iterable[Mapping[str, Any]] | Mapping[str, list] | None,
    *,
    components: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Deterministic facts of one repository snapshot for applicability, candidates and post-checks.

    ``inventory`` is the route inventory document or its ``routes`` list.
    ``scanner_findings`` are this repository's scanner findings, as threats or
    raw sidecar findings, or the controller's lists keyed by component.
    ``components`` maps each component of this repository to the
    repository-relative files it owns; the component-scoped functions need it.
    Routes registered in test files are left out, like every other signal
    there. The result holds no absolute path and no file content.
    """
    root = Path(repo_root).resolve()
    files = _admitted_files(root)
    admitted = set(files)
    rules_at: dict[tuple[str, int], set[str]] = {}
    for hit in _scanner_hits(scanner_findings):
        rules_at.setdefault((hit["file"], hit["line"]), set()).add(hit["rule_id"])
    resolver = HandlerResolver(root)
    routes: dict[str, dict] = {}
    rows = inventory.get("routes") if isinstance(inventory, Mapping) else inventory
    for row in rows or []:
        if not _usable_route(row) or row["route_id"] in routes or _TEST_PATH_RE.search(row["handler_file"]):
            continue
        # The comment-blanked handler code authz_confirm judges, and the
        # (file, first line, last line) of every resolved chain element.
        body = authz_confirm._handler_body(root, resolver, row)
        signal = resolver.route_signal(row)
        bodies = signal.bodies if signal else []
        chain = sorted({(rel, line, line + code.count("\n")) for rel, line, code in bodies if rel in admitted})
        routes[row["route_id"]] = {
            "route_id": row["route_id"],
            "method": str(row.get("method") or ""),
            "path": str(row.get("path") or ""),
            "framework": str(row.get("framework") or ""),
            "handler_file": row["handler_file"],
            "handler_line": row["handler_line"],
            "handler_module": row.get("handler_module") if isinstance(row.get("handler_module"), str) else None,
            "authn_signal": row.get("authn_signal") or "unknown",
            "authn_handler_signal": row.get("authn_handler_signal"),
            "authz_signal": row.get("authz_signal") or "unknown",
            "missing_auth_suspect": bool(row.get("missing_auth_suspect")),
            "missing_authz_suspect": bool(row.get("missing_authz_suspect")),
            "object_id": bool(_PATH_PARAM_RE.search(str(row.get("path") or "")))
            or "object-id argument" in (row.get("notes") or []),
            "handler_read": bool(body),
            "object_access": bool(body) and authz_confirm._object_access(body),
            "ownership_predicate": bool(body) and authz_confirm.has_ownership_predicate(body),
            "chain": [list(span) for span in chain],
            # Rules a scanner reports at the registration, such as authz_confirm's AUTHZ-301/302.
            "scanner_rules": sorted(rules_at.get((row["handler_file"], row["handler_line"]), ())),
        }
    return {
        "files": files,
        "routes": routes,
        "signals": _signals(root, files),
        "components": None if components is None else _component_routes(components, routes, admitted),
    }


def applies(case: Mapping[str, Any], facts: Mapping[str, Any], component_id: str | None = None) -> tuple[bool, str]:
    """Whether the test case applies, with a fixed reason; ``component_id`` limits the signals to its files.

    Any one signal suffices. A signal without an evaluator applies, and so does
    a test case without signals, so applicability never fails open to a skip."""
    component = None if component_id is None else _component(facts, component_id)
    found = []
    for entry in case.get("applies_when") or []:
        signal = entry.get("signal") if isinstance(entry, Mapping) else None
        result = _signal_found(signal, facts, component)
        if result:
            return True, APPLIES_REASONS[signal]
        found.append(result)
    if not found or None in found:
        return True, NO_EVALUATOR_REASON
    return False, NOT_APPLICABLE_REASON


def starting_candidates(
    case: Mapping[str, Any],
    component_id: str,
    facts: Mapping[str, Any],
    scanner_findings: Iterable[Mapping[str, Any]] | Mapping[str, list] | None,
    cap: int | None = None,
) -> dict[str, Any]:
    """``{candidates, overflow}``: the pre-check locations of one component for one test case.

    Each candidate is ``{candidate_id, origin: "pre-check", anchor: {file, line}}``
    with ``route_id`` for a route registration and ``rule_ids`` for the
    starting rules a scanner reported there. Scanner hits come first, then
    routes the inventory flags, then the other routes; ``overflow`` counts the
    candidates beyond ``cap``, without a cap none.
    """
    if cap is not None and (type(cap) is not int or cap < 0):
        raise ValueError("cap must be a non-negative integer")
    component = _component(facts, component_id)
    owned = set(component["files"])
    admitted = set(facts["files"])
    rules = set(case["starting_points"].get("rules") or [])
    # One candidate per location; the first route registered there names it.
    registered: dict[tuple[str, int], str] = {}
    for route_id in component["route_ids"]:
        row = facts["routes"][route_id]
        registered.setdefault((row["handler_file"], row["handler_line"]), route_id)
    located: dict[tuple[str, int], dict] = {}
    for route_id in _selected_routes(case, facts, component):
        row = facts["routes"][route_id]
        anchor = (row["handler_file"], row["handler_line"])
        located.setdefault(anchor, _route_entry(registered[anchor], facts))
    for hit in _scanner_hits(scanner_findings):
        if hit["rule_id"] not in rules or hit["file"] not in admitted:
            continue
        # A finding keeps the owner the scanner intake gave it; without one, its file decides.
        owner = hit["component_id"]
        if (owner is not None and owner != component_id) or (owner is None and hit["file"] not in owned):
            continue
        anchor = (hit["file"], hit["line"])
        if anchor not in located:
            route_id = registered.get(anchor)
            located[anchor] = (
                _route_entry(route_id, facts)
                if route_id
                else {"key": ["location", *anchor], "flagged": False, "rule_ids": set()}
            )
        located[anchor]["rule_ids"].add(hit["rule_id"])
    ordered = sorted(located.items(), key=lambda item: (not item[1]["rule_ids"], not item[1]["flagged"], item[0]))
    candidates = []
    for (file, line), entry in ordered[:cap]:
        candidate = {
            "candidate_id": _candidate_id(case["id"], component_id, entry["key"]),
            "origin": "pre-check",
            "anchor": {"file": file, "line": line},
        }
        if "route_id" in entry:
            candidate["route_id"] = entry["route_id"]
        if entry["rule_ids"]:
            candidate["rule_ids"] = sorted(entry["rule_ids"])
        candidates.append(candidate)
    return {"candidates": candidates, "overflow": len(ordered) - len(candidates)}


def batches(precheck: Mapping[str, list[dict]], limit: int | None = None) -> list[dict[str, list[dict]]]:
    """The model jobs of one component and aspect: per job, each test case's share of ``precheck``.

    ``precheck`` maps each test case ID to its starting candidates. All
    candidates of one location go to the same job, in the order the test
    cases first name the locations, and a job takes whole locations up to
    ``limit`` candidates, ``MAX_CANDIDATES`` by default; a location alone may
    exceed it. The first job lists every test case, also one without a
    candidate there, because only the first job adds model candidates. Later
    jobs list the test cases they hold candidates of.
    """
    limit = MAX_CANDIDATES if limit is None else limit
    if type(limit) is not int or limit < 1:
        raise ValueError("limit must be a positive integer")
    locations: dict[tuple[str, int], list[tuple[str, dict]]] = {}
    for case_id, rows in precheck.items():
        for row in rows:
            locations.setdefault((row["anchor"]["file"], row["anchor"]["line"]), []).append((case_id, row))
    jobs: list[dict[str, list[dict]]] = [{case_id: [] for case_id in precheck}]
    size = 0
    for location in locations.values():
        if size and size + len(location) > limit:
            jobs.append({})
            size = 0
        for case_id, row in location:
            jobs[-1].setdefault(case_id, []).append(row)
        size += len(location)
    # Test cases keep their catalog order in every job.
    return [{case_id: job[case_id] for case_id in precheck if case_id in job} for job in jobs]


def _route_entry(route_id: str, facts: Mapping[str, Any]) -> dict:
    row = facts["routes"][route_id]
    return {
        "route_id": route_id,
        "key": ["route", row["method"], row["path"], row["handler_file"], row["handler_line"]],
        "flagged": _flagged(row),
        "rule_ids": set(),
    }


def _candidate_id(case_id: str, component_id: str, key: list) -> str:
    """Stable ``pc-<16 hex>`` of a test case, a component and a route or location key."""
    digest = hashlib.sha256(json.dumps([case_id, component_id, *key], ensure_ascii=True).encode("utf-8"))
    return "pc-" + digest.hexdigest()[:16]


# --- facts ------------------------------------------------------------------


def _admitted_files(root: Path) -> list[str]:
    """Repository-relative regular files the scanners may read; escaping symlinks are left out."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = sorted(name for name in dirnames if not _is_excluded(prefix + name))
        for name in filenames:
            rel = prefix + name
            if not _is_excluded(rel) and is_safe_to_read(Path(dirpath) / name, root):
                found.append(rel)
    return sorted(found)


def _signals(root: Path, files: list[str]) -> dict[str, list[str]]:
    """Files per evaluated signal, from paths and comment-blanked code outside test files."""
    found: dict[str, list[str]] = {signal: [] for signal in _SIGNAL_CODE}
    for rel in files:
        if _TEST_PATH_RE.search(rel):
            continue
        hits = {signal for signal, pattern in _SIGNAL_PATHS.items() if pattern.search(rel)}
        suffix = Path(rel).suffix.lower()
        if suffix in _CODE_EXTS:
            code = _code(root / rel, suffix)
            hits.update(
                signal for signal, pattern in _SIGNAL_CODE.items() if signal not in hits and pattern.search(code)
            )
        for signal in sorted(hits):
            found[signal].append(rel)
    return found


def _code(path: Path, suffix: str) -> str:
    """A file's text with its comments blanked; empty when it cannot be read or is too large."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return ""
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if suffix in _MARKUP_EXTS:
        text = _MARKUP_COMMENT_RE.sub(lambda m: _NOT_NEWLINE_RE.sub(" ", m[0]), text)
        if suffix in {".html", ".htm"}:
            return text
    return without_comments(text, python=suffix in _HASH_COMMENT_EXTS)


def _usable_route(row: Any) -> bool:
    return (
        isinstance(row, Mapping)
        and isinstance(row.get("route_id"), str)
        and isinstance(row.get("handler_file"), str)
        and type(row.get("handler_line")) is int
        and row["handler_line"] > 0
    )


def _scanner_hits(findings: Any) -> list[dict]:
    """``{rule_id, file, line, component_id}`` of each well-formed scanner finding."""
    if isinstance(findings, Mapping):
        findings = [row for rows in findings.values() if isinstance(rows, list) for row in rows]
    hits = []
    for finding in findings or []:
        if not isinstance(finding, Mapping):
            continue
        rule = next((finding[key] for key in _RULE_KEYS if isinstance(finding.get(key), str) and finding[key]), None)
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), Mapping) else finding
        file, line = evidence.get("file"), evidence.get("line")
        owner = finding.get("component_id")
        if rule and isinstance(file, str) and type(line) is int and line > 0:
            hits.append(
                {"rule_id": rule, "file": file, "line": line, "component_id": owner if isinstance(owner, str) else None}
            )
    return hits


def _component_routes(components: Mapping[str, Iterable[str]], routes: dict, admitted: set[str]) -> dict[str, dict]:
    """Files and routes of each component; a route belongs to the owner of its handler module.

    As in the component analysis (MR-13), a component that owns a route's
    registration file but not its handler module leaves the route to the
    component that owns the module.
    """
    owned = {
        str(cid): sorted({path for path in paths if isinstance(path, str) and path in admitted})
        for cid, paths in components.items()
    }
    module_owners: dict[str, set[str]] = {}
    for cid, paths in owned.items():
        for path in paths:
            module_owners.setdefault(path, set()).add(cid)
    result = {}
    for cid, paths in owned.items():
        own = set(paths)
        result[cid] = {
            "files": paths,
            "route_ids": [
                route_id
                for route_id, row in routes.items()
                if row["handler_module"] in own
                or (row["handler_file"] in own and not (module_owners.get(row["handler_module"] or "", set()) - {cid}))
            ],
        }
    return result


# --- shared lookups ---------------------------------------------------------


def _component(facts: Mapping[str, Any], component_id: str) -> dict:
    """The component's files and routes; an unassigned component is a caller error, never an empty scope."""
    components = facts.get("components")
    if not isinstance(components, Mapping):
        raise ValueError("the facts were built without component assignments")
    if not isinstance(component_id, str) or component_id not in components:
        raise ValueError("the component is not part of these facts")
    return components[component_id]


def _signal_found(signal: Any, facts: Mapping[str, Any], component: dict | None) -> bool | None:
    """True or False for an evaluated signal, None when no evaluator exists."""
    if signal == "always":
        return True
    if signal in _ROUTE_SIGNALS:
        route_ids = facts["routes"] if component is None else component["route_ids"]
        return any(signal == "routes" or facts["routes"][route_id]["object_id"] for route_id in route_ids)
    if not isinstance(signal, str) or signal not in facts["signals"]:
        return None
    files = facts["signals"][signal]
    return bool(files) if component is None else bool(set(files) & set(component["files"]))


def _selected_routes(case: Mapping[str, Any], facts: Mapping[str, Any], component: dict) -> list[str]:
    """Component routes that the test case's route facts select, limited to object routes when it applies only there."""
    selectors = [_ROUTE_FACTS[fact] for fact in case["starting_points"].get("facts") or [] if fact in _ROUTE_FACTS]
    if not selectors:
        return []
    object_only = any(
        isinstance(entry, Mapping) and entry.get("signal") == "object_id_routes" for entry in case["applies_when"]
    )
    selected = []
    for route_id in component["route_ids"]:
        row = facts["routes"][route_id]
        if any(select(row) for select in selectors) and (row["object_id"] or not object_only):
            selected.append(route_id)
    return selected


def _flagged(row: Mapping[str, Any]) -> bool:
    """Whether the inventory marks the route for review: a suspect, or authentication proven absent."""
    return bool(
        row["missing_auth_suspect"]
        or row["missing_authz_suspect"]
        or row["authn_signal"] == "absent"
        or row["authn_handler_signal"] == "decode_only"
    )
