"""Bounded, passive Spring mappings and effective request-security evidence.

Only literal declarations are resolved. Conditional beans, custom matchers and
unresolved expressions retain uncertainty; Java and configuration are never run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from analyzers.handler_resolver import _matching, _skip_string, _split_args

MAX_DECLARATIONS = 2048
MAX_PATHS = 64
MAX_EVIDENCE = 8
_IDENT = r"[A-Za-z_$][\w$]*"
_MAPPING = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": "ANY",
}
_CONDITIONAL = re.compile(r"@(?:[\w.]+\.)?(?:Profile|Conditional\w*)\b")


def _clean(text: str, *, literals: bool) -> str:
    result, pos = list(text), 0
    while pos < len(text):
        start = pos
        comment = False
        if text.startswith('"""', pos):
            end = text.find('"""', pos + 3)
            while end >= 0:
                back = end - 1
                while back >= start and text[back] == "\\":
                    back -= 1
                if (end - 1 - back) % 2 == 0:
                    break
                end = text.find('"""', end + 3)
            pos = len(text) if end < 0 else end + 3
        elif text[pos] in "\"'":
            pos = min(len(text), _skip_string(text, pos))
        elif text.startswith("//", pos):
            end = text.find("\n", pos)
            pos, comment = len(text) if end < 0 else end, True
        elif text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            pos, comment = len(text) if end < 0 else end + 2, True
        else:
            pos += 1
            continue
        if literals or comment:
            result[start:pos] = ["\n" if c == "\n" else " " for c in text[start:pos]]
    return "".join(result)


def _strip_comments(text: str) -> str:
    return _clean(text, literals=False)


def mask(text: str) -> str:
    """Blank comments, ordinary strings and Java text blocks, preserving offsets."""
    return _clean(text, literals=True)


@dataclass
class Annotation:
    name: str
    args: str
    start: int
    end: int
    line: int


def annotations(text: str) -> list[list[Annotation]]:
    code = mask(text)
    found = []
    end = 0
    for m in re.finditer(r"@([\w.]+)\b", code):
        if m.start() < end:
            continue
        pos = m.end()
        while pos < len(code) and code[pos].isspace():
            pos += 1
        end = _matching(code, pos) if code[pos : pos + 1] == "(" else m.end()
        item = Annotation(
            m[1].rsplit(".", 1)[-1],
            text[pos + 1 : end - 1] if end > m.end() else "",
            m.start(),
            end,
            text.count("\n", 0, m.start()) + 1,
        )
        if found and not code[found[-1][-1].end : m.start()].strip():
            found[-1].append(item)
        else:
            found.append([item])
        if sum(map(len, found)) >= MAX_DECLARATIONS:
            break
    return found


def attributes(args: str) -> dict[str, str]:
    result = {}
    for part in _split_args(args):
        m = re.match(r"^(\w+)\s*=\s*([\s\S]*)$", part)
        result[m[1] if m else "value"] = m[2] if m else part
    return result


def strings(value: str, constants: dict[str, str] | None = None, *, _depth=0) -> list[str] | None:
    if _depth > 16 or len(value) > 4096:
        return None
    value = value.strip()
    if value in (constants or {}):
        return [constants[value]]
    if value.startswith("{") and value.endswith("}"):
        parts = _split_args(value[1:-1])
        result = [strings(p, constants, _depth=_depth + 1) for p in parts]
        return [s for part in result for s in part][:MAX_PATHS] if all(p is not None for p in result) else None
    try:
        result = json.loads(value)
    except (ValueError, TypeError, RecursionError):
        return None
    return [result] if isinstance(result, str) and not re.search(r"\$\{|#\{", result) else None


def _constants(text: str) -> dict[str, str]:
    result = {}
    code = mask(text)
    for m in re.finditer(
        r"\b(?:static\s+final|final\s+static)\s+String\s+(\w+)\s*=\s*(\"(?:[^\"\\]|\\.)*\")\s*;",
        _strip_comments(text),
    ):
        if code[m.start() : m.end()].strip() and (value := strings(m[2])):
            result[m[1]] = value[0]
    return result


def _mapping(group, constants):
    annotation = next((a for a in group if a.name in _MAPPING), None)
    if annotation is None:
        return None
    attrs = attributes(annotation.args)
    paths = strings(attrs.get("path", attrs.get("value", '""')), constants)
    methods = [_MAPPING[annotation.name]]
    if annotation.name == "RequestMapping" and "method" in attrs:
        raw = attrs["method"].strip().strip("{}")
        methods = [p.strip().rsplit(".", 1)[-1] for p in _split_args(raw)]
        if any(m not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"} for m in methods):
            return None
    return annotation, paths, methods


def _classes(text: str, groups):
    code = mask(text)
    classes = []
    for m in list(re.finditer(r"\b(?:class|interface|record)\s+(\w+)", code))[:128]:
        start = code.find("{", m.end())
        if start < 0:
            continue
        attached = next(
            (
                g
                for g in reversed(groups)
                if g[-1].end <= m.start()
                and re.fullmatch(
                    r"\s*(?:(?:public|private|protected|static|final|abstract)\s+)*", code[g[-1].end : m.start()]
                )
            ),
            [],
        )
        classes.append((m[1], start, _matching(code, start), attached))
    return classes


def extract(text: str, file: str) -> list[dict]:
    """Return actual annotated handler routes, never class-prefix pseudo routes."""
    text = _strip_comments(text)
    code = mask(text)
    groups = annotations(text)
    classes = _classes(text, groups)
    constants = _constants(text)
    result = []
    for group in groups:
        mapping = _mapping(group, constants)
        if mapping is None:
            continue
        annotation, paths, methods = mapping
        owner = next((c for c in sorted(classes, key=lambda c: -c[1]) if c[1] < annotation.start < c[2]), None)
        if owner is None or not any(a.name in {"Controller", "RestController"} for a in owner[3]):
            continue
        # An annotation inside a method body is data for that method, not a route.
        before = code[owner[1] + 1 : annotation.start]
        if before.count("{") != before.count("}"):
            continue
        signature = code[group[-1].end : group[-1].end + 2048]
        opening = signature.find("(")
        header = signature[:opening] if opening >= 0 else ""
        declaration = re.search(r"(\w+)\s*$", header)
        if not declaration or any(c in header for c in "{};=") or len(re.findall(r"\w+", header)) < 2:
            continue
        params = group[-1].end + opening
        body_start = code.find("{", _matching(code, params))
        semicolon = code.find(";", _matching(code, params))
        if body_start < 0 or body_start >= owner[2] or 0 <= semicolon < body_start:
            continue
        body_end = _matching(code, body_start)
        parent = _mapping(owner[3], constants)
        prefixes = parent[1] if parent else [""]
        notes = []
        if parent and parent[2] != ["ANY"]:
            if methods == ["ANY"]:
                methods = parent[2]
            elif set(methods) != set(parent[2]):
                methods = ["ANY"]
                notes.append("Conflicting class and method HTTP conditions require source review")
        if paths is None or prefixes is None:
            paths, prefixes = ["/<unresolved>"], [""]
            notes.append("Spring mapping expression could not be resolved")
        for prefix in prefixes:
            for path in paths:
                for method in methods:
                    result.append(
                        {
                            "method": method,
                            "path": "/" + "/".join(p.strip("/") for p in (prefix, path) if p.strip("/")),
                            "handler_file": file,
                            "handler_line": text.count("\n", 0, annotation.start) + 1,
                            "body": text[body_start:body_end],
                            "annotations": [*owner[3], *group],
                            "method_annotations": group,
                            "class_annotations": owner[3],
                            "notes": notes,
                        }
                    )
                    if len(result) >= MAX_DECLARATIONS:
                        return result
    return result


def calls(text: str, names: set[str]):
    code = mask(text)
    for m in re.finditer(r"\.\s*(\w+)\s*\(", code):
        if m[1] in names:
            start = code.find("(", m.start())
            end = _matching(code, start)
            yield m[1], text[start + 1 : end - 1], m.start(), end


@dataclass
class Rule:
    paths: list[str] | None
    method: str | None
    effect: str
    line: int


@dataclass
class Chain:
    file: str
    line: int
    order: int
    selector: list[str] | None
    rules: list[Rule]
    methods: list[str]
    uncertain: bool = False
    evidence: list[dict] = field(default_factory=list)
    bearer_routes: list[tuple[str, list[dict]]] = field(default_factory=list)
    login: tuple[str, int] | None = None


def _paths(args):
    parts = _split_args(args)
    method = None
    if parts and re.fullmatch(r"(?:HttpMethod\.)?(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)", parts[0]):
        method = parts.pop(0).rsplit(".", 1)[-1]
    paths = [strings(p) for p in parts]
    return ([s for p in paths for s in p] if paths and all(p is not None for p in paths) else None), method


def chains(text: str, file: str, filters: dict | None = None) -> list[Chain]:
    text = _strip_comments(text)
    code = mask(text)
    groups = annotations(text)
    found = []
    owners = _classes(text, groups)
    for m in list(re.finditer(r"\b(SecurityFilterChain|SecurityWebFilterChain)\s+(\w+)\s*\(", code))[:128]:
        group = next(
            (
                g
                for g in reversed(groups)
                if g[-1].end <= m.start()
                and re.fullmatch(r"\s*(?:(?:public|private|protected|static|final)\s+)*", code[g[-1].end : m.start()])
            ),
            [],
        )
        if not any(a.name == "Bean" for a in group):
            continue
        params = code.find("(", m.start())
        body_start = code.find("{", _matching(code, params))
        if body_start < 0:
            continue
        end = _matching(code, body_start)
        body = text[body_start:end]
        parameters = text[params + 1 : _matching(code, params) - 1]
        receiver = re.search(r"\b(?:HttpSecurity|ServerHttpSecurity)\s+(\w+)", parameters)
        line = text.count("\n", 0, m.start()) + 1
        order_annotation = next((a for a in group if a.name == "Order"), None)
        order = 2**31 - 1
        uncertain = bool(_CONDITIONAL.search(text[:body_start])) or bool(
            re.search(r"\b(?:if|switch)\s*\(|\?", mask(body))
        )
        owner = next((c for c in sorted(owners, key=lambda c: -c[1]) if c[1] < m.start() < c[2]), None)
        if owner is None or not any(
            a.name in {"Configuration", "SpringBootApplication", "Component"} for a in owner[3]
        ):
            uncertain = True
        if receiver is None or not re.search(
            r"\breturn\s+" + re.escape(receiver[1]) + r"\s*\.\s*build\s*\(\s*\)", mask(body)
        ):
            uncertain = True
        if receiver and re.search(r"(?<![.\w])\w+\s*\(\s*" + re.escape(receiver[1]) + r"\s*[,)]", mask(body)):
            uncertain = True
        if any(calls(body, {"apply", "with"})):
            uncertain = True
        if order_annotation:
            raw = order_annotation.args.strip()
            try:
                order = int(raw)
            except ValueError:
                if raw.endswith("HIGHEST_PRECEDENCE"):
                    order = -(2**31)
                elif not raw.endswith("LOWEST_PRECEDENCE"):
                    uncertain = True
        selectors = list(calls(body, {"securityMatcher", "securityMatchers"}))
        selector = ["/**"]
        if selectors:
            selector, _ = _paths(selectors[0][1])
            uncertain |= len(selectors) > 1 or selector is None
        rules = []
        for _, args, start, _ in calls(body, {"authorizeHttpRequests", "authorizeRequests", "authorizeExchange"}):
            matchers = list(
                calls(
                    args, {"requestMatchers", "antMatchers", "mvcMatchers", "pathMatchers", "anyRequest", "anyExchange"}
                )
            )
            for i, (kind, raw, offset, after) in enumerate(matchers):
                paths, method = (["/**"], None) if kind.startswith("any") else _paths(raw)
                tail = args[after : matchers[i + 1][2] if i + 1 < len(matchers) else len(args)]
                policy = next(
                    calls(
                        tail,
                        {
                            "permitAll",
                            "authenticated",
                            "fullyAuthenticated",
                            "rememberMe",
                            "hasRole",
                            "hasAnyRole",
                            "hasAuthority",
                            "hasAnyAuthority",
                            "denyAll",
                            "access",
                        },
                    ),
                    None,
                )
                effect = policy[0] if policy else "unknown"
                if policy and effect in {"hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority"}:
                    authorities = strings("{" + policy[1] + "}")
                    if authorities is None:
                        effect = "unknown"
                    elif any(v in {"ANONYMOUS", "ROLE_ANONYMOUS"} for v in authorities):
                        effect = "permitAll"
                rules.append(Rule(paths, method, effect, line + body[:start].count("\n") + args[:offset].count("\n")))
        methods, login = [], None
        for name, args, start, after in calls(body, {"formLogin", "httpBasic", "oauth2ResourceServer"}):
            if re.search(r"\bdisable\b", mask(args)) or re.match(r"\s*\.\s*disable\s*\(", mask(body[after:])):
                continue
            if (
                name == "formLogin"
                and args.strip()
                and not (
                    re.fullmatch(r"(?:Customizer\.)?withDefaults\s*\(\s*\)", args.strip())
                    or (
                        re.match(r"\s*\(?\s*" + _IDENT + r"\s*\)?\s*->\s*" + _IDENT + r"\s*\.", args)
                        and all(
                            call[0]
                            in {
                                "loginPage",
                                "loginProcessingUrl",
                                "defaultSuccessUrl",
                                "failureUrl",
                                "permitAll",
                                "usernameParameter",
                                "passwordParameter",
                            }
                            for call in calls(args, set(re.findall(r"\.\s*(\w+)\s*\(", mask(args))))
                        )
                    )
                )
            ):
                continue
            methods.append({"formLogin": "cookie", "httpBasic": "basic", "oauth2ResourceServer": "bearer"}[name])
            if name == "formLogin" and m[1] == "SecurityFilterChain":
                processing = list(calls(args, {"loginProcessingUrl"})) or list(calls(args, {"loginPage"}))
                paths = strings(processing[-1][1]) if processing else ["/login"]
                if paths and len(paths) == 1 and matches(paths[0], paths[0]) is True:
                    login = paths[0], line + body[:start].count("\n")
        # Unknown helper calls must not manufacture a complete request policy.
        if not rules:
            uncertain = True
        bearer_routes = []
        for _, args, _, _ in calls(body, {"addFilterBefore", "addFilterAfter", "addFilterAt"}):
            arguments = _split_args(args)
            if arguments and re.fullmatch(_IDENT, arguments[0]):
                parameter = re.search(r"\b(\w+)\s+" + re.escape(arguments[0]) + r"\b", parameters)
                if parameter and parameter[1] in (filters or {}):
                    bearer_routes.append(filters[parameter[1]])
        found.append(
            Chain(
                file,
                line,
                order,
                selector,
                rules,
                sorted(set(methods)),
                uncertain,
                [{"file": file, "line": line}],
                bearer_routes,
                login,
            )
        )
    return found


def matches(pattern: str, path: str) -> bool | None:
    if (
        len(pattern) > 512
        or len(path) > 2048
        or not pattern.startswith("/")
        or any(s in pattern for s in ("${", "#{", ":", "[", "]"))
    ):
        return None
    parts = pattern.strip("/").split("/") if pattern != "/" else []
    values = path.strip("/").split("/") if path != "/" else []
    if "**" in parts[:-1]:
        return None

    def segment(pattern, value):
        # A bounded wildcard walk avoids user-controlled backtracking regexes.
        i = j = 0
        star = -1
        checkpoint = 0
        while j < len(value):
            if i < len(pattern) and (pattern[i] == "?" or pattern[i] == value[j]):
                i += 1
                j += 1
            elif i < len(pattern) and pattern[i] == "*":
                star, checkpoint = i, j
                i += 1
            elif star >= 0:
                checkpoint += 1
                i, j = star + 1, checkpoint
            else:
                return False
        return all(c == "*" for c in pattern[i:])

    position = 0
    for part in parts:
        if part == "**":
            return True
        if position >= len(values):
            return False
        elif "{" in values[position] or "}" in values[position] or "*" in values[position]:
            if part != "*" and not re.fullmatch(r"\{[\w]+\}", part):
                return None
        elif part.startswith("{") and part.endswith("}"):
            if not re.fullmatch(r"\{[\w]+\}", part):
                return None
        elif not segment(part, values[position]):
            return False
        position += 1
    return position == len(values)


def policy(route: dict, configured: list[Chain]) -> tuple[str, list[str], list[dict], str]:
    """Resolve the first applicable chain and its first matching rule."""
    if route.get("notes"):
        return "unknown", [], [], "The Spring mapping could not be resolved completely"
    for chain in sorted(configured, key=lambda c: c.order):
        selected = [matches(p, route["path"]) for p in chain.selector or []]
        if selected and all(v is False for v in selected):
            continue
        if chain.uncertain or not selected or None in selected:
            return "unknown", [], chain.evidence, "Spring security activation or chain selection is unresolved"
        peers = [c for c in configured if c is not chain and c.order == chain.order]
        if any(c.selector is None or any(matches(p, route["path"]) is not False for p in c.selector) for c in peers):
            return "unknown", [], chain.evidence, "Spring security chains have ambiguous precedence"
        for rule in chain.rules:
            if rule.method and route["method"] != rule.method:
                if route["method"] in {"ANY", "UNKNOWN"}:
                    return "unknown", [], chain.evidence, "The request method selects different Spring security rules"
                continue
            selected = [matches(p, route["path"]) for p in rule.paths or []]
            if not selected or None in selected:
                return "unknown", [], chain.evidence, "A Spring request matcher could not be resolved"
            if any(selected):
                evidence = [{"file": chain.file, "line": rule.line}, *chain.evidence][:MAX_EVIDENCE]
                methods = list(chain.methods)
                for prefix, refs in chain.bearer_routes:
                    if route["path"].startswith(prefix):
                        methods.append("bearer")
                        evidence = [*evidence, *refs][:MAX_EVIDENCE]
                return (
                    rule.effect,
                    sorted(set(methods)),
                    evidence,
                    "Spring Security applies the first matching request rule",
                )
        return "unknown", [], chain.evidence, "No explicit Spring request rule was resolved"
    return "unknown", [], [], "No applicable Spring security chain was resolved"


def method_policy(route: dict, enabled: dict[str, bool]) -> tuple[str, list[dict]]:
    guards = {"PreAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll"}
    own = [a for a in route["method_annotations"] if a.name in guards]
    inherited = [a for a in route["class_annotations"] if a.name in guards]
    selected = own or inherited
    if not selected:
        return "unknown", []
    effects = []
    for a in selected:
        family = (
            "jsr250"
            if a.name in {"RolesAllowed", "PermitAll", "DenyAll"}
            else "secured"
            if a.name == "Secured"
            else "prepost"
        )
        if not enabled.get(family):
            continue
        expression = attributes(a.args).get("value", a.args)
        if a.name in {"Secured", "RolesAllowed"} and strings(expression) is None:
            effects.append("unresolved")
            continue
        if "ANONYMOUS" in expression:
            effects.append("unresolved")
            continue
        if a.name == "PermitAll" or (a.name == "PreAuthorize" and strings(expression) == ["permitAll()"]):
            effects.append("permitAll")
        elif a.name == "DenyAll" or (a.name == "PreAuthorize" and strings(expression) == ["denyAll()"]):
            effects.append("denyAll")
        elif a.name == "PreAuthorize" and not re.fullmatch(
            r'"(?:isAuthenticated\(\)|has(?:Any)?(?:Role|Authority)\([^"\n]+\))"', expression.strip()
        ):
            effects.append("unresolved")
        else:
            effects.append("role")
    evidence = [{"file": route["handler_file"], "line": a.line} for a in selected][:MAX_EVIDENCE]
    return ("role" if "role" in effects else effects[0] if effects else "unknown"), evidence


def method_security(sources: dict[str, str]) -> dict[str, bool]:
    result = {"prepost": False, "secured": False, "jsr250": False}
    for text in sources.values():
        if _CONDITIONAL.search(_strip_comments(text)):
            continue
        for group in annotations(text):
            if not any(a.name in {"Configuration", "SpringBootApplication", "Component"} for a in group):
                continue
            for a in group:
                if a.name in {"EnableMethodSecurity", "EnableGlobalMethodSecurity"}:
                    attrs = attributes(a.args)
                    result["prepost"] |= (
                        attrs.get("prePostEnabled", "true" if a.name == "EnableMethodSecurity" else "false") == "true"
                    )
                    result["secured"] |= attrs.get("securedEnabled") == "true"
                    result["jsr250"] |= attrs.get("jsr250Enabled") == "true"
    return result


def bearer_filters(sources: dict[str, str]) -> dict:
    """Follow the narrow verified-JWS service/filter pattern; unknown helpers add no claim."""
    services = {}
    for file, text in sources.items():
        code = mask(text)
        kind = re.search(r"\bclass\s+(\w+)", code)
        method = re.search(r"\bClaims\s+verify\s*\(\s*String\s+(\w+)\s*\)", code)
        if not kind or not method:
            continue
        start = code.find("{", method.end())
        if start < 0:
            continue
        body = code[start : _matching(code, start)]
        parse = re.search(r"\.parseClaimsJws\s*\(\s*" + re.escape(method[1]) + r"\s*\)", body)
        assignment = re.search(r"\b(?:var|Jws\s*<\s*Claims\s*>)\s+(\w+)\s*=\s*Jwts\.parserBuilder\s*\(", body)
        if (
            parse
            and assignment
            and re.search(r"\.setSigningKey\s*\(", body[: parse.start()])
            and not re.search(r"\b(?:if|switch|for|while|try|return)\b", body[: parse.start()])
            and not re.search(r"\bcatch\b", body)
            and re.search(r"\breturn\s+" + re.escape(assignment[1]) + r"\.getBody\s*\(\s*\)\s*;", body)
        ):
            services[kind[1]] = {"file": file, "line": text.count("\n", 0, method.start()) + 1}
    result = {}
    for file, text in sources.items():
        code = mask(text)
        kind = re.search(r"\bclass\s+(\w+)\s+extends\s+OncePerRequestFilter\b", code)
        if not kind:
            continue
        for service, evidence in services.items():
            field = re.search(r"\b" + re.escape(service) + r"\s+(\w+)\s*;", code)
            if not field:
                continue
            verify = re.search(r"\b" + re.escape(field[1]) + r"\.verify\s*\(", code)
            install = re.search(r"SecurityContextHolder\.getContext\s*\(\s*\)\.setAuthentication\s*\(", code)
            rejection = re.search(
                r"catch\s*\(\s*JwtException\s+\w+\s*\)\s*\{[^{}]*\.sendError\s*\([^;]+;\s*return\s*;", code
            )
            header = re.search(r"\.getHeader\s*\(\s*HttpHeaders\.AUTHORIZATION\s*\)", code)
            prefix = re.search(
                r'return\s+!\s*\w+\.getServletPath\s*\(\s*\)\.startsWith\s*\(\s*("[^"\n]+")\s*\)\s*;',
                _strip_comments(text),
            )
            if (
                all((verify, install, rejection, header, prefix))
                and verify.start() < install.start() < rejection.start()
            ):
                parsed = strings(prefix[1])
                if parsed:
                    result[kind[1]] = (
                        parsed[0],
                        [evidence, {"file": file, "line": text.count("\n", 0, verify.start()) + 1}],
                    )
    return result


def control_sources(
    component: dict, components: list[dict], inventories: dict, repositories: dict | None = None
) -> tuple[list[dict], list[dict], list[dict]]:
    """Exact admitted enforcement files supporting this component's registered routes."""
    own = {(p["repository_id"], p["path"]) for p in component["paths"]}
    indexed = {(p["repository_id"], p["path"]): p for c in components for p in c["paths"]}
    routes, references, keys = [], [], set()
    imports = {}
    for rid, inventory in inventories.items():
        for row in inventory.get("routes", []):
            if row.get("framework") != "spring" or (rid, row.get("handler_file")) not in own:
                continue
            routes.append(
                {
                    k: row[k]
                    for k in (
                        "method",
                        "path",
                        "handler_file",
                        "handler_line",
                        "authn_signal",
                        "authz_signal",
                        "authentication_methods",
                    )
                    if k in row
                }
            )
            cache_key = rid, row["handler_file"]
            if repositories and cache_key not in imports:
                body = repositories.get(rid, {}).get(row["handler_file"], b"").decode("utf-8", errors="replace")
                local = []
                for match in re.finditer(r"(?m)^\s*import\s+([\w.]+)\s*;", _strip_comments(body)):
                    suffix = match[1].replace(".", "/") + ".java"
                    candidates = [
                        p
                        for repository, p in indexed
                        if repository == rid and (p == suffix or p.endswith("/" + suffix))
                    ]
                    if len(candidates) == 1:
                        local.append({"file": candidates[0], "line": 1})
                    if len(local) >= 16:
                        break
                imports[cache_key] = local
            for ref in [
                {"file": row["handler_file"], "line": row["handler_line"]},
                *(row.get("authn_handler_evidence") or []),
                *imports.get(cache_key, []),
            ]:
                key = rid, ref.get("file")
                if key not in indexed or not isinstance(ref.get("line"), int) or ref["line"] < 1:
                    continue
                qualified = {**ref, "repository_id": rid, "sha256": indexed[key]["sha256"]}
                if qualified not in references and len(references) < 256:
                    references.append(qualified)
                    keys.add(key)
    supporting = []
    for other in components:
        if other["id"] != component["id"]:
            paths = [p for p in other["paths"] if (p["repository_id"], p["path"]) in keys - own]
            if paths:
                supporting.append({**other, "paths": paths})
    return routes[:128], references[:256], supporting
