"""Spring route and effective-policy regressions, including uncertain configuration."""

import json
from pathlib import Path

import jsonschema
import pytest
from analyzers.route_inventory import build_inventory

ROOT = Path(__file__).resolve().parents[1]


def inventory(tmp_path, controller, config=""):
    (tmp_path / "Controller.java").write_text("import org.springframework.web.bind.annotation.*;\n" + controller)
    if config:
        (tmp_path / "SecurityConfig.java").write_text(config)
    doc = build_inventory(tmp_path)
    jsonschema.validate(doc, json.loads((ROOT / "schemas/route-inventory.schema.json").read_text()))
    return doc["routes"]


def config(rules, *, selector="", order="", extra="", condition="", reactive=False):
    chain, http = (
        ("SecurityWebFilterChain", "ServerHttpSecurity") if reactive else ("SecurityFilterChain", "HttpSecurity")
    )
    authorize = "authorizeExchange" if reactive else "authorizeHttpRequests"
    return f"""import org.springframework.security.web.SecurityFilterChain;
@Configuration
{condition}
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
class SecurityConfig {{
 @Bean {order}
 {chain} web({http} http) throws Exception {{
  http{selector}.{authorize}(auth -> auth{rules}){extra};
  return http.build();
 }}
}}
"""


def controller(path="/business", annotation="", mapping=None):
    return f"""@RestController
{annotation}
class Controller {{
 {mapping or f'@GetMapping("{path}")'}
 public String read() {{ return "ok"; }}
}}
"""


@pytest.mark.parametrize("annotation", ["@GetMapping", "@GetMapping()", "@RequestMapping(method = RequestMethod.GET)"])
def test_class_mapping_and_empty_method_mapping_are_composed(tmp_path, annotation):
    rows = inventory(tmp_path, controller(annotation='@RequestMapping("/api/projects")', mapping=annotation))
    assert [(r["method"], r["path"]) for r in rows] == [("GET", "/api/projects")]


def test_mapping_arrays_and_named_attributes_preserve_each_endpoint(tmp_path):
    rows = inventory(
        tmp_path,
        controller(annotation='@RequestMapping(path = {"/api", "/v2"})', mapping='@GetMapping(value = {"/a", "/b"})'),
    )
    assert {r["path"] for r in rows} == {"/api/a", "/api/b", "/v2/a", "/v2/b"}


def test_class_role_annotation_applies_when_method_security_is_enabled(tmp_path):
    (row,) = inventory(
        tmp_path, controller(annotation="@PreAuthorize(\"hasRole('ADMIN')\")"), config(".anyRequest().authenticated()")
    )
    assert row["authz_signal"] == "decorator_present"
    assert row["authn_handler_signal"] == "verified"


def test_inactive_method_security_does_not_prove_a_guard(tmp_path):
    (row,) = inventory(tmp_path, controller(annotation="@PreAuthorize(\"hasRole('ADMIN')\")"))
    assert row["authz_signal"] == row["authn_signal"] == "unknown"


def test_authenticated_fallback_and_alternative_credentials(tmp_path):
    rows = inventory(
        tmp_path,
        controller(),
        config(
            '.requestMatchers("/public").permitAll().anyRequest().authenticated()',
            extra=".formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults())",
        ),
    )
    business = next(r for r in rows if r["path"] == "/business")
    assert business["authn_signal"] == "middleware_present"
    assert business["authentication_methods"] == ["basic", "cookie"]
    login = next(r for r in rows if r["path"] == "/login")
    assert login["method"] == "POST"
    assert login["authentication_methods"] == ["password"]


def test_first_matching_rule_and_http_method_are_preserved(tmp_path):
    rows = inventory(
        tmp_path,
        controller(path="/api/auth/token"),
        config(
            '.requestMatchers(HttpMethod.GET, "/api/auth/token").authenticated().requestMatchers("/api/auth/**").permitAll().anyRequest().authenticated()'
        ),
    )
    assert rows[0]["authn_signal"] == "middleware_present"
    rows = inventory(
        tmp_path,
        controller(path="/api/auth/token"),
        config(
            '.requestMatchers(HttpMethod.POST, "/api/auth/token").authenticated().requestMatchers("/api/auth/**").permitAll().anyRequest().authenticated()'
        ),
    )
    assert rows[0]["authn_signal"] == "absent"


@pytest.mark.parametrize(
    "extra,selector,condition,expected",
    [
        ('.formLogin(form -> form.loginProcessingUrl("/signin"))', "", "", "/signin"),
        (".formLogin(Customizer.withDefaults())", '.securityMatcher("/api/**")', "", None),
        (".formLogin(form -> form.disable())", "", "", None),
        (".formLogin().disable()", "", "", None),
        (".formLogin(Customizer.withDefaults())", "", '@Profile("prod")', None),
        (".formLogin(form -> form.loginProcessingUrl(dynamicUrl))", "", "", None),
    ],
)
def test_framework_login_requires_an_active_matching_chain(tmp_path, extra, selector, condition, expected):
    rows = inventory(
        tmp_path,
        controller(),
        config(".anyRequest().authenticated()", extra=extra, selector=selector, condition=condition),
    )
    logins = [r for r in rows if r.get("authentication_methods") == ["password"]]
    assert [r["path"] for r in logins] == ([expected] if expected else [])


@pytest.mark.parametrize(
    "rules,condition",
    [
        (".requestMatchers(customMatcher()).permitAll().anyRequest().authenticated()", ""),
        (".anyRequest().authenticated()", '@Profile("production")'),
    ],
)
def test_unresolved_matchers_and_activation_remain_unknown(tmp_path, rules, condition):
    (row,) = inventory(tmp_path, controller(), config(rules, condition=condition))
    assert row["authn_signal"] == "unknown"
    assert row["authn_handler_signal"] == "unresolved"


def test_reactive_annotated_routes_use_reactive_security_chain(tmp_path):
    (row,) = inventory(
        tmp_path,
        controller(),
        config('.pathMatchers("/public").permitAll().anyExchange().authenticated()', reactive=True),
    )
    assert row["authn_signal"] == "middleware_present"


def test_comments_and_literals_never_register_routes_or_guards(tmp_path):
    text = controller() + '\n// @GetMapping("/fake")\nclass Data { String s = "@GetMapping(\\"/fake2\\")"; }'
    rows = inventory(tmp_path, text)
    assert [r["path"] for r in rows] == ["/business"]
    assert rows[0]["authn_signal"] == "unknown"


def test_mapping_in_an_unregistered_helper_is_not_an_endpoint(tmp_path):
    assert inventory(tmp_path, controller().replace("@RestController", "@Component")) == []


def test_method_override_does_not_inherit_class_role_requirement(tmp_path):
    text = controller(
        annotation="@PreAuthorize(\"hasRole('ADMIN')\")",
        mapping='@GetMapping("/business")\n @PreAuthorize("permitAll()")',
    )
    (row,) = inventory(tmp_path, text, config(".anyRequest().permitAll()"))
    assert row["authz_signal"] == "unknown" and row["authn_signal"] == "absent"


def test_unsupported_custom_authorization_expression_is_not_a_confirmed_guard(tmp_path):
    (row,) = inventory(
        tmp_path,
        controller(annotation='@PreAuthorize("@policy.allowed(authentication)")'),
        config(".anyRequest().permitAll()"),
    )
    assert row["authn_signal"] == "unknown"


def test_multiple_chains_follow_literal_order(tmp_path):
    first = config(".anyRequest().permitAll()", selector='.securityMatcher("/business")', order="@Order(1)")
    second = config(".anyRequest().authenticated()", order="@Order(2)").replace(
        "class SecurityConfig", "class SecondConfig"
    )
    (row,) = inventory(tmp_path, controller(), first + second)
    assert row["authn_signal"] == "absent"


def test_equal_priority_overlapping_chains_remain_unknown(tmp_path):
    first = config(".anyRequest().permitAll()")
    second = config(".anyRequest().authenticated()").replace("class SecurityConfig", "class SecondConfig")
    (row,) = inventory(tmp_path, controller(), first + second)
    assert row["authn_signal"] == "unknown"


def test_anonymous_authority_does_not_become_required_authentication(tmp_path):
    (row,) = inventory(tmp_path, controller(), config('.anyRequest().hasRole("ANONYMOUS")'))
    assert row["authn_signal"] == "absent"


def test_unregistered_configuration_does_not_prove_security(tmp_path):
    (row,) = inventory(tmp_path, controller(), config(".anyRequest().authenticated()").replace("@Configuration", ""))
    assert row["authn_signal"] == "unknown"


def test_dynamic_mapping_cannot_select_a_protective_fallback(tmp_path):
    (row,) = inventory(
        tmp_path,
        controller(mapping='@GetMapping("${endpoint}")'),
        config('.requestMatchers("/public").permitAll().anyRequest().authenticated()'),
    )
    assert row["authn_signal"] == "unknown"


def test_java_text_blocks_cannot_register_fake_routes_or_configuration(tmp_path):
    text = (
        controller()
        + '''
class TextData {
 String text = """
   @Configuration
   @EnableMethodSecurity
   class Fake {
    @GetMapping("/fake")
    public String fake() { return "not code"; }
   }
 """;
}
'''
    )
    rows = inventory(tmp_path, text)
    assert [r["path"] for r in rows] == ["/business"]
    assert rows[0]["authn_signal"] == "unknown"


def test_text_block_cannot_supply_a_route_constant(tmp_path):
    text = '''@RestController
class Controller {
 static final String PATH = "${endpoint}";
 String documentation = """
 static final String PATH = "/fake";
 """;
 @GetMapping(PATH)
 public String read() { return "ok"; }
}
'''
    (row,) = inventory(tmp_path, text, config(".anyRequest().authenticated()"))
    assert row["path"] == "/<unresolved>"
    assert row["authn_signal"] == "unknown"


def test_matcher_work_is_bounded_and_unknown_patterns_stay_unknown():
    from analyzers.spring_security import matches, strings

    assert matches("/" + "*a" * 300, "/abc") is None
    assert matches("/**", "/" + "a" * 3000) is None
    assert matches("/api/**", "/api") is True
    assert matches("/api/{id}", "/api/42") is True
    assert matches("/api/*", "/api/a/b") is False
    assert matches("/api/public", "/api/{id}") is None
    assert matches("/api/*", "/api/{id}") is True
    assert strings("{" * 100 + '"path"' + "}" * 100) is None


def test_global_web_security_customizer_prevents_unqualified_chain_proof(tmp_path):
    (tmp_path / "Bypass.java").write_text("""@Configuration
class Bypass {
 @Bean WebSecurityCustomizer bypass() { return web -> web.ignoring().requestMatchers("/business"); }
}
""")
    (row,) = inventory(tmp_path, controller(), config(".anyRequest().authenticated()"))
    assert row["authn_signal"] == "unknown"


def test_variable_route_cannot_skip_an_overlapping_public_matcher(tmp_path):
    (row,) = inventory(
        tmp_path,
        controller(path="/api/{id}"),
        config('.requestMatchers("/api/public").permitAll().anyRequest().authenticated()'),
    )
    assert row["authn_signal"] == "unknown"


@pytest.mark.parametrize("verified", [True, False])
def test_custom_jws_filter_requires_an_evidenced_verification_service(tmp_path, verified):
    service = """class TokenService {
 public Claims verify(String token) {
  var parsed = Jwts.parserBuilder().setSigningKey(key).build().PARSE(token);
  return parsed.getBody();
 }
}
""".replace("PARSE", "parseClaimsJws" if verified else "parseClaimsJwt")
    (tmp_path / "TokenService.java").write_text(service)
    (tmp_path / "BearerFilter.java").write_text("""class BearerFilter extends OncePerRequestFilter {
 private final TokenService service;
 protected boolean shouldNotFilter(HttpServletRequest request) {
  return !request.getServletPath().startsWith("/api/");
 }
 protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain next) {
  String header = request.getHeader(HttpHeaders.AUTHORIZATION);
  if (header != null && header.startsWith("Bearer ")) {
   try {
    Claims claims = service.verify(header.substring(7));
    var auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), "jwt", roles);
    SecurityContextHolder.getContext().setAuthentication(auth);
   } catch (JwtException exception) {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
    return;
   }
  }
  next.doFilter(request, response);
 }
}
""")
    security = config(
        ".anyRequest().authenticated()", extra=".addFilterBefore(bearer, UsernamePasswordAuthenticationFilter.class)"
    )
    security = security.replace("HttpSecurity http)", "HttpSecurity http, BearerFilter bearer)")
    (row,) = inventory(tmp_path, controller(path="/api/profile"), security)
    assert ("bearer" in row.get("authentication_methods", [])) is verified
