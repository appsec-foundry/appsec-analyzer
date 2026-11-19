"""Remove recognized credentials from model data before serialization or provider dispatch."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from functools import cached_property
from threading import RLock
from urllib.parse import unquote

from validators.secret_scan import scan_text

REDACTED = "[REDACTED]"
# Bound matching work for source-controlled collections of distinct credentials.
MAX_VALUES = 2048
MAX_VALUE_BYTES = 256 * 1024
_CREDENTIAL_FIELDS = re.compile(
    r"(?:^|[_-])(?:password|passwd|pwd|client[_-]?secret|private[_-]?key|api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|"
    r"token|access[_-]?token|refresh[_-]?token|auth[_-]?token)$",
    re.I,
)
_PROVIDER_PATTERN = re.compile(r"(?<![\w-])(?:sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{16,})")
_HTTP_AUTH = re.compile(r"""(?i)\bauthorization["']?[ \t]*[:=][ \t]*["']?(?:basic|bearer)[ \t]+([a-z0-9._~+/=-]+)""")
_URL_PASSWORD = re.compile(r"""(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@"'<>]*:([^/\s@"'<>]+)@""")
_QUOTED = re.compile(
    r"""(?ix)(?:\b|(?<=_))(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)"""
    r"""["']?[ \t]*[=:][ \t]*(?P<q>["'])(?P<value>(?:\\[^\n]|(?!(?P=q))[^\\\n])*)(?P=q)"""
)
# A quoted interpolation is a reference, not the value supplied at runtime.
_INTERPOLATION = re.compile(r"\$\{[^{}\n]+\}")
_BARE_ASSIGNMENT = re.compile(
    r"""(?ix)(?:\b|(?<=_))(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|bearer|token|auth)"""
    r"""[ \t]*[=:][ \t]*([^\s"'`]+)"""
)
_PROVIDER_TOKENS = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "OPENAI_API_KEY",
    "LITELLM_API_KEY",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "APPSEC_GATEWAY_API_KEY",
    "APPSEC_GIT_TOKEN",
    "GIT_TOKEN",
    "GITLAB_TOKEN",
    "COPILOT_GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
)


def _marker(value: str) -> bool:
    return value in (REDACTED, "[REDACTED secret value]", "[PEM PRIVATE KEY — REDACTED]") or bool(
        re.fullmatch(r"\*{4}(?: \(\d+ chars\))?", value)
    )


class ModelSecretError(ValueError):
    def __init__(self):
        super().__init__("Model input could not be checked for secrets; the request was withheld")


def _strings(data):
    if isinstance(data, str):
        yield data
    elif isinstance(data, (tuple, list)):
        for item in data:
            yield from _strings(item)
    elif isinstance(data, dict):
        for key, item in data.items():
            yield str(key)
            yield from _strings(item)


def _fields(data):
    if isinstance(data, dict):
        for key, item in data.items():
            if str(key).lower() == "authorization" and isinstance(item, str):
                yield from (match[1] for match in _HTTP_AUTH.finditer("Authorization: " + item))
            if _CREDENTIAL_FIELDS.search(str(key)) and isinstance(item, (int, float)) and not isinstance(item, bool):
                raise ModelSecretError()
            if isinstance(item, str) and _CREDENTIAL_FIELDS.search(str(key)) and item and not _marker(item):
                yield item
            else:
                yield from _fields(item)
    elif isinstance(data, (list, tuple)):
        for item in data:
            yield from _fields(item)


def detected_values(text: str):
    yield from (match[1] for match in _HTTP_AUTH.finditer(text))
    for match in _URL_PASSWORD.finditer(text):
        if not _marker(match[1]):
            yield match[1]
            yield unquote(match[1])
    for match in _PROVIDER_PATTERN.finditer(text):
        yield match[0]
    for match in _QUOTED.finditer(text):
        value = match["value"]
        # Embedded snippets in prose include query parameters and tiny example
        # inputs. Structured fields and standalone assignments also cover short literals.
        line_prefix = text[text.rfind("\n", 0, match.start()) + 1 : match.start()].strip()
        standalone = line_prefix in ("", "const", "let", "var", "export", "val")
        if value and (standalone or len(value) >= 8) and not _marker(value) and not _INTERPOLATION.fullmatch(value):
            yield value
    assignment_prefixes = set()
    for hit in scan_text(text):
        if not hit.value:
            raise ModelSecretError()
        yield hit.value
        if hit.pattern == "generic_credential_assignment":
            assignment_prefixes.add(hit.value)
        if hit.pattern == "pem_private_key":
            # A copied private key body is still reusable without its PEM delimiters.
            parts = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", re.sub(r"\\+[rn]", "\n", hit.value))
            yield from parts
            if parts:
                yield "".join(parts)
    if assignment_prefixes:
        # The report scanner can stop at punctuation inside an unquoted
        # password. Replace the whole token, including any such suffix.
        for match in _BARE_ASSIGNMENT.finditer(text):
            value = match[1]
            prefix = re.match(r"[A-Za-z0-9_+/=.!@#$%?-]+", value)
            if prefix and prefix[0].rstrip(".,") in assignment_prefixes:
                yield value
    # Quoted JSON keys and escaped JSON string values lose their relationship in a text-only scan.
    if text.lstrip().startswith(("{", "[")):
        try:
            document = json.loads(text)
        except ValueError:
            return
        yield from _fields(document)
        for item in _strings(document):
            yield from (hit.value for hit in scan_text(item) if hit.value)
            yield from (match[0] for match in _PROVIDER_PATTERN.finditer(item))


class ModelSecrets:
    """An in-memory set for one source snapshot or request. Never serialize it."""

    def __init__(self, values: Iterable[str] = ()):
        self._lock = RLock()
        self.values: set[str] = set()
        self._bytes = 0
        self._uncheckable = False
        self.add(values)

    @classmethod
    def configured(cls, extra_env: str | None = None):
        names = (*_PROVIDER_TOKENS, os.environ.get("APPSEC_GIT_TOKEN_ENV"), extra_env)
        return cls(os.environ[name] for name in names if name and os.environ.get(name))

    def add(self, values):
        with self._lock:
            self._add(values)

    def _add(self, values):
        if self._uncheckable:
            raise ModelSecretError()
        for value in values:
            if not value or value in self.values:
                continue
            self._bytes += len(value.encode())
            if len(self.values) >= MAX_VALUES or self._bytes > MAX_VALUE_BYTES:
                self._uncheckable = True
                raise ModelSecretError()
            self.values.add(value)
            self.__dict__.pop("pattern", None)

    @cached_property
    def pattern(self):
        if self.values:
            return re.compile("|".join(re.escape(value) for value in sorted(self.values, key=len, reverse=True)))
        return None

    def learn(self, data):
        try:
            self.add(_fields(data))
            for value in _strings(data):
                self.add(detected_values(value))
        except Exception:
            with self._lock:
                self._uncheckable = True
            raise ModelSecretError() from None

    def text(self, value, *, source=False):
        if self.pattern is None:
            return value

        def replacement(match):
            raw = match[0]
            marker = REDACTED
            if source:
                marker = "[PEM PRIVATE KEY — REDACTED]" if raw.startswith("-----BEGIN ") else f"**** ({len(raw)} chars)"
            return marker + "\n" * raw.count("\n")

        result = self.pattern.sub(replacement, value)
        if self.pattern.search(result):
            raise ModelSecretError()
        return result

    def clean(self, data):
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, dict):
            if any(self.text(str(key)) != str(key) for key in data):
                raise ModelSecretError()
            return {key: self.clean(item) for key, item in data.items()}
        if isinstance(data, (list, tuple)):
            return [self.clean(item) for item in data]
        return data

    def protect(self, data):
        with self._lock:
            return self._protect(data)

    def _protect(self, data):
        self.learn(data)
        if not self.values:
            return data
        clean = self.clean(data)
        # Keep the trust boundary closed even when escaping/decoding a structured
        # literal made an exact replacement impossible.
        for value in _strings(clean):
            if any(v != REDACTED for v in detected_values(value)):
                raise ModelSecretError()
            if "\\" in value and value.lstrip().startswith(("{", "[")):
                try:
                    document = json.loads(value)
                except ValueError:
                    continue
                if any(self.pattern.search(item) for item in _strings(document)):
                    raise ModelSecretError()
        return clean

    def require_clean(self, data):
        if self.protect(data) != data:
            raise ModelSecretError()

    def check_request(self, system, prompt, schema):
        # Instructions and schemas define the contract. Withhold the call if masking
        # would change them. Preserve prompt subclasses carrying provider cache blocks.
        blocks = getattr(prompt, "blocks", None)
        if blocks is not None and "".join(blocks) != str(prompt):
            raise ModelSecretError()
        self.require_clean([system, schema, str(prompt)])

    def invoke(self, transport, system, prompt, schema, timeout_s, should_stop):
        self.check_request(system, prompt, schema)
        return transport.invoke(system, prompt, schema, timeout_s, should_stop)
