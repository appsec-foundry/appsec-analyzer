"""Offline-testable, tool-less Responses API transport for fixed host profiles.

This adapter does not qualify any model or gateway route. A caller must supply
an independently reviewed profile and keep the public assessment gate closed
until complete live qualification has been recorded.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Callable
from urllib.parse import urlsplit

from appsec_analyzer import resource_root

_scripts = str(resource_root() / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)
from runtime.analyst_host import HostCancelled, HostReply, TransportError

MAX_REPLY_BYTES = 1_048_576
MAX_REQUEST_BYTES = 1_048_576
_WIRE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["payload_json"],
    "properties": {"payload_json": {"type": "string"}},
}


class ApiTransportError(TransportError):
    def __init__(self, reason: str, *, retry_after_s: float | None = None):
        super().__init__(reason, reason=reason, usd=None, retry_after_s=retry_after_s)


def _retry_after(value: object) -> float | None:
    """Accept bounded HTTP Retry-After values, never provider error prose."""
    if type(value) is not str or len(value) > 128 or not value.isascii() or any(ord(c) < 32 for c in value):
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        reset = parsedate_to_datetime(value)
        if reset.tzinfo is None:
            return None
        return max(0.0, reset.timestamp() - time.time())
    except (ValueError, TypeError, OverflowError):
        return None


@dataclass(frozen=True)
class ApiProfile:
    kind: str
    endpoint: str
    model: str
    key_env: str
    input_usd_per_million: float
    output_usd_per_million: float
    price_revision: str
    max_output_tokens: int | None = None
    reasoning_effort: str | None = None
    model_output_limit: int = 128_000
    max_request_bytes: int = MAX_REQUEST_BYTES
    gateway_route_revision: str | None = None
    pinned_ip: str | None = None

    def __post_init__(self) -> None:
        url = urlsplit(self.endpoint)
        if self.kind not in ("openai", "gateway"):
            raise ValueError("unsupported API host kind")
        if (
            url.scheme != "https"
            or not url.hostname
            or url.port not in (None, 443)
            or url.username
            or url.password
            or url.query
            or url.fragment
            or not url.path.endswith("/v1/responses")
        ):
            raise ValueError("API endpoint must be a fixed HTTPS Responses URL")
        if self.kind == "openai" and (url.hostname != "api.openai.com" or url.path != "/v1/responses"):
            raise ValueError("direct OpenAI calls use the official Responses endpoint")
        if self.kind == "gateway" and not self.gateway_route_revision:
            raise ValueError("gateway profile requires a fixed route revision")
        if self.key_env not in ("OPENAI_API_KEY", "APPSEC_GATEWAY_API_KEY"):
            raise ValueError("API credentials must use an approved environment variable")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", self.model):
            raise ValueError("model identifier is invalid")
        if not self.price_revision or len(self.price_revision) > 128:
            raise ValueError("price profile needs a dated revision")
        if (
            any(
                type(x) not in (int, float) or not math.isfinite(x) or x <= 0
                for x in (self.input_usd_per_million, self.output_usd_per_million)
            )
            or type(self.model_output_limit) is not int
            or not 1 <= self.model_output_limit <= 128000
            or (
                self.max_output_tokens is not None
                and (
                    type(self.max_output_tokens) is not int
                    or not 1 <= self.max_output_tokens <= self.model_output_limit
                )
            )
        ):
            raise ValueError("price rates and output cap must be positive and bounded")
        if self.reasoning_effort not in (None, "none", "low", "medium", "high", "xhigh", "max"):
            raise ValueError("unsupported reasoning effort")
        if type(self.max_request_bytes) is not int or not 1 <= self.max_request_bytes <= MAX_REQUEST_BYTES:
            raise ValueError("request byte cap must be positive and bounded")
        if self.pinned_ip:
            address = ipaddress.ip_address(self.pinned_ip)
            if self.kind == "openai" or address.is_loopback or address.is_link_local or address.is_multicast:
                raise ValueError("private pin is unavailable for this destination")

    @property
    def output_token_bound(self) -> int:
        return self.max_output_tokens if self.max_output_tokens is not None else self.model_output_limit


def _public_addresses(host: str) -> tuple[str, ...]:
    try:
        rows = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise ApiTransportError("dns_unavailable") from None
    addresses = tuple(sorted({row[4][0] for row in rows}))
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ApiTransportError("destination_denied")
    return addresses


class _PinnedHTTPS(http.client.HTTPSConnection):
    """Connect to the inspected address while verifying TLS for the DNS name."""

    def __init__(self, host: str, address: str, timeout: float):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, 443), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class ResponsesTransport:
    def __init__(self, profile: ApiProfile, ceiling: float):
        if type(ceiling) not in (int, float) or not math.isfinite(ceiling) or ceiling <= 0:
            raise ValueError("API call needs a positive finite USD ceiling")
        self.profile, self.ceiling = profile, float(ceiling)

    def invoke(self, system: str, prompt: str, schema: dict, timeout_s: int, should_stop: Callable[[], bool]):
        # Import at invocation to keep deterministic scanning independent of hosts.
        if should_stop():
            raise HostCancelled("API call cancelled before transmission")
        if type(timeout_s) is not int or not 1 <= timeout_s <= 3600:
            raise ApiTransportError("invalid_timeout")
        credential = os.environ.get(self.profile.key_env)
        if not credential or len(credential) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in credential):
            raise ApiTransportError("authentication_failed")
        if type(schema) is not dict or type(system) is not str or type(prompt) is not str:
            raise ApiTransportError("invalid_request")
        # The wire schema is deliberately separate from the canonical contract.
        # JSON inside the one required string is decoded exactly; the controller
        # then validates the complete canonical artifact and correction rules.
        contract = json.dumps(schema, separators=(",", ":"), ensure_ascii=False)
        instructions = (
            system + "\nReturn exactly one JSON object with payload_json: a JSON string "
            "containing your response to this canonical contract. Preserve null and "
            "absent fields exactly. Contract:\n" + contract
        )
        request = {
            "model": self.profile.model,
            "instructions": instructions,
            "input": prompt,
            "store": False,
            "text": {
                "format": {"type": "json_schema", "name": "appsec_exchange", "strict": True, "schema": _WIRE_SCHEMA}
            },
        }
        if self.profile.max_output_tokens is not None:
            request["max_output_tokens"] = self.profile.max_output_tokens
        if self.profile.reasoning_effort:
            request["reasoning"] = {"effort": self.profile.reasoning_effort}
        body = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > self.profile.max_request_bytes:
            raise ApiTransportError("request_too_large")
        # UTF-8 byte length bounds text token count, with room for API framing.
        # Output is bounded by an explicit request limit or the catalog model maximum.
        input_bound = len(body) + 4096
        bound = (
            input_bound * self.profile.input_usd_per_million
            + self.profile.output_token_bound * self.profile.output_usd_per_million
        ) / 1_000_000
        if bound > self.ceiling:
            raise ApiTransportError("budget_exhausted")
        url = urlsplit(self.profile.endpoint)
        address = self.profile.pinned_ip or _public_addresses(url.hostname or "")[0]
        connection = _PinnedHTTPS(url.hostname or "", address, timeout=min(timeout_s, 10))
        result: list[object] = []

        def send() -> None:
            try:
                connection.request(
                    "POST",
                    url.path,
                    body=body,
                    headers={"Authorization": "Bearer " + credential, "Content-Type": "application/json"},
                )
                reply = connection.getresponse()
                data = reply.read(MAX_REPLY_BYTES + 1)
                retry_after = _retry_after(reply.getheader("Retry-After")) if reply.status == 429 else None
                result.append((reply.status, data, retry_after))
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                result.append(exc)
            finally:
                connection.close()

        worker = threading.Thread(target=send, daemon=True)
        worker.start()
        deadline = time.monotonic() + timeout_s
        while worker.is_alive():
            if should_stop():
                connection.close()
                raise HostCancelled("API call cancelled; reserved cost is unsettled")
            if time.monotonic() >= deadline:
                connection.close()
                raise ApiTransportError("timeout")
            worker.join(timeout=min(0.1, max(0.01, deadline - time.monotonic())))
        if not result or isinstance(result[0], Exception):
            raise ApiTransportError("transport")
        status, data, retry_after = result[0]
        if len(data) > MAX_REPLY_BYTES:
            raise ApiTransportError("response_too_large")
        if status in (401, 403):
            raise ApiTransportError("authentication_failed")
        if status == 402:
            raise ApiTransportError("billing_error")
        if status == 429:
            raise ApiTransportError("rate_limit", retry_after_s=retry_after)
        if status >= 500:
            raise ApiTransportError("server_error")
        if status != 200:
            raise ApiTransportError("invalid_request")
        # Keep token exhaustion distinct from malformed structured output.
        try:
            truncated = json.loads(data)
            if (
                isinstance(truncated, dict)
                and truncated.get("status") == "incomplete"
                and isinstance(truncated.get("incomplete_details"), dict)
                and truncated["incomplete_details"].get("reason") == "max_output_tokens"
            ):
                raise ApiTransportError("output_token_limit")
        except (json.JSONDecodeError, UnicodeError):
            pass
        try:
            response = json.loads(data)
            if type(response) is not dict:
                raise ValueError("response is not an object")
            if response.get("status") != "completed":
                raise ValueError("incomplete response")
            usage = response["usage"]
            input_tokens, output_tokens = usage["input_tokens"], usage["output_tokens"]
            if (
                type(input_tokens) is not int
                or type(output_tokens) is not int
                or input_tokens < 0
                or output_tokens < 0
                or input_tokens > input_bound
                or output_tokens > self.profile.output_token_bound
            ):
                raise ValueError("invalid token usage")
            if type(response["output"]) is not list:
                raise ValueError("output is not a list")
            content = [
                part
                for item in response["output"]
                if type(item) is dict and item.get("type") == "message"
                for part in item.get("content", [])
                if type(part) is dict
            ]
            if len(content) != 1 or content[0].get("type") != "output_text":
                raise ValueError("refusal or ambiguous output")
            wire = json.loads(content[0]["text"])
            if type(wire) is not dict or set(wire) != {"payload_json"} or type(wire["payload_json"]) is not str:
                raise ValueError("wire schema mismatch")
            payload = json.loads(wire["payload_json"])
            measured = (
                input_tokens * self.profile.input_usd_per_million + output_tokens * self.profile.output_usd_per_million
            ) / 1_000_000
            if measured > self.ceiling:
                raise ValueError("cost ceiling exceeded")
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ApiTransportError("invalid_response") from None
        return HostReply(payload=payload, usd=measured)
