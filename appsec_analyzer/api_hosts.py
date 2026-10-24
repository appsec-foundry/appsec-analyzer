"""Bounded, tool-less Responses and Bedrock Converse exchanges.

Connections and model prices come from installed or operator-owned definitions.
Offline protocol coverage never establishes live model quality.
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
from urllib.parse import quote, urlsplit

from appsec_analyzer import resource_root

_scripts = str(resource_root() / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)
from runtime.analyst_host import HostCancelled, HostReply, TransportError

MAX_REPLY_BYTES = 1_048_576
MAX_REQUEST_BYTES = 1_048_576
PREFLIGHT_SECONDS = 10
_WIRE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["payload_json"],
    "properties": {"payload_json": {"type": "string"}},
}


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ambiguous JSON")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("non-finite JSON")

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON")
        return number

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid, parse_float=finite)


class ApiTransportError(TransportError):
    def __init__(self, reason: str, *, retry_after_s: float | None = None, http_status: int | None = None):
        super().__init__(reason, reason=reason, usd=None, retry_after_s=retry_after_s, http_status=http_status)


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
    deployment_id: str | None = None

    def __post_init__(self) -> None:
        url = urlsplit(self.endpoint)
        if self.kind not in ("openai", "gateway", "lite", "bedrock"):
            raise ValueError("unsupported API host kind")
        if (
            url.scheme != "https"
            or not url.hostname
            or url.port not in (None, 443)
            or url.username
            or url.password
            or url.query
            or url.fragment
            or any(ord(char) <= 32 or ord(char) >= 127 for char in self.endpoint)
            or "%" in self.endpoint
            or ".." in url.path
            or "//" in url.path
            or (self.kind != "bedrock" and not url.path.endswith("/v1/responses"))
        ):
            raise ValueError("API endpoint must be a fixed HTTPS Responses URL")
        if self.kind == "openai" and (url.hostname != "api.openai.com" or url.path != "/v1/responses"):
            raise ValueError("direct OpenAI calls use the official Responses endpoint")
        if self.kind == "gateway" and not self.gateway_route_revision:
            raise ValueError("gateway profile requires a fixed route revision")
        if self.kind == "lite" and (not self.gateway_route_revision or not self.deployment_id):
            raise ValueError("LiteLLM requires a route revision and deployment id")
        if self.kind == "bedrock" and (
            not re.fullmatch(
                r"bedrock-runtime\.(?:us|eu|ap|ca|sa|me|af|il|mx)-(?:north|south|east|west|central|northeast|northwest|southeast|southwest)-[1-9]\.amazonaws\.com",
                url.hostname or "",
            )
            or url.path
            or self.pinned_ip
            or self.reasoning_effort is not None
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,127}", self.model)
            or ".." in self.model
        ):
            raise ValueError("Bedrock requires a regional runtime endpoint and a supported model id")
        approved_key = {
            "openai": "OPENAI_API_KEY",
            "gateway": "APPSEC_GATEWAY_API_KEY",
            "lite": "LITELLM_API_KEY",
            "bedrock": "AWS_BEARER_TOKEN_BEDROCK",
        }
        if self.key_env != approved_key[self.kind]:
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
            permitted_private = any(
                address in ipaddress.ip_network(network)
                for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
                if ipaddress.ip_network(network).version == address.version
            )
            if (
                self.kind not in ("gateway", "lite")
                or not (address.is_global or permitted_private)
                or address.is_multicast
                or address.is_loopback
                or address.is_link_local
                or address.is_unspecified
                or address.is_reserved
                or getattr(address, "is_site_local", False)
            ):
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
    if not addresses or any(
        not ipaddress.ip_address(ip).is_global
        or ipaddress.ip_address(ip).is_multicast
        or getattr(ipaddress.ip_address(ip), "is_site_local", False)
        for ip in addresses
    ):
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


def credential(profile: ApiProfile) -> str:
    """Validate external credentials without exposing them in diagnostics."""
    value = os.environ.get(profile.key_env)
    if not value or len(value) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ApiTransportError("authentication_failed")
    return value


def preflight(profile: ApiProfile, *, metadata: bool = True) -> str:
    """No generation: verify TLS and, where supported, authenticated model metadata.

    Bedrock's runtime bearer-key interface has no model metadata operation.
    A TLS-only success must never be described as successful authentication.
    """
    token = credential(profile)
    url = urlsplit(profile.endpoint)
    result = []
    connections = []
    stopped = threading.Event()

    def check():
        connection = None
        try:
            address = profile.pinned_ip or _public_addresses(url.hostname or "")[0]
            if stopped.is_set():
                return
            connection = _PinnedHTTPS(url.hostname or "", address, timeout=5)
            connections.append(connection)
            if stopped.is_set():
                return
            if profile.kind == "bedrock" or not metadata:
                connection.connect()
                result.append("tls_only")
                return
            prefix = url.path.removesuffix("/responses")
            path = prefix + "/models"
            if profile.kind == "openai":
                path += "/" + quote(profile.model, safe="")
            connection.request("GET", path, body=None, headers={"Authorization": "Bearer " + token})
            reply = connection.getresponse()
            # Do not read or retain provider error bodies.
            if reply.status != 200:
                reasons = {
                    401: "authentication_failed",
                    403: "access_denied",
                    404: "model_metadata_unavailable",
                    402: "billing_error",
                    429: "rate_limit",
                }
                raise ApiTransportError(reasons.get(reply.status, "metadata_request_failed"))
            data = reply.read(MAX_REPLY_BYTES + 1)
            if len(data) > MAX_REPLY_BYTES:
                raise ApiTransportError("response_too_large")
            document = _json(data)
            if type(document) is not dict:
                raise ApiTransportError("invalid_metadata")
            if profile.kind == "openai":
                found = document.get("id") == profile.model
            else:
                rows = document.get("data")
                if type(rows) is not list or any(type(row) is not dict for row in rows):
                    raise ApiTransportError("invalid_metadata")
                found = any(row.get("id") == profile.model for row in rows)
            if not found:
                raise ApiTransportError("model_not_available")
            result.append("model_metadata")
        except ApiTransportError as exc:
            result.append(exc)
        except TimeoutError:
            result.append(ApiTransportError("timeout"))
        except ssl.SSLError:
            result.append(ApiTransportError("tls_failed"))
        except (OSError, http.client.HTTPException):
            result.append(ApiTransportError("connection_failed"))
        except (ValueError, RecursionError):
            result.append(ApiTransportError("invalid_metadata"))
        finally:
            if connection is not None:
                connection.close()

    worker = threading.Thread(target=check, daemon=True)
    worker.start()
    try:
        worker.join(timeout=PREFLIGHT_SECONDS)
    finally:
        stopped.set()
        for connection in connections:
            connection.close()
    if worker.is_alive():
        raise ApiTransportError("timeout")
    if not result:
        raise ApiTransportError("connection_failed")
    if isinstance(result[0], ApiTransportError):
        raise result[0]
    return result[0]


def _request_body(profile: ApiProfile, system: str, prompt: str, schema: dict) -> bytes:
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
        "model": profile.model,
        "instructions": instructions,
        "input": prompt,
        "store": False,
        "text": {"format": {"type": "json_schema", "name": "appsec_exchange", "strict": True, "schema": _WIRE_SCHEMA}},
    }
    if profile.max_output_tokens is not None:
        request["max_output_tokens"] = profile.max_output_tokens
    if profile.reasoning_effort:
        request["reasoning"] = {"effort": profile.reasoning_effort}
    if profile.kind == "lite":
        request.update(num_retries=0, disable_fallbacks=True)
    if profile.kind == "bedrock":
        request = {
            "system": [{"text": instructions}],
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": {"maxTokens": profile.output_token_bound},
            "outputConfig": {
                "textFormat": {
                    "type": "json_schema",
                    "structure": {"jsonSchema": {"schema": json.dumps(_WIRE_SCHEMA), "name": "appsec_exchange"}},
                }
            },
        }
    return json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# The body carries the prompt as a JSON string, so each quote and backslash of
# the JSON packet is escaped once more: observed packets grow by up to 12%.
# One sixth of the room stays for that growth; invoke still checks the body.
_ESCAPE_SHARE = 6


def prompt_capacity(profiles):
    """Prompt bytes that keep every role's request body within its size limit."""
    profiles = tuple(profiles)
    if not profiles:
        raise ValueError("API prompt capacity needs at least one profile")

    def capacity(system, schema):
        return min(
            max(0, profile.max_request_bytes - len(_request_body(profile, system, "", schema)))
            * (_ESCAPE_SHARE - 1)
            // _ESCAPE_SHARE
            for profile in profiles
        )

    return capacity


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
        token = credential(self.profile)
        if type(schema) is not dict or type(system) is not str or type(prompt) is not str:
            raise ApiTransportError("invalid_request")
        body = _request_body(self.profile, system, prompt, schema)
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
        path = (
            "/model/" + quote(self.profile.model, safe="") + "/converse" if self.profile.kind == "bedrock" else url.path
        )
        address = self.profile.pinned_ip or _public_addresses(url.hostname or "")[0]
        connection = _PinnedHTTPS(url.hostname or "", address, timeout=min(timeout_s, 10))
        result: list[object] = []

        def send() -> None:
            try:
                headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
                if self.profile.kind == "lite":
                    headers["x-litellm-num-retries"] = "0"
                connection.request(
                    "POST",
                    path,
                    body=body,
                    headers=headers,
                )
                reply = connection.getresponse()
                data = reply.read(MAX_REPLY_BYTES + 1)
                retry_after = _retry_after(reply.getheader("Retry-After")) if reply.status == 429 else None
                metadata = (
                    {
                        "deployment": reply.getheader("x-litellm-model-id"),
                        "cost": reply.getheader("x-litellm-response-cost"),
                    }
                    if self.profile.kind == "lite"
                    else {}
                )
                result.append((reply.status, data, retry_after, metadata))
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
        if not result:
            raise ApiTransportError("transport")
        if isinstance(result[0], ssl.SSLError):
            raise ApiTransportError("tls_failed")
        if isinstance(result[0], Exception):
            # A reset, refused or closed connection; a repeated call may succeed.
            raise ApiTransportError("connection_failed")
        status, data, retry_after, metadata = result[0]
        if len(data) > MAX_REPLY_BYTES:
            raise ApiTransportError("response_too_large")
        if status in (401, 403):
            raise ApiTransportError("authentication_failed", http_status=status)
        if status == 402:
            raise ApiTransportError("billing_error", http_status=status)
        if status == 429:
            raise ApiTransportError("rate_limit", retry_after_s=retry_after, http_status=status)
        if status >= 500:
            raise ApiTransportError("server_error", http_status=status)
        if status != 200:
            raise ApiTransportError("invalid_request", http_status=status)
        # Keep token exhaustion distinct from malformed structured output.
        try:
            truncated = _json(data)
            if (
                isinstance(truncated, dict)
                and truncated.get("status") == "incomplete"
                and isinstance(truncated.get("incomplete_details"), dict)
                and truncated["incomplete_details"].get("reason") == "max_output_tokens"
            ):
                raise ApiTransportError("output_token_limit")
        except (ValueError, UnicodeError, RecursionError):
            pass
        try:
            response = _json(data)
            if type(response) is not dict:
                raise ValueError("response is not an object")
            if self.profile.kind == "bedrock":
                if response.get("stopReason") == "max_tokens":
                    raise ApiTransportError("output_token_limit")
                message = response["output"]["message"]
                if response.get("stopReason") != "end_turn" or message.get("role") != "assistant":
                    raise ValueError("incomplete Bedrock response")
                if any(response["usage"].get(key, 0) for key in ("cacheReadInputTokens", "cacheWriteInputTokens")):
                    raise ValueError("unexpected Bedrock cache accounting")
                response = {
                    "status": "completed",
                    "usage": {
                        "input_tokens": response["usage"]["inputTokens"],
                        "output_tokens": response["usage"]["outputTokens"],
                    },
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {"type": "output_text", "text": item["text"]} if set(item) == {"text"} else {}
                                for item in message["content"]
                            ],
                        }
                    ],
                }
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
            wire = _json(content[0]["text"])
            if type(wire) is not dict or set(wire) != {"payload_json"} or type(wire["payload_json"]) is not str:
                raise ValueError("wire schema mismatch")
            payload = _json(wire["payload_json"])
            measured = (
                input_tokens * self.profile.input_usd_per_million + output_tokens * self.profile.output_usd_per_million
            ) / 1_000_000
            if self.profile.kind == "lite":
                if metadata.get("deployment") != self.profile.deployment_id:
                    raise ValueError("gateway deployment changed")
                cost = metadata.get("cost")
                if (
                    type(cost) is not str
                    or len(cost) > 64
                    or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", cost)
                ):
                    raise ValueError("gateway cost unavailable")
                charged = float(cost)
                if not math.isfinite(charged) or charged < 0:
                    raise ValueError("gateway cost invalid")
                # A gateway without prices may report zero; configured rates remain the floor.
                measured = max(measured, charged)
            if measured > self.ceiling:
                raise ValueError("cost ceiling exceeded")
        except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
            raise ApiTransportError("invalid_response") from None
        # This host reports no cache split, so only the counters it measured are named.
        return HostReply(
            payload=payload,
            usd=measured,
            usage={self.profile.model: {"input": input_tokens, "output": output_tokens, "usd": measured}},
        )
