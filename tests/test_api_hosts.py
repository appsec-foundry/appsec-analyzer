"""Offline contracts for the fixed Responses transport; no model calls."""

from __future__ import annotations

import json

import pytest

from appsec_analyzer import api_hosts
from appsec_analyzer.codex_profiles import CODEX_PROFILES


def _profile(**changes):
    values = dict(
        kind="openai",
        endpoint="https://api.openai.com/v1/responses",
        model="reviewed-model",
        key_env="OPENAI_API_KEY",
        input_usd_per_million=1.0,
        output_usd_per_million=2.0,
        price_revision="2026-10-17",
        max_output_tokens=1024,
    )
    values.update(changes)
    return api_hosts.ApiProfile(**values)


def _response(payload, **changes):
    result = {
        "status": "completed",
        "usage": {"input_tokens": 100, "output_tokens": 20},
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps({"payload_json": json.dumps(payload)})}],
            }
        ],
    }
    result.update(changes)
    return json.dumps(result).encode()


class _Reply:
    def __init__(self, data, status=200):
        self.data, self.status = data, status

    def read(self, limit):
        return self.data[:limit]


class _Connection:
    instances = []

    def __init__(self, host, address, timeout):
        self.host, self.address, self.timeout = host, address, timeout
        self.requests = []
        self.reply = _Reply(_response({"action": "complete", "artifact": None, "reads": []}))
        self.instances.append(self)

    def request(self, method, path, body, headers):
        self.requests.append((method, path, json.loads(body), headers))

    def getresponse(self):
        return self.reply

    def close(self):
        pass


@pytest.fixture
def fake_host(monkeypatch):
    _Connection.instances.clear()
    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", _Connection)
    monkeypatch.setattr(api_hosts, "_public_addresses", lambda host: ("203.0.113.1",))
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-key")
    return _Connection


def test_wire_decoder_preserves_absent_and_null_and_requests_no_tools(fake_host):
    transport = api_hosts.ResponsesTransport(_profile(), 0.1)
    response = transport.invoke("system", "source", {"type": "object"}, 5, lambda: False)
    assert response.payload == {"action": "complete", "artifact": None, "reads": []}
    assert response.usd > 0
    method, path, body, headers = fake_host.instances[0].requests[0]
    assert method == "POST" and path == "/v1/responses"
    assert body["store"] is False and "tools" not in body
    assert body["text"]["format"]["strict"] is True
    assert headers["Authorization"] == "Bearer test-only-key"


def test_missing_credential_or_insufficient_ceiling_sends_no_source(fake_host, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY")
    with pytest.raises(api_hosts.TransportError, match="authentication_failed"):
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "source", {}, 5, lambda: False)
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-key")
    with pytest.raises(api_hosts.TransportError, match="budget_exhausted"):
        api_hosts.ResponsesTransport(_profile(), 0.000001).invoke("s", "source", {}, 5, lambda: False)
    assert not fake_host.instances


def test_gateway_route_and_destination_are_explicit(fake_host):
    with pytest.raises(ValueError, match="route revision"):
        _profile(kind="gateway", endpoint="https://gateway.example/v1/responses", key_env="APPSEC_GATEWAY_API_KEY")
    with pytest.raises(ValueError, match="official Responses"):
        _profile(endpoint="https://metadata.internal/v1/responses")
    with pytest.raises(ValueError, match="unavailable"):
        _profile(pinned_ip="127.0.0.1")


def test_refusal_missing_usage_and_malformed_wire_fail_closed(fake_host, monkeypatch):
    scenarios = [
        _response({}, status="incomplete"),
        _response({}, usage={}),
        _response({}, output=[{"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}]),
        _response({}, output=[{"type": "message", "content": [{"type": "output_text", "text": "{}"}]}]),
    ]
    for payload in scenarios:

        class Bad(_Connection):
            def __init__(self, host, address, timeout):
                super().__init__(host, address, timeout)
                self.reply = _Reply(payload)

        monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Bad)
        with pytest.raises(api_hosts.TransportError, match="invalid_response"):
            api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "p", {}, 5, lambda: False)


def test_cancellation_before_transmission(fake_host):
    with pytest.raises(api_hosts.HostCancelled):
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "p", {}, 5, lambda: True)
    assert not fake_host.instances


@pytest.mark.parametrize(
    "depth, effort, cap",
    [
        ("quick", "low", None),
        ("standard", "medium", None),
        ("thorough", "high", None),
    ],
)
def test_codex_profiles_pin_safe_wire_and_bounded_cost(fake_host, depth, effort, cap):
    profile = CODEX_PROFILES[depth]
    assert profile.model == "gpt-6.1-sol"
    assert profile.max_request_bytes == 240_000
    assert profile.max_output_tokens == cap
    assert profile.input_usd_per_million == 2.5
    assert profile.output_usd_per_million == 10.0
    api_hosts.ResponsesTransport(profile, 2).invoke("system", "source", {}, 5, lambda: False)
    body = fake_host.instances[0].requests[0][2]
    assert body["reasoning"] == {"effort": effort}
    assert "max_output_tokens" not in body
    assert body["store"] is False and "tools" not in body


def test_codex_profile_rejects_oversized_request_before_transmission(fake_host):
    profile = CODEX_PROFILES["standard"]
    with pytest.raises(api_hosts.TransportError, match="request_too_large"):
        api_hosts.ResponsesTransport(profile, 2).invoke("system", "x" * 250_000, {}, 5, lambda: False)
    assert not fake_host.instances


def test_default_output_allowance_is_not_reduced_to_fit_budget(fake_host):
    with pytest.raises(api_hosts.TransportError, match="budget_exhausted"):
        api_hosts.ResponsesTransport(CODEX_PROFILES["standard"], 1).invoke("s", "p", {}, 5, lambda: False)
    assert not fake_host.instances


def test_output_limit_exhaustion_is_explicit_and_never_accepted(fake_host, monkeypatch):
    class Truncated(_Connection):
        def __init__(self, host, address, timeout):
            super().__init__(host, address, timeout)
            self.reply = _Reply(_response({}, status="incomplete", incomplete_details={"reason": "max_output_tokens"}))

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Truncated)
    with pytest.raises(api_hosts.TransportError, match="output_token_limit"):
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "p", {}, 5, lambda: False)
    assert fake_host.instances[0].requests[0][2]["max_output_tokens"] == 1024


def test_default_accepts_output_above_former_caps_but_explicit_limit_is_enforced(fake_host, monkeypatch):
    class Large(_Connection):
        def __init__(self, host, address, timeout):
            super().__init__(host, address, timeout)
            self.reply = _Reply(_response({"accepted": True}, usage={"input_tokens": 100, "output_tokens": 40000}))

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Large)
    response = api_hosts.ResponsesTransport(CODEX_PROFILES["standard"], 2).invoke("s", "p", {}, 5, lambda: False)
    assert response.payload == {"accepted": True}
    with pytest.raises(api_hosts.TransportError, match="invalid_response"):
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "p", {}, 5, lambda: False)
