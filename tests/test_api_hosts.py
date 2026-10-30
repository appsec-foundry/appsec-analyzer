"""Offline contracts for the fixed Responses transport; no model calls."""

from __future__ import annotations

import http.client
import json
import ssl

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

    def getheader(self, name):
        return None


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
    # The reply names the profile's model and the counters it measured; this host reports no cache split.
    assert list(response.usage) == [_profile().model]
    row = response.usage[_profile().model]
    assert set(row) == {"input", "output", "usd"} and row["usd"] == response.usd
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
    "value,expected",
    [("90", 90), ("0", 0), ("-5", None), ("NaN", None), ("1e300", None), ("12\nsecret", None), ("9" * 129, None)],
)
def test_retry_after_validates_untrusted_header(value, expected):
    assert api_hosts._retry_after(value) == expected


def test_retry_after_http_date(monkeypatch):
    monkeypatch.setattr(api_hosts.time, "time", lambda: 0)
    assert api_hosts._retry_after("Thu, 01 Jan 1970 00:01:00 GMT") == 60
    assert api_hosts._retry_after("Thu, 01 Jan 1970 00:01:00") is None


def test_rate_limit_transports_only_validated_reset_not_body(fake_host, monkeypatch):
    class Limited(_Connection):
        def getresponse(self):
            reply = _Reply(b"private-provider-diagnostic", 429)
            reply.getheader = lambda name: "120"
            return reply

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Limited)
    with pytest.raises(api_hosts.TransportError) as caught:
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "source", {}, 5, lambda: False)
    assert caught.value.reason == "rate_limit" and caught.value.retry_after_s == 120
    assert caught.value.http_status == 429
    assert caught.value.usd == 0.0
    assert "private-provider-diagnostic" not in str(caught.value)


def _bound(profile, prompt="source"):
    body = api_hosts._request_body(profile, "s", prompt, {})
    return (
        (len(body) + 4096) * profile.input_usd_per_million + profile.output_token_bound * profile.output_usd_per_million
    ) / 1_000_000


def test_a_call_refused_before_sending_costs_nothing(fake_host, monkeypatch):
    with pytest.raises(api_hosts.TransportError) as caught:
        api_hosts.ResponsesTransport(_profile(), 0.000001).invoke("s", "source", {}, 5, lambda: False)
    assert (caught.value.reason, caught.value.usd) == ("budget_exhausted", 0.0)
    monkeypatch.delenv("OPENAI_API_KEY")
    with pytest.raises(api_hosts.TransportError) as caught:
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "source", {}, 5, lambda: False)
    assert (caught.value.reason, caught.value.usd) == ("authentication_failed", 0.0)
    assert not fake_host.instances


@pytest.mark.parametrize(
    "status, refused", [(401, True), (402, True), (403, True), (429, True), (400, False), (500, False)]
)
def test_a_refused_request_costs_nothing_and_another_failure_at_most_its_bound(fake_host, monkeypatch, status, refused):
    class Failed(_Connection):
        def getresponse(self):
            return _Reply(b"{}", status)

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Failed)
    with pytest.raises(api_hosts.TransportError) as caught:
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "source", {}, 5, lambda: False)
    assert caught.value.usd == (0.0 if refused else pytest.approx(_bound(_profile())))


@pytest.mark.parametrize(
    "data, reason, usd",
    [
        # A reply with usage is charged what it used, not its reservation.
        (_response({}, output=[]), "invalid_response", (100 * 1.0 + 20 * 2.0) / 1_000_000),
        (
            json.dumps(
                {
                    "status": "incomplete",
                    "incomplete_details": {"reason": "max_output_tokens"},
                    "usage": {"input_tokens": 100, "output_tokens": 1024},
                }
            ).encode(),
            "output_token_limit",
            (100 * 1.0 + 1024 * 2.0) / 1_000_000,
        ),
        # Without usage it cost at most its bound; usage beyond the bounds leaves the reservation.
        (json.dumps({"status": "failed"}).encode(), "invalid_response", "bound"),
        (_response({}, usage={"input_tokens": 10**9, "output_tokens": 20}), "invalid_response", None),
    ],
)
def test_a_rejected_reply_is_charged_by_its_own_usage(fake_host, monkeypatch, data, reason, usd):
    class Rejected(_Connection):
        def getresponse(self):
            return _Reply(data)

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Rejected)
    with pytest.raises(api_hosts.TransportError) as caught:
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "source", {}, 5, lambda: False)
    assert caught.value.reason == reason
    expected = _bound(_profile()) if usd == "bound" else usd
    assert caught.value.usd == (None if expected is None else pytest.approx(expected))


@pytest.mark.parametrize(
    "error, reason",
    [
        (ConnectionResetError("private-peer-detail"), "connection_failed"),
        (http.client.RemoteDisconnected("private-peer-detail"), "connection_failed"),
        (ssl.SSLCertVerificationError("private-peer-detail"), "tls_failed"),
    ],
)
def test_a_failed_send_names_a_dropped_connection_apart_from_a_certificate_error(fake_host, monkeypatch, error, reason):
    class Dropped(_Connection):
        def getresponse(self):
            raise error

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Dropped)
    with pytest.raises(api_hosts.TransportError) as caught:
        api_hosts.ResponsesTransport(_profile(), 0.1).invoke("s", "source", {}, 5, lambda: False)
    assert caught.value.reason == reason and "private-peer-detail" not in str(caught.value)


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


_BEDROCK = dict(
    kind="bedrock",
    endpoint="https://bedrock-runtime.eu-central-1.amazonaws.com",
    key_env="AWS_BEARER_TOKEN_BEDROCK",
    model="reviewed.model-v1:0",
)


@pytest.mark.parametrize("changes", [{}, _BEDROCK])
def test_prompt_capacity_admits_an_escaped_packet_within_the_body_limit(fake_host, monkeypatch, changes):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "test-only-key")
    profile = _profile(**changes)
    system, schema = 'trusted € "quoted"', {"type": "object", "description": "€"}
    capacity = api_hosts.prompt_capacity([profile])(system, schema)
    # Fixed framing is measured, not estimated: the room is below the limit.
    assert 0 < capacity < profile.max_request_bytes - len(system)
    # A JSON packet whose escapes grow it by 15%, more than dense context does, fits.
    packet = json.dumps({"rows": ['a"b\\' + "x" * 29] * (capacity // 46)})
    assert len(packet.encode()) <= capacity
    try:
        api_hosts.ResponsesTransport(profile, 10).invoke(system, packet, schema, 5, lambda: False)
    except api_hosts.TransportError as exc:
        # The fake replies in Responses format; this test needs the transmission.
        assert changes and exc.reason == "invalid_response"
    assert len(fake_host.instances[0].requests) == 1


def test_prompt_capacity_is_the_smallest_role_bound_and_the_host_still_rejects_overflow(fake_host):
    small, large = _profile(max_request_bytes=100_000), _profile()
    capacity = api_hosts.prompt_capacity([large, small])("system", {})
    assert capacity == api_hosts.prompt_capacity([small])("system", {}) < 100_000
    # The capacity plans packets; the transport check remains authoritative.
    with pytest.raises(api_hosts.TransportError, match="request_too_large"):
        api_hosts.ResponsesTransport(small, 10).invoke("system", '"' * capacity, {}, 5, lambda: False)
    assert not fake_host.instances
    with pytest.raises(ValueError):
        api_hosts.prompt_capacity([])


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


def test_a_controller_prompt_is_sent_like_any_other_text(fake_host):
    """The exchange layer sends a str subclass; refusing it stopped every API assessment."""
    from runtime.assessment_host import _prompt

    prompt = _prompt({"context": {"name": "artificial"}, "source_slices": []})
    assert type(prompt) is not str
    transport = api_hosts.ResponsesTransport(_profile(), 0.1)
    transport.invoke("system", prompt, {"type": "object"}, 5, lambda: False)
    assert fake_host.instances[0].requests, "the request was refused before transmission"


def test_the_reply_may_take_as_long_as_the_call_may(fake_host):
    """Only connecting has a short limit; a reply over ten seconds is not a failure."""
    transport = api_hosts.ResponsesTransport(_profile(), 0.1)
    transport.invoke("system", "source", {"type": "object"}, 90, lambda: False)
    assert fake_host.instances[0].timeout == 90


def test_connect_limit_is_short_and_the_established_socket_gets_the_call_limit(monkeypatch):
    seen = {}

    class Socket:
        def settimeout(self, value):
            seen["read"] = value

    class Context:
        def wrap_socket(self, raw, server_hostname):
            return Socket()

    monkeypatch.setattr(
        api_hosts.socket, "create_connection", lambda address, timeout: seen.update(connect=timeout) or object()
    )
    connection = api_hosts._PinnedHTTPS("api.example.test", "203.0.113.1", timeout=90)
    connection._context = Context()
    connection.connect()
    assert seen == {"connect": api_hosts.CONNECT_SECONDS, "read": 90}
