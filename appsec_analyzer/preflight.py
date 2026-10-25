"""Early, read-only source and provider checks. No assessment or source upload."""

from __future__ import annotations

import json
import math
import os
import sys
import tempfile
import textwrap
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from appsec_analyzer.terminal import field

_LABEL = 12
# Before an assessment: low-cost models that share the account's login, quota and billing.
# Analyzer knows none for LiteLLM, Bedrock and Copilot, which therefore get no model test.
_TEST_MODELS = {"claude-cli": "haiku", "openai": "gpt-luna", "codex-cli": "gpt-luna"}
TEST_LIMIT_USD = 0.05
# Only these failures prove a setup problem; any other outcome leaves the setup unknown.
_SETUP_FAILURES = {"authentication_failed", "billing_error", "quota_exhausted"}
_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ok"],
    "properties": {"ok": {"type": "boolean", "const": True}},
}
_REASONS = {
    "authentication_failed",
    "rate_limit",
    "quota_exhausted",
    "billing_error",
    "budget_exhausted",
    "error_max_budget_usd",
    "timeout",
    "output_token_limit",
    "invalid_response",
    "invalid_response_stream",
    "invalid_response_envelope",
    "invalid_response_payload",
    "unexpected_host_item",
    "incomplete_response",
    "invalid_request",
    "response_too_large",
}


def _say(ns, label, message, *, status="muted", always=False):
    """One ``  ✓ Label       value`` row under a single ``Preflight`` heading.

    Before an assessment, completed checks wait for the console, which shows
    them as a Preflight block under the run summary; a failure still prints here.
    """
    symbol = {"ok": "✓", "warn": "⚠", "critical": "✗", "muted": "·"}[status]
    if getattr(ns, "command", "preflight") != "preflight" and status != "critical" and not always:
        ns.preflight_checks = (*getattr(ns, "preflight_checks", ()), (symbol, label, message))
        return
    if always or not ns.quiet:
        from renderers.term_style import Style

        style = Style.for_stream(sys.stderr)
        if not getattr(ns, "_preflight_heading", False):
            ns._preflight_heading = True
            print(style("Preflight", "bold"), file=sys.stderr, flush=True)
        width = max(60, min(getattr(ns, "width", None) or 100, 160))
        indent = 4 + _LABEL
        body = textwrap.fill(message, width=width - indent, break_on_hyphens=False)
        body = body.replace("\n", "\n" + " " * indent)
        print(
            f"  {style(symbol, status)} {style(f'{label:<{_LABEL}}', 'muted')}{body}",
            file=sys.stderr,
            flush=True,
        )


def run(ns, *, api_profile=None, runtime=None):
    from runtime.multi_repo_scope import _selected_root
    from runtime.remote_repositories import MAX_REPOSITORIES, check_access, parse_remote

    repositories = ns.repo or [str(Path.cwd())]
    if len(repositories) > MAX_REPOSITORIES:
        raise ValueError("Preflight accepts at most 16 repositories")
    selections = [parse_remote(value) for value in repositories]
    try:
        identities = [
            remote.url if remote else str(Path(value).resolve()) for value, remote in zip(repositories, selections)
        ]
    except (OSError, RuntimeError, ValueError):
        raise ValueError("Preflight repository paths could not be resolved") from None
    if len(set(identities)) != len(identities):
        raise ValueError("Preflight requires distinct repositories")
    checks = []
    for index, (value, remote) in enumerate(zip(repositories, selections), 1):
        label = "Repository" if len(repositories) == 1 else f"Repo {index}/{len(repositories)}"
        try:
            if remote:
                check_access(remote)
            else:
                _selected_root(value)
        except (OSError, RuntimeError, ValueError) as exc:
            # RemoteError and ScopeError carry controlled diagnostics; no raw paths/stderr.
            from runtime.multi_repo_scope import ScopeError
            from runtime.remote_repositories import RemoteError

            reason = str(exc) if isinstance(exc, (ScopeError, RemoteError)) else "repository could not be checked"
            _say(ns, label, "access check failed", status="critical")
            raise ValueError(f"Preflight repository {index}: {reason}") from None
        checks.append({"repository": index, "status": "readable"})
        _say(ns, label, "remote read access" if remote else "local Git checkout", status="ok")
    host = ns.run_profile["adapter"]
    result = {
        "interface_version": 1,
        "kind": "preflight",
        "assessment_status": "not_run",
        "repositories": checks,
        "host": host,
        "generation_test": "not_run",
        "limitations": [],
    }
    test_model = getattr(ns, "test_model", False)
    if api_profile is not None:
        from appsec_analyzer.api_hosts import ApiTransportError, preflight
        from appsec_analyzer.profiles import api_profile as role_profile

        profiles = [role_profile(settings) for settings in ns.run_profile["models"].values()]
        # Each role can use a different model. Metadata checks do not generate tokens.
        seen = set()
        for profile in profiles:
            identity = (profile.kind, profile.endpoint, profile.model, profile.key_env, profile.pinned_ip)
            if identity in seen:
                continue
            seen.add(identity)
            destination = urlsplit(profile.endpoint).hostname
            try:
                status = preflight(profile, metadata=not test_model)
            except ApiTransportError as exc:
                _say(ns, "Model", f"{field(profile.model)}: provider check failed", status="critical")
                raise ValueError(
                    f"Preflight model {field(profile.model)}: {exc.reason}; check provider credentials, "
                    "model access and network configuration"
                ) from None
            checked = "model metadata accessible" if status == "model_metadata" else "TLS and credential format checked"
            _say(
                ns,
                "Model",
                f"{field(profile.model)} ({field(profile.kind)}, {field(destination)}) · {checked}",
                status="ok",
            )
        result["provider_check"] = status
        if status == "model_metadata":
            result["limitations"].append(
                "Model metadata access does not prove inference permission or available quota."
            )
        else:
            result["limitations"].append(
                "TLS and credential format checked; server authentication and model access remain unverified."
            )
    else:
        result["provider_check"] = "local_configuration"
        if host == "codex-cli":
            _say(ns, "Codex CLI", f"{field(runtime['version'])} · ChatGPT login configured", status="ok")
            result["limitations"].append(
                "Local CLI login or credential configuration checked; server authentication, model access and quota remain unverified."
            )
        elif host == "copilot-cli":
            _say(ns, "Copilot CLI", f"{field(runtime['version'])} · login/model access not tested", status="ok")
            result["limitations"].append(
                "CLI version checked only; authentication, model access, quota, and live assessment quality remain unverified."
            )
        else:
            _say(ns, "Local CLI", "login or credential configuration checked", status="ok")
            result["limitations"].append(
                "Local CLI login or credential configuration checked; server authentication, model access and quota remain unverified."
            )
    if test_model:
        try:
            _test_model(ns, api_profile=api_profile, runtime=runtime)
        except OSError:
            raise ValueError("Preflight generation test could not prepare its private temporary workspace") from None
        result["generation_test"] = "primary_model_passed"
        result["limitations"] = [
            "Only the survey's model, the primary model, was tested for generation; other roles and live assessment quality remain unverified."
        ]
    elif getattr(ns, "command", "preflight") != "preflight" and host in _TEST_MODELS:
        result["generation_test"] = _test_low_cost_model(ns, api_profile=api_profile, runtime=runtime)
    for limitation in result["limitations"]:
        if result["generation_test"] == "test_model_passed":
            limitation = "only the test model answered; the run's own models answer for the first time in the run"
        elif not test_model:
            if result["provider_check"] == "local_configuration":
                limitation = (
                    "not tested; no model call before the assessment"
                    if getattr(ns, "command", "preflight") == "preflight"
                    else "not tested yet; the first model call in Reconnaissance checks it"
                )
            else:
                limitation += " No model call made."
        # The default check is limited by design; the note informs, it does not warn.
        _say(ns, "Provider", limitation)
    return result


def _test_model(ns, *, api_profile, runtime):
    from runtime.analyst_host import TransportError

    host = ns.run_profile["adapter"]
    settings = ns.run_profile["models"]["stride_analyzer"]
    destination = urlsplit(api_profile.endpoint).hostname if api_profile else host
    selected_model = (ns.stride_model or ns.model or settings["model"]) if host == "claude-cli" else settings["model"]
    _say(
        ns,
        "Model test",
        f"{field(selected_model)} at {field(destination)}: fixed synthetic prompt only; no repository content",
        always=True,
    )
    if host == "codex-cli":
        _say(ns, "", "one exchange consumes ChatGPT plan allowance", always=True)
    elif host == "copilot-cli":
        _say(ns, "", "one CLI session uses a minimum 30-credit soft limit; a response may exceed it", always=True)
    else:
        _say(ns, "", f"separate generation-test budget: USD {ns.hard_budget:g}", always=True)
    try:
        reply = _exchange(ns, settings, selected_model, ns.hard_budget, runtime, api=api_profile is not None)
    except TransportError as exc:
        raise ValueError(
            f"Preflight generation test failed ({_reason(exc)}); check credentials, model access and limits"
        ) from None
    if not _valid(reply):
        raise ValueError("Preflight generation test returned an invalid response")
    _say(ns, "Model test", "primary model generation passed", status="ok")


def _test_low_cost_model(ns, *, api_profile, runtime):
    """Before an assessment: one exchange with a low-cost model, outside the run's limit.

    Only a failure that proves a setup problem stops the run; any other outcome
    warns, and the run's own first model call checks the setup again.
    """
    from runtime.analyst_host import HostCancelled, TransportError

    from appsec_analyzer.profiles import api_profile as role_profile
    from appsec_analyzer.profiles import resolve_model

    host = ns.run_profile["adapter"]
    if host == "claude-cli":
        settings = {"model": _TEST_MODELS[host]}
    else:
        settings = resolve_model({"model": _TEST_MODELS[host], "reasoning_effort": "low"}, host)
    model = settings["model"]
    destination = urlsplit(role_profile(settings).endpoint).hostname if api_profile else host
    cost = (
        "one exchange from ChatGPT plan allowance"
        if host == "codex-cli"
        else f"own limit USD {TEST_LIMIT_USD:.2f} outside the run budget"
    )
    _notice(f"{field(model)} at {field(destination)}: fixed synthetic prompt only, no repository content; {cost}")
    try:
        reply = _exchange(ns, settings, model, TEST_LIMIT_USD, runtime, api=api_profile is not None)
    except TransportError as exc:
        outcome = _reason(exc)
        if outcome in _SETUP_FAILURES:
            _say(ns, "Model test", f"{field(model)}: {outcome}", status="critical")
            raise ValueError(
                f"Preflight model test failed ({outcome}); check the login or API key, billing and quota"
            ) from None
    except (HostCancelled, OSError):
        outcome = "no answer"
    else:
        if _valid(reply):
            from appsec_analyzer.assessment.console import api_billing

            # Like the run's own costs: shown with API billing or --show-costs, never for a subscription.
            shown = getattr(ns, "show_costs", False) or api_billing(host)
            usd = f" · USD {reply.usd:.4f}" if shown and reply.usd is not None else ""
            _say(ns, "Model test", f"{field(model)} answered{usd}", status="ok")
            return "test_model_passed"
        outcome = "invalid_response"
    _say(ns, "Model test", f"{field(model)}: inconclusive ({outcome}); the run continues", status="warn")
    return "test_model_inconclusive"


def _exchange(ns, settings, model, ceiling, runtime, *, api):
    """One synthetic exchange from a private temporary directory outside every source."""
    from runtime.analyst_host import ClaudeCliTransport

    from appsec_analyzer.profiles import reject_source_paths

    host = ns.run_profile["adapter"]
    with tempfile.TemporaryDirectory(prefix="appsec-model-check-") as work:
        reject_source_paths([work], ns.repo or [str(Path.cwd())])
        if api:
            from appsec_analyzer.api_hosts import ResponsesTransport
            from appsec_analyzer.profiles import api_profile as role_profile

            profile = role_profile(settings)
            transport = ResponsesTransport(
                replace(profile, max_output_tokens=min(1024, profile.output_token_bound)), ceiling
            )
        elif host == "codex-cli":
            from appsec_analyzer.codex_cli import CodexCliTransport

            transport = CodexCliTransport(Path(work), settings["model"], settings["reasoning_effort"], runtime)
        elif host == "copilot-cli":
            from appsec_analyzer.copilot_cli import CopilotCliTransport

            transport = CopilotCliTransport(Path(work), settings["model"], settings["reasoning_effort"], runtime)
        else:
            transport = ClaudeCliTransport(
                Path(work) / "work",
                model=model,
                max_budget_usd=math.floor(ceiling) + math.floor((ceiling % 1) * 100) / 100,
                executable=os.environ.get("APPSEC_CLAUDE_EXECUTABLE") or "claude",
                effort=settings.get("reasoning_effort"),
            )
        return transport.invoke(
            "Connectivity test. Return the requested JSON object.",
            'Return {"ok": true}.',
            _SCHEMA,
            30,
            lambda: False,
        )


def _reason(exc):
    # Only host-defined classifications, never provider prose or model output.
    return exc.reason if exc.reason in _REASONS else "host_failure"


def _valid(reply):
    return type(reply.payload) is dict and reply.payload == {"ok": True} and type(reply.payload["ok"]) is bool


def _notice(message):
    """Shown before the call, even with --quiet; the result joins the Preflight block."""
    from renderers.term_style import Style

    print(Style.for_stream(sys.stderr)(f"Model test: {message}", "muted"), file=sys.stderr, flush=True)


def print_result(result, *, as_json=False):
    if as_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"Preflight completed for {len(result['repositories'])} repository/repositories; assessment not run.")
        print(f"Provider check: {result['provider_check']}; generation test: {result['generation_test']}.")
        for limitation in result["limitations"]:
            print(limitation)
