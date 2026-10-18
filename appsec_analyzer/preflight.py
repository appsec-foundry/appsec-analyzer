"""Early, read-only source and provider checks. No assessment or source upload."""

from __future__ import annotations

import json
import math
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from appsec_analyzer.terminal import field


def _say(ns, message, *, always=False):
    if always or not ns.quiet:
        print("Preflight: " + message, file=sys.stderr, flush=True)


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
        _say(
            ns,
            f"checking repository {index}/{len(repositories)} ({'remote read access' if remote else 'local Git checkout'})",
        )
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
            raise ValueError(f"Preflight repository {index}: {reason}") from None
        checks.append({"repository": index, "status": "readable"})
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
            _say(
                ns,
                f"checking {field(profile.kind)} model {field(profile.model)} at {field(destination)} (no generation)",
            )
            try:
                status = preflight(profile, metadata=not test_model)
            except ApiTransportError as exc:
                raise ValueError(
                    f"Preflight model {field(profile.model)}: {exc.reason}; check provider credentials, "
                    "model access and network configuration"
                ) from None
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
            "Only the primary STRIDE model was tested for generation; other roles and live assessment quality remain unverified."
        ]
    for limitation in result["limitations"]:
        _say(ns, limitation)
    _say(ns, "checks completed; assessment has not started")
    return result


def _test_model(ns, *, api_profile, runtime):
    from runtime.analyst_host import ClaudeCliTransport, TransportError

    from appsec_analyzer.profiles import reject_source_paths

    host = ns.run_profile["adapter"]
    settings = ns.run_profile["models"]["stride_analyzer"]
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["ok"],
        "properties": {"ok": {"type": "boolean", "const": True}},
    }
    destination = urlsplit(api_profile.endpoint).hostname if api_profile else host
    selected_model = (ns.stride_model or ns.model or settings["model"]) if host == "claude-cli" else settings["model"]
    _say(
        ns,
        f"generation test for {field(selected_model)} at {field(destination)}: fixed synthetic prompt only; no repository content",
        always=True,
    )
    if host == "codex-cli":
        _say(ns, "one exchange consumes ChatGPT plan allowance", always=True)
    else:
        _say(ns, f"separate generation-test budget: USD {ns.hard_budget:g}", always=True)
    with tempfile.TemporaryDirectory(prefix="appsec-model-check-") as work:
        reject_source_paths([work], ns.repo or [str(Path.cwd())])
        if api_profile is not None:
            from appsec_analyzer.api_hosts import ResponsesTransport
            from appsec_analyzer.profiles import api_profile as role_profile

            api_profile = role_profile(settings)
            transport = ResponsesTransport(
                replace(api_profile, max_output_tokens=min(1024, api_profile.output_token_bound)), ns.hard_budget
            )
        elif host == "codex-cli":
            from appsec_analyzer.codex_cli import CodexCliTransport

            transport = CodexCliTransport(Path(work), settings["model"], settings["reasoning_effort"], runtime)
        else:
            transport = ClaudeCliTransport(
                Path(work) / "work",
                model=selected_model,
                max_budget_usd=math.floor(ns.hard_budget) + math.floor((ns.hard_budget % 1) * 100) / 100,
                executable=os.environ.get("APPSEC_CLAUDE_EXECUTABLE") or "claude",
                effort=settings.get("reasoning_effort"),
            )
        try:
            reply = transport.invoke(
                "Connectivity test. Return the requested JSON object.",
                'Return {"ok": true}.',
                schema,
                30,
                lambda: False,
            )
        except TransportError as exc:
            # Only host-defined classifications, never provider prose or model output.
            allowed = {
                "authentication_failed",
                "rate_limit",
                "quota_exhausted",
                "billing_error",
                "budget_exhausted",
                "timeout",
                "output_token_limit",
                "invalid_response",
                "invalid_request",
            }
            reason = exc.reason if exc.reason in allowed else "host_failure"
            raise ValueError(
                f"Preflight generation test failed ({reason}); check credentials, model access and limits"
            ) from None
        if type(reply.payload) is not dict or reply.payload != {"ok": True} or type(reply.payload["ok"]) is not bool:
            raise ValueError("Preflight generation test returned an invalid response")
        _say(ns, "primary model generation test passed")


def print_result(result, *, as_json=False):
    if as_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"Preflight completed for {len(result['repositories'])} repository/repositories; assessment not run.")
        print(f"Provider check: {result['provider_check']}; generation test: {result['generation_test']}.")
        for limitation in result["limitations"]:
            print(limitation)
