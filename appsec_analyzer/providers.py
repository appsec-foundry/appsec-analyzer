"""Operator-owned provider connections, separate from analysis profiles."""

from __future__ import annotations

import re

from appsec_analyzer import resource_root

PROVIDERS = ("lite", "bedrock")
MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")


def selection(value: str) -> tuple[str, str] | None:
    """Recognize an explicit provider prefix without interpreting arbitrary text."""
    for provider in PROVIDERS:
        if value.startswith(provider + " "):
            alias = value[len(provider) + 1 :]
            if not MODEL_NAME.fullmatch(alias) or ".." in alias:
                from appsec_analyzer.profiles import ProfileError

                raise ProfileError("provider model must be a prefix and one configured model name")
            return provider, alias
    return None


def load(provider, *, home, repositories=()):
    import yaml
    from jsonschema import Draft202012Validator

    from appsec_analyzer.profiles import ProfileError, read_document

    path = home / "providers.yaml"
    document = read_document(path, repositories=repositories, operator_connection=True)
    schema = yaml.safe_load((resource_root() / "schemas/provider-connections.schema.yaml").read_text())
    if next(Draft202012Validator(schema).iter_errors(document), None):
        raise ProfileError("invalid provider connections; check providers.yaml schema and required fields")
    connection = document.get(provider)
    if connection is None:
        raise ProfileError(f"providers.yaml has no {provider} connection")
    return connection, str(path)


def resolve(settings, provider, connection):
    from appsec_analyzer.profiles import ProfileError

    parsed = selection(settings["model"])
    if not parsed or parsed[0] != provider:
        raise ProfileError(f"{provider} model names require the '{provider} ' prefix")
    entry = connection["models"].get(parsed[1])
    if entry is None:
        raise ProfileError("model is not in the selected operator provider connection")
    if ".." in entry["model"]:
        raise ProfileError("provider model identifier is invalid")
    effort = settings.get("reasoning_effort")
    if effort is not None and effort not in entry.get("reasoning_efforts", []):
        raise ProfileError("reasoning effort is unsupported by the configured provider model")
    if "max_output_tokens" in settings and settings["max_output_tokens"] > entry["max_output_tokens"]:
        raise ProfileError("output token limit exceeds the configured provider model capacity")
    endpoint = (
        connection["endpoint"]
        if provider == "lite"
        else f"https://bedrock-runtime.{connection['region']}.amazonaws.com"
    )
    result = {
        **settings,
        "adapter": provider,
        "requested_model": settings["model"],
        "model": entry["model"],
        "model_output_limit": entry["max_output_tokens"],
        "input_usd_per_million": entry["input_usd_per_million"],
        "output_usd_per_million": entry["output_usd_per_million"],
        "price_revision": connection["price_revision"],
        "endpoint": endpoint,
        "gateway_route_revision": connection["route_revision"],
        "deployment_id": entry.get("deployment_id"),
        "pinned_ip": connection.get("pinned_ip"),
        "model_family": entry.get("model_family"),
    }
    from appsec_analyzer.profiles import api_profile

    try:
        api_profile(result)
    except ValueError:
        raise ProfileError("invalid provider endpoint, model, or price configuration") from None
    return result
