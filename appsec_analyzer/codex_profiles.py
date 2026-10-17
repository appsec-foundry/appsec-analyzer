"""Compatibility view of the built-in OpenAI profile, without extra output caps."""

from appsec_analyzer.profiles import DEPTHS, _builtin, api_profile, resolve_model

_definition = _builtin("codex", "model")
CODEX_PROFILES = {
    depth: api_profile(
        resolve_model(
            {
                **_definition["defaults"],
                **_definition.get("depths", {}).get(depth, {}).get("defaults", {}),
            },
            "openai",
        )
    )
    for depth in DEPTHS
}
