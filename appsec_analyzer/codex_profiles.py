"""Depth configurations of the built-in codex assessment profile.

These are selectable configurations, not a claim of live assessment quality.
The request cap keeps input below the model's long-context price threshold.
"""

from appsec_analyzer.api_hosts import ApiProfile

_ENDPOINT = "https://api.openai.com/v1/responses"
_PRICE_REVISION = "openai-standard-2026-10-17"

CODEX_PROFILES = {
    depth: ApiProfile(
        kind="openai",
        endpoint=_ENDPOINT,
        model=model,
        key_env="OPENAI_API_KEY",
        # Include the possible 1.25x cache-write charge in the ceiling.
        input_usd_per_million=2.5,
        output_usd_per_million=10.0,
        price_revision=_PRICE_REVISION,
        max_output_tokens=output_tokens,
        reasoning_effort=effort,
        max_request_bytes=240_000,
    )
    for depth, model, effort, output_tokens in (
        ("quick", "gpt-6.1-sol", "low", 16_384),
        ("standard", "gpt-6.1-sol", "medium", 24_576),
        ("thorough", "gpt-6.1-sol", "high", 32_768),
    )
}
