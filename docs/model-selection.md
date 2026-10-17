# Hosts, models, and cost

`scan` makes no model calls and needs no model or price catalog. `assess`
requires an explicit `--host`. The `claude-cli` compatibility host retains
the extracted role defaults for `quick`, `standard`, and `thorough` and accepts
`--model` and selected per-role overrides. They remain subject to the
controller's validation and USD budget.

The code includes tool-less OpenAI Responses and fixed gateway protocol
adapters. They have no publicly qualified model, depth, gateway revision, or
retention profile in this offline build, so `assess --host openai` and
`assess --host gateway` refuse before source transmission. An OpenAI-compatible
gateway label alone does not prove route stability, cost, structured output,
or equivalent assessment quality.

The API adapter requires a dated price profile with conservative per-million
input and output token rates, a maximum output token count, and a per-call USD
ceiling. A gateway also requires a fixed route revision and an approved
destination. `models.dev/api.json` can inform a reviewed snapshot of direct
provider prices; `openrouter.ai/api/v1/models` describes OpenRouter routes.
Neither is an automatic authority for another gateway's markup or routing.
This build does not make live catalog requests or silently update prices.

The [historical model guide](history/advisor/model-selection.md) records the
Advisor defaults and observed trade-offs at import time. Its particular model
prices and recommendations are not a current qualification claim.
