---
reason: Add user-requested native Bedrock and LiteLLM gateway backends with an explicit lite model prefix.
affected_ids: [REQ-016, REQ-018, REQ-020, REQ-023, REQ-031, REQ-033]
compatibility: Existing providers and profiles retain their behavior; new lite and bedrock profiles require a separate operator-owned connection file and external credentials, and any connection change invalidates resume. Public interfaces remain version 1 with additive profile adapters and a new version-1 connection schema.
verification: Offline profile and CLI selection, strict transport contracts, intended and negative destination and credential cases, gateway deployment and cost checks, Bedrock completion and usage checks, organization restrictions, full controller publication, packaging inventory, documentation commands and specification gates; no live model calls.
---

# Bedrock and LiteLLM backends

The user requested both backends and the `lite claude` spelling. A prefixed CLI model selects the corresponding built-in provider when no other provider was selected; a prefixed profile is a shorthand. Custom role profiles retain one adapter and select prefixed connection aliases. Operator configuration and CLI choices remain outside analyzed source authority.

The existing bounded HTTPS transport supports LiteLLM Responses and native Bedrock Converse with externally supplied bearer credentials. Bedrock API keys avoid adding an SDK dependency; SigV4 and AWS credential-chain authentication are not included. Neither adapter grants model tools. The controller keeps its canonical validation, admission limits, negative cases and completion gates.

`providers.yaml` admits explicit endpoints, model deployments, maximum output and conservative prices through a strict separate schema. Gateway deployment headers must match and gateway cost headers must be present; unknown routing or charges fail closed. Bedrock destinations are derived from a bounded Region, and model IDs are encoded as one path segment. Connection and price revisions participate in the saved profile identity. New provider support does not establish live quality, retention behavior or actual cost accuracy.
