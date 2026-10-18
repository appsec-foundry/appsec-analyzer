---
reason: Detect inaccessible repositories and unusable provider configuration before cloning or model-backed analysis, and offer an independent check with explicit optional generation authorization.
affected_ids: [REQ-016, REQ-023, REQ-033]
compatibility: Adds preflight and automatic checks to scan and assess without changing saved artifact schemas. Remote repositories need a readable HEAD; OpenAI and LiteLLM startup now requires authenticated model metadata access. CLI login and Bedrock TLS checks retain explicit limits. Standalone generation tests consume a separate explicit budget or one authorized subscription exchange.
verification: Offline preflight, authenticated metadata, prohibited destinations, redirect denial, malformed replies, missing credentials, synthetic generation authorization, Git read-access and process cleanup tests; affected public CLI and provider tests; Ruff and specification checks against b73f05c264db9d6bada31299b8f3f5b02cc763c5. Live paid qualification is not authorized or executed.
---

# Startup preflight

Run repository and provider checks before full-assessment checkout and analysis. Keep the existing source admission and controller checks, since access can change after preflight. The independent command writes no assessment state and downloads no source objects. Its default requests generate no model output.

Use the existing pinned HTTPS transport for OpenAI model retrieval and LiteLLM model listing, preserving endpoint prefixes and private gateway pins. Native Bedrock checks TLS and credential format; CLI adapters retain local login checks. Expose their unverified server authentication, model access and quota explicitly. Metadata access does not establish inference permission or assessment quality.

Offer one optional primary-model generation test through the existing isolated transports. Require a separately explicit monetary budget or subscription call limit. Send only a fixed synthetic prompt, bound the exchange to 30 seconds without retries, and preserve untested-role and live-quality limitations. This test does not authorize another assessment or increase its budget.
