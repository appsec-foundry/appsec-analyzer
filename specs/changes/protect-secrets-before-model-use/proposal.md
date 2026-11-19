---
reason: A publication check runs too late to prevent a credential in a model request from reaching the provider.
affected_ids: [REQ-051]
compatibility: Existing commands keep their interfaces. Model inputs can contain redaction markers and a request that cannot be checked safely can stop.
verification: Exercise the provider handoff, source copies, follow-ups and correction requests offline with synthetic secrets, then run the standalone gate.
---

# Protect secrets before model use

The user approved the REQ-051 wording and its four acceptance points. The check covers every Analyzer-managed provider, every stage of a dialogue, model-readable files, and refusal before transmission if checking fails. Tests examine the outgoing content.

The user accepted that detection can mask legitimate text or stop a run. Secrets in arbitrary text without a known value or recognizable format cannot be identified reliably. The deterministic commands remain available for work that must have no model contact.
