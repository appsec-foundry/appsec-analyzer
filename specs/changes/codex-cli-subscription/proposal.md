---
reason: Let users run Analyzer assessments through their existing Codex CLI ChatGPT login without configuring separately billed API access.
affected_ids: [REQ-016, REQ-018, REQ-019, REQ-020, REQ-023, REQ-031, REQ-032, REQ-033, REQ-034, REQ-035]
compatibility: Existing claude and codex profiles retain USD budgets and version 1 monetary states and receipts. The opt-in codex-cli profile uses version 2 states and receipts with null monetary fields and rejects USD options; no cross-mode reuse or automatic migration is permitted.
verification: Offline adapter tests cover structured replies, rejected tools and malformed JSON, login/version checks, API environment removal, quota failures, timeout/cancellation/output bounds; lifecycle and job tests cover call reserves, null costs and resume; a complete fake-host controller run checks validated publication; an explicit loopback wire test checks actual CLI tools and configuration isolation. Live plan consumption and assessment quality are not qualified.
---

# Codex CLI subscription assessments

The user authorized implementation and user documentation after reviewing the smaller CLI-adapter approach. REQ-023 now distinguishes monetary limits from subscription call/time limits. The other affected requirements retain their existing acceptance rules and receive provider-specific implementation and tests.

The existing controller owns source admission, bounded reads, semantic roles, canonical validation, completion reserves, cancellation, and publication. The new built-in codex-cli adapter reuses those controls and delegates authentication to Codex CLI 0.163.0. It does not implement OAuth or access token copying. CLI versions are deliberately restricted until their isolation settings are reviewed.

Subscription states and accepted-job receipts record monetary cost as null. Version 1 monetary artifacts keep their prior validation. A changed accounting mode cannot reuse an accepted receipt. Optional model work cannot hide a quota or authentication failure; these failures stop the run with accepted progress retained. Local call and time limits do not guarantee a token, credit, or account-wide allowance ceiling.

The adapter is experimental and remains unqualified for live assessment quality. The real-CLI qualification fixture uses only loopback and an artificial credential; no live model call is authorized or performed by this change.
