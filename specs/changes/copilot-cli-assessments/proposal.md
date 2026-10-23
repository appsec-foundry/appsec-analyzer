---
reason: Let users run full Analyzer assessments through their existing GitHub Copilot CLI login without separately configured API access.
affected_ids: [REQ-016, REQ-018, REQ-020, REQ-021, REQ-023, REQ-031, REQ-033, REQ-034, REQ-035, REQ-041]
compatibility: The new opt-in copilot-cli profile uses subscription call/time limits, a per-exchange soft AI-credit limit, null monetary accounting, and version 2 subscription states and receipts. Existing provider defaults and monetary artifacts remain unchanged; focused analysis and requirements audits do not gain Copilot support.
verification: Offline adapter tests cover reviewed-version and executable checks, empty tool allow-list, isolated process arguments and environment, bounded/cancellable execution, strict duplicate-free JSON and schema validation, and safe error classification. Profile, CLI, preflight, lifecycle, and controller tests cover opt-in selection, limits, null accounting, compatibility, and validated publication. Run the standalone offline gate. Do not run a live Copilot request or claim live assessment quality without explicit authorization.
---

# GitHub Copilot CLI assessments

The user approved the experimental, tool-less Copilot CLI approach and its documented limitations before implementation. The adapter sends selected source excerpts, analysis context, and intermediate answers to GitHub Copilot through the user's own CLI login. No model call is part of routine preflight or offline verification.

Analyzer keeps source admission, role selection, call/time accounting, required-completion reserves, cancellation, canonical validation, and publication in its existing controller. The CLI runs from a fresh private temporary directory with an empty tool allow-list, no repository instructions, no built-in MCPs, and no remote sharing. Analyzer does not read or copy login credentials; Copilot CLI retains its own authentication and local session behavior.

Each Copilot CLI exchange has a minimum supported 30-credit soft session limit. Because the limit is soft and applies per CLI session, it is not an exact monetary or account-wide cap. Analyzer records monetary cost as null and applies its own call and elapsed-time limits. The profile remains experimental and unqualified for live assessment quality.
