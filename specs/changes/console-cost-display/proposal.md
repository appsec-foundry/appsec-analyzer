---
reason: Hide monetary console costs for subscription users by default and let operators explicitly enable them.
affected_ids: [REQ-023]
compatibility: API console costs remain visible by default. Subscription console costs are hidden unless --show-costs is supplied. Accounting, saved result amounts, spending limits and authorization remain unchanged.
verification: Offline billing-mode, flag forwarding, progress, completion, unavailable-cost and accounting-preservation tests, Ruff checks, and the standalone Analyzer gate.
---

# Console cost display

The operator approved the REQ-023 wording and its three acceptance points in the conversation: default costs only for API billing, an explicit override for every mode, and unknown amounts rather than invented costs. The operator selected implementation directly on main and inclusion of all subscription providers, including Claude CLI.

This display option makes no extra model calls, sends no additional source data, and grants no spending authority. Required limit disclosures and budget-increase authorization remain visible. Claude CLI keeps its existing monetary accounting; the display follows its existing API-versus-subscription selection. Codex CLI and Copilot CLI retain unavailable monetary amounts.
