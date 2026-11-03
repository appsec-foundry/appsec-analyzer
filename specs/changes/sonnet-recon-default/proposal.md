---
reason: Reconnaissance discovers runtime components and interfaces; use Sonnet by default as requested instead of treating this work as mechanical extraction on Haiku.
affected_ids: [REQ-018]
compatibility: The Claude Recon default changes at every depth. Explicit operator model selections remain authoritative, other provider profiles retain their routing, and saved report formats stay compatible. Runtime and profile identity changes can prevent resuming an older run.
verification: Offline profile inspection, runtime resolution and snapshot tests cover every depth, explicit profile and environment overrides, and unchanged non-Claude routing. Run requirement checks, Ruff and the standalone offline gate; make no live model calls.
---

# Sonnet as the Claude reconnaissance default

The user approved the REQ-018 acceptance rule in the conversation on 2026-11-03 and requested implementation on `main`. This refines the existing requirement without adding a requirement ID or changing the outcome text in `requirements.md`.

Approved wording: "In the Claude profile, reconnaissance uses Sonnet by default at every assessment depth unless the user selects another model."

The shipped Claude model profile and the retained runtime resolver use the installed Sonnet model for `recon_scanner` at quick, standard and thorough depth. Profile inspection and the run snapshot must name the model actually selected. Explicit user model files, environment overrides and global CLI model selection keep their existing precedence.

Reconnaissance may cost more and take longer than with Haiku. These effects and any quality improvement have not been measured. The user chose the default change after the lower-cost alternative of retaining Haiku and selecting Sonnet per run was presented. Existing spending, call and time limits remain authoritative. This change selects no new host, supplies no credential and changes no source-admission or model-tool permissions. No live comparison was authorized.
