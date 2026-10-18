---
reason: Explain the planned assessment scope and the loaded abuse-case sources at startup without implying complete business-logic, dependency, secret, or runtime coverage.
affected_ids: [REQ-011, REQ-016]
compatibility: Adds four informational rows to full-assessment startup and its structured start event without changing report schemas, model permissions, or source-only commands. Quiet mode still suppresses terminal progress. Invalid explicitly selected case sources now fail before model analysis instead of at later case matching. Carries the resolved active organization profile path into the existing matcher, renderer and deriver configuration so startup and analysis honor the same case settings; affected saved configurations need a fresh run.
verification: Offline scope tests cover defaults, organization settings, enabled case counts, deduplication, explicit IDs, frozen sources, safe filenames, invalid inputs, disabled verification, multiple repositories, console output and structured start events; controller, source resolver and public CLI regressions; Ruff and specification checks against HEAD. No live model calls.
---

# Assessment startup scope

Show Focus, Abuse cases, Coverage and Excludes within the existing startup facts. Reuse the canonical case resolver on the admitted masked snapshot so the displayed source summary follows effective settings and counts definitions only once. Never load prior derived cases into this summary or claim that loaded cases were checked. Keep the actual coverage results and budget-gap messages authoritative for performed work.

List source categories and enabled user-supplied case counts. Include a bounded terminal-safe relative filename when a single explicit file is selected. Do not print case titles or contents in normal startup output. Keep automatic repository-file rejections distinct from active sources and stop safely on invalid explicit sources.

The configuration resolver stores the active organization profile path in nested metadata, while case consumers expect the retained flat field. Populate that field before run-state admission so case matching, derivation, rendering and startup use the same active profile and configuration identity.
