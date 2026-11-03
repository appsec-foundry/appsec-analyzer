---
reason: Correct Spring endpoint and security-rule interpretation, preserve unresolved authentication, and retain evidenced authentication methods in reports and architecture.
affected_ids: [REQ-003, REQ-004, REQ-005, REQ-006, REQ-008, REQ-013, REQ-019, REQ-040]
compatibility: Existing commands and boolean assessment models remain supported. Analysis version 6 adds null for unresolved route authentication; consumers assuming a boolean must update. No existing assessment is rewritten and no verification aspect is enabled by default.
verification: Run focused Spring mapping, effective-policy, uncertainty, control-source admission, flow, model, report and controller tests; run Ruff and the standalone offline gate. Compare deterministic output with the selected insecure Spring fixture without executing it or making model calls.
---

# Spring security coverage corrections

The existing requirements already promise source-backed controls, architecture and visible uncertainty. The user requested the verified corrections and framework tests on main; no new user outcome or requirement entry is introduced.

Resolve literal MVC and annotated WebFlux handlers, HTTP methods, ordered request rules, explicitly activated method security and the narrow verified-JWS filter pattern. Conditional configuration, unsupported expressions and ambiguous policies remain unresolved. Keep source parsing bounded and passive.

Retain configured credential alternatives when architecture authoring omits them. Give control analysis exact admitted enforcement sources, including shared configuration owned by another selected component, with ownership and evidence validation unchanged. Model input may include these additional masked source excerpts under the existing host and budget controls; this change authorizes no live qualification or additional spending.

Keep unresolved authentication separate throughout the model and its readers. The version-6 representation is deliberately explicit; old boolean results retain their meaning. Registration ratings must not inherit unrelated profile or privileged account-creation findings.

The complete Spring framework is not statically resolved. Functional router DSLs, external configuration and arbitrary user-defined security helpers require source review and cannot be claimed covered by these literal-source checks.
