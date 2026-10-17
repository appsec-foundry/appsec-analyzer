---
reason: Use a smaller model for bounded reconnaissance while preserving Sol for security analysis and verification, as requested by the user.
affected_ids: [REQ-016, REQ-018, REQ-020]
compatibility: New runs using the built-in codex and codex-cli model profiles select Luna for reconnaissance at every depth; operator overrides retain precedence and changed profile definitions require a new run under existing resume checks.
verification: Offline profile resolution at every depth, operator default and role overrides, full-controller dispatch and publication through both OpenAI adapters, and specification checks; no live model qualification.
---

# Use Luna for OpenAI reconnaissance

The built-in `codex` and `codex-cli` model profiles select `gpt-luna` with low reasoning effort for `recon_scanner`. Other roles retain `gpt-sol` and their existing depth-dependent reasoning effort. Parallelism, model permissions, validation, and completion gates retain their existing behavior.

Custom profiles inherit the Recon selection unless their own defaults or role settings override it. Existing saved runs whose profile definition differs are rejected by the current resume checks; start a new run with the new defaults. Offline tests establish model selection and report publication, not Luna's assessment quality or provider availability. Both adapters remain unqualified for live assessment quality.
