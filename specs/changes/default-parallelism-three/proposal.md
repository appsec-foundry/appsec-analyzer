---
reason: Measured runs showed that more parallel jobs shorten verification clearly and the survey hardly, and that the earlier default of two left verification, trust-boundary review and abuse-case checks slower than needed.
affected_ids: [REQ-018]
compatibility: The default of max_parallel is 4 instead of 2, or 3 when the user did not set a value and the run's component count divides by three; 2 for the subscription profiles codex-cli and copilot-cli, whose rate limits are unknown. A profile or --max-parallel value always applies as given. The setting is part of a run's identity, so a run saved with the earlier default cannot resume under the new one and a new run reuses its accepted jobs.
verification: Profile resolution tests for the default, its provenance, the CLI and profile overrides and the subscription adapters; tests of the effective pool size for counts that divide by three and that do not, for the default and for a set value; the controller test that the pool respects the limit; the standalone offline gate.
---

# Default parallelism of four

The acceptance contract names the default of `max_parallel` in REQ-018. It now reads 4, or 2 for `codex-cli` and `copilot-cli` profiles. While the default applies and the run's components divide by three, the run works three jobs at a time. The Claude host's earlier separate default of 3 is gone.
