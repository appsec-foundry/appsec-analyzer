# E2E fixture suite

A frozen Advisor-era run directory exercises historical renderer and validator
replays without invoking a model. It is not a current Analyzer result bundle.

`frozen-run/` is the canonical output of a (synthetic) Juice-Shop-style scan:

```
frozen-run/
├── threat-model.yaml          # structured output (4 threats, 3 mitigations)
├── .threats-merged.json       # canonical threat register consumed downstream
├── .stride-C-01.json          # per-component STRIDE analyzer output
├── .stride-C-02.json
├── .triage-flags.json         # Phase 10b flags
├── .recon-summary.md          # Phase 2 recon summary
├── .appsec-cache/baseline.json  # baseline state (for incremental tests)
└── .fragments/                  # Jinja2 fragments for renderers/compose_threat_model.py
```

Note: `.dep-scan.json` was removed in 2026-05 along with the in-tree SCA
producer. Supply-chain posture now flows through `.sca-practice-findings.json`
and `.known-bad-libs-findings.json` (Phase 10 emitters) — those sidecars
are not part of this frozen fixture; tests for them live in
`test_emit_sca_practice.py` and the live emitters self-detect repo state.

`synthetic-repo/` is the code-bearing live assessment fixture. It contains deliberately
planted SQL/command injection, SSRF, missing object authorization, hardcoded
secrets, an LLM prompt boundary, multi-tenancy/B2B actor signals, and weak CI
configuration. `run-full.sh` assesses a fresh standalone Git copy through
`appsec-analyzer scan`, with an explicit budget and output under `/tmp`.

`oracle/expected-signals.json` lives outside the scanned repo. The offline
controller and fixture tests use the relevant expected signals.

## Current manual run

After installing the package, run `make e2e-full BUDGET=<USD>` only when a
live Claude CLI run is authorized. The old frozen-run files must not be
replaced with current output because their consumers test the historical format.
