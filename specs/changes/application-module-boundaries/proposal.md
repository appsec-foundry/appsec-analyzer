---
reason: Give score, focused threat analysis and assessment clear module ownership and remove dependencies from reusable workflows back to CLI internals.
affected_ids: [REQ-001, REQ-016, REQ-019, REQ-024, REQ-029, REQ-035, REQ-036]
compatibility: Public commands, result schemas and scoring version remain unchanged. Retained Python and script entry points have compatibility adapters. Application source now participates in runtime identity, so assessments created before this implementation change require a fresh run rather than compatible resume.
verification: Run module import and pure-calculation tests, waiting-job isolation and lock tests, current standalone contract tests, distribution and context-routing checks, offline controller tests, specification checks and Ruff.
---
# Application module boundaries

Keep score calculation, scanner collection, workflow coordination and presentation under `appsec_analyzer/score/`. Retain the direct score script and previous import paths as adapters to the same implementation. Pass loaded scoring catalogs explicitly when deterministic calculation must run without filesystem access.

Separate `analyze-threats` terminal interaction from scope and document preparation. Expose a controller-owned waiting-job view, read under the existing job lock and checked against the selected repository and job. Existing answer and cancellation operations retain execution ownership.

Extract shared catalog admission, private artifact operations, terminal formatting, export target validation, source preflight, configuration-surface discovery, and scanner execution primitives. Keep each workflow's scanner selection, applicability and partial-result policy. Retain the existing source snapshots, evidence checks, secret handling, output restrictions and model limits.

Move the assessment console into its application package and pass a structured request from the public CLI. Retain argument-list adapters for direct controller callers and the existing configuration resolver. Fingerprint application source files alongside retained engine resources so moved executable code remains part of resume compatibility.

The retained engine directories stay under `scripts/` during this step. Their complete relocation is a separate migration because filesystem dispatch and bundled resources still depend on those paths. This change preserves the existing product outcomes and acceptance rules.
