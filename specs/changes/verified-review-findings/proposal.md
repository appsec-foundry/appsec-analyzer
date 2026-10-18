---
reason: Close verified source-boundary, resume-accounting, publication, export and disclosure gaps found by the requirements review.
affected_ids: [REQ-015, REQ-016, REQ-023, REQ-030, REQ-031, REQ-032, REQ-033, REQ-035]
compatibility: Runtime changes now reject resume; existing scan results cannot be replaced; saved-result export is additive and requires completed compatible state.
verification: Public CLI regression tests, hostile declaration and export inputs, monetary and subscription resume tests, offline controller tests, distribution tests and requirements checks.
---

# Verified review findings

Related-repository preflight reads only a bounded regular declaration through non-link directory handles. Rejected URL values and parser source excerpts are not included in diagnostics. A runtime fingerprint change refuses resume before it changes saved accounting or deadlines; an explicit new attempt retains the existing compatible-job reuse behavior.

Deterministic scan publication uses exclusive creation and cannot replace another result. Requirements Audit discloses model-bound data before analysis. Its existing FAIL/PARTIAL gate policy remains unchanged; unverifiable results stay separate from verified passes.

The public `export` command reads a completed saved assessment, checks every recorded digest and the current model contract, and invokes deterministic converters without a model host. The new private destination cannot replace existing output. Document conversion rejects active markup and resources outside the frozen bundle, uses finite subprocess deadlines, and rechecks the source before publication. The command exposes conversion limitations in its JSON result. No product requirement or acceptance criterion is weakened or retired.
