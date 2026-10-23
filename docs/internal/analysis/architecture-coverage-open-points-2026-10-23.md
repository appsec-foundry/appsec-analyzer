# Architecture coverage: open points

Status: working document, written 2026-10-23 after merge 4ca5073a. That merge lets high-confidence architecture anti-patterns and confirmed architecture hypotheses become findings after the evidence review (REQ-004). The change and its decisions are in the [proposal](../../../specs/changes/architecture-rule-findings/proposal.md). The three points below were left open on purpose. Each needs a decision by the product owner before implementation.

## 1. Control statuses of the architecture coverage are unused (REQ-006)

The architecture coverage records a status per control in `control_assessments`: partial, weak, missing, or anti-pattern, with the rule ID, control name, confidence, and evidence. `scripts/model/assessment_posture.py` merges these records into `.architecture-coverage.json`, but no later step reads them. The completeness gate `scripts/validators/qa_arch_coverage.py` would require every such status to be visible as a control, a hypothesis, or a finding, but nothing calls it. In the earlier plugin pipeline, Phase 8 used these statuses to pre-populate the security controls; the plugin commit e67be5326 dropped that stage text.

Adding a control row for every status the model did not cover failed review for three reasons. The rule control names, such as `Schema / Allowlist Input Validation`, do not match the control names the model writes reliably, so matching by name yields duplicate or missing rows. On Juice Shop all three statuses were `partial` with low confidence and no evidence, so such rows would make unevidenced claims. And the description in `schemas/fragments/security-controls.schema.json` says that the model's rating wins on conflict.

Options:

- Give the control analyst the statuses and their evidence as deterministic input, the way it already receives platform settings (REQ-038). This changes what the model receives, so per AGENTS.md it needs a requirement decision first.
- Link control rows to rules by ID instead of name. The controls sidecar schema already allows an optional `rule_id` on each row.
- Call `qa_arch_coverage.py` as an advisory check that reports statuses missing from the report, without blocking publication.
- Retire `control_assessments` and the gate deliberately, and record that in the [decision register](../decisions.md).

## 2. Architecture hits as verification starting points (REQ-040)

`data/test-cases.yaml` lists architecture rules as starting points of verification items, for example ARCH-XSS-002 in TC-INPUT-04, ARCH-TLS-001 in TC-DATA-04, ARCH-CORS-001 in TC-FRONT-01, and ARCH-DBSEP-001 in TC-INFRA-03. The [acceptance contract](../contracts/requirement-acceptance.md) asks that every shipped scanner rule be a starting point or have a recorded reason why not. Their hits still never become candidates. `_scanner_hits` in `scripts/model/case_candidates.py` reads a rule only from `source_check_id`, `config_check_id`, or `check_id`, and an architecture finding names its rule in `rule_id`. Merge 4ca5073a changed only the report link in `scripts/model/case_outcomes.py`, so verification job counts and costs stayed as they were.

Adding `rule_id` to the keys in `case_candidates.py` would make these hits candidates. A hit at a route registration joins that route's existing candidate. A hit anywhere else becomes a new location candidate and can add verification jobs. Before deciding, count the change offline with `case_candidates.starting_candidates` over the Juice Shop facts and state the extra jobs and their cost. The other option is to record for each of these rules why it is no starting point.

## 3. A rule matches its own description text

At thorough depth on the `appsec-advisor` repository, ARCH-CORS-001 reported a high-confidence anti-pattern at `data/architecture-coverage-rules.yaml:183`. That line is the rule's own `finding_when` text, not a CORS configuration. The coverage reads every file with a source or configuration extension, including `.yaml` and `.json` (`_SOURCE_EXTS` in `scripts/analyzers/architecture_coverage_checks.py`). Prose stored in such files, such as rule catalogs, documentation strings, or test fixtures, can therefore match the same patterns as real configuration.

Since merge 4ca5073a such a hit reaches the evidence review. The review should refute it, but it costs part of a review call. The fix has to hold for any repository. Excluding this one file or path would only hide the witness. One possible direction is to require that a YAML or JSON match be a configuration value rather than text inside a quoted prose string. First establish which rules and file kinds are affected, then add a guard test with a prose fixture and a real configuration fixture.
