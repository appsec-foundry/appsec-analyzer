# Plain requirement IDs and user outcomes

## Reason and scope

The repository owner approved simplifying the requirements into clear, relevant user outcomes and replacing category-coded IDs with `REQ-NNN`. This is the explicit one-time ID migration; subsequent edits retain stable IDs. No runtime feature, security control, analysis method, spending limit, or export format is removed or newly implemented by this change.

The catalog now has 35 short requirements instead of 33 mixed-granularity entries. The general product-purpose entry becomes introductory context and the risk-coverage requirement. Run progress and interruption handling are consolidated. Architecture and controls, export and re-export, reassessment history and run operation, and interface compatibility and provider qualification each receive distinct outcomes. The count follows these boundaries rather than a reduction target.

The normative [acceptance contract](../../../docs/internal/contracts/requirement-acceptance.md) retains detailed evidence, severity, analysis-depth, case-count, report-layout, lifecycle, permission, privacy, and budget rules. The short catalog remains readable without understanding internal schemas or orchestration. Optional capabilities such as business misuse analysis remain in scope. Exporting existing assessments remains a requirement even though the public CLI does not yet expose it; standalone exporter tests provide only partial evidence.

## ID migration

Every previously active ID is retired. The following mapping preserves traceability, including splits and consolidations. Older Advisor retirements remain recorded. The table below also maps IDs from the earlier 73-entry catalog so this migration can be read independently. Historical proposals and review records keep their original IDs and verification counts.

| Earlier ID | Current requirement | Change |
| --- | --- | --- |
| `REQ-PUR-001` | `REQ-004` | Product purpose moves to the introduction; scope and source-analysis limits remain in the risk-coverage contract. |
| `REQ-SCN-001` | `REQ-001` | Short user outcome; detailed acceptance rules retained. |
| `REQ-PUR-003` | `REQ-002` | Short user outcome; detailed acceptance rules retained. |
| `REQ-FLW-005` | `REQ-003` | Short user outcome; detailed acceptance rules retained. |
| `REQ-FLW-002` | `REQ-004` | Short user outcome; detailed acceptance rules retained. |
| `REQ-ARC-003` | `REQ-005`, `REQ-006` | Separate architecture description from evaluation of security controls. |
| `REQ-ARC-002` | `REQ-007` | Short user outcome; detailed acceptance rules retained. |
| `REQ-MOD-001` | `REQ-008` | Short user outcome; detailed acceptance rules retained. |
| `REQ-RPT-001` | `REQ-009` | Short user outcome; detailed acceptance rules retained. |
| `REQ-BIZ-001` | `REQ-010` | Short user outcome; detailed acceptance rules retained. |
| `REQ-MOD-004` | `REQ-011` | Short user outcome; detailed acceptance rules retained. |
| `REQ-RPT-005` | `REQ-012` | Short user outcome; detailed acceptance rules retained. |
| `REQ-RPT-007` | `REQ-013` | Short user outcome; detailed acceptance rules retained. |
| `REQ-RPT-016` | `REQ-014`, `REQ-015` | Separate output formats from exporting an existing assessment. |
| `REQ-USE-004` | `REQ-016`, `REQ-017`, `REQ-021` | Separate run operation, reassessment history, and published-result integrity. |
| `REQ-CFG-002` | `REQ-018` | Short user outcome; detailed acceptance rules retained. |
| `REQ-EVO-003` | `REQ-019`, `REQ-020` | Separate compatibility from provider qualification. |
| `REQ-FLW-003` | `REQ-021` | Short user outcome; detailed acceptance rules retained. |
| `REQ-FLW-006` | `REQ-022` | Short user outcome; detailed acceptance rules retained. |
| `REQ-FLW-007` | `REQ-016`, `REQ-034` | Merge progress and recovery into run operation; move diagnostic-sharing consent to action permissions. |
| `REQ-FLW-008` | `REQ-023` | Short user outcome; detailed acceptance rules retained. |
| `REQ-ANA-001` | `REQ-024` | Short user outcome; detailed acceptance rules retained. |
| `REQ-ANA-008` | `REQ-025` | Short user outcome; detailed acceptance rules retained. |
| `REQ-ANA-009` | `REQ-026` | Short user outcome; detailed acceptance rules retained. |
| `REQ-ANA-010` | `REQ-027` | Short user outcome; detailed acceptance rules retained. |
| `REQ-ANA-007` | `REQ-028` | Short user outcome; detailed acceptance rules retained. |
| `REQ-REQ-002` | `REQ-029` | Short user outcome; detailed acceptance rules retained. |
| `REQ-REQ-005` | `REQ-030` | Short user outcome; detailed acceptance rules retained. |
| `REQ-TRU-001` | `REQ-031` | Short user outcome; detailed acceptance rules retained. |
| `REQ-TRU-002` | `REQ-032` | Short user outcome; detailed acceptance rules retained. |
| `REQ-TRU-003` | `REQ-033` | Short user outcome; detailed acceptance rules retained. |
| `REQ-TRU-004` | `REQ-034` | Short user outcome; detailed acceptance rules retained. |
| `REQ-TRU-005` | `REQ-035` | Short user outcome; detailed acceptance rules retained. |

## Earlier catalog IDs

These additional IDs were present in the 73-entry catalog at `e79ac6b7`. Their outcomes either belong to a current requirement or are explicitly outside the standalone Analyzer scope.

| Earlier ID | Current requirement or scope decision |
| --- | --- |
| `REQ-PUR-002` | `REQ-004` |
| `REQ-PUR-004` | `REQ-004` |
| `REQ-FLW-009` | `REQ-002` |
| `REQ-FLW-010` | `REQ-004` |
| `REQ-ARC-001` | `REQ-005`, `REQ-006` |
| `REQ-MOD-003` | `REQ-005`, `REQ-006` |
| `REQ-ARC-004` | `REQ-007` |
| `REQ-MOD-002` | `REQ-008` |
| `REQ-MOD-009` | `REQ-008` |
| `REQ-MOD-015` | `REQ-008` |
| `REQ-BIZ-003` | `REQ-009` |
| `REQ-BIZ-008` | `REQ-009` |
| `REQ-BIZ-005` | The standalone assessment has no two-question business-context dialog. Supplied context remains covered by `REQ-010`. |
| `REQ-BIZ-006` | Dialog answer persistence is not exposed by the assessment CLI. Analyst answer persistence remains covered by `REQ-028`. |
| `REQ-BIZ-010` | `REQ-010` |
| `REQ-BIZ-004` | `REQ-010` |
| `REQ-BIZ-002` | Conversational actor selection and persistence belong to the interactive integration; profile inputs remain covered by `REQ-018`. |
| `REQ-MOD-010` | `REQ-026`; selected cases and preview are exposed through `analyst hypothesis --abuse-case`, not a separate plugin command. |
| `REQ-MOD-012` | `REQ-011` |
| `REQ-RPT-003` | `REQ-012` |
| `REQ-RPT-002` | `REQ-013` |
| `REQ-RPT-006` | `REQ-013` |
| `REQ-RPT-008` | `REQ-013` |
| `REQ-RPT-009` | `REQ-013` |
| `REQ-RPT-012` | `REQ-014`, `REQ-015` |
| `REQ-USE-005` | Conversational questions about an existing model are an Advisor skill; Analyzer exposes status/progress/results, not that dialog. |
| `REQ-USE-006` | `REQ-016`, `REQ-017`, `REQ-021` |
| `REQ-USE-001` | Interactive triage, persistent risk decisions, and code remediation are not public Analyzer commands. |
| `REQ-USE-007` | `REQ-016`, `REQ-017`, `REQ-021` |
| `REQ-USE-008` | `REQ-016`, `REQ-017`, `REQ-021` |
| `REQ-ANA-002` | `REQ-022` |
| `REQ-ANA-003` | `REQ-024` |
| `REQ-ANA-004` | `REQ-018` |
| `REQ-ANA-005` | `REQ-024` |
| `REQ-ANA-011` | `REQ-034` |
| `REQ-REQ-001` | `REQ-029` |
| `REQ-REQ-003` | `REQ-029` |
| `REQ-SCO-001` | No public security-score command or score in scan-sources. Retained scoring modules are not a supported CLI promise. |
| `REQ-SCO-002` | The separate scoring contract is outside the current public CLI scope. |
| `REQ-CFG-001` | `REQ-018` |
| `REQ-CFG-003` | Baseline installation/refresh belongs to Advisor; the baseline package was excluded from this repository. |

## Compatibility and bindings

Binding schema version 2 requires `REQ-NNN` for active requirements and accepts both `REQ-NNN` and the old category-coded format for retired IDs. Version 1 documents are rejected explicitly by schema validation; update their active keys using the mapping above and retain old keys in `retired_ids`. The catalog checker accepts only the new format for active entries. Duplicate IDs, malformed IDs, missing bindings, retired-ID reuse, unsafe paths, and missing test references remain errors.

The catalog checker's proposal requirement also covers the new acceptance contract. Moving detailed rules out of the user catalog therefore preserves the existing change-control check.

Current source and test references are migrated without changing executable behavior. The decision register receives reference-only changes. Supplied security requirements catalogs and their report IDs are a separate interface and are not renamed. Historical snapshots, proposals, and analysis records are not rewritten.

Bindings retain existing producer/consumer paths and test references, redistribute them where requirements split, and name the acceptance contract. Coverage remains partial, including the existing-export requirement: helper tests do not establish public CLI availability. The provider-readiness binding uses the public capabilities test rather than unrelated artifact-migration tests.

## Verification

Run `python3 scripts/check_specs.py`, `PYTHONPATH=.:scripts python3 -m pytest tests/test_check_specs.py -q`, and `make test-analyzer`. Run Ruff lint and format checks on changed Python files. Check current references and Markdown links, and compare the before/after binding union so no evidence is silently dropped during migration. New checker cases cover the ID and version transition, malformed IDs, and preservation of retired-ID rejection. Runtime model calls and live provider qualification are outside this editorial migration.

Verification completed: the catalog checker accepts all 35 requirements, its suite passes 58 tests, and `make test-analyzer` passes 119 offline tests. Ruff lint and format checks pass on all 33 changed Python files. All 55 checked local Markdown links resolve, every earlier active ID has a migration target and retirement entry, and the union of previous binding references is preserved. Reference-only Python changes were checked against their starting syntax trees; runtime behavior is unchanged. `git diff --check` passes. These results qualify the catalog migration and offline checks, not complete requirement coverage or live provider quality.
