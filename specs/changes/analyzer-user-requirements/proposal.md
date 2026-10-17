# Analyzer user requirements and documentation review

## Request and scope

The repository owner requested a complete repository review, a user-centered `requirements.md` in the style of Create Threat Model, and integration with contributor/agent instructions. This records that already-authorized change. It does not authorize live model spending, package publication, or removal of runtime code.

The previous 73-entry catalog mixed standalone behavior and Advisor plugin functions. The new 33-entry catalog consolidates user outcomes while retaining representative existing IDs. A new `REQ-SCN-001` covers the provider-free source scan. Removed IDs remain retired and must not be reassigned. The [historical catalog](../../../docs/history/advisor/requirements.md) preserves the earlier wording.

## Implementation limits

The catalog is normative; test bindings are partial evidence, not certification. Live provider quality and host isolation remain unqualified. There is no public standalone export-existing command; exports are assessment options. The separate audit identifies its catalog as local/demo but does not yet record the catalog digest or admitted source revision in its published verdict. Its publication path also needs the secret-output gate described in the [review](../../../docs/internal/analysis/repository-review-2026-10-17.md). These are gaps, not requirements silently removed to match implementation.

## Requirement migration

Consolidation retains evidence and security constraints unless the scope distinction below explicitly applies. CLI availability is documented in the current guides.

| Earlier ID | Current requirement or scope decision |
| --- | --- |
| REQ-PUR-001 | REQ-PUR-001 |
| REQ-PUR-002 | REQ-PUR-001 |
| REQ-PUR-003 | REQ-PUR-003 |
| REQ-MOD-001 | REQ-MOD-001 |
| REQ-MOD-002 | REQ-MOD-001 |
| REQ-MOD-003 | REQ-ARC-003 |
| REQ-MOD-004 | REQ-MOD-004 |
| REQ-MOD-009 | REQ-MOD-001 |
| REQ-MOD-010 | REQ-ANA-009; selected cases and preview are exposed through `analyst hypothesis --abuse-case`, not a separate plugin command. |
| REQ-ARC-001 | REQ-ARC-003 |
| REQ-ARC-002 | REQ-ARC-002 |
| REQ-FLW-002 | REQ-FLW-002 |
| REQ-FLW-003 | REQ-FLW-003 |
| REQ-REQ-001 | REQ-REQ-002 |
| REQ-BIZ-001 | REQ-BIZ-001 |
| REQ-BIZ-002 | Conversational actor selection and persistence belong to the interactive integration; profile inputs remain covered by REQ-CFG-002. |
| REQ-BIZ-003 | REQ-RPT-001 |
| REQ-BIZ-004 | REQ-BIZ-001 |
| REQ-BIZ-005 | The standalone assessment has no two-question business-context dialog. Supplied context remains covered by REQ-BIZ-001. |
| REQ-RPT-001 | REQ-RPT-001 |
| REQ-RPT-002 | REQ-RPT-007 |
| REQ-RPT-003 | REQ-RPT-005 |
| REQ-RPT-005 | REQ-RPT-005 |
| REQ-RPT-006 | REQ-RPT-007 |
| REQ-RPT-007 | REQ-RPT-007 |
| REQ-RPT-008 | REQ-RPT-007 |
| REQ-USE-001 | Interactive triage, persistent risk decisions, and code remediation are not public Analyzer commands. |
| REQ-ANA-001 | REQ-ANA-001 |
| REQ-ANA-002 | REQ-FLW-006 |
| REQ-ANA-003 | REQ-ANA-001 |
| REQ-ANA-004 | REQ-CFG-002 |
| REQ-ANA-005 | REQ-ANA-001 |
| REQ-ANA-007 | REQ-ANA-007 |
| REQ-ANA-008 | REQ-ANA-008 |
| REQ-ANA-009 | REQ-ANA-009 |
| REQ-ANA-010 | REQ-ANA-010 |
| REQ-ANA-011 | REQ-TRU-004 |
| REQ-TRU-001 | REQ-TRU-001 |
| REQ-TRU-002 | REQ-TRU-002 |
| REQ-CFG-001 | REQ-CFG-002 |
| REQ-CFG-002 | REQ-CFG-002 |
| REQ-CFG-003 | Baseline installation/refresh belongs to Advisor; the baseline package was excluded from this repository. |
| REQ-EVO-003 | REQ-EVO-003 |
| REQ-SCO-001 | No public security-score command or score in scan-sources. Retained scoring modules are not a supported CLI promise. |
| REQ-PUR-004 | REQ-PUR-001 |
| REQ-FLW-005 | REQ-FLW-005 |
| REQ-FLW-009 | REQ-PUR-003 |
| REQ-FLW-010 | REQ-FLW-002 |
| REQ-ARC-003 | REQ-ARC-003 |
| REQ-ARC-004 | REQ-ARC-002 |
| REQ-MOD-015 | REQ-MOD-001 |
| REQ-BIZ-008 | REQ-RPT-001 |
| REQ-BIZ-006 | Dialog answer persistence is not exposed by the assessment CLI. Analyst answer persistence remains covered by REQ-ANA-007. |
| REQ-BIZ-010 | REQ-BIZ-001 |
| REQ-MOD-012 | REQ-MOD-004 |
| REQ-RPT-009 | REQ-RPT-007 |
| REQ-RPT-012 | REQ-RPT-016 |
| REQ-RPT-016 | REQ-RPT-016 |
| REQ-USE-004 | REQ-USE-004 |
| REQ-USE-005 | Conversational questions about an existing model are an Advisor skill; Analyzer exposes status/progress/results, not that dialog. |
| REQ-USE-006 | REQ-USE-004 |
| REQ-USE-007 | REQ-USE-004 |
| REQ-USE-008 | REQ-USE-004 |
| REQ-REQ-002 | REQ-REQ-002 |
| REQ-REQ-003 | REQ-REQ-002 |
| REQ-REQ-005 | REQ-REQ-005 |
| REQ-SCO-002 | The separate scoring contract is outside the current public CLI scope. |
| REQ-TRU-003 | REQ-TRU-003 |
| REQ-TRU-004 | REQ-TRU-004 |
| REQ-TRU-005 | REQ-TRU-005 |
| REQ-FLW-006 | REQ-FLW-006 |
| REQ-FLW-007 | REQ-FLW-007 |
| REQ-FLW-008 | REQ-FLW-008 |

## Binding changes

Existing test references are retained when their files and nodes exist. The following dangling references were removed from the active bindings; this does not replace their missing coverage. Current public CLI, audit, state, and provider tests are added where they exercise the new entry points. Consolidated requirements use `partial` coverage; no removed test is replaced with a claim of full coverage.

| Current ID | Field | Missing inherited reference |
| --- | --- | --- |
| REQ-ARC-002 | guards | `tests/test_agent_definitions.py::test_cross_repo_mismatch_requires_target_evidence` |
| REQ-MOD-001 | guards | `tests/test_agent_definitions.py::test_cross_repo_mismatch_requires_target_evidence` |
| REQ-RPT-005 | guards | `tests/test_agent_definitions.py::test_architecture_agent_states_access_variants_and_unauthenticated_access` |
| REQ-RPT-005 | guards | `tests/test_agent_definitions.py::TestProseStyleAnchor::test_prose_style_file_exists` |
| REQ-RPT-005 | guards | `tests/test_agent_definitions.py::TestProseStyleAnchor::test_prose_authoring_files_reference_anchor` |
| REQ-RPT-007 | documents | `specs/changes/figure1-stays-readable-at-page-width/proposal.md` |
| REQ-RPT-007 | documents | `specs/changes/figure1-splits-runtime-and-supply-chain/proposal.md` |
| REQ-USE-004 | applies_to | `skills/security-assessment-health/**` |
| REQ-CFG-002 | applies_to | `scripts/package_internal_plugin.py` |
| REQ-CFG-002 | guards | `tests/test_package_internal_plugin.py::test_policy_surface_explicit_block` |
| REQ-CFG-002 | guards | `tests/test_package_internal_plugin.py::test_the_package_policy_can_exclude_an_added_skill` |
| REQ-CFG-002 | guards | `tests/test_skill_policy_gate.py::test_blocks_a_disabled_skill_invoked_by_claude` |
| REQ-EVO-003 | applies_to | `scripts/check_release_meta.py` |
| REQ-FLW-003 | applies_to | `scripts/auto_emitter_pass.sh` |
| REQ-FLW-007 | applies_to | `skills/report-error/**` |
| REQ-FLW-007 | applies_to | `skills/fix-run-issues/**` |
| REQ-FLW-007 | applies_to | `skills/clean-run-state/**` |
| REQ-TRU-001 | applies_to | `scripts/appsec-reviewer-cli` |
| REQ-TRU-001 | guards | `tests/test_appsec_reviewer_cli.py::test_repository_owned_claude_configuration_is_refused_unless_trusted` |
| REQ-TRU-001 | guards | `tests/test_appsec_reviewer_cli.py::test_a_checked_in_verdict_is_never_reported_as_this_review` |

## Verification

Run `python3 scripts/check_specs.py` and the catalog/guard tests. Run public CLI tests for the corrected scan instructions. The full inherited suite and routing audit have pre-existing extraction failures recorded in the repository review; this change must not suppress or skip them to obtain a green result.
