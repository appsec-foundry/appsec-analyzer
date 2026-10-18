---
reason: Users want to continue working on an existing assessment directly in Claude Code or Codex with the relevant review capabilities, without another export or analysis.
affected_ids: [REQ-037]
compatibility: Add review RESULT_DIR with optional --with and --preview. Existing commands and state formats remain compatible. Default only from a recorded CLI adapter; older state and API adapters require a choice. Share artifact validation with exports and preserve reports.
verification: Run offline review and export tests, controller completion tests, package checks, specification gates against b855fce57706a359194b9c6663147634bebbfe78, the standalone test gate, and Ruff. Cover selection, launch, preview, unavailable CLI, noninteractive rejection, invalid artifacts, secrets, links, injection attempts, and facts lookup. Live assistant sessions require separate model-use authorization and remain unexecuted.
---

# Continue work on a saved assessment

The result directory is the positional input to `appsec-analyzer review`. The command validates existing deliverables and starts the selected interactive assistant with the bundled `review-assessment` skill. This adapts evidence-grounded questions and targeted facts queries from Advisor's `ask-security-assessment` workflow to standalone artifacts, without plugin paths, repository-local discovery, or unavailable sibling commands.

The shared saved-assessment reader retains the export boundary. A read-only query helper reuses the existing facts builder on validated published YAML, without unrecorded requirements sidecars. Skill and helper ship in the package and are supplied to the launched session; nothing is installed globally. Queries remain local; assistant discussion uses the native account and billing settings.

The host profile chooses only between two fixed executables, never arbitrary commands or arguments. Launch from a fresh private directory with planning/read-only permissions and automatic project configuration and instructions excluded, preserving native user and managed controls. Saved report content remains evidence rather than authority. The external assistant retains its native permission workflow; implementation needs a separate request and source selection. This does not continue Analyzer's admitted-snapshot sandbox or budget.

Completion includes the quoted review command without starting a model session or waiting for input, preserving automation and gate exit codes. Offline tests cannot establish native live permission enforcement, model quality, or billing.

Verification completed: the review and affected closing tests passed 39 cases, followed by seven passing launch/configuration regressions after the final native-option changes and one passing capability test. The initial combined review/export run passed 51 tests. The installed-wheel/source-distribution test passed, and the specification-checker plus console tests passed 120 cases after updating the catalog count to 37. Skill validation, changed-file Ruff checks, local documentation links, diff whitespace, and the specification gate against the explicit base passed. These counts overlap.

The broader `make test-analyzer` run completed with 911 passes and seven failures in `tests/test_codex_cli.py` while the separate transport and fixtures were being edited concurrently. Those failures concerned structured-response envelopes and request capacity. A fresh run of that entire test file against the then-current tree passed all 64 cases; the full standalone gate was not repeated. No live assistant session or model call was made for this change.

Before committing, an isolated copy of the staged changes passed all 65 review, export, and affected closing tests, plus the catalog and Ruff checks. Contributor instructions now include the module overview and main workflows; the review help also explains default assistant selection and launch prerequisites. Documentation links and module paths were checked.
