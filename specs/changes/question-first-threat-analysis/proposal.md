---
reason: Users want to ask focused security questions without selecting technical subcommands, review MRs and PRs, and include existing Markdown threat models, requirements and specifications.
affected_ids: [REQ-024, REQ-025]
compatibility: Add analyze-threats over the existing analyst controller while preserving analyst subcommands, structured YAML adapters, separate job state and per-call Claude budgets. Add optional document context, validated document references and review provenance to version-1 contracts; older artifacts remain readable. New fields require the updated reader. Do not alter full assessments or existing user changes.
verification: Exercise the public CLI and real controller with fake model transport, revision-bound document capture, exact citation validation, dialogue and resume, scope and budget rejection, symlinks, secrets and limits, read-only forge resolution and pinned network boundaries, isolated real Git retrieval, installed wheel entry and resource inventory, specification comparison and Ruff. No live model calls or real forge access are authorized for qualification.
---

# Question-first threat analysis

The public entry accepts a question and optional scope flags. Interactive terminals choose missing scope and answer the controller's required questions; unattended invocations fail clearly on ambiguity. The existing controller remains responsible for captured source, evidence validation, job limits, publication and cancellation.

Additional documents are bounded data with provenance and exact-line references. Commit reviews retain earlier and proposed declarations; MR/PR reviews use target-tip documents separately from merge-base source comparison. Automatic selection records omissions; explicit missing or sensitive context fails before a model call. Conventional filenames are discoverable without granting repository documents execution authority.

Forge adapters use standard-library HTTPS with validated and pinned addresses, verified TLS and no redirects, then the existing restricted Git transport to retrieve exact objects in a private temporary checkout. Returned URLs never select new destinations. Existing externally supplied Git credentials are used only for the explicitly selected forge. The feature posts no comments and changes no caller-owned checkout.

The installed analyze-threats skill provides the conversational adapter. Direct terminal use also supports required-question dialogue and frozen-job continuation. Claude CLI remains the only focused-analysis provider, and its USD ceiling remains per call rather than a new job-wide budget.

Verification of the final focused change passed 105 tests across the CLI, document admission, review sources, analyst isolation, context builder and installed distribution; `make test-analyzer` passed all 761 offline tests. Ruff lint and formatting and both installed skill validations passed. The requirements comparison passed before concurrent unrelated test edits; the final workspace check reports REQ-018 referencing the removed `test_valid_org_profile_fixture_passes` in `tests/test_org_profile_schema.py`. Those unrelated edits were left untouched. No live model or forge qualification was performed.
