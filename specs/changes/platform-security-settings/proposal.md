---
reason: Platform settings such as branch protection, push protection, workflow token permissions, and approval for runs from forks decide whether CI/CD and supply-chain threats are exploitable, and no current command or scan phase examines them.
affected_ids: [REQ-038]
compatibility: Adds the requirement, its acceptance rules, and the `platform-settings` command; existing commands and saved results are unchanged. `scan` gains the Platform Security Settings phase and the option `--platform-token-env`; its result is stored in the working directory and given to the Controls and STRIDE roles as fixed-value context. Roles do not cite it as evidence, because their output schemas have no field for it. The model gains the optional `meta.platform_security_settings` field in both output schemas, with no schema version change, and the report gains an unnumbered Platform Security Settings section that appears only when the field is present, so older results stay valid. Structured platform-setting evidence in role outputs is not implemented. Existing stage numbers stay unchanged.
verification: Offline tests cover each check with a set case and a not-set or not-checkable case on both platforms, an unreadable setting that never counts as set, a missing field that signals insufficient access, token and free-text handling, refused redirects, host-pinned tokens, and a local path that sends no request. Phase tests cover a skipped local checkout, a Git remote that does not start the check, a failed check that does not stop the scan, credentials that are not stored, and reuse on resume. Projection tests cover allow-listing, untrusted labels, and absent data. A controller test records what each role receives and checks the model field and the report section. Tests cover the report block, its schema, and the section renderer. `make test-controller` and `make e2e-controller` passed before the context change. No live platform request was made.
---

# Platform security settings

Adds REQ-038. Analyzer is to check security settings of a GitHub or GitLab repository without model calls, either through a separate command or as the Platform Security Settings phase of `scan`, before Reconnaissance. Each check reports `set`, `not set`, or `not checkable` with a reason.

The [platform security settings table](../../../docs/internal/contracts/platform-security-settings.md) is the check catalog. It gives seven checks stable `PLATSEC-NNN` IDs, defines when each is `set`, maps it to its GitHub and GitLab sources, and lists the access levels and open points that still need confirmation against the platform APIs. Every check ID needs a `set` test and a `not set` or `not checkable` test that reference it.

## Decisions

The user approved the requirement wording in the conversation that drafted it. These decisions were made there:

- The check runs in `scan` before the threat analysis, because the settings change how CI/CD and supply-chain threats are rated. A command-only variant with a next-step hint after `scan` was considered; it would avoid a token in `scan` and schema changes, but it gives the analysis no input.
- A separate command remains, as the model-free way to run the check alone.
- A token is used only when the user supplies it explicitly, and it must be read-only. Reusing an existing CLI login was rejected.
- GitHub and GitLab are both in scope, with per-platform sources in the table.
- For a local repository, the phase is shown as skipped rather than hidden, so readers see that the check did not run. Git remotes never trigger the check, because they are repository content.
- Repository visibility is reported as context and administrator access is left out, because neither has a target value. For runs from forks, only GitHub's strictest approval policy counts as `set` for public repositories; for private GitHub repositories, fork workflows must be disabled or require approval.
- A missing field or an empty result that the platform also returns for insufficient access counts as `not checkable`, never as `not set`. GitHub, for example, omits `security_and_analysis` for callers without admin access.
- Open questions about the GitLab roles needed for reading do not block implementation; they are confirmed with real tokens during implementation, because missing access already yields `not checkable`.
- The name Platform Security Settings and the `PLATSEC` prefix avoid confusion with Analyzer's own settings and organization profiles.

## Risks raised

- **Credentials:** `scan` accepts a platform token in addition to the model connection. The acceptance rules keep it out of model context, run state, results, logs, and diagnostics, and send it only to the selected host.
- **Data sent to other hosts:** Requests reveal the repository and, with a token, the requesting account to the platform. No source code is sent.
- **Model context:** Platform data entering prompts could carry injected instructions. Only check IDs, states, reasons, and other allow-listed values reach model roles.
- **Cost:** The check makes no model calls. Controls and STRIDE jobs receive slightly more context.
- **Existing scans and saved results:** `scan` gains a phase, options, a report section, and an evidence type; golden fixtures change and older results lack the section.
- **Low value without a token:** Anonymous checks leave most results `not checkable`. The report must make that visible, and the analysis treats those results as unknown.

REQ-006, REQ-008, and REQ-009 are unchanged. The REQ-038 acceptance rules define how platform-setting evidence relates to them.

Structured platform-setting evidence in role outputs (step 3b) is deferred on purpose. The deferred items and their order are listed under Deferred work in the [check catalog](../../../docs/internal/contracts/platform-security-settings.md#deferred-work).
