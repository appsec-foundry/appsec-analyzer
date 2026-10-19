# Platform security settings table

This table is the check catalog for [REQ-038](requirement-acceptance.md#req-038-check-platform-security-settings). The separate command and the Platform Security Settings phase of `scan` run the same checks. The table maps each check to its GitHub and GitLab sources and describes intended behavior that does not exist yet. Field names and access levels come from the platform documentation listed under [Sources](#sources), as checked on 2026-10-19. Verify them against the current platform API before implementation, and confirm the open points below with real tokens during implementation.

Each check keeps its `PLATSEC-NNN` ID when it is reworded or moved. A removed check's ID is never reused. Results, platform-setting evidence, and tests reference checks by this ID.

## Checks

| ID | Check | `set` when | GitHub source | GitHub access | GitLab source | GitLab access |
| --- | --- | --- | --- | --- | --- | --- |
| PLATSEC-001 | Required reviews on the default branch | At least one approval is required | Active branch rule `pull_request` with `required_approving_review_count`; classic branch protection, `required_pull_request_reviews` | Branch rules: fine-grained `Metadata` read, anonymous for public repositories. Classic protection: fine-grained `Administration` read | Merge request approval rules, `approvals_required` for a rule covering the default branch (Premium, Ultimate) | Authentication required; role: open point 1. A 403 or 404 on Free cannot be told from a missing role and is reported as missing permission |
| PLATSEC-002 | Force pushes blocked on the default branch | No matching rule allows force pushes | Active branch rule `non_fast_forward`; classic branch protection, `allow_force_pushes.enabled` | As for PLATSEC-001 | Protected branch `allow_force_push` | Open point 2 |
| PLATSEC-003 | Secret scanning enabled | Status is `enabled` | Repository `security_and_analysis.secret_scanning.status` | Repository admin, organization owner, or security manager | No platform setting; pipeline secret detection is configured in CI files | Always `not checkable`, feature not offered by the platform |
| PLATSEC-004 | Push protection enabled | Status is `enabled` | Repository `security_and_analysis.secret_scanning_push_protection.status` | As for PLATSEC-003 | Project security settings, `secret_push_protection_enabled` (Ultimate; on self-managed instances an administrator must allow it first) | Security Manager, Developer, Maintainer, or Owner. A private project returns not found to non-members |
| PLATSEC-005 | Workflow token read-only by default | Default token permissions are read-only | Actions workflow permissions, `default_workflow_permissions` is `read` | Fine-grained `Administration` read; classic token `repo` | No equivalent setting: a job token receives the access level of the user who triggered the pipeline | Always `not checkable`, feature not offered by the platform |
| PLATSEC-006 | Workflows cannot approve pull requests | Workflow approval of pull requests is disabled | Actions workflow permissions, `can_approve_pull_request_reviews` is `false` | As for PLATSEC-005 | No equivalent setting known | Open point 3 |
| PLATSEC-007 | Runs from forks require approval | Public GitHub repository: approval is required for all external contributors. Private GitHub repository: fork workflows are disabled or require approval. GitLab: fork pipelines cannot run in the parent project | Public: fork pull request contributor approval, `approval_policy` is `all_external_contributors`. Private: private repository fork pull request workflow settings, `run_workflows_from_fork_pull_requests` is `false` or `require_approval_for_fork_pr_workflows` is `true` | Fine-grained `Administration` read | Project setting `ci_allow_fork_pipelines_to_run_in_parent_project` is `false` | Open point 4 |

The GitHub default fork approval policy, `first_time_contributors`, therefore results in `not set` for PLATSEC-007.

GitLab's job token allowlist (`inbound_enabled` in the job token scope) controls which other projects' job tokens may access this project. It does not limit this project's own job token, so it is not a source for PLATSEC-005.

## Evaluation rules

Evaluate the default branch reported by the platform at check time. A check is `set` when at least one active source enforces it. On GitHub, classic branch protection and active branch rules both count; rules in evaluate or disabled mode do not.

Report `not set` only when every source for the check was readable and none enforces the setting. If one source is unreadable and no readable source enforces the setting, the check is `not checkable` with the reason of the unreadable source. For example, an anonymous check of a public GitHub repository can read active branch rules but not classic branch protection: if no rule enforces PLATSEC-001, the result is `not checkable` with the reason missing permission.

A forbidden or not-found answer from a source that needs higher access is `not checkable` with the reason missing permission, never `not set`. The same applies to a missing field or an empty result that the platform also returns for insufficient access. For example, GitHub omits `security_and_analysis` from the repository response for callers without admin or security manager access, so a missing block makes PLATSEC-003 and PLATSEC-004 `not checkable`, not `not set`. Unless the platform documentation states otherwise for a source, treat a missing field or an empty result as possibly caused by insufficient access. A source that requires a plan or instance feature the repository lacks is `not checkable` with the reason feature not offered by the platform or plan.

On GitLab, force-push permission follows the most permissive protected-branch rule that matches the default branch. Report `set` for PLATSEC-002 only if no matching rule allows force pushes.

## Context

Report repository visibility (`visibility` on both platforms) as context in every result. It is not a check, because a public repository is not a misconfiguration. Administrator access is not part of the catalog.

## Open points

These points are not answered by the platform documentation. They do not block implementation: until a point is confirmed, the evaluation rules above apply, so missing access yields `not checkable`. Confirm each point during implementation against a real project with tokens of different roles, and record the minimum token permissions in the user guide.

1. GitLab approval rules: the documentation requires authentication but names no role for reading project approval rules.
2. GitLab protected branches: the documentation names no role for reading protected-branch details, including `allow_force_push`.
3. GitLab: confirm that a CI/CD job token cannot approve merge requests. If it cannot, PLATSEC-006 is `not checkable` on GitLab with the reason feature not offered by the platform.
4. GitLab fork pipelines: confirm the role and subscription tier needed to read `ci_allow_fork_pipelines_to_run_in_parent_project` through the projects API.

## Deferred work

These items are not implemented. Start with the first two, which need no design decision.

1. **Live check.** No request to a real platform has been made; all tests use test data and a local server. Run `platform-settings` and `scan` against a repository you own, with a read-only token, on GitHub and on GitLab. Compare each result with the settings page. Then close the open points above and record the minimum token permissions in the user guide.
2. **End-to-end run.** Run `make e2e-controller` once. The scan report gained a section for every scan, including a skipped line for local repositories, and this run has not been executed since.
3. **Structured platform evidence in role outputs (step 3b).** Today the Controls and STRIDE roles receive the settings only as prompt context, so how a result influences a finding cannot be checked. Add a field such as `platform_check_ids` to the control and finding schemas, and validators that enforce the rules of REQ-038: only IDs that were checked may be cited, a finding or control never rests on platform evidence alone, and a `not checkable` or unchecked result never raises a severity. This changes role schemas and needs a version decision under REQ-019. Do it only if a live run shows that the prompt context is ignored or misused.
4. **Repository to component mapping.** In a combined scan every role receives every checked repository, because checkout paths and URLs do not map to repositories reliably. A reliable mapping is a prerequisite for item 3 in multi-repository scans.
5. **Console phase list.** The phase appears only as progress lines. Add it to the phase list of the assessment console.
6. **Context routing catalog.** `data/context-routing-catalog.yaml` does not list the new input. It describes the Advisor engine's roles, which the assessment controller does not use. Add the input only if the controller starts using the catalog.

## Sources

- [GitHub REST API endpoints for rules](https://docs.github.com/en/rest/repos/rules)
- [GitHub REST API endpoints for protected branches](https://docs.github.com/en/rest/branches/branch-protection)
- [GitHub REST API endpoints for repositories](https://docs.github.com/en/rest/repos/repos)
- [GitHub REST API endpoints for GitHub Actions permissions](https://docs.github.com/en/rest/actions/permissions)
- [GitLab protected branches API](https://docs.gitlab.com/api/protected_branches/)
- [GitLab merge request approvals API](https://docs.gitlab.com/api/merge_request_approvals/)
- [GitLab project security settings API](https://docs.gitlab.com/api/project_security_settings/)
- [GitLab CI/CD job token scope API](https://docs.gitlab.com/api/project_job_token_scopes/)
- [GitLab CI/CD job token](https://docs.gitlab.com/ci/jobs/ci_job_token/)
- [GitLab merge request pipelines](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/)
