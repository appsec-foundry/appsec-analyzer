"""The PLATSEC checks of docs/internal/contracts/platform-security-settings.md."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from urllib.parse import quote

from appsec_analyzer.platform_settings.client import ApiClient, Response
from appsec_analyzer.platform_settings.source import Repository

SET, NOT_SET, NOT_CHECKABLE = "set", "not set", "not checkable"
MISSING_PERMISSION = "missing permission"
NOT_OFFERED = "feature not offered by the platform or plan"
PLATFORM_ERROR = "platform error"

CATALOG = (
    ("PLATSEC-001", "Required reviews on the default branch"),
    ("PLATSEC-002", "Force pushes blocked on the default branch"),
    ("PLATSEC-003", "Secret scanning enabled"),
    ("PLATSEC-004", "Push protection enabled"),
    ("PLATSEC-005", "Workflow token read-only by default"),
    ("PLATSEC-006", "Workflows cannot approve pull requests"),
    ("PLATSEC-007", "Runs from forks require approval"),
)
IDS = tuple(check_id for check_id, _ in CATALOG)


@dataclass(frozen=True)
class Outcome:
    state: str
    reason: str | None = None


def _unreadable(response: Response) -> Outcome:
    if response.rate_limited or response.status >= 500:
        return Outcome(NOT_CHECKABLE, PLATFORM_ERROR)
    return Outcome(NOT_CHECKABLE, MISSING_PERMISSION)


def _combine(sources: list[Outcome]) -> Outcome:
    """Set if any readable source enforces it; not set only if every source was readable."""
    for outcome in sources:
        if outcome.state == SET:
            return outcome
    unreadable = [outcome for outcome in sources if outcome.state == NOT_CHECKABLE]
    return unreadable[0] if unreadable else Outcome(NOT_SET)


def _flag(value: object, wanted: bool) -> Outcome:
    if not isinstance(value, bool):
        return Outcome(NOT_CHECKABLE, MISSING_PERMISSION)
    return Outcome(SET if value is wanted else NOT_SET)


@dataclass
class Context:
    visibility: str = "unknown"
    default_branch: str | None = None


class GitHub:
    def __init__(self, client: ApiClient, repo: Repository, token: bool):
        self.client, self.token = client, token
        self.base = f"/repos/{repo.path}"
        self.project: dict = {}

    def context(self) -> Context:
        response = self.client.get(self.base)
        if response.status != 200 or not isinstance(response.body, dict):
            raise LookupError(response)
        self.project = response.body
        visibility = self.project.get("visibility")
        branch = self.project.get("default_branch")
        return Context(
            visibility if visibility in ("public", "private", "internal") else "unknown",
            branch if isinstance(branch, str) and 0 < len(branch) <= 255 else None,
        )

    def evaluate(self, context: Context) -> dict[str, Outcome]:
        out: dict[str, Outcome] = {}
        branch = quote(context.default_branch or "", safe="")
        if context.default_branch:
            rules = self.client.get(f"{self.base}/rules/branches/{branch}")
            classic = self.client.get(f"{self.base}/branches/{branch}/protection")
            out["PLATSEC-001"] = _combine([self._rule_reviews(rules), self._classic_reviews(classic)])
            out["PLATSEC-002"] = _combine([self._rule_force(rules), self._classic_force(classic)])
        else:
            out["PLATSEC-001"] = out["PLATSEC-002"] = Outcome(NOT_CHECKABLE, PLATFORM_ERROR)
        analysis = self.project.get("security_and_analysis")
        for check_id, key in (("PLATSEC-003", "secret_scanning"), ("PLATSEC-004", "secret_scanning_push_protection")):
            if not isinstance(analysis, dict):
                # GitHub omits this block for callers without admin or security manager access.
                out[check_id] = Outcome(NOT_CHECKABLE, MISSING_PERMISSION)
            elif not isinstance(analysis.get(key), dict):
                out[check_id] = Outcome(NOT_CHECKABLE, NOT_OFFERED)
            else:
                out[check_id] = Outcome(SET if analysis[key].get("status") == "enabled" else NOT_SET)
        workflow = self.client.get(f"{self.base}/actions/permissions/workflow")
        if workflow.status == 200 and isinstance(workflow.body, dict):
            out["PLATSEC-005"] = Outcome(
                SET if workflow.body.get("default_workflow_permissions") == "read" else NOT_SET
            )
            out["PLATSEC-006"] = _flag(workflow.body.get("can_approve_pull_request_reviews"), False)
        else:
            out["PLATSEC-005"] = out["PLATSEC-006"] = _unreadable(workflow)
        out["PLATSEC-007"] = self._forks(context)
        return out

    @staticmethod
    def _rule_reviews(response: Response) -> Outcome:
        if response.status != 200 or not isinstance(response.body, list):
            return _unreadable(response)
        for rule in response.body:
            if isinstance(rule, dict) and rule.get("type") == "pull_request":
                count = (rule.get("parameters") or {}).get("required_approving_review_count")
                if isinstance(count, int) and not isinstance(count, bool) and count >= 1:
                    return Outcome(SET)
        return Outcome(NOT_SET)

    @staticmethod
    def _rule_force(response: Response) -> Outcome:
        if response.status != 200 or not isinstance(response.body, list):
            return _unreadable(response)
        blocked = any(isinstance(rule, dict) and rule.get("type") == "non_fast_forward" for rule in response.body)
        return Outcome(SET if blocked else NOT_SET)

    def _classic(self, response: Response) -> Outcome | dict:
        if response.status == 200 and isinstance(response.body, dict):
            return response.body
        message = response.body.get("message") if isinstance(response.body, dict) else None
        # A 404 is unambiguous only for an authenticated caller and the documented message.
        if response.status == 404 and self.token and message == "Branch not protected":
            return Outcome(NOT_SET)
        return _unreadable(response)

    def _classic_reviews(self, response: Response) -> Outcome:
        body = self._classic(response)
        if isinstance(body, Outcome):
            return body
        count = (body.get("required_pull_request_reviews") or {}).get("required_approving_review_count")
        return Outcome(SET if isinstance(count, int) and not isinstance(count, bool) and count >= 1 else NOT_SET)

    def _classic_force(self, response: Response) -> Outcome:
        body = self._classic(response)
        if isinstance(body, Outcome):
            return body
        return _flag((body.get("allow_force_pushes") or {}).get("enabled"), False)

    def _forks(self, context: Context) -> Outcome:
        if context.visibility == "public":
            response = self.client.get(f"{self.base}/actions/permissions/fork-pr-contributor-approval")
            if response.status != 200 or not isinstance(response.body, dict):
                return _unreadable(response)
            return Outcome(SET if response.body.get("approval_policy") == "all_external_contributors" else NOT_SET)
        if context.visibility == "unknown":
            return Outcome(NOT_CHECKABLE, PLATFORM_ERROR)
        response = self.client.get(f"{self.base}/actions/permissions/fork-pr-workflows-private-repos")
        if response.status != 200 or not isinstance(response.body, dict):
            return _unreadable(response)
        disabled = _flag(response.body.get("run_workflows_from_fork_pull_requests"), False)
        approval = _flag(response.body.get("require_approval_for_fork_pr_workflows"), True)
        return _combine([disabled, approval])


class GitLab:
    def __init__(self, client: ApiClient, repo: Repository, token: bool):
        self.client, self.token = client, token
        self.base = f"/projects/{quote(repo.path, safe='')}"
        self.project: dict = {}

    def context(self) -> Context:
        response = self.client.get(self.base)
        if response.status != 200 or not isinstance(response.body, dict):
            raise LookupError(response)
        self.project = response.body
        visibility = self.project.get("visibility")
        branch = self.project.get("default_branch")
        return Context(
            visibility if visibility in ("public", "private", "internal") else "unknown",
            branch if isinstance(branch, str) and 0 < len(branch) <= 255 else None,
        )

    def evaluate(self, context: Context) -> dict[str, Outcome]:
        out: dict[str, Outcome] = {}
        branch = context.default_branch
        rules = self.client.get(f"{self.base}/approval_rules")
        protected = self.client.get(f"{self.base}/protected_branches")
        if branch:
            out["PLATSEC-001"] = self._reviews(rules, branch)
            out["PLATSEC-002"] = self._force(protected, branch)
        else:
            out["PLATSEC-001"] = out["PLATSEC-002"] = Outcome(NOT_CHECKABLE, PLATFORM_ERROR)
        out["PLATSEC-003"] = Outcome(NOT_CHECKABLE, NOT_OFFERED)
        settings = self.client.get(f"{self.base}/security_settings")
        if settings.status == 200 and isinstance(settings.body, dict):
            out["PLATSEC-004"] = _flag(settings.body.get("secret_push_protection_enabled"), True)
        else:
            out["PLATSEC-004"] = _unreadable(settings)
        out["PLATSEC-005"] = Outcome(NOT_CHECKABLE, NOT_OFFERED)
        out["PLATSEC-006"] = Outcome(NOT_CHECKABLE, NOT_OFFERED)
        out["PLATSEC-007"] = _flag(self.project.get("ci_allow_fork_pipelines_to_run_in_parent_project"), False)
        return out

    @staticmethod
    def _reviews(response: Response, branch: str) -> Outcome:
        if response.status != 200 or not isinstance(response.body, list):
            return _unreadable(response)
        for rule in response.body:
            if not isinstance(rule, dict):
                continue
            count = rule.get("approvals_required")
            names = [b.get("name") for b in rule.get("protected_branches") or [] if isinstance(b, dict)]
            covers = not names or any(isinstance(n, str) and fnmatch.fnmatchcase(branch, n) for n in names)
            if isinstance(count, int) and not isinstance(count, bool) and count >= 1 and covers:
                return Outcome(SET)
        return Outcome(NOT_SET)

    def _force(self, response: Response, branch: str) -> Outcome:
        if response.status != 200 or not isinstance(response.body, list):
            return _unreadable(response)
        matching = [
            rule
            for rule in response.body
            if isinstance(rule, dict)
            and isinstance(rule.get("name"), str)
            and fnmatch.fnmatchcase(branch, rule["name"])
        ]
        if not matching:
            # An empty list is also returned to callers who may not read protection details.
            return Outcome(NOT_SET) if self.token and response.body else Outcome(NOT_CHECKABLE, MISSING_PERMISSION)
        # The most permissive matching rule decides.
        return _flag(any(rule.get("allow_force_push") is not False for rule in matching), False)
