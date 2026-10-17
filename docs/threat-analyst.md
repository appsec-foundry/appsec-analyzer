# Focused Threat Analyst

The focused analyst examines a design, a selected code change, or a concrete
threat hypothesis. It is a separate function from the complete
[security assessment](security-assessment.md). It uses a Claude CLI model
session and scoped, captured source; it does not claim a complete assessment.

```sh
appsec-analyzer analyst design --repo /path/to/project --design-file /path/to/design.md
appsec-analyzer analyst review --ci --repo /path/to/project \
  --base BASE_SHA --head HEAD_SHA
appsec-analyzer analyst hypothesis --repo /path/to/project \
  --hypothesis "Can a user read another account?" --revision HEAD --path src/api
```

`answer` resumes a job with supplied answers; `cancel` stops a running job or closes one waiting for answers. `forget` removes a selected saved answer from a feature-context file and requires its expected hash and question fingerprint; it is not a command to delete job history. `--help` after the
operation lists its exact arguments. Analyst jobs live under the user's private
`appsec-analyzer/analyst` state directory by default. The original detailed
discussion of source grants, questions, feature files, and limits is preserved
in the [historical guide](history/advisor/threat-analyst.md); its old entry
point and plugin instructions do not apply here.

The analyst uses `--max-budget-usd`, defaulting to USD 1 per model call. This is a per-call ceiling, not the full-assessment `--budget` or a total-job spending guarantee. Its configured job limits also bound calls and elapsed time. Model-backed analyst commands transmit selected source/design context and incur provider costs.

For a defined abuse case, `analyst hypothesis --abuse-case ID --revision HEAD --preview --repo /path/to/project` shows the selected case and scope without starting a model job. Omit `--preview` to check it. `--interactive` enables supported dialogue/worktree modes; `--explore` additionally permits read-only access to a redacted snapshot for design or review. Organization constraints still apply.
