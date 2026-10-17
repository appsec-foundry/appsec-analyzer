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

`answer`, `cancel`, and `forget` manage an analyst job. `--help` after the
operation lists its exact arguments. Analyst jobs live under the user's private
`appsec-analyzer/analyst` state directory by default. The original detailed
discussion of source grants, questions, feature files, and limits is preserved
in the [historical guide](history/advisor/threat-analyst.md); its old entry
point and plugin instructions do not apply here.
