# Organization profiles in Analyzer assessments

An organization profile supplies assessment defaults such as depth, selected
exports, budget guardrails, context documents, actors, and requirements. The
engine validates a selected profile against
[`org-profile.schema.yaml`](../schemas/org-profile.schema.yaml). The inherited
format identifier is `appsec-advisor.org-profile/v2`; it names the file
contract, not a dependency on an Advisor checkout.

Select an existing local profile explicitly:

```sh
appsec-analyzer assess --repo /checkout --host claude-cli --budget 20 \
  --org-profile /private/policy/org-profile.yaml --preset release-review
```

`--no-org-profile` disables profile selection for that run. The profile is an
operator input outside the analyzed checkout; source files cannot choose a
host, provider credential, endpoint, model, or profile. CLI flags take
precedence over profile defaults where the resolver supports both. Invalid
profiles stop configuration resolution. Source and output controls still apply
to the assessment.

The current standalone CLI does not install organization plugins, execute
Claude Code hooks, or expose skill toggles. Do not rely on those keys as
Analyzer enforcement points. Keep profile context documents and secrets out
of the analyzed repository; any selected context sent to a model should be
reviewed by the operator.

### Business abuse cases

Repository-owned cases under `docs/security/abuse-cases/` express business
rules that source patterns cannot settle alone. A case can name the legitimate
exceptions and questions that only an owner can answer. The verifier cites
admitted source; an unresolved case is not reported as a pass.

```yaml
schema_version: 2
abuse_cases:
  - id: REPO-AC-010
    kind: descriptive
    title: Requester approves their own expense report
    check: Check whether an employee can approve an expense report they submitted.
    exclusions:
      - Reports below the amount that policy lets employees self-approve.
    open_questions:
      - Which amount, if any, may be self-approved?
    scope_qualifier:
      path_patterns: ["*expense*", "*approv*"]
```

An organization profile can add cases with `ORG-AC-NNN` IDs. Selection is
bounded by assessment depth and the packaged case limits. See the archived
guide for the full field semantics and source matching rules.

For the original profile field explanations and plugin migration context, see
the [archived Advisor guide](history/advisor/org-profiles.md). Its plugin
layouts and commands are historical, not instructions for this package. See
[configuration](configuration.md) for the current public command and
[model selection](model-selection.md) for host qualification limits.
