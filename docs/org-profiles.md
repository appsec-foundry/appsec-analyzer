# Organization profiles in Analyzer assessments

To include your organization's profile in an internal installation and select it automatically, use a separate organization distribution. The [packaging guide](organization-distributions.md) includes a complete example, wheel builds, offline installation checks and CI instructions. The upstream engine remains a separate pinned dependency.

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

## Depth defaults

An organization profile can set its own defaults for single assessment depths under `depths`, with the keys and limits of the [depth settings](profiles.md#what-each-depth-does): `verify`, `abuse_cases`, `derived_abuse_cases`, `architect_review`, `actor_discovery`, and `budget`. A team's scan profile can still change each of them. Values the organization does not name keep the shipped default.

```yaml
depths:
  standard:
    architect_review: true
    abuse_cases: 5
```

Defaults are not binding. To make a security aspect binding, use `test_cases.required_aspects`; to keep an abuse case from running, use `abuse_cases.disable`, which a scan profile's `check_abuse_cases` cannot override. Organization distributions do not carry these keys yet.

## Business abuse cases

Business abuse cases express rules that source patterns cannot settle alone. Select a repository-owned YAML file with `--abuse-case-file PATH`, or save its repository-relative path in a scan profile's `abuse_case_files` list. No particular directory is required. The former `docs/security/abuse-cases/` and `.appsec/abuse-cases/` locations remain discoverable for compatibility. A case can name legitimate exceptions and questions that only an owner can answer. The verifier cites admitted source; an unresolved case is not reported as a pass. See [custom abuse cases](security-assessment.md#custom-abuse-cases) for selection and limits.

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

An organization profile can add cases with `ORG-AC-NNN` IDs through `abuse_cases.add`, a glob relative to the organization profile's directory, for example `abuse_cases: {add: "abuse-cases/*.yaml"}`. This provides organization-owned cases outside the source repository. Selection is bounded by assessment depth and the packaged case limits. See the archived guide for the full field semantics and source matching rules.

For the original profile field explanations and plugin migration context, see
the [archived Advisor guide](history/advisor/org-profiles.md). Its plugin
layouts and commands are historical, not instructions for this package. See
[configuration](configuration.md) for the current public command and
[model selection](model-selection.md) for host qualification limits.
