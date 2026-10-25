# Organization profiles in Analyzer assessments

To include your organization's profile in an internal installation and select it automatically, use a separate organization distribution. The [packaging guide](organization-distributions.md) includes a complete example, wheel builds, offline installation checks and CI instructions. The upstream engine remains a separate pinned dependency.

An organization profile sets defaults for depth, exports, budget limits, context documents, actors, and requirements. Analyzer validates it against [org-profile.schema.yaml](../schemas/org-profile.schema.yaml). The format name `appsec-advisor.org-profile/v2` identifies the file contract; it does not require an Advisor checkout.

Select an existing local profile explicitly:

```sh
appsec-analyzer assess --repo /checkout --host claude-cli --budget 20 \
  --org-profile /private/policy/org-profile.yaml --preset release-review
```

`--no-org-profile` disables profile selection for that run. Keep the profile outside the analyzed checkout. Repository content cannot choose a host, credential, endpoint, model, or profile. CLI flags override supported profile defaults. Invalid profiles stop configuration resolution; source and output checks still apply.

The standalone CLI does not install organization plugins, run Claude Code hooks, or expose skill toggles. Those profile keys do not enforce Analyzer policy. Keep profile context and secrets outside the analyzed repository, and review context before sending it to a model.

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

Business abuse cases describe actions the application must prevent. Select a repository YAML file with `--abuse-case-file PATH`, or list its repository-relative path under `abuse_case_files` in a scan profile. No special directory is required. Earlier locations remain supported. A case can list legitimate exceptions and questions for the owner. Verification cites checked source; an unresolved case never counts as a pass. See [custom abuse cases](security-assessment.md#custom-abuse-cases) for the format and limits.

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

See the [archived Advisor guide](history/advisor/org-profiles.md) for original field definitions and migration context. Its plugin commands are historical. Use [configuration](configuration.md) for current commands and [model selection](model-selection.md) for provider limits.
