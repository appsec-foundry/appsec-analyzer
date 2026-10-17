# Separate requirements audit

`audit-requirements` grades a bounded YAML requirements catalog against one
admitted Git checkout. It uses the selected Claude CLI host to inspect source
excerpts and produces a separate requirements verdict. It does not run the
complete security assessment. `scan` remains fully deterministic and has no
provider dependency.

```sh
mkdir -p /private/audit
appsec-analyzer audit-requirements --repo /checkout \
  --requirements /catalog.yaml --output /private/audit \
  --host claude-cli --budget 5 --md --gate
```

The audit makes paid model calls with a default spending limit of USD 5. Use `--budget USD` to change the limit; `--hard-budget` remains a compatible alias. The CLI prints the selected limit before starting.

The output directory must exist, be outside the checkout, and have no prior
audit result. The command writes `.requirements-audit.json` and, with `--md`,
`appsec-requirements-report.md`. The CLI response has interface version 1,
`kind: requirements-audit`, `audit_status: complete`, and
`assessment_status: not_run`. The verdict uses the existing
[requirements-audit schema](../schemas/requirements-audit.schema.json).
All conclusive rows need a cited line actually served from the frozen source;
missing source cannot establish a pass or failure. A changed checkout or
invalid result stops publication. Reports are private to the current user.

`--category FILTER` selects catalog IDs or categories; `--demo` uses the
packaged sample catalog. The current entry accepts a local regular catalog
file, at most 160 selected requirements, and a bounded file inventory. It
does not fetch remote catalogs or resume an interrupted audit. The historical
Advisor audit's plugin skill, remote-source precedence, and PDF output are
documented in the [archived guide](history/advisor/security-requirements-audit-skill.md),
but are not available through this entry.

`--gate` makes MUST failures return exit status 1 by default; `--gate-on
partial` also blocks on partial findings, and `--priority-floor SHOULD` or
`MAY` widens priority coverage. Exit status 2 means an operational or contract
error. A gate result is a deterministic policy decision over the published
verdict, not proof that all controls were verified. See
[configuration](configuration.md) and [full assessment](security-assessment.md)
for their distinct operations.
