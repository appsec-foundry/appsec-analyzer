# Separate requirements audit

`audit-requirements` checks a local requirements catalog (Analyzer YAML or an OSCAL catalog, see [catalog formats](#catalog-formats)) against one admitted Git checkout or directory without Git. It sends selected source excerpts to Claude CLI and produces a separate requirements verdict. For a complete security assessment, use `assess`. For fixed source checks without a model, use `scan-sources`.

```sh
mkdir -p /private/audit
appsec-analyzer audit-requirements --repo /checkout \
  --requirements /catalog.yaml --output /private/audit \
  --host claude-cli --budget 5 --md --gate
```

The audit makes paid model calls with a default spending limit of USD 5. Use `--budget USD` to change the limit; `--hard-budget` remains a compatible alias. The CLI prints the selected limit before starting.

The output directory must exist outside the checkout and contain no earlier audit result. The audit writes private `.requirements-audit.json` and, with `--md`, `appsec-requirements-report.md`.

The CLI response uses interface version 1 with `kind: requirements-audit`, `audit_status: complete`, and `assessment_status: not_run`. New verdicts follow version 2 of the [audit schema](../schemas/requirements-audit.schema.json); version-1 verdicts remain readable. They record the catalog hash, Git commit, captured state, file hashes, and exclusions.

Every conclusive result must cite a source line served from the fixed source copy. Missing evidence cannot establish a pass or failure. A changed checkout or invalid result stops publication.

`--category FILTER` selects catalog IDs or categories. `--demo` uses the packaged sample. The command accepts a local regular catalog file and at most 160 selected requirements, with a size-limited source inventory. It cannot fetch remote catalogs or resume an interrupted audit.

Before publishing, the audit scans the JSON and the optional Markdown for unmasked secrets. A match blocks both files. The error does not print the secret. See the [security policy](../SECURITY.md) for handling results.

`--gate` returns exit 1 for MUST failures by default. `--gate-on partial` also blocks on partial results. `--priority-floor SHOULD` or `MAY` adds those priorities. Exit 2 means an operational error or an invalid result. A passing gate means that none of the selected blocking conditions occurred. It does not mean that every control was verified. See [configuration](configuration.md) and [full assessment](security-assessment.md) for the other commands.

## Catalog formats

Every command that takes `--requirements` (`assess`, `audit-requirements`, `authnz-review`, and `analyze-threats`) reads two formats: the Analyzer's own catalog (`categories[].requirements[]`, in YAML or JSON) and an OSCAL catalog in JSON or YAML. Analyzer takes the format from the file content, not from the file name, and there is no option to choose it. The result records the format and the checksum of the file as you supplied it. For an OSCAL catalog it also records the title and version.

An OSCAL catalog is converted when it is loaded:

- Each group becomes a category. A nested group becomes a category titled with its path, and controls outside any group form the category Controls.
- Each control, including enhancements, becomes a requirement with the control ID as its ID. The text is the control statement. A parameter shows its value, or `[Assignment: …]` or `[Selection: …]` when the catalog leaves it open. Guidance and assessment objectives are not used.
- Withdrawn controls are left out. The console and the result give their number.
- OSCAL has no obligation level, so every control gets the priority `MUST`. A gate on `MUST` therefore blocks on every violated control.

Analyzer refuses, with the reason, an OSCAL profile or other OSCAL document, an XML file, a file with both formats, and a control without an ID or with a repeated ID. Resolve a profile to a catalog first, for example with oscal-cli, and convert XML to JSON. A catalog file may be up to 16 MiB as JSON and up to 4 MiB as YAML.

Each command also has a limit that is checked before any model call:

| Command | Limit |
| --- | --- |
| `assess` | 32 context rows per component (a row holds the requirements of one category up to a size limit), and a size limit for the requirements assessment of the report |
| `audit-requirements` | 160 selected requirements; `--category` selects part of a catalog |
| `authnz-review` | 128 000 bytes after conversion |
| `analyze-threats` | 300 requirements |

A catalog above a limit is refused with its size and the limit, for every format. For example, the full NIST SP 800-53 Rev. 5.2.0 catalog has 1 014 active controls and fits only `audit-requirements --category`. Its resolved LOW baseline has 149 controls and fits all four commands. A catalog is never checked in part.

`UNVERIFIABLE` results are reported apart from `PASS`, and neither gate policy blocks on them. An audit where everything is unverifiable can still pass the gate. Check coverage and the unverifiable counts before you treat an audit as evidence of compliance. Before the analysis, the command states that masked source excerpts, the file inventory, and the catalog requirements are sent to Claude CLI. Provider retention is not verified.
