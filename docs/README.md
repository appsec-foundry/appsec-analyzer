# Documentation guide

Start with the [repository README](../README.md) to choose a source scan, full assessment, focused analysis, or requirements audit. [Product requirements](../requirements.md) describe intended user outcomes; the guides below describe available commands and their limits.

## User guides

| Task | Guide |
| --- | --- |
| Analyze a complete system | [Security assessment](security-assessment.md) |
| Run unattended and inspect results | [Command-line operation](headless-mode.md) |
| Select settings and organization defaults | [Configuration](configuration.md), [organization profiles](org-profiles.md) |
| Understand provider, model, and cost limits | [Hosts and models](model-selection.md), [security policy](../SECURITY.md) |
| Review a design, change, or hypothesis | [Focused Threat Analyst](threat-analyst.md) |
| Grade a requirements catalog | [Requirements audit](security-requirements-audit-skill.md) |
| Prepare a local catalog | [Requirements harvester](harvester.md), [examples](../examples/README.md) |
| Export a Threat Dragon model | [Threat Dragon export](threat-dragon-export.md) |

## Maintainer references

[AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md) explain requirement integration, change boundaries, and verification. [Local release preparation](local-release-preparation.md) describes archive inspection and offline qualification. The [repository review](internal/analysis/repository-review-2026-10-17.md) records outstanding extraction defects and legacy candidates.

The [requirement acceptance contract](internal/contracts/requirement-acceptance.md) contains the detailed rules behind the short user requirements. The [ID migration](../specs/changes/plain-requirement-ids/proposal.md) maps earlier category-coded IDs to stable `REQ-NNN` IDs.

The [Juice Shop standard and thorough comparison](internal/analysis/stride-model-cost-comparison-2026-10-17.md) records measured costs, business logic findings, and the limits of drawing model-quality conclusions from two runs.

The technical contracts in `internal/contracts/` include retained Advisor mechanisms. Read their scope notes and check current callers before treating one as an active standalone interface. The [extraction record](internal/extraction/phase-a-record.md), `internal/analysis/`, and `proposals/` preserve dated decisions and plans; they are not a release or capability declaration.

[Historical Advisor guides](history/advisor/INDEX.md) retain old plugin commands for migration context. Their installation, hook, version, and output conventions do not apply to the current Analyzer CLI.

## Scan and model profiles

[Scan and model profiles](profiles.md) explains reusable scan defaults, USD budgets, exports, report attributes, per-role models, and the included YAML examples.
