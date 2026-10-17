# Security policy

AppSec Analyzer reads source code and generates sensitive security reports. This policy describes the standalone engine; the [earlier Advisor policy](docs/history/advisor/SECURITY.md) is historical.

## Version and reporting

The current engine version is `0.1.0a0`, an unpublished development preview. Offline tests do not establish production readiness, live host isolation, or model quality. There is no support commitment for the inherited Advisor `0.10.x-beta` version in this repository.

Do not report vulnerabilities through public issues. Use the repository's private security-advisory channel where available, or contact the repository maintainers privately. Include the affected revision, impact, and reproduction steps without real credentials or confidential assessment data. This repository does not define a response-time or patch-release guarantee.

## Data use by operation

| Operation | Source and external access | Local result |
| --- | --- | --- |
| `scan-sources` | Deterministic inspection; no model host or model credentials needed. An explicitly selected Git URL requires network retrieval. | Summary or JSON, optionally `scan-result.json`. Findings are unverified observations. |
| `scan` / `assess` | Admitted source excerpts, architecture/context packets, and model responses pass through the selected Claude CLI or OpenAI host. | Validated `security-assessment.md`, YAML, figures, and requested exports. |
| `audit-requirements` | Selected catalog text, filenames, and bounded source excerpts pass through Claude CLI. | Separate requirements verdict and optional Markdown report. |
| `analyst` analysis / answer | Scoped source or supplied design, context, and answers pass through Claude CLI. Optional exploration uses a redacted source copy. | Private analyst job state and requested result files. |
| `status`, `progress`, `stop`, `results` | Local state operations; no model analysis. | Versioned lifecycle response or cancellation request. |

Source slices use the engine's secret masking, but pattern detection cannot guarantee removal of every sensitive value. Supplied business context, designs, catalogs, and answers may themselves contain sensitive information. Review the data classification and selected provider arrangement before sending them. A scan does not authorize sharing its results.

The OpenAI adapter targets the fixed Responses endpoint and requests `store: false`; that request is not a verified retention guarantee. Claude CLI uses the operator's configured authentication and service arrangement. Retention, account terms, and any provider routing must be verified by the operator. The public gateway route remains unavailable. See [configuration](docs/configuration.md) and [host qualification](docs/model-selection.md).

## Source and execution boundaries

Repositories are untrusted by default. The full assessment and deterministic scan perform admission checks, freeze selected source, reject escaping paths and links, and verify source consistency. Source content and model replies cannot select an arbitrary tool, executable, credential, or output path. Structured source requests are validated and served by the controller from admitted files.

Full assessments and audits use model sessions without executable tools. The Claude transport requests isolation from project settings, plugins, hooks, MCP configuration, and session persistence. Optional focused analyst exploration is a separate read-only mode. These controls have offline tests; the real host's enforcement still needs the live negative-control qualification in `tests/test_host_isolation_live.py`.

`--trust-mode trusted` relaxes the repository-configuration preflight. It does not grant model actions additional authority. Use it only after reviewing the selected source configuration. Running Analyzer does not execute a target application's tests or install its packages.

Explicit Git URLs are handled separately from URLs found in repository content. Remote checkout code restricts protocols, pins the selected connection address, disables redirects and repository hooks, and bounds retrieval. It may use operator-selected Git credentials or a credential helper. Keep credentials outside source, command-line URLs, and reports.

## Local storage and sharing

Default assessment and analyst state are outside the analyzed checkout in the user's Analyzer data/state directories. Managed state uses private files; callers should select private external output directories. `--keep-runtime-files` retains sensitive intermediate material and requires mode 0700 for an explicit output directory.

Reports, source excerpts, filenames, supplied context, and diagnostics can disclose architecture and vulnerabilities. Inspect them before sharing. `results` verifies recorded deliverable hashes; it does not establish that a report is suitable for public disclosure.

The full assessment has secret-redaction and publication checks. The separate audit validates schemas and source citations and rejects its JSON and Markdown artifacts when recognized unmasked secrets remain. Its verdict records the exact catalog digest and admitted source inventory. Review reports before distribution for sensitive information outside the recognized secret patterns.

## Qualification limits

The complete inherited test suite and release targets have unresolved extraction failures. Use the [contributor guide](CONTRIBUTING.md) for actual checks and the [review record](docs/internal/analysis/repository-review-2026-10-17.md) for open issues. A successful fake-host assessment does not demonstrate protection against every malicious repository, provider behavior, or production-only control.

The retained mock server is a development tool for synthetic data. Keep real credentials, source excerpts, and confidential findings out of it.
