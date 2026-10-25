# Security policy

AppSec Analyzer reads source code and creates reports that can reveal security weaknesses. This policy explains what data leaves your machine, how Analyzer limits access, and how to handle its results. The [earlier Advisor policy](docs/history/advisor/SECURITY.md) is kept for reference.

## Version and reporting

Version `0.1.0a0` is an unpublished development preview. Offline tests do not show that Analyzer is ready for production, that a real model host enforces access limits, or that its findings are reliable. This repository provides no support commitment for the earlier Advisor `0.10.x-beta` version.

Report vulnerabilities privately through the repository's security-advisory channel, where available, or contact the maintainers directly. Include the affected revision, impact, and steps to reproduce the problem. Leave out real credentials and confidential assessment data. There is no guaranteed response time or patch release date.

## Data use by operation

| Operation | Source and external access | Local result |
| --- | --- | --- |
| `scan-sources` | Runs fixed checks without a model or model credentials. Downloads source when you select a Git URL. | Summary or JSON, optionally `scan-result.json`. Observations are unverified. |
| `score REPO` | Four scanners read a checked source copy with recognized secrets masked. No model calls. Downloads source when you select a Git URL. | Text, JSON, or YAML on stdout. Writes nothing to the target checkout. Shows coverage and unverified observations. |
| `assess` | Sends selected source excerpts, architecture information, context, and model responses through the selected model host. | Validated `security-assessment.md`, YAML, figures, and requested exports. |
| `audit-requirements` | Sends selected requirements, filenames, and limited source excerpts through Claude CLI. | Separate requirements verdict and optional Markdown report. |
| `analyst` analysis / answer | Sends selected source, designs, context, and answers through Claude CLI. Optional exploration reads a source copy with recognized secrets masked. | Private job state and requested result files. |
| `status`, `progress`, `stop`, `results` | Reads or updates local run state. No model analysis. | Run information or a cancellation request. |

Analyzer masks recognized secrets in source excerpts, but can miss sensitive values. Business context, designs, catalogs, and answers can also contain confidential information. Check which data your organization allows you to send to the selected provider before starting. Review results separately before sharing them.

The OpenAI adapter sends requests to the fixed Responses endpoint with `store: false`. That setting alone does not verify how the provider retains data. Claude CLI uses your configured login and service agreement. Check the provider's retention terms, account terms, and routing. The legacy generic gateway is unavailable through the public CLI. See [configuration](docs/configuration.md) and [provider support and limits](docs/model-selection.md).

## Source and execution boundaries

Analyzer treats repositories as untrusted. Before an assessment or source scan, it checks the selected files and captures a fixed copy. It rejects paths and links that escape the repository and checks that the source has not changed. Repository text and model replies cannot choose arbitrary tools, programs, credentials, or output paths. The controller checks model requests for source and returns only approved files.

The `score` command also checks source, masks recognized secrets, and gives scanners a private copy containing only regular files. It rechecks the source before printing. The score is not a risk rating or proof of safety. Compare results only for commits of the same repository with matching source rules and check coverage; see [security scoring](docs/security-score.md).

Models used for full assessments and audits receive no executable tools. The Claude connection requests sessions that ignore project settings, plugins, hooks, MCP configuration, and saved sessions. Optional exploration by the focused analyst uses a separate read-only mode. Offline tests cover these controls. Checking whether the real host enforces them still requires the live tests in `tests/test_host_isolation_live.py`, including attempts to bypass the limits.

`--trust-mode trusted` relaxes the initial repository-configuration check. Use it only after reviewing that configuration. Models retain the same action limits. Analyzer does not run the target application's tests or install its packages.

Analyzer downloads a Git repository only when you explicitly select its URL. It restricts connection protocols, fixes the selected connection address, disables redirects and repository hooks, and limits the download. It can use your selected Git credentials or credential helper. Keep credentials out of source, command-line URLs, and reports.

## Local storage and sharing

By default, assessment and analyst state are stored in your Analyzer data and state directories, outside the analyzed checkout. Analyzer creates private state files. Choose a private directory outside the checkout for your output. `--keep-runtime-files` keeps sensitive intermediate files; an explicit output directory must then have mode `0700` (access for its owner only).

Reports, source excerpts, filenames, context, and diagnostics can reveal architecture and vulnerabilities. Inspect them before sharing. The `results` command checks whether deliverables match their recorded hashes. It does not check whether they are safe to publish.

Full assessments mask recognized secrets and check output before publication. The separate audit checks the result format and source citations. It rejects JSON and Markdown output if recognized secrets remain unmasked. Its verdict records the catalog hash and the files analyzed. Review reports for other sensitive information before distributing them.

## Qualification limits

The inherited test suite and release targets still have failures from the engine extraction. See the [contributor guide](CONTRIBUTING.md) for supported checks and the [review record](docs/internal/analysis/repository-review-2026-10-17.md) for open issues. A passing assessment with a fake model host does not verify real provider behavior or every protection needed in production.

Use the retained mock server only for development with synthetic data. Keep real credentials, source excerpts, and confidential findings out of it.
