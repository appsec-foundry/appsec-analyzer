# appsec-analyzer

[![Version](https://img.shields.io/badge/version-0.1.0a0-orange.svg)](engine.json)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](setup.py)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-blue.svg)](#reports-and-exports)

AppSec Analyzer is a command-line tool for reviewing application security from source code. It maps components, data flows, and trust boundaries, examines security controls, and produces findings with code references and suggested fixes.

Use it when taking over an unfamiliar codebase, preparing a security review, or deciding what to fix next. It works with one Git repository or several repositories that form a system.

The tool combines rule-based source scanners with model-backed analysis. A source scan runs without an AI account. A full security assessment uses Claude CLI by default with a USD 20 spending limit, configurable with `--budget`.

> [!NOTE]
> **Alpha.** Commands and report formats may change. Live assessment quality is still being qualified; review findings before acting on them.

[Install](#install) · [Quick start](#quick-start) · [Reports](#reports-and-exports) · [More commands](#more-commands) · [Security](#security-and-data-use) · [Documentation](#documentation) · [Contributing](#contributing)

## What does it check?

A full assessment helps answer:

- How do components communicate, and where does data cross a trust boundary?
- Which security controls are present, missing, or incorrectly implemented?
- Which weaknesses and attack paths are supported by the code?
- What should the team fix, and how can it verify the fix?

The assessment covers implementation weaknesses and design risks. It connects findings to the application architecture and separates supported findings from unresolved questions. You can add business context, security requirements, and organization settings to guide the analysis.

To check your own business rules, select a YAML file with `--abuse-case-file review/abuse-cases.yaml`, or save the selection in a scan profile. Paths are relative to the repository being assessed; no special documentation directory is required. See [custom abuse cases](docs/security-assessment.md#custom-abuse-cases) for the format and limits.

Source code cannot establish how an application behaves in production. Deployment controls, business assumptions, and findings still need review by the team.

## Install

Requires **Python 3.10+**, **Git**, and [pipx installed and on your PATH](https://pipx.pypa.io/stable/). Install the current preview directly from the repository in one command:

```sh
pipx install "git+https://github.com/appsec-foundry/appsec-analyzer.git@dev"
```

This command requires the `dev` branch to be available in the GitHub repository and accessible to you. pipx manages a separate virtual environment and exposes `appsec-analyzer` on your PATH. No manual clone or environment activation is needed. Verify the installation with `appsec-analyzer version`.

If you prefer `pip`, run this in an activated virtual environment:

```sh
python -m pip install "git+https://github.com/appsec-foundry/appsec-analyzer.git@dev"
```

<details>
<summary>Install from a local checkout</summary>

To install local changes, use the checkout workflow instead:

```sh
git clone --branch dev https://github.com/appsec-foundry/appsec-analyzer.git
cd appsec-analyzer
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
appsec-analyzer version
```

If you already have a checkout, start with `cd appsec-analyzer`. With pipx installed, you can also run `pipx install .` from the checkout. The `pip` workflow above uses bash/zsh; keep its virtual environment active when running the commands below.

</details>

<details>
<summary>Run directly from a local checkout without installation</summary>

You can run the CLI as a Python module without installing Analyzer or activating a virtual environment. This requires Python 3.10+, Git, and the runtime dependencies declared in [setup.py](setup.py) (`PyYAML>=6,<7`, `jsonschema>=4.20,<5`, and `Jinja2>=3.1,<4`) to be available to `python3`.

From your Analyzer checkout, check the entry point:

```sh
cd /path/to/appsec-analyzer
python3 -m appsec_analyzer.cli version
python3 -m appsec_analyzer.cli scan --help
```

Replace `/path/to/appsec-analyzer` with your checkout path. For the commands below, replace `appsec-analyzer` with `python3 -m appsec_analyzer.cli` and keep your working directory at the Analyzer checkout. Select the repository to assess explicitly with `--repo`, because its default is the current directory. For example, with Claude CLI configured:

```sh
python3 -m appsec_analyzer.cli scan --repo /path/to/project --output /path/to/assessment
```

Replace `/path/to/project` with the target Git repository and `/path/to/assessment` with an existing result directory outside it. This runs the same paid assessment, sends selected source excerpts and context to the model provider, and uses the default USD 20 spending limit. Use `python3 -m appsec_analyzer.cli scan-sources --repo /path/to/project` for a source scan without model calls.

</details>

Installing by package name with `pip install appsec-analyzer` requires a release on PyPI. The current preview is listed as unpublished in [local release preparation](docs/local-release-preparation.md), which also describes installation from a locally built wheel.

A full assessment with the default `claude` profile needs `claude` on your `PATH`, with a working login or externally configured Anthropic API credentials. The experimental `codex` profile uses `OPENAI_API_KEY` instead. The source scan needs neither. See [profile configuration](docs/configuration.md) for provider setup.

## Quick start

Replace `/path/to/project` with the path to the Git repository you want to examine.

### 1. Run a source scan

Start with a scan that makes no model calls:

```sh
appsec-analyzer scan-sources --repo /path/to/project
```

It prints observations from the applicable authorization, mass-assignment, and configuration scanners, along with their coverage. These observations are unverified; this command does not perform a full security assessment. Add `--json` for machine-readable output.

### 2. Run a full assessment

With Claude CLI configured, run this from the Git repository you want to assess:

```sh
appsec-analyzer scan
```

`scan` uses the current directory by default. To assess a different repository, add `--repo /path/to/project`.

This command sends selected source excerpts and supplied context to the model provider and makes paid model calls. The default spending limit is **USD 20** for `scan` and `assess`. To choose another limit, use `appsec-analyzer scan --budget 10`. The CLI prints the selected limit before starting. This is a maximum, not an estimate or a guarantee that the assessment will finish within that amount. If the remaining budget cannot cover required work, the run preserves progress and reports an incomplete assessment. `--hard-budget` remains a compatible alias for `--budget`.

The terminal shows progress. Completed results include `security-assessment.md` for reading and `security-assessment.yaml` for further processing. Results go to a private directory under your user's `appsec-analyzer/assessments` data directory, outside the analyzed repository.

Progress output immediately warns when optional model jobs are skipped. Architect Review and abuse-case totals distinguish actual checks from unchecked work, including at `thorough` depth. See [assessment coverage and limits](docs/security-assessment.md).

An interactive terminal outside CI may ask for a higher total USD budget before budget-limited work is skipped. Only entering a higher total authorizes an increase; an empty answer keeps the current limit. Use `--non-interactive` for CI and unattended runs. Compatible resume retains earlier approved increases for the same run.

The default profile is `claude` and the default depth is `standard`. A scan profile supplies the model profile, depth, USD budget, exports, and report attributes. CLI options override its defaults. For example, with `OPENAI_API_KEY` configured:

```sh
appsec-analyzer scan --profile codex --assessment-depth thorough --budget 20
```

You can also create [your own scan and model profiles](docs/profiles.md), including per-role model settings. Inspect them with `appsec-analyzer profiles show NAME` or check them with `appsec-analyzer profiles validate NAME`. The built-in profiles impose no output-token cap.

Component analysis runs at most two components at once by default. Set `max_parallel` in a scan profile or pass `--max-parallel 4` to override it for a run. Accepted values are integers from 1 to 16; higher values can encounter provider rate limits.

No `--host` argument is needed. The `codex` profile uses the OpenAI API, not a Codex CLI login, and has not completed live assessment qualification. See [profiles, models, and cost](docs/model-selection.md) before a paid run.

`standard` also analyzes business logic. `thorough` can cost more without producing more verified results when later checks cannot fit the budget; see [choosing standard or thorough](docs/model-selection.md#choosing-standard-or-thorough).

### 3. Inspect and continue a run

Use the output directory reported by the assessment in place of `/path/to/assessment`:

```sh
appsec-analyzer status --output /path/to/assessment
appsec-analyzer results --output /path/to/assessment
```

`status` shows the run state. `results` lists published files after checking their recorded hashes. To continue an interrupted run with compatible source and settings:

```sh
appsec-analyzer scan --repo /path/to/project --budget 20 \
  --output /path/to/assessment --resume
```

Use `progress` to inspect progress from another terminal and `stop` to request a stop, each with `--output /path/to/assessment`. See [command-line operation](docs/headless-mode.md) for unattended runs and recovery.

## Reports and exports

The Markdown report describes the architecture, security controls, findings, open questions, and prioritized remediation. The YAML file contains the structured assessment.

Request additional formats when starting an assessment:

```sh
appsec-analyzer scan --repo /path/to/project --budget 20 --sarif --html
```

| Flag | Output |
| --- | --- |
| `--sarif` | SARIF 2.1.0 findings for compatible code-scanning tools. |
| `--html` | HTML report. Requires Pandoc. |
| `--pdf` | PDF report. Requires Pandoc and WeasyPrint; diagrams may also need Mermaid CLI and Chrome. |
| `--threatdragon` | OWASP Threat Dragon model. |
| `--pentest-tasks` | Tasks for follow-up penetration testing. |

Exports run as part of the assessment. There is currently no public command to export an existing result without rerunning analysis.

To choose where results are stored, create a directory outside every selected repository and pass it with `--output`. For `scan-sources`, this saves `scan-result.json` in addition to printing the summary.

## More commands

Use the same CLI for a combined assessment, a focused security question, or a requirements audit.

| Task | Command | Guide |
| --- | --- | --- |
| Assess several repositories together | `scan --repo /path/to/api --repo /path/to/client --budget 30` | [Security assessment](docs/security-assessment.md) |
| Select the model host explicitly | `assess --repo /path/to/project --host claude-cli --budget 20` | [Hosts and models](docs/model-selection.md) |
| Review a design, code change, or threat hypothesis | `analyst design`, `analyst review`, `analyst hypothesis` | [Threat Analyst](docs/threat-analyst.md) |
| Check a security requirements catalog, optionally as a CI gate | `audit-requirements` | [Requirements audit](docs/security-requirements-audit-skill.md) |
| Show available scanners and provider qualification | `capabilities` | [Configuration](docs/configuration.md) |

Prefix each command with `appsec-analyzer`. Add `--help` to see its arguments. Focused analysis and requirements audits also make paid model calls; their guides explain the required inputs and budget controls. `scan` and `assess` run the same full assessment; `assess` requires an explicit `--host`.

Repeated `--repo` arguments combine repositories into one system. You can also supply explicit HTTPS or SSH Git URLs. Fetching a remote repository requires network access, including for a source scan.

## Security and data use

**Model-backed commands send source excerpts and context to the selected provider.** This includes full assessments, focused analysis, and requirements audits. Check your organization's rules and the provider's data-handling terms before analyzing confidential code. `scan-sources` does not send source to a model.

Repositories are treated as untrusted input by default. Repository content cannot authorize tools or select provider credentials. Keep credentials outside repository files and Git URLs, and treat reports and intermediate files as sensitive.

The Claude CLI adapter is available. The experimental OpenAI profiles have offline protocol and budget tests, but have not completed live assessment qualification. The gateway adapter is not available through the public CLI. See the [security policy](SECURITY.md) for boundaries, data handling, and vulnerability reporting.

## Documentation

- [Security assessment](docs/security-assessment.md): scope, depth, output, and recovery.
- [Scan and model profiles](docs/profiles.md): defaults, user files, examples, and per-role model selection.
- [Configuration](docs/configuration.md) and [organization profiles](docs/org-profiles.md): settings for local and team use.
- [Hosts, models, and cost](docs/model-selection.md): provider support and spending controls.
- [Command-line operation](docs/headless-mode.md): unattended runs and lifecycle commands.
- [Documentation index](docs/README.md): all current guides and maintainer references.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and tests, and [product requirements](requirements.md) for intended behavior. Read [AGENTS.md](AGENTS.md) before changing runtime behavior or report contracts.

AppSec Analyzer grew out of [AppSec Advisor](https://github.com/appsec-foundry/appsec-advisor) and is distributed under the [Apache 2.0 license](LICENSE).
