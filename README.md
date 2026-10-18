# appsec-analyzer

[![Version](https://img.shields.io/badge/version-0.1.0a0-orange.svg)](engine.json)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](setup.py)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude CLI](https://img.shields.io/badge/default%20provider-Claude%20CLI-5A67D8.svg)](docs/model-selection.md)
[![Security assessment](https://img.shields.io/badge/security%20assessment-repository--based-5A67D8)](docs/security-assessment.md)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

> [!NOTE]
> **Alpha.** Commands and report formats may change. Live assessment quality is still being qualified; review findings before acting on them.

AppSec Analyzer is a command-line tool for reviewing application security from source code. It maps components, data flows, and trust boundaries, checks the security controls it finds, and reports findings with code references and suggested fixes.

Use it when you take over an unfamiliar codebase, prepare a security review, or need to decide what to fix next. It works on a single Git repository or on several repositories that form one system.

There are two kinds of commands. `scan-sources` and `score` run rule-based scanners locally and make no model calls. `scan` and `assess` run a full assessment that sends source excerpts to a model provider; by default this is Claude CLI with a spending limit of USD 20.

[What it checks](#what-it-checks) · [Security](#security-and-data-use) · [Install](#install) · [Quick start](#quick-start) · [Configuration](#configure-an-assessment) · [Reports](#reports-and-exports) · [More commands](#more-commands) · [Documentation](#documentation) · [Contributing](#contributing)

## What it checks

A full assessment helps answer these questions:

- How do the components communicate, and where does data cross a trust boundary?
- Which security controls are present, missing, or implemented incorrectly?
- Which weaknesses and attack paths does the code support?
- What should the team fix first, and how can it verify the fix?

The assessment covers implementation weaknesses and design risks. It ties each finding to the architecture and keeps supported findings apart from open questions. You can add business context, security requirements, your own abuse cases, and organization settings to guide the analysis.

It does not perform SCA/CVE scanning, comprehensive secret scanning, or runtime testing. Source code also cannot show how the application behaves in production, so the team still has to review deployment controls, business assumptions, and the findings themselves.

## Security and data use

> [!IMPORTANT]
> **Model-backed commands send source excerpts and context to the selected provider.** This applies to full assessments, focused analysis, and requirements audits. Check your organization's rules and the provider's data-handling terms before you analyze confidential code.

`scan-sources` and `score` send no source to a model. They still need network access when you pass a Git URL instead of a local path.

Analyzed repositories are treated as untrusted input. Their content cannot authorize tools or select provider credentials. Keep credentials out of repository files and Git URLs, and treat reports and intermediate files as sensitive.

The Claude CLI adapter is the default. The OpenAI, Codex CLI, LiteLLM, and Bedrock profiles are experimental and have not completed live assessment qualification. The [security policy](SECURITY.md) covers boundaries, data handling, and vulnerability reporting.

## Install

You need **Python 3.10+**, **Git**, and [pipx](https://pipx.pypa.io/stable/) on your `PATH`. Install the current preview from the `dev` branch:

```sh
pipx install "git+https://github.com/appsec-foundry/appsec-analyzer.git@dev"
appsec-analyzer version
```

pipx creates its own virtual environment and puts `appsec-analyzer` on your `PATH`. The command only works if the `dev` branch is reachable for your GitHub account.

To use `pip` instead, run this inside an activated virtual environment:

```sh
python -m pip install "git+https://github.com/appsec-foundry/appsec-analyzer.git@dev"
```

The package is not yet on PyPI, so `pip install appsec-analyzer` does not work. [Local release preparation](docs/local-release-preparation.md) explains how to build and install a wheel locally.

<details>
<summary>Install from a local checkout</summary>

Use this if you want to install local changes:

```sh
git clone --branch dev https://github.com/appsec-foundry/appsec-analyzer.git
cd appsec-analyzer
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
appsec-analyzer version
```

With pipx, `pipx install .` from the checkout works as well. The commands above are for bash or zsh; keep the virtual environment active while you use Analyzer.

</details>

<details>
<summary>Run from a checkout without installing</summary>

You can run the CLI as a Python module. `python3` then needs the runtime dependencies from [setup.py](setup.py): `PyYAML>=6,<7`, `jsonschema>=4.20,<5`, and `Jinja2>=3.1,<4`.

```sh
cd /path/to/appsec-analyzer
python3 -m appsec_analyzer.cli version
python3 -m appsec_analyzer.cli scan-sources --repo /path/to/project
```

In all later examples, replace `appsec-analyzer` with `python3 -m appsec_analyzer.cli` and stay in the Analyzer checkout. Always pass `--repo`, because it defaults to the current directory.

</details>

### Model provider

The source scan and score need no provider. For a full assessment, set up one of these:

| Profile | Requirement |
| --- | --- |
| `claude` (default) | `claude` on your `PATH` with a working login or externally configured Anthropic API credentials. |
| `codex` (experimental) | `OPENAI_API_KEY`. |
| `codex-cli` (experimental) | Codex CLI 0.163.0 signed in with a ChatGPT plan. See [Codex CLI setup and limits](docs/profiles.md#use-your-chatgpt-plan-with-codex-cli). |
| `bedrock` and LiteLLM (experimental) | An external Bedrock API key or LiteLLM gateway with verified connection and price settings. See [LiteLLM and Bedrock setup](docs/providers.md). |

[Profile configuration](docs/configuration.md) describes provider setup in detail. Organizations can also ship their own package with preconfigured profiles; see the [organization packaging guide](docs/organization-distributions.md).

## Quick start

In the examples, replace `/path/to/project` with the Git repository you want to examine and `/path/to/assessment` with a result directory.

### 1. Scan without model calls

```sh
appsec-analyzer scan-sources --repo /path/to/project
appsec-analyzer score /path/to/project
```

`scan-sources` prints observations from the authorization, mass-assignment, and configuration scanners that apply to the repository, together with their coverage. These observations are unverified and do not replace a full assessment.

`score` shows a score from 0 to 100 with findings, coverage, and limits. It also accepts an HTTPS or SSH Git URL. If coverage is too low, it reports `undetermined` instead of a number. See [security scoring](docs/security-score.md) for interpretation and exit codes.

Both commands accept `--json`; `score` also accepts `--yaml`. Progress goes to stderr and the result to stdout. With `--output DIR`, `scan-sources` also saves `scan-result.json` there and never overwrites an existing result.

### 2. Run a full assessment

Run this from the repository you want to assess, or add `--repo /path/to/project`:

```sh
appsec-analyzer scan
```

This makes paid model calls with a default limit of **USD 20**. Use `--budget 10` to choose another limit. The limit is a maximum, not an estimate. If the remaining budget cannot cover required work, the run keeps its progress and reports the assessment as incomplete.

Before any model call, `scan` checks repository access and provider setup. You can run the same checks on their own with `appsec-analyzer preflight --repo /path/to/project --profile claude`; see [preflight checks and limits](docs/security-assessment.md#preflight-checks).

Results go to a private directory under your user's `appsec-analyzer/assessments` data directory, outside the analyzed repository. They include `security-assessment.md` for reading and `security-assessment.yaml` for further processing. To choose the location, pass `--output` with a directory outside every analyzed repository.

To use your ChatGPT plan instead of a USD budget:

```sh
codex login
appsec-analyzer scan --profile codex-cli --max-calls 1000
```

This profile counts model exchanges instead of money and rejects USD budget options. Source excerpts still leave the machine.

### 3. Follow, resume, and review a run

```sh
# Show the run state and the published files
appsec-analyzer status --output /path/to/assessment
appsec-analyzer results --output /path/to/assessment

# Continue an interrupted run with compatible source and settings
appsec-analyzer scan --repo /path/to/project --output /path/to/assessment --resume

# Discuss findings and plan fixes in Claude Code or Codex
appsec-analyzer review /path/to/assessment
```

`progress` and `stop` with `--output` let you watch or stop a run from another terminal. See [command-line operation](docs/headless-mode.md) for unattended runs and recovery.

`review` hands the saved reports and a bundled review skill to your coding assistant. By default it uses the assistant recorded in the assessment; `--with codex` selects another, and `--preview` shows the handoff without model calls. The review starts in read-only mode and is billed to that assistant's account, separately from the scan budget. See [reviewing an assessment](docs/security-assessment.md#review-an-assessment-with-ai).

## Configure an assessment

Command-line options override the defaults from a scan profile. The most common ones:

| Option | Effect |
| --- | --- |
| `--profile NAME` | Model profile. Default: `claude`. |
| `--assessment-depth LEVEL` | Default: `standard`, which includes business-logic analysis. `thorough` can cost more without producing more verified results; see [choosing standard or thorough](docs/model-selection.md#choosing-standard-or-thorough). |
| `--budget USD` | Maximum spend for `claude`, `codex`, LiteLLM, and Bedrock. `--hard-budget` is an alias. |
| `--repo PATH_OR_URL` | Repeat to assess several repositories as one system. |
| `--abuse-case-file PATH` | Check your own business rules from a YAML file in the repository. See [custom abuse cases](docs/security-assessment.md#custom-abuse-cases). |
| `--max-parallel N` | Components analyzed at once, 1 to 16. Default: 2. Higher values can hit provider rate limits. |
| `--non-interactive` | For CI and unattended runs. Without it, an interactive terminal may ask for a higher budget before skipping work. |
| `--verbose` | Show job and call identities and detailed correction messages. |

[Scan and model profiles](docs/profiles.md) explains how to store these settings and how to choose models per role. Check a profile with `appsec-analyzer profiles show NAME` or `appsec-analyzer profiles validate NAME`.

When a provider rate-limits the run, Analyzer retries and then pauses with exit code 3 if the wait is too long. Accepted work is kept; rerun the same command with `--resume` once capacity is back. [Security assessment](docs/security-assessment.md) describes retries, coverage reporting, source-read failures, and diagnostics.

## Reports and exports

The Markdown report describes the architecture, security controls, findings, open questions, and prioritized remediation. The YAML file holds the same assessment as structured data.

Request additional formats when you start the assessment:

```sh
appsec-analyzer scan --repo /path/to/project --sarif --html
```

| Flag | Output |
| --- | --- |
| `--sarif` | SARIF 2.1.0 findings for code-scanning tools. |
| `--html` | HTML report. Requires Pandoc. |
| `--pdf` | PDF report. Requires Pandoc and WeasyPrint; diagrams may also need Mermaid CLI and Chrome. |
| `--threatdragon` | OWASP Threat Dragon model. |
| `--pentest-tasks` | Tasks for follow-up penetration testing. |

To export a completed assessment later, without model calls:

```sh
appsec-analyzer export --assessment /path/to/assessment \
  --output /path/to/new-export --formats markdown yaml sarif html
```

The export directory must be new and outside any Git checkout. See [export prerequisites and limits](docs/security-assessment.md#exports-and-compatibility).

## More commands

Prefix each command with `appsec-analyzer` and add `--help` for its options.

| Task | Command | Guide |
| --- | --- | --- |
| Assess several repositories together | `scan --repo /path/to/api --repo /path/to/client --budget 30` | [Security assessment](docs/security-assessment.md) |
| Select the model host explicitly | `assess --repo /path/to/project --host claude-cli --budget 20` | [Hosts and models](docs/model-selection.md) |
| Ask a security question or review a design, change, MR, or PR | `analyze-threats "Question" --path src/api`, `analyze-threats --staged`, `analyze-threats --mr URL` | [Threat Analyst](docs/threat-analyst.md) |
| Review authentication and authorization | `authnz-review --repo /path/to/project --budget 5` | [AuthNZ review](docs/authnz-review.md) |
| Check a security requirements catalog, optionally as a CI gate | `audit-requirements` | [Requirements audit](docs/security-requirements-audit-skill.md) |
| Show scanners and provider qualification | `capabilities` | [Configuration](docs/configuration.md) |

`scan` and `assess` run the same assessment; `assess` requires `--host`. `analyze-threats`, `authnz-review`, and `audit-requirements` also make paid model calls. Their guides list the required inputs and budget options.

## Documentation

- [Security assessment](docs/security-assessment.md): scope, depth, output, and recovery.
- [Scan and model profiles](docs/profiles.md): defaults, user files, and per-role model selection.
- [Configuration](docs/configuration.md) and [organization profiles](docs/org-profiles.md): settings for local and team use.
- [Hosts, models, and cost](docs/model-selection.md): provider support and spending limits.
- [Command-line operation](docs/headless-mode.md): unattended runs and lifecycle commands.
- [Documentation index](docs/README.md): all current guides and maintainer references.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and tests, and [product requirements](requirements.md) for intended behavior. Read [AGENTS.md](AGENTS.md) before changing runtime behavior or report contracts.

AppSec Analyzer grew out of [AppSec Advisor](https://github.com/appsec-foundry/appsec-advisor) and is distributed under the [Apache 2.0 license](LICENSE).
