# appsec-analyzer

[![Version](https://img.shields.io/badge/version-0.1.0a0-orange.svg)](engine.json)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](setup.py)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude CLI](https://img.shields.io/badge/default%20provider-Claude%20CLI-5A67D8.svg)](docs/model-selection.md)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

> [!NOTE]
> **Alpha.** Commands and report formats may change. Live assessment quality is still being qualified; review findings before acting on them.

AppSec Analyzer reviews application security from source code. It maps components, data flows, and trust boundaries, checks the security controls it finds, and reports findings with code references and suggested fixes. It works on one Git repository or on several repositories that form one system.

It does not scan dependencies for known CVEs, search comprehensively for secrets, or test the running application. Deployment controls and business assumptions still need your own review.

If you work in Claude Code, you can use AppSec Analyzer through [AppSec Advisor](https://github.com/appsec-foundry/appsec-advisor), which packages it as a Claude Code plugin.

[Quick start](#quick-start) · [Commands](#commands) · [Data use](#security-and-data-use) · [Install](#install) · [Options](#options) · [Abuse cases](#abuse-cases) · [Reports](#reports-and-exports) · [Documentation](#documentation)

## Quick start

This example assesses the intentionally vulnerable [OWASP Juice Shop](https://github.com/juice-shop/juice-shop). You need Python 3.10+, Git, [pipx](https://pipx.pypa.io/stable/), and a set-up [model provider](#model-provider).

1. **Install Analyzer** from GitHub (preview):

   ```sh
   pipx install git+https://github.com/appsec-foundry/appsec-analyzer.git
   ```

2. **Run a full assessment.** Analyzer creates the output directory, readable only by you, and writes the report to `security-assessment.md` there:

   ```sh
   appsec-analyzer assess --repo https://github.com/juice-shop/juice-shop.git \
     --output ~/assessments/juice-shop
   ```

   For your own code, pass its Git URL or local path to `--repo`.

3. **Review the findings with your coding agent.** Discuss the results and plan fixes in Claude Code or Codex:

   ```sh
   appsec-analyzer review ~/assessments/juice-shop
   ```

> [!NOTE]
> With API billing, the Juice Shop scan costs about USD 14. Analyzer asks before it exceeds the default limit of USD 20.

## Commands

`appsec-analyzer <command> --help` lists the options of each command. Commands with model calls send source excerpts to your provider (see [Security and data use](#security-and-data-use)) and stay within the default cost limit shown below. Change it with `--budget`, or `--max-budget-usd` for `analyze-threats`.

| Command | Purpose | Model calls |
| --- | --- | --- |
| [`assess`](#assess-full-security-assessment) | Full security assessment of a repository or a system of repositories. | Yes, up to USD 20 |
| [`review`](#review-discuss-an-assessment-with-your-coding-agent) | Discuss a finished assessment and plan fixes with an AI coding assistant. | Through the assistant's own account |
| [`analyze-threats`](#analyze-threats-answer-a-security-question) | Answer one security question about the code, a planned design, or a change. | Yes, up to USD 1 per call |
| [`authnz-review`](#authnz-review-authentication-and-authorization-review) | Review authentication and authorization only. | Yes, up to USD 5 |
| [`audit-requirements`](#audit-requirements-requirements-audit) | Check a repository against a security requirements catalog. | Yes, up to USD 5 |
| [`score`](#score-deterministic-security-rating) | Quick security rating from 0 to 100. | No |
| [`scan-sources`](#scan-sources-raw-scanner-observations) | Raw scanner observations without a rating. | No |
| [`abuse-cases`](#abuse-cases-list-the-defined-cases) | List the defined abuse cases, or show one with the result a saved assessment records. | No |
| [`repo-profile`](#repo-profile-size-languages-and-layout) | Size, languages, and build manifests of a local directory before a scan. | No |
| [`platform-settings`](#platform-settings-github-and-gitlab-security-settings) | Security settings of a GitHub or GitLab repository, such as branch protection. | No |
| [`distribution`](#distribution-start-your-organizations-own-command) | Create the files for your organization's own command, and align its engine pins after an engine update. | No |
| [`export`](#export-other-report-formats) | Convert a finished assessment to SARIF, HTML, PDF, and other formats. | No |

### `assess`: full security assessment

`assess` analyzes one repository, or several repositories as one system, and writes the full assessment report. See [Security assessment](docs/security-assessment.md).

```sh
# Assess a local checkout
appsec-analyzer assess --repo /path/to/project

# Assess a remote repository; Analyzer clones it into a temporary directory
appsec-analyzer assess --repo https://github.com/your-org/your-project.git

# Assess a backend and its web frontend together as one system
appsec-analyzer assess --repo /path/to/backend --repo /path/to/frontend
```

With `--non-interactive`, `assess` requires `--repo` and an explicit `--profile`, so a script or CI job never starts on a default provider. See [Hosts and models](docs/model-selection.md).

```sh
# Run in CI with a fixed provider profile and without questions
appsec-analyzer assess --repo /path/to/project --profile claude --non-interactive
```

### `review`: discuss an assessment with your coding agent

`review` opens a finished assessment in Claude Code or Codex so you can discuss findings and plan fixes. The assistant starts in read-only mode and uses its own account, not the scan budget. `--preview` shows what the assistant would receive, without starting it. See [Review guide](docs/security-assessment.md#review-an-assessment-with-ai).

```sh
# Discuss the findings with the assistant recorded in the assessment
appsec-analyzer review /path/to/assessment

# Use Codex instead
appsec-analyzer review /path/to/assessment --with codex
```

### `analyze-threats`: answer a security question

`analyze-threats` answers one security question about the current code, a planned design, or a selected change. It needs no prior assessment. See [Threat Analyst](docs/threat-analyst.md).

This is more than pasting the question into a chat. The command reads only the files or the change you select, takes your requirements and threat model into account, and reports a finding only when the source code backs it up. The report lists the documents it used.

```sh
# Ask about one part of the code
appsec-analyzer analyze-threats "Can a normal user read another tenant's records?" --path src/api

# Use case: before you commit, check whether the staged change breaks
# a requirement or contradicts your threat model
appsec-analyzer analyze-threats "Does this change violate our requirements?" --staged \
  --context requirements.md --context docs/security/threatmodel.md

# Review a GitHub pull request (GitLab: --mr); --preview shows the scope without a model call
appsec-analyzer analyze-threats --pr https://github.com/team/app/pull/42 --preview
```

`--design-file`, `--context`, `--mr`, and `--pr` take documents or a remote change as input. Documents given with `--context` add background and do not replace the question or the change under review.

### `authnz-review`: authentication and authorization review

`authnz-review` checks the routes, login checks, and permission checks of one repository. It needs no prior assessment. See [AuthNZ review](docs/authnz-review.md).

```sh
# Review login and permission checks
appsec-analyzer authnz-review --repo /path/to/project

# Save the report and fail a CI job on Critical or High findings
appsec-analyzer authnz-review --repo /path/to/project --save --gate
```

### `audit-requirements`: requirements audit

`audit-requirements` checks whether a repository implements each requirement of a local YAML catalog. The output directory must already exist. See [Requirements audit](docs/security-requirements-audit-skill.md).

```sh
# Try the audit with the bundled sample catalog
mkdir /path/to/audit
appsec-analyzer audit-requirements --repo /path/to/project --demo --output /path/to/audit --host claude-cli

# Check your own catalog and write a Markdown report
appsec-analyzer audit-requirements --repo /path/to/project \
  --requirements /path/to/catalog.yaml --output /path/to/audit --host claude-cli --md
```

### `score`: deterministic security rating

`score` rates a local checkout or Git URL from 0 to 100 and lists findings, coverage, and limits. It sees only what its rules cover and reports `undetermined` when coverage is too low. It does not replace `assess`. See [Security score](docs/security-score.md).

```sh
# Rate a local checkout
appsec-analyzer score /path/to/project

# Rate a remote repository and print JSON for scripts
appsec-analyzer score https://github.com/your-org/your-project.git --json
```

### `scan-sources`: raw scanner observations

`scan-sources` lists unverified observations from the authorization, mass-assignment, and configuration scanners, with their coverage. It does not replace `assess`.

```sh
# Show what the scanners found, without a rating
appsec-analyzer assess-sources --repo /path/to/project
```

### `abuse-cases`: list the defined cases

`abuse-cases` lists the technical and business [abuse cases](#abuse-cases) a run in this repository would load, with origin, kind, and title. With an ID it shows that case's definition and what the saved assessment records for it. It is read-only and does not check a case against the code; use `analyze-threats --abuse-case <ID>` for that.

```sh
# List all cases, or show one
appsec-analyzer abuse-cases --repo /path/to/project
appsec-analyzer abuse-cases AC-B-001 --repo /path/to/project
```

### `repo-profile`: size, languages, and layout

`repo-profile` shows what a scan would have to read: working-tree size, how much of it is installed dependencies or build output, the language split by bytes, the build manifests and whether they sit in one root or several, and tracked versus untracked content. It reads directory entries only and passes no judgement on security.

```sh
# Profile the current directory, or print JSON for scripts
appsec-analyzer repo-profile /path/to/project --json
```

### `platform-settings`: GitHub and GitLab security settings

`platform-settings` checks security settings of a repository on github.com or gitlab.com, such as required reviews, blocked force pushes, secret scanning, and workflow permissions. It sends read requests to the platform API only, makes no model calls, and sends no source code. Each of seven checks is reported as `set`, `not set`, or `not checkable`, with the reason. Without a read-only token only public data is visible, so many results are `not checkable`. See [Platform security settings](docs/platform-security-settings.md).

```sh
# Public data only
appsec-analyzer platform-settings https://github.com/your-org/your-project

# With a read-only token held in an environment variable
appsec-analyzer platform-settings https://github.com/your-org/your-project --token-env GITHUB_READ_TOKEN --json
```

`assess` runs the same checks for repositories selected as a URL (add `--platform-token-env NAME` for a read-only token); local checkouts are skipped. Controls and STRIDE use the result as context, and the report shows it in a Platform Security Settings section.

### `distribution`: start your organization's own command

`distribution` helps an organization ship its own command, such as `northstar-appsec`, on top of this engine. It reads and writes local files only: no model calls, no network, no build, and nothing existing is overwritten.

```sh
# Create the organization repository from the example, under your name
appsec-analyzer distribution init northstar ./northstar-appsec

# After installing a newer engine: set every engine pin in that repository to it
appsec-analyzer distribution update-engine ./northstar-appsec
```

`init` needs a name of 2 to 30 lowercase letters and digits, and a directory that does not exist or is empty. The profiles, context, abuse cases and requirements it creates are sample content to replace. `update-engine` changes the engine version in `setup.cfg`, `requirements.lock` and `organization.yaml`, and stops without changes if one is missing. Building the wheels, installing and releasing remain manual; see the [organization packaging guide](docs/organization-distributions.md).

### `export`: other report formats

`export` writes a finished assessment to other formats. The destination must be a new directory outside any Git checkout. See [Reports and exports](#reports-and-exports).

```sh
# Create SARIF for code scanning and HTML for reading
appsec-analyzer export --assessment /path/to/assessment --output /path/to/export --formats sarif html
```

### Helper commands

| Command | Purpose |
| --- | --- |
| `preflight` | Checks repository access and provider setup before you spend budget. |
| `status`, `progress`, `results`, `stop` | Follow, inspect, or stop a running assessment. |
| `profiles` | Lists and validates scan and model profiles. |
| `capabilities` | Shows the available scanners and provider qualification. |

## Security and data use

> [!IMPORTANT]
> **Model-backed commands send source excerpts and context to the selected provider.** Check your organization's rules and the provider's data-handling terms before you analyze confidential code.

`score` and `scan-sources` send no source to a model. They still need network access when you pass a Git URL.

Analyzed repositories are untrusted input: their content cannot authorize tools or select provider credentials. Keep credentials out of repository files and Git URLs, and treat reports and intermediate files as sensitive. See the [security policy](SECURITY.md).

## Install

pipx creates its own virtual environment and puts `appsec-analyzer` on your `PATH`. The install command only works if the repository is reachable for your GitHub account. The package is not yet on PyPI.

<details>
<summary>Install with pip or from a local checkout</summary>

With `pip`, inside an activated virtual environment:

```sh
python -m pip install "git+https://github.com/appsec-foundry/appsec-analyzer.git"
```

From a local checkout, for example to install local changes:

```sh
git clone https://github.com/appsec-foundry/appsec-analyzer.git
cd appsec-analyzer
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
appsec-analyzer version
```

`pipx install .` from the checkout works as well. [Local release preparation](docs/local-release-preparation.md) explains how to build a wheel.

</details>

<details>
<summary>Run from a checkout without installing</summary>

Install the runtime dependencies listed in [setup.py](setup.py) first (PyYAML, jsonschema, and Jinja2).

```sh
cd /path/to/appsec-analyzer
python3 -m appsec_analyzer.cli scan-sources --repo /path/to/project
```

Replace `appsec-analyzer` with `python3 -m appsec_analyzer.cli` in all examples and always pass `--repo`, because it defaults to the current directory.

</details>

### Model provider

`score` and `scan-sources` need no provider. `assess` selects its provider with `--profile`; without it, `assess` uses `claude`. `analyze-threats`, `authnz-review`, and `audit-requirements` always use the Claude CLI.

| `--profile` | Provider | Requirement |
| --- | --- | --- |
| `claude` (default) | Claude CLI | `claude` on your `PATH` with a working login or externally configured Anthropic API credentials. |
| `codex` (experimental) | OpenAI API | `OPENAI_API_KEY`. |
| `codex-cli` (experimental) | Codex CLI with your ChatGPT plan | Codex CLI 0.163.0, signed in with `codex login`. See [Codex CLI setup and limits](docs/profiles.md#use-your-chatgpt-plan-with-codex-cli). |
| `lite` (experimental) | LiteLLM gateway | `LITELLM_API_KEY` and a gateway entry in `providers.yaml` with verified prices. See [LiteLLM setup](docs/providers.md#use-litellm). |
| `bedrock` (experimental) | Amazon Bedrock Converse API | `AWS_BEARER_TOKEN_BEDROCK` and a Bedrock entry in `providers.yaml` with verified prices. See [Bedrock setup](docs/providers.md#use-amazon-bedrock). |

The experimental profiles have not yet been qualified in live assessments. `appsec-analyzer profiles list` shows all built-in and user profiles.

```sh
# Check the provider setup without model calls
appsec-analyzer preflight --repo /path/to/project --profile codex

# OpenAI API
appsec-analyzer assess --repo /path/to/project --profile codex

# Codex CLI with a ChatGPT plan: counts model exchanges instead of USD
codex login
appsec-analyzer assess --repo /path/to/project --profile codex-cli --max-calls 1000

# LiteLLM gateway: "claude" names the model entry in providers.yaml
appsec-analyzer assess --repo /path/to/project --profile "lite claude" --budget 20

# Amazon Bedrock
appsec-analyzer assess --repo /path/to/project --profile bedrock --budget 20
```

`codex-cli` rejects USD budget options; limit it with `--max-calls` and optionally `--max-duration SECONDS`. All other profiles use the USD budget from `--budget`.

[Configuration](docs/configuration.md) describes provider setup in detail. Organizations can ship preconfigured profiles; see the [organization packaging guide](docs/organization-distributions.md).

## Options

Command-line options override the defaults from a scan profile.

| Option | Effect |
| --- | --- |
| `--profile NAME` | Model profile. Default: `claude`. |
| `--budget USD` | Maximum spend for `claude`, `codex`, LiteLLM, and Bedrock. Default: 20. |
| `--assessment-depth LEVEL` | `quick` (no business-logic checks), `standard` (default), or `thorough`. With Claude, `thorough` uses Opus for STRIDE and cost about 1.8× as much in one Juice Shop comparison, without more verified results. See [choosing standard or thorough](docs/model-selection.md#choosing-standard-or-thorough). |
| `--repo PATH_OR_URL` | Repeat to assess several repositories as one system. |
| `--abuse-case-file PATH` | Check your own business rules from a YAML file. See [custom abuse cases](docs/security-assessment.md#custom-abuse-cases). |
| `--max-parallel N` | Components analyzed at once, 1 to 16. Default: 2. |
| `--non-interactive` | For CI. Without it, an interactive terminal may ask for a higher budget before skipping work. |
| `--verbose` | Show job and call identities and detailed correction messages. |

[Scan and model profiles](docs/profiles.md) explains how to store settings and choose models per role.

## Abuse cases

An abuse case is something an attacker or a user must not be able to do. Analyzer comes with two sets. [business.yaml](data/abuse-cases/business.yaml) has seven business rules: a user must not, for example, see other users' data, give themselves a higher role, approve their own request, or redeem a coupon twice. [technical.yaml](data/abuse-cases/technical.yaml) has attack chains such as account takeover through XSS or admin access through a forged JWT.

`assess` checks the cases that fit the code, except at `quick` depth. A standard run checks up to three business rules, a thorough run up to eight. If the code allows an abuse case, the report gets a new finding or links the case to an existing one. A confirmed attack chain can also raise the severity of its findings. The results are in section 9 of the report. When the code does not answer the question, the case stays open. It is not counted as safe.

To add your own rules, put them in a YAML file in the repository and pass it to `assess`:

```sh
appsec-analyzer assess --repo /path/to/project \
  --abuse-case-file abuse-cases.yaml
```

For example, `abuse-cases.yaml`:

```yaml
schema_version: 2
abuse_cases:
  - id: REPO-AC-001
    kind: descriptive
    title: Customer lowers the order total with a negative quantity
    check: Check whether a customer can put a negative quantity of a product into the basket and so lower the order total.
    scope_qualifier: {path_patterns: ["*cart*", "*order*"]}
```

The path is relative to the repository root. Rules passed this way are also checked at `quick` depth. Limits and further fields are described under [custom abuse cases](docs/security-assessment.md#custom-abuse-cases). To use the same rules in several repositories, put them in an [organization profile](docs/org-profiles.md#business-abuse-cases). To check a single built-in or organization case without a full assessment, run `analyze-threats --abuse-case <ID>`.

## Reports and exports

Each assessment writes `security-assessment.md` for reading and `security-assessment.yaml` for further processing. The report includes diagrams of the analyzed system. The two details below come from an assessment of OWASP Juice Shop; click a diagram to open it in full.

The runtime architecture with its data flows and attack paths:

<a href="docs/images/figure1-example.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/figure1-example-crop-dark.svg">
  <img src="docs/images/figure1-example-crop.svg" alt="Detail of the runtime architecture and attack paths in the Juice Shop assessment">
</picture>
</a>

The build pipeline and the most severe supply-chain attacks on it:

<a href="docs/images/figure1b-example.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/figure1b-example-crop-dark.svg">
  <img src="docs/images/figure1b-example-crop.svg" alt="Detail of the build pipeline and supply-chain attack paths in the Juice Shop assessment">
</picture>
</a>

Request more formats when you start the scan, for example `assess --repo /path/to/project --sarif --html`:

| Flag | Output |
| --- | --- |
| `--sarif` | SARIF 2.1.0 findings for code-scanning tools. |
| `--html` | HTML report. Requires Pandoc. |
| `--pdf` | PDF report. Requires Pandoc and WeasyPrint; diagrams may also need Mermaid CLI and Chrome. |
| `--threatdragon` | OWASP Threat Dragon model. |
| `--pentest-tasks` | Tasks for follow-up penetration testing. |

To export a finished assessment later:

```sh
appsec-analyzer export --assessment /path/to/assessment \
  --output /path/to/new-export --formats markdown yaml sarif html
```

The export directory must be new and outside any Git checkout. See [export prerequisites and limits](docs/security-assessment.md#exports-and-compatibility).

## Documentation

- [Security assessment](docs/security-assessment.md): scope, depth, output, and recovery.
- [Scan and model profiles](docs/profiles.md): defaults, user files, and per-role model selection.
- [Configuration](docs/configuration.md) and [organization profiles](docs/org-profiles.md): settings for local and team use.
- [Hosts, models, and cost](docs/model-selection.md): provider support and spending limits.
- [Command-line operation](docs/headless-mode.md): unattended runs and lifecycle commands.
- [Documentation index](docs/README.md): all current guides and maintainer references.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and tests, and [product requirements](requirements.md) for intended behavior. Read [AGENTS.md](AGENTS.md) before changing runtime behavior or report contracts.

AppSec Analyzer grew out of AppSec Advisor and is distributed under the [Apache 2.0 license](LICENSE).
