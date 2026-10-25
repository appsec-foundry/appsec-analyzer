# Configuration

Use this guide to choose a command, set its spending limit, and configure repository and provider access. Save settings you reuse in a [scan profile](profiles.md).

An [organization distribution](organization-distributions.md) can provide its own command with bundled scan, model, and organization defaults. The upstream `appsec-analyzer` command keeps its defaults.

## Assessment settings

`appsec-analyzer assess` accepts local paths or explicitly selected HTTPS/SSH Git URLs through `--repo`. You can also select an output directory, profile, depth, and trust mode. Defaults are the current directory, standard depth, and your `default` scan profile if present, otherwise `claude`. With `--non-interactive`, name the repository and profile explicitly (or use the compatible `--host` option). Run `assess --help` for all options.

Select `--profile claude`, `codex`, `codex-cli`, or `copilot-cli` for Claude CLI, OpenAI API, Codex CLI, or GitHub Copilot CLI. The last three are experimental. Profiles set models, depth, budget or call limit, exports, and report attributes. Explicit CLI options override profile defaults.

Store your YAML files under `~/.config/appsec-analyzer/profiles/` and `model-profiles/`, or select an external scan file. See [scan and model profiles](profiles.md) for examples and [models and cost](model-selection.md) for provider defaults.

Use `--org-profile FILE` and optionally `--preset NAME` to select [organization defaults](org-profiles.md). `--no-org-profile` disables them for the run.

For custom abuse cases in a single-repository assessment, repeat `--abuse-case-file PATH` or save repository-relative YAML paths in the scan profile's `abuse_case_files` list. CLI selections replace that list. Files can live anywhere inside the repository; the former `docs/security/abuse-cases/` and `.appsec/abuse-cases/` locations remain automatic compatibility inputs. See [custom abuse cases](security-assessment.md#custom-abuse-cases) for the format, model costs, and limits.

## Other commands

`scan-sources` runs fixed checks without a model account. It supports repeated `--repo`, depth, trust mode, an existing external output directory, and `--json`. Git URLs still require a download.

`score REPO` gives a quick scanner-based indication without model calls. It accepts one top-level Git checkout or explicit Git URL, with text, JSON, or YAML output. It uses no model profile or budget and writes nothing into the checkout. See [security scoring](security-score.md) for coverage and limits.

`analyze-threats` answers a focused question about selected code, a design, or a change. It uses Claude CLI and a per-call budget. Select background documents with repeatable `--context FILE`. See [focused threat analysis](threat-analyst.md) for scope and remote-review options.

[AuthNZ review](authnz-review.md) checks authentication and authorization in one local checkout through Claude CLI. It accepts explicit requirements and can save reports and pentest plans. Saved output needs an empty private directory outside the source; `--save` creates a fresh application subdirectory.

## Git repository access

Keep credentials out of Git URLs. HTTPS can use your Git credential helper or external `APPSEC_GIT_TOKEN` and optional `APPSEC_GIT_USERNAME`. SSH uses existing authentication and trusted host keys; `APPSEC_GIT_SSH_KEY_FILE` selects an external key file.

Set `APPSEC_URL_ALLOWLIST` to restrict destinations to exact hostnames, separated by commas. Retrieval rejects prohibited network addresses, disables redirects, and does not load repository-owned Git hooks or filters.

## Spending limits

`assess` makes model calls. The `claude` and `codex` profiles default to USD 20; `audit-requirements` and `authnz-review` default to USD 5. Set a positive, finite `--budget USD` to change the limit. Audit and AuthNZ review require at least USD 0.05. `--hard-budget` is a compatible alias.

The selected limit appears on stderr before analysis. These defaults do not change with depth. Your scan profile can set a budget for a particular depth under `depths`. Codex CLI and Copilot CLI use call and time limits instead of USD budgets.

## Provider access

The `claude` profile uses `APPSEC_CLAUDE_EXECUTABLE` (default `claude`) with your Claude login or external Anthropic API credential. Keep credentials outside repositories and reports.

The `codex` profile uses `OPENAI_API_KEY` and models from the installed catalog. It sends limited source excerpts to `https://api.openai.com/v1/responses`, sets `store: false`, and gives the model no tools. Requests have no explicit output-token limit unless your model profile sets one. The legacy generic gateway is available only to offline contract tests. Repository content cannot select profiles, hosts, endpoints, credentials, or models.

Select `--model "lite claude"` for LiteLLM or `--profile bedrock` for native Bedrock Converse. Configure the operator-owned `providers.yaml` separately from scan/model profiles, and supply `LITELLM_API_KEY` or `AWS_BEARER_TOKEN_BEDROCK` externally. These adapters use USD budgets and remain unqualified for live assessment quality. See [provider connections](providers.md) for the schema, gateway deployment checks, regional pricing, model prefixes and authentication limits.

The `codex-cli` profile requires Linux/macOS and Codex CLI 0.163.0 on `PATH` with a ChatGPT login. It uses the CLI's credential store, forces ChatGPT authentication, and removes API-key and endpoint overrides from the child environment. Configure model roles through Analyzer profiles; Codex user configuration, repository instructions, hooks, MCP servers, and model tools are disabled for these exchanges. It uses `max_calls` instead of `budget`, with defaults of 1,000 exchanges, four hours, and at most two components at a time. Monetary accounting is unavailable. See [setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli).

The `copilot-cli` profile requires Linux/macOS and GitHub Copilot CLI 1.0.101 on `PATH`. It uses the CLI's external login and applies `max_calls` and `max_duration` rather than a USD budget. Each CLI process receives a 30-AI-credit soft limit; it may be exceeded by an in-progress response and does not cap aggregate account usage. The adapter disables custom instructions, built-in MCPs, remote sharing, and all model tools, and accepts only schema-validated JSON. Authentication and model access are not checked without a model call. See [Copilot CLI setup and limits](profiles.md#use-github-copilot-cli).

The resolver keeps supported `APPSEC_*` model overrides from the extracted controller. It needs no root `config.json`. Requirements source defaults still live in the packaged `skills/audit-security-requirements/config.json`; they do not refer to a neighboring Advisor checkout. See [model selection](model-selection.md) for current options. The [historical configuration guide](history/advisor/configuration.md) describes earlier settings, some of which this CLI does not expose.
