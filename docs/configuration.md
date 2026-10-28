# Configuration

Use this guide to choose a command, set its spending limit, and configure repository and provider access. Save settings you reuse in a [scan profile](profiles.md).

An [organization distribution](organization-distributions.md) can provide its own command with bundled scan, model, and organization defaults. The upstream `appsec-analyzer` command keeps its defaults.

## Assessment settings

`appsec-analyzer assess` accepts local paths or explicitly selected HTTPS/SSH Git URLs through `--repo`. You can also select an output directory, profile, depth, and trust mode. Defaults are the current directory, standard depth, and your `default` scan profile if present, otherwise `claude`. With `--non-interactive`, name the repository and profile explicitly (or use the compatible `--host` option). Run `assess --help` for all options.

Select `--profile claude`, `codex`, `codex-cli`, or `copilot-cli` for Claude CLI, OpenAI API, Codex CLI, or GitHub Copilot CLI. The last three are experimental. Profiles set models, depth, budget or call limit, exports, and report attributes. Explicit CLI options override profile defaults.

Store your YAML files under `~/.config/appsec-analyzer/profiles/` and `model-profiles/`, or select an external scan file. See [scan and model profiles](profiles.md) for examples and [models and cost](model-selection.md) for provider defaults.

Use `--org-profile FILE` and optionally `--preset NAME` to select [organization defaults](org-profiles.md). `--no-org-profile` disables them for the run.

For custom abuse cases, repeat `--abuse-case-file PATH` or list the paths under `abuse_case_files` in a scan profile. See [custom abuse cases](security-assessment.md#custom-abuse-cases) for the format and limits.

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

The `codex-cli` profile needs Linux or macOS, Codex CLI 0.163.0 or newer on `PATH`, and a ChatGPT login. It uses `max_calls` instead of a USD budget and reports no monetary cost. See [setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli).

The `copilot-cli` profile needs Linux or macOS, GitHub Copilot CLI 1.0.101 on `PATH`, and its login. It uses `max_calls` and `max_duration` instead of a USD budget. See [Copilot CLI setup and limits](profiles.md#use-github-copilot-cli).

Supported `APPSEC_*` environment variables can override models. See [model selection](model-selection.md) for the current options.
