# Configuration

For a focused security question, use `appsec-analyzer analyze-threats` with `--path`, `--staged`, `--worktree`, `--design`, a commit comparison, or an explicit `--mr`/`--pr` URL. It uses Claude CLI independently of scan profiles and retains the analyst's per-call budget. Project documents can be discovered or selected with repeatable `--context FILE`. See [focused threat analysis](threat-analyst.md) for formats, dialogue, remote credentials and limits.

An internal organization distribution can supply installed scan, model and organization defaults through its own command. See [organization packaging](organization-distributions.md) for the package manifest, override rules and CI setup. The upstream `appsec-analyzer` command keeps its existing defaults.

The public command is `appsec-analyzer`. `scan` takes local `--repo` paths or explicitly selected HTTPS/SSH Git URLs, an optional existing `--output` directory, `--profile`, `--assessment-depth`, and `--trust-mode`. It defaults to the current directory, the `claude` profile, and `standard` depth. `assess` requires an explicit profile (or legacy `--host`) and repository; `--help` lists the supported depth, model, context, requirements, resume, and export flags.

Choose `--profile claude` for the Claude CLI, `--profile codex` for the experimental OpenAI API adapter, or `--profile codex-cli` for the experimental Codex CLI connection with your ChatGPT login. A scan profile supplies the model profile, depth, USD budget, exports, and report attributes; explicit CLI options override those defaults. No `--host` argument is needed. Users can create YAML files under `~/.config/appsec-analyzer/profiles/` and `model-profiles/`, or select an external scan file. See [scan and model profiles](profiles.md) for the format, examples, and precedence, and [models and cost](model-selection.md) for provider defaults.

An operator may pass `--org-profile FILE`, `--preset NAME`, or
`--no-org-profile` to select or disable inherited assessment defaults. See
[organization profiles](org-profiles.md).

Use `scan-sources` for a deterministic source scan without a model account. It supports repeated `--repo`, `--assessment-depth`, `--trust-mode`, an existing external `--output` directory, and `--json`. Git URLs still require network retrieval.

Use `score REPO` for a quick deterministic indication without model calls. It accepts one top-level Git checkout or explicit Git URL and mutually exclusive `--json` or `--yaml` output. It does not use model profiles or budgets and writes no result into the selected checkout. See [security scoring](security-score.md) for coverage, source policy, comparison limits, and exit codes.

For Git URLs, keep credentials out of the URL. HTTPS retrieval can use an operator-configured Git credential helper or externally supplied `APPSEC_GIT_TOKEN` and optional `APPSEC_GIT_USERNAME`. SSH retrieval uses existing authentication and trusted host keys; `APPSEC_GIT_SSH_KEY_FILE` can select an external key file. `APPSEC_URL_ALLOWLIST`, when set, restricts Git destinations to its exact comma-separated hostnames. Retrieval rejects prohibited network addresses, disables redirects, and never loads repository-owned Git hooks or filters.

For custom abuse cases in a single-repository assessment, repeat `--abuse-case-file PATH` or save repository-relative YAML paths in the scan profile's `abuse_case_files` list. CLI selections replace that list. Files can live anywhere inside the repository; the former `docs/security/abuse-cases/` and `.appsec/abuse-cases/` locations remain automatic compatibility inputs. See [custom abuse cases](security-assessment.md#custom-abuse-cases) for the format, model costs, and limits.

Full `scan` and `assess` are model-backed; `claude` and `codex` default to a USD 20 spending limit; the separate `audit-requirements` and `authnz-review` commands default to USD 5. Set `--budget USD` to override the default. The amount must be positive and finite; the separate audit and AuthNZ review additionally require at least USD 0.05. The CLI prints the selected limit to stderr before starting, leaving structured stdout unchanged. `--hard-budget` remains a compatible alias. These defaults do not vary with assessment depth and never enable unlimited spending.

The focused [AuthNZ review](authnz-review.md) uses Claude CLI independently of full-assessment profiles. It accepts one local Git checkout, optional explicit requirements, JSON/YAML results, and the legacy pentest plan in JSON or YAML. Saving requires an empty private destination outside the source; `--save` selects a fresh application subdirectory.

The `claude` profile reads `APPSEC_CLAUDE_EXECUTABLE` (default `claude`) and uses a Claude login or externally configured Anthropic API credential. Credentials must remain outside repositories and reports. The `codex` profile uses `OPENAI_API_KEY` with catalog-validated model settings for each role and depth. By default, requests omit `max_output_tokens`; users can set an explicit limit in an OpenAI model profile. It sends bounded source excerpts to `https://api.openai.com/v1/responses`, requests `store: false`, and gives the model no tools. The legacy generic gateway uses `APPSEC_GATEWAY_API_KEY` only in offline contract tests and remains unavailable through the public CLI. No repository may select a profile, host, endpoint, credential name, or model by declaring it in source.

Select `--model "lite claude"` for LiteLLM or `--profile bedrock` for native Bedrock Converse. Configure the operator-owned `providers.yaml` separately from scan/model profiles, and supply `LITELLM_API_KEY` or `AWS_BEARER_TOKEN_BEDROCK` externally. These adapters use USD budgets and remain unqualified for live assessment quality. See [provider connections](providers.md) for the schema, gateway deployment checks, regional pricing, model prefixes and authentication limits.

The `codex-cli` profile requires Linux/macOS and Codex CLI 0.163.0 on `PATH` with a ChatGPT login. It uses the CLI's credential store, forces ChatGPT authentication, and removes API-key and endpoint overrides from the child environment. Configure model roles through Analyzer profiles; Codex user configuration, repository instructions, hooks, MCP servers, and model tools are disabled for these exchanges. It uses `max_calls` instead of `budget`, with defaults of 1,000 exchanges, four hours, and at most two components at a time. Monetary accounting is unavailable. See [setup and recovery](profiles.md#use-your-chatgpt-plan-with-codex-cli).

The assessment resolver retains its tested role defaults and certain `APPSEC_*`
model overrides from the extracted controller. A root `config.json` is not
required. Requirements source defaults currently live in the packaged
`skills/audit-security-requirements/config.json`; this is a migration item,
not a path to a neighboring Advisor checkout. See [model selection](model-selection.md)
and the [historical configuration guide](history/advisor/configuration.md) for
earlier settings, which are not all exposed by this CLI.
