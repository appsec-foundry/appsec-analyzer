# Models and cost

The built-in scan profiles work without user configuration:

```sh
appsec-analyzer scan --profile codex --assessment-depth standard
appsec-analyzer scan --profile codex --assessment-depth thorough
appsec-analyzer scan --profile claude --assessment-depth quick
```

`scan` defaults to `claude` and `standard`. `assess` requires an explicit profile or legacy host selection. Both built-in scan profiles use a USD 20 budget. Override it with `--budget USD`, or define a budget in your own scan profile. See [scan and model profiles](profiles.md) for file locations, per-role settings, output formats, report attributes, and examples.

## Codex profile

`codex` uses the tool-less OpenAI Responses adapter and `OPENAI_API_KEY`, not a Codex CLI login. It requests structured JSON, sets `store: false`, and exposes no tools to the model.

| Depth | Model alias | Current model | Reasoning effort |
| --- | --- | --- | --- |
| `quick` | `gpt-sol` | `gpt-6.1-sol` | `low` |
| `standard` | `gpt-sol` | `gpt-6.1-sol` | `medium` |
| `thorough` | `gpt-sol` | `gpt-6.1-sol` | `high` |

These defaults apply to all roles. A user model profile can change the model or effort for individual roles and depths. Analyzer resolves `gpt-sol`, `gpt-luna`, and `gpt-astra` using its installed [model catalog](../data/model-catalog.yaml). Explicit model IDs are also supported when present in that catalog. Catalog changes ship with Analyzer; the aliases do not discover new models over the network.

By default, requests omit `max_output_tokens`. Analyzer imposes no cap below the model maximum. An explicit limit is optional and includes both reasoning and visible output tokens. Incomplete answers caused by that limit fail with `output_token_limit`.

Each request is capped at 240,000 bytes, below the catalog models' 272,000 input-token long-context price threshold. Before sending it, the adapter reserves the cost of bounded input plus the configured output limit or model maximum. For the default Sol model, the dated snapshot uses a conservative USD 2.50 per million input tokens, including a possible cache-write charge, and USD 10 per million output tokens. A large reservation can stop a call even when its eventual response would have been shorter. The total authorized USD budget still applies.

An OpenAI `--model` value must match the selected STRIDE model or its requested alias. Claude role flags and `--reasoning-model` are rejected on this adapter; use a model profile for per-role OpenAI settings. Before a paid run, check the [official model page](https://developers.openai.com/api/docs/models/gpt-6.1-sol) and [pricing table](https://developers.openai.com/api/docs/pricing).

## Claude profile

`claude` uses the Claude CLI and its configured login or external credentials. The built-in model profile records the existing role defaults for `quick`, `standard`, and `thorough`. Repository-dependent controller adjustments and supported environment overrides still apply unless a user model profile explicitly overrides that role's model. Explicit `--model` and supported per-role CLI flags take precedence. Organization restrictions still apply.

Users can set models and reasoning effort in their own Claude model profiles. The adapter does not expose `max_output_tokens`; a Claude profile containing that field is rejected. The USD budget and existing execution bounds remain in force.

## Compatibility and qualification

Existing `--host claude-cli` and `--host openai` calls remain supported. The old `--host openai --profile codex-quick|codex-standard|codex-thorough` forms also remain supported when their suffix matches `--assessment-depth`. Prefer `--profile codex` with a separate depth for new commands. If both profile and host are supplied, they must select the same adapter; conflicts fail before host preflight or repository retrieval.

`--org-profile` selects separate organization assessment settings. The requirements audit continues to use `--host claude-cli`.

Offline protocol, boundary, and budget tests do not establish assessment quality. The `codex` profile has not completed live end-to-end qualification at any depth. User model combinations also remain unqualified. The gateway adapter has no fixed public route and remains unavailable through the CLI.
