# Models and cost

The built-in scan profiles work without user configuration:

```sh
appsec-analyzer assess --repo /path/to/project --profile codex --assessment-depth standard
appsec-analyzer assess --repo /path/to/project --profile codex --assessment-depth thorough
appsec-analyzer assess --repo /path/to/project --profile claude --assessment-depth quick
```

`assess` uses standard depth and your scan profile `default`, if present, otherwise `claude`. Non-interactive runs require an explicit profile or compatible host selection. The `claude` and `codex` profiles default to USD 20; change that with `--budget USD` or a scan profile. Codex CLI uses ChatGPT plan allowance with local call and time limits. See [scan and model profiles](profiles.md) for settings and examples.

## Codex profile

`codex` uses the tool-less OpenAI Responses adapter and `OPENAI_API_KEY`, not a Codex CLI login. It requests structured JSON, sets `store: false`, and exposes no tools to the model.

| Depth | Model alias | Current model | Reasoning effort |
| --- | --- | --- | --- |
| `quick` | `gpt-sol` | `gpt-6.1-sol` | `low` |
| `standard` | `gpt-sol` | `gpt-6.1-sol` | `medium` |
| `thorough` | `gpt-sol` | `gpt-6.1-sol` | `high` |

These defaults apply to every role except `recon_scanner`, which uses `gpt-luna` (`gpt-6-luna`) with low reasoning effort at every depth. This routing has offline coverage; live assessment quality remains unqualified. A user model profile can change the model or effort for individual roles and depths. Analyzer resolves `gpt-sol`, `gpt-luna`, and `gpt-astra` using its installed [model catalog](../data/model-catalog.yaml). Explicit model IDs are also supported when present in that catalog. Catalog changes ship with Analyzer; the aliases do not discover new models over the network.

By default, requests omit `max_output_tokens`. Analyzer imposes no cap below the model maximum. An explicit limit is optional and includes both reasoning and visible output tokens. Incomplete answers caused by that limit fail with `output_token_limit`.

Each OpenAI request is limited to 240,000 bytes, including instructions, the output contract, and JSON escaping. That is below the catalog’s 272,000 input-token threshold for long-context pricing. Large components can therefore need more exchanges than with Claude CLI.

Before a call, Analyzer reserves the cost of its allowed input and output. It uses your output limit, or the model maximum if none is set. The catalog snapshot for the default Sol model uses conservative rates of USD 2.50 per million input tokens, including possible cache-write charges, and USD 10 per million output tokens. A reservation can prevent a call even if its eventual answer would be short. The total approved budget still applies.

An OpenAI `--model` value must match the selected survey model or its requested alias. Claude role flags and `--reasoning-model` are rejected on this adapter; use a model profile for per-role OpenAI settings. Before a paid run, check the [official model page](https://developers.openai.com/api/docs/models/gpt-6.1-sol) and [pricing table](https://developers.openai.com/api/docs/pricing).

## Codex CLI profile

`codex-cli` uses the same installed model aliases and depth-specific reasoning defaults as `codex`, through Codex CLI 0.163.0 and its ChatGPT login. The account/workspace must allow the selected model. It does not use `OPENAI_API_KEY` and cannot enforce or report a dollar charge. It defaults to 1,000 model exchanges, four hours, and at most two components at a time. Use `--max-calls` and `--max-duration`; `--budget`, profile `budget`, and `max_output_tokens` are rejected. See [setup and limitations](profiles.md#use-your-chatgpt-plan-with-codex-cli).

## Claude profile

`claude` uses the Claude CLI and its configured login or external credentials. The built-in model profile records the existing role defaults for `quick`, `standard`, and `thorough`. Repository-dependent controller adjustments and supported environment overrides still apply unless a user model profile explicitly overrides that role's model. Explicit `--model` and supported per-role CLI flags take precedence. Organization restrictions still apply.

Users can set models and reasoning effort in their own Claude model profiles. The adapter does not expose `max_output_tokens`; a Claude profile containing that field is rejected. The USD budget and existing execution bounds remain in force.

### Choosing standard or thorough

Start with `standard`. Both Sonnet and Opus can identify business logic problems, such as spending a wallet balance without a valid payment or changing another user's basket. `thorough` can find additional problems, but it changes both analysis limits and model selection; it does not guarantee that every finding is new, correct, or more thoroughly verified.

In one comparison of the same Juice Shop source on 2026-10-17, a standard run using Sonnet for the survey cost USD 15.85 and a thorough run using Opus cost USD 28.01: about USD 12 more, or 77%. The survey, then called the STRIDE analysis, is the component threat-analysis stage; its cost rose from USD 8.35 to USD 21.91. These were two runs of the inherited Advisor engine, not a price estimate or a controlled model benchmark for the current Analyzer release. Costs depend on the project, selected models, work limits, and retries.

The thorough run identified additional cases involving negative basket quantities and expired discounts. Sonnet also found business logic problems, and some apparently new thorough findings were already present in the standard analysis but grouped together or rated below the report's severity threshold. More report entries do not necessarily mean more independent weaknesses.

Both runs had a USD 30 limit. The thorough run spent enough on early analysis that later model checks, including all abuse-case verification, were skipped to preserve the report budget. Standard reported five confirmed abuse scenarios; all fourteen thorough scenarios remained inconclusive. Check the run summary for skipped work before treating a completed report as a fully verified assessment. A higher budget permits more work but does not guarantee better findings.

## Compatibility and qualification

Existing `--host claude-cli` and `--host openai` calls remain supported. The old `--host openai --profile codex-quick|codex-standard|codex-thorough` forms also remain supported when their suffix matches `--assessment-depth`. Prefer `--profile codex` with a separate depth for new commands. If both profile and host are supplied, they must select the same adapter; conflicts fail before host preflight or repository retrieval.

`--org-profile` selects separate organization assessment settings. The requirements audit continues to use `--host claude-cli`.

Offline protocol, boundary, and budget tests do not establish assessment quality. The `codex`, `codex-cli`, `lite`, and `bedrock` profiles have not completed live end-to-end qualification at any depth. User model combinations also remain unqualified. The legacy generic gateway remains unavailable through the CLI; the separate LiteLLM adapter uses an explicitly configured operator connection. See [LiteLLM and Bedrock setup](providers.md) for model prefixes, authentication, pricing and limits.
