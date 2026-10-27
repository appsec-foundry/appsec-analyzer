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

### Choosing a depth

Start with `standard`. Use `quick` for a fast first overview, and `thorough` when you want the widest coverage and can pay about two to three times as much as for `standard`. [What each depth does](profiles.md#what-each-depth-does) lists the settings behind each depth.

On 2026-10-26 and 2026-10-27, one run per depth assessed the same Juice Shop source (about 820 source files) with the `claude` profile:

| | `quick` | `standard` | `thorough` |
| --- | ---: | ---: | ---: |
| Cost | USD 8.17 | USD 14.71 | USD 39.74 |
| Time | 22 minutes | 41 minutes | 1 hour 36 minutes, including earlier attempts that `--resume` continued |
| Findings in the register | 51 | 104 | 147 |
| Critical and High findings | 24 | 35 | 50 |
| Verification results | none | 31 findings, 3 controls, 14 undecidable | 49 findings, 6 controls, 1 partial, 28 undecidable |
| Confirmed abuse cases | not checked | 6 of 14, 4 not checked because of the limit | 8 of 14 |

`quick` found the most severe known problems of this application: SQL injection in login and product search, code execution through the stored user name, XXE and path traversal in file uploads, server-side request forgery, and the JWT signing key in the source code. It missed code execution in B2B orders, which both other depths rated High, and problems with two-factor authentication, CAPTCHA, and the metrics endpoint. It runs no verification and checks no abuse cases, so its findings rest on the survey and the scanners alone.

`standard` found all of these problems, verified the main security aspects, and checked abuse cases. At USD 0.14 per finding, it had the lowest cost per finding.

`thorough` reported the widest coverage: 61 instead of 48 weakness types (CWEs), including an open redirect, unsigned coupon codes, and missing WebSocket handshake authentication that no other depth reported. With Claude, it uses Opus for the survey and for verification, which caused most of the additional cost. Each additional Critical or High finding cost about USD 1.70. The run needed about USD 40, twice the default `--budget` of USD 20. When the budget runs short, Analyzer skips later checks, such as verification and abuse cases, to complete the report. Check the run summary for skipped work before treating a completed report as fully verified.

Read the counts with care:

- More findings do not mean as many more weaknesses. In the thorough run, several problems appear two or three times, for example once from the survey and once from verification under another weakness type.
- The same problem can get a different severity in another run. An endpoint that returns user records together with uploaded photos was Critical in `quick`, Medium in `standard`, and High in `thorough`.
- Abuse-case results also varied. Two attack chains that `standard` confirmed as Critical stayed unresolved in `thorough`, although both runs used the same model for this check.

These are single runs on one application, not a benchmark. Costs and results depend on the project, models, limits, budget, and retries.

## Compatibility and qualification

Existing `--host claude-cli` and `--host openai` calls remain supported. The old `--host openai --profile codex-quick|codex-standard|codex-thorough` forms also remain supported when their suffix matches `--assessment-depth`. Prefer `--profile codex` with a separate depth for new commands. If both profile and host are supplied, they must select the same adapter; conflicts fail before host preflight or repository retrieval.

`--org-profile` selects separate organization assessment settings. The requirements audit continues to use `--host claude-cli`.

Offline protocol, boundary, and budget tests do not establish assessment quality. The `codex`, `codex-cli`, `lite`, and `bedrock` profiles have not completed live end-to-end qualification at any depth. User model combinations also remain unqualified. The legacy generic gateway remains unavailable through the CLI; the separate LiteLLM adapter uses an explicitly configured operator connection. See [LiteLLM and Bedrock setup](providers.md) for model prefixes, authentication, pricing and limits.
