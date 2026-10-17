# Profiles, models, and cost

Select a model profile and an independent analysis depth:

```sh
appsec-analyzer scan --profile codex --assessment-depth standard
appsec-analyzer scan --profile codex --assessment-depth thorough
appsec-analyzer scan --profile claude --assessment-depth quick
```

The profile supplies the connection and model settings for the chosen depth. `scan` defaults to `claude` and `standard`. `assess` requires an explicit profile or legacy host selection. The `claude` profile retains the existing Claude CLI role defaults for `quick`, `standard`, and `thorough`. It accepts `--model` and selected per-role overrides, subject to controller validation and the USD budget.

The `codex` profile selects the tool-less OpenAI Responses adapter. Its depth configuration specifies the model, reasoning effort, and output cap. All three depths currently use `gpt-6.1-sol` for every semantic role; each depth has its own entry, so the profile can specify different models when reviewed and qualified.

| Depth | Model | Reasoning effort | Output token cap per call |
| --- | --- | --- | ---: |
| `quick` | `gpt-6.1-sol` | `low` | 16,384 |
| `standard` | `gpt-6.1-sol` | `medium` | 24,576 |
| `thorough` | `gpt-6.1-sol` | `high` | 32,768 |

The `codex` profile uses `OPENAI_API_KEY`, not a Codex CLI login. It requests structured JSON, sets `store: false`, and exposes no tools to the model. Each request is capped at 240,000 bytes, below the model's 272,000 input-token long-context price threshold. The dated standard-price snapshot uses a conservative $2.50 per million input tokens (including a possible cache-write charge) and $10 per million output tokens to reserve and account for costs. An explicit `--model` must match the selected depth's model; Claude reasoning and role overrides are rejected.

Profiles are built into Analyzer. Loading custom profile files or profiles from Codex CLI configuration is not supported. `--org-profile` continues to select separate organization assessment settings.

Existing `--host claude-cli` and `--host openai` calls remain supported. The old `--host openai --profile codex-quick|codex-standard|codex-thorough` forms also remain supported when their suffix matches `--assessment-depth`. Prefer `--profile codex` with a separate depth for new commands. If both a profile and a host are supplied, they must name the same connection; conflicts fail before host preflight or repository retrieval. The separate requirements audit still uses `--host claude-cli`.

The spending limit defaults to USD 20 for `scan` and `assess` at every depth; use `--budget USD` to override it. See the [official model page](https://developers.openai.com/api/docs/models/gpt-6.1-sol) and [pricing table](https://developers.openai.com/api/docs/pricing) before a paid run.

Offline wire, boundary, and cost checks do not establish assessment quality. The `codex` profile has not completed a live end-to-end qualification run at any depth; review its reports before relying on them. The gateway adapter has no fixed public route and remains unavailable through the CLI.

The [historical model guide](history/advisor/model-selection.md) records the
Advisor defaults and observed trade-offs at import time. Its particular model
prices and recommendations are not a current qualification claim.
