# Hosts, models, and cost

`scan` runs the full assessment with Claude CLI by default. `assess` requires
an explicit `--host`. The Claude compatibility host retains the extracted role
defaults for `quick`, `standard`, and `thorough`. It accepts `--model` and
selected per-role overrides, subject to controller validation and the USD budget.

`--host openai` selects the tool-less OpenAI Responses adapter. Its fixed Codex
profiles use the same `gpt-6.1-sol` model for every semantic role:

| Depth | Profile | Reasoning effort | Output token cap per call |
| --- | --- | --- | ---: |
| `quick` | `codex-quick` | `low` | 16,384 |
| `standard` | `codex-standard` | `medium` | 24,576 |
| `thorough` | `codex-thorough` | `high` | 32,768 |

The profile defaults to the selected depth; an explicit `--profile` must match
it. These profiles use the OpenAI API key, not a Codex CLI login. They request
structured JSON, set `store: false`, and expose no tools to the model. Each
request is capped at 240,000 bytes, below the model's 272,000 input-token
long-context price threshold. The dated standard-price snapshot uses a
conservative $2.50 per million input tokens (including a possible cache-write
charge) and $10 per million output tokens to reserve and account for costs.

The spending limit defaults to USD 20 for `scan` and `assess` at every depth; use `--budget USD` to override it. See the [official model page](https://developers.openai.com/api/docs/models/gpt-6.1-sol) and [pricing table](https://developers.openai.com/api/docs/pricing) before a paid run.

Offline wire, boundary, and cost checks do not establish assessment quality.
These Codex profiles have not completed a live end-to-end qualification run;
review their reports before relying on them. The gateway adapter has no fixed
public route and remains unavailable through the CLI.

The [historical model guide](history/advisor/model-selection.md) records the
Advisor defaults and observed trade-offs at import time. Its particular model
prices and recommendations are not a current qualification claim.
