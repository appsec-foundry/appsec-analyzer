# Configuration

The public command is `appsec-analyzer`. `scan` takes local `--repo` paths, an optional existing `--output` directory, `--assessment-depth`, and `--trust-mode`. It defaults to the current directory and the Claude CLI host. `assess` requires an explicit `--host` and repository; `--help` lists the supported depth, model, context, requirements, resume, and export flags.
An operator may pass `--org-profile FILE`, `--preset NAME`, or
`--no-org-profile` to select or disable inherited assessment defaults. See
[organization profiles](org-profiles.md).

Full `scan` and `assess` are model-backed and default to a USD 20 spending limit; the separate `audit-requirements` command defaults to USD 5. Set `--budget USD` to override the default. The amount must be positive and finite; the requirements audit additionally requires at least USD 0.05. The CLI prints the selected limit to stderr before starting, leaving structured stdout unchanged. `--hard-budget` remains a compatible alias. These defaults do not vary with assessment depth and never enable unlimited spending.

The Claude CLI host reads `APPSEC_CLAUDE_EXECUTABLE` (default `claude`) and
uses a Claude login or externally configured Anthropic API credential.
Credentials must remain outside repositories and reports. The direct OpenAI
host uses `OPENAI_API_KEY` with a pinned `codex-<depth>` profile. It sends
bounded source excerpts to `https://api.openai.com/v1/responses`, requests
`store: false`, and gives the model no tools. The fixed gateway transport uses
`APPSEC_GATEWAY_API_KEY` only in offline contract tests; public use remains
blocked until a fixed route has been qualified. No repository may select a host,
endpoint, credential name, or model by declaring it in source.

The assessment resolver retains its tested role defaults and certain `APPSEC_*`
model overrides from the extracted controller. A root `config.json` is not
required. Requirements source defaults currently live in the packaged
`skills/audit-security-requirements/config.json`; this is a migration item,
not a path to a neighboring Advisor checkout. See [model selection](model-selection.md)
and the [historical configuration guide](history/advisor/configuration.md) for
earlier settings, which are not all exposed by this CLI.
