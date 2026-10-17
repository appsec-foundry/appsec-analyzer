# Configuration

The public command is `appsec-analyzer`. `scan` takes local `--repo` paths,
an optional existing `--output` directory, `--assessment-depth`, and
`--trust-mode`. It has no provider configuration. `assess` requires `--host`
and `--hard-budget`; `--help` lists the supported depth, model, context,
requirements, resume, and export flags.
An operator may pass `--org-profile FILE`, `--preset NAME`, or
`--no-org-profile` to select or disable inherited assessment defaults. See
[organization profiles](org-profiles.md).

The Claude CLI host reads `APPSEC_CLAUDE_EXECUTABLE` (default `claude`) and
uses a Claude login or externally configured Anthropic API credential.
Credentials must remain outside repositories and reports. The direct OpenAI
and gateway transports use `OPENAI_API_KEY` and `APPSEC_GATEWAY_API_KEY`
respectively in offline contract tests; public use is blocked until a fixed
model and gateway route have been qualified. No repository may select a host,
endpoint, credential name, or model by declaring it in source.

The assessment resolver retains its tested role defaults and certain `APPSEC_*`
model overrides from the extracted controller. A root `config.json` is not
required. Requirements source defaults currently live in the packaged
`skills/audit-security-requirements/config.json`; this is a migration item,
not a path to a neighboring Advisor checkout. See [model selection](model-selection.md)
and the [historical configuration guide](history/advisor/configuration.md) for
earlier settings, which are not all exposed by this CLI.
