# Configuration

The public command is `appsec-analyzer`. `scan` takes local `--repo` paths or explicitly selected HTTPS/SSH Git URLs, an optional existing `--output` directory, `--profile`, `--assessment-depth`, and `--trust-mode`. It defaults to the current directory, the `claude` profile, and `standard` depth. `assess` requires an explicit profile (or legacy `--host`) and repository; `--help` lists the supported depth, model, context, requirements, resume, and export flags.

Choose `--profile claude` for the Claude CLI or `--profile codex` for the experimental OpenAI API adapter. A scan profile supplies the model profile, depth, USD budget, exports, and report attributes; explicit CLI options override those defaults. No `--host` argument is needed. Users can create YAML files under `~/.config/appsec-analyzer/profiles/` and `model-profiles/`, or select an external scan file. See [scan and model profiles](profiles.md) for the format, examples, and precedence, and [models and cost](model-selection.md) for provider defaults.

An operator may pass `--org-profile FILE`, `--preset NAME`, or
`--no-org-profile` to select or disable inherited assessment defaults. See
[organization profiles](org-profiles.md).

Use `scan-sources` for a deterministic source scan without a model account. It supports repeated `--repo`, `--assessment-depth`, `--trust-mode`, an existing external `--output` directory, and `--json`. Git URLs still require network retrieval.

For custom abuse cases in a single-repository assessment, repeat `--abuse-case-file PATH` or save repository-relative YAML paths in the scan profile's `abuse_case_files` list. CLI selections replace that list. Files can live anywhere inside the repository; the former `docs/security/abuse-cases/` and `.appsec/abuse-cases/` locations remain automatic compatibility inputs. See [custom abuse cases](security-assessment.md#custom-abuse-cases) for the format, model costs, and limits.

Full `scan` and `assess` are model-backed and default to a USD 20 spending limit; the separate `audit-requirements` command defaults to USD 5. Set `--budget USD` to override the default. The amount must be positive and finite; the requirements audit additionally requires at least USD 0.05. The CLI prints the selected limit to stderr before starting, leaving structured stdout unchanged. `--hard-budget` remains a compatible alias. These defaults do not vary with assessment depth and never enable unlimited spending.

The `claude` profile reads `APPSEC_CLAUDE_EXECUTABLE` (default `claude`) and uses a Claude login or externally configured Anthropic API credential. Credentials must remain outside repositories and reports. The `codex` profile uses `OPENAI_API_KEY` with catalog-validated model settings for each role and depth. By default, requests omit `max_output_tokens`; users can set an explicit limit in an OpenAI model profile. It sends bounded source excerpts to `https://api.openai.com/v1/responses`, requests `store: false`, and gives the model no tools. The fixed gateway transport uses `APPSEC_GATEWAY_API_KEY` only in offline contract tests; public use remains blocked until a fixed route has been qualified. No repository may select a profile, host, endpoint, credential name, or model by declaring it in source.

The assessment resolver retains its tested role defaults and certain `APPSEC_*`
model overrides from the extracted controller. A root `config.json` is not
required. Requirements source defaults currently live in the packaged
`skills/audit-security-requirements/config.json`; this is a migration item,
not a path to a neighboring Advisor checkout. See [model selection](model-selection.md)
and the [historical configuration guide](history/advisor/configuration.md) for
earlier settings, which are not all exposed by this CLI.
