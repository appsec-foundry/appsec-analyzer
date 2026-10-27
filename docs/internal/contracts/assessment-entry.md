# Host assessment entry

This contract describes how a Claude Code host starts and follows an assessment through the installed engine. It is not a user guide. Users start assessments with `appsec-analyzer assess`; see the [security assessment guide](../../security-assessment.md).

The installed engine entry includes `skills/appsec-analyzer/claude-code.md` for the existing Claude Code assessment dialogue. A composed host binds its commands to the exact bundled engine.

## Launch defaults

`scan --interactive-launch` keeps the host's quick, standard, and thorough hard ceilings of USD 10, 20, and 40, concurrency 3, and width 72, unless explicitly overridden. `--component-workers` keeps its range of 1 to 4. The switch selects only the Claude CLI adapter and disables budget prompts. It grants no spending authorization. Other CLI workflows keep their defaults.

The composed binding selects `--launch-defaults advisor` for the existing depth budgets and concurrency defaults, independently of Claude host selection, unattended operation, and display width. `--interactive-launch` remains a compatibility adapter with its original defaults and saved-profile identity. Explicit budgets and parallel limits take precedence. For a host-default launch with `--output`, the engine creates its public progress feed without the host naming an internal file.

## `assessment-entry`

`assessment-entry` exposes the launch helpers without model calls:

- `destination --repo PATH [--output DIR] [--storage analyzer|advisor]`
- `trust --repo PATH`
- `holder --output DIR`
- `legacy --repo PATH --output DIR`
- `context-preview` and `context-save`, with the same repository and output selection
- `clean --output DIR [--apply]`

Source selections must name a local top-level Git checkout. Default storage is Analyzer. The explicit Advisor namespace keeps the plugin's existing application destination. Output paths must be canonical, private, and outside checkouts. Context preview and save reuse the existing bounded dialog and validation. Only an answered dialog can persist confirmed business context. `clean` defaults to inspection, serializes with launch ownership, and refuses active holders before deleting the existing stale-state allowlist. Reports, audit history, caches, and accepted receipts remain.

The JSON responses carry `interface_version: 1`, `kind: assessment-entry`, and `operation`:

- `destination` returns `repo` and `output`.
- `holder` returns the boolean `live` and its `run_id`, or null.
- `legacy` returns `action: none|offer|incomplete` and an incomplete reason when present.
- `context-preview` returns the existing bounded preview object under `preview`.
- `context-save` returns the existing save action.
- `clean` returns the existing inspection or cleanup record.
- `trust` returns `kind: assessment-trust` and the existing strict preflight report. It exits with 2 on findings.

Missing, unsafe, or incompatible selections fail with exit 2. Preparation does not authorize a later assessment or make repository text authoritative.

## `progress`

`progress --output DIR --after N` accepts a nonnegative public event cursor. The response keeps the existing progress fields and adds `next_offset` and the boolean `events_omitted`. At most 100 events are returned. Bind a cursor to its returned `run_id`, reset it for a new owner, and keep an omission warning. A cleaned feed may be empty while the public state is terminal. A display must never infer successful completion from an empty feed or cancel the owner when the display exits.

## `query`

`query --output DIR [--id ID|--grep TERM|--severity LEVEL|--component NAME]` uses the same validated saved-result facts as `review`. Filters compose. `--id` cannot combine with filters. `--summary` renders the existing fixed summary and cannot combine with filters. These operations verify completion, saved artifact digests, and the current model contract before answering. Modified or incomplete results fail. They do not launch an assistant, call models, edit source, or authorize triage. Use `export` for an explicit re-export.
