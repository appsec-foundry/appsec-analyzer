# Public budget defaults

## Reason and affected requirements

The user requested the shorter `--budget` spelling and a default budget when no flag is supplied, so a full assessment can start with `appsec-analyzer scan`. This changes REQ-FLW-008 from requiring an explicit spending argument to applying documented finite defaults with explicit overrides and displaying the selected limit before starting. The requirement ID remains unchanged; no IDs are retired.

## Behavior and compatibility

The public CLI defaults to USD 20 for `scan` and `assess`, and USD 5 for the separate `audit-requirements` command. The defaults apply at every assessment depth. `--budget USD` overrides the default; `--hard-budget USD` remains an alias. Missing budget arguments now permit a paid run within the default limit instead of causing a parser error. The CLI prints the selected limit to stderr before starting, preserving structured stdout.

Both spellings reject non-positive, non-finite, and malformed amounts before host preflight. The audit retains its existing minimum of USD 0.05. The public adapter passes the selected amount to the existing controller or audit budget enforcement without changing accounting, reservations, cancellation, or incomplete-result behavior. Internal controller arguments and persisted limit fields retain their existing names. Existing explicit-budget calls remain compatible; scripts that relied on an omitted budget preventing execution must supply their intended budget or use `scan-sources` for a run without model calls.

The installed agent entry skill still requires the user's spending authorization before making paid calls. CLI defaults do not grant the coding assistant or test suite permission to call live providers.

## Verification

Public CLI tests cover defaults and both override spellings reaching the controller and separate audit, the current-directory scan default, the stderr budget notice, CLI help, and invalid values rejected before a host call. Existing offline controller and audit tests continue to check enforced spending bounds. Run the standalone Analyzer test target, the specification checker and its tests, the installed-entry command contract, and Ruff checks on changed Python files. No live model call is part of this change.
