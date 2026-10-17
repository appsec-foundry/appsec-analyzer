# Operator scan and model profiles

## Reason

The user requested reusable scan settings, user-defined model profiles, per-role model and reasoning selection, model-family aliases, examples, and documentation. The subsequent clarification requires no default output-token cap below the provider model maximum. Budget values are always USD.

## Contract

REQ-018 gains versioned operator-owned scan/model YAML files, one built-in model base, strict validation, XDG lookup, explicit external paths, provenance, and offline inspection. CLI depth, budget, and export selection override scan defaults. Profiles cannot grant tools, supply credentials or destinations, set prices, suppress evidence, or bypass organization restrictions. Report attributes are bounded literal metadata.

REQ-019 covers schema version 1 and stored profile snapshots. REQ-016 requires compatible profile definitions and configuration on resume; OpenAI alias targets are retained and validated against the installed catalog. REQ-003 and REQ-014 gain report metadata and recorded model settings. REQ-020 keeps all new model combinations unqualified. REQ-023 retains finite USD, time, input, and transport limits; requests omit max_output_tokens unless explicitly selected, and pre-call reservations include the catalog model maximum. The per-call reservation can rise for a more expensive selected model, without raising the total budget. REQ-031 and REQ-035 apply to profile loading and private lifecycle state.

## Compatibility

The existing built-in and legacy host/profile forms remain accepted. OpenAI quick, standard, and thorough keep their existing reasoning defaults but no longer set the former 16384/24576/32768 output caps. Unknown OpenAI CLI model overrides still fail; user model files supply role-specific selection. Claude retains controller routing where the user did not override it and continues to enforce organization restrictions. Markdown and YAML remain the base result; the scan profile selects additional exports. The public interface remains version 1; the file format has its own version.

Pre-profile runs have no resolved profile snapshot and are rejected on resume through the new public profile path with instructions to start a new run. Existing saved results remain readable and exportable. No requirement ID is retired or reused.

## Verification

Offline profile tests cover intended precedence, explicit caps and absent default caps, role dispatch, alias resume, attributes in real composed reports, budget reservations, provider rejection, unsafe YAML, file boundaries, and organization policy preservation. Public CLI and adapter tests retain compatibility assertions. Controller, schema, report replay, requirements catalog, documentation, and distribution checks cover affected consumers. Live model qualification and spending are not authorized by this change.

The controller, state, source-reference, schema, and fixture tests passed 253 cases; 17 existing freeze/replay cases skipped because their git-ignored `_last-run` input is absent. The checked-in Juice Shop golden replay still reports differences in the extracted product's name/version and missing source-repository metadata. Repeating the same YAML/Markdown/SARIF replay against pre-change commit `db7a33c4` produced identical differences. Refresh those historical fixtures separately; this change does not rewrite their expected reports.

`make test-analyzer` passed 224 tests. The spec-checker and distribution test files passed 59 tests; package tests validate the bundled release example from the built package and check guide links and wheel/sdist contents. Ruff lint/format checks and the requirement catalog checker pass. No paid model calls were made.
