# Model profiles with independent analysis depth

## Reason and affected requirements

The user requested `--profile codex` with a separate `--assessment-depth standard|thorough|quick`. Repeating the depth in `codex-standard` and separately selecting a host exposed redundant configuration. The profile now selects the connection and supplies a model configuration for each depth. This extends the acceptance rules of REQ-018; REQ-002, REQ-020, REQ-023, and REQ-033 remain relevant to depth, qualification, spending, and provider disclosure. No requirement IDs change or retire.

## Behavior and compatibility

`scan` and `assess` accept the built-in `claude` and `codex` profiles. The `codex` profile resolves through the existing depth-to-API-configuration mapping, with an explicit model identifier in each depth entry. All entries retain their current model, reasoning, token caps, endpoint, credential source, and price snapshot. The `claude` profile uses the existing controller's depth and role model resolution, including its supported overrides. This change introduces no new models, endpoints, profile files, or provider qualification claims.

`scan` retains Claude and standard depth as defaults. `assess` still needs an explicit selection, now satisfied by a profile or the existing host flag. Existing `--host claude-cli`, `--host openai`, and `--host openai --profile codex-<depth>` calls remain valid with their previous depth-match rules. The older depth-profile names still require `--host openai`. Conflicting profile and host selections, unsupported gateway use, and incompatible model overrides fail before source retrieval or host invocation. `capabilities` adds the canonical names while retaining the legacy OpenAI names. Public interface version 1 remains compatible with existing valid invocations and result consumers.

The separate requirements audit and analyst interfaces keep their existing host contracts. Organization profiles remain assessment settings rather than provider profiles. Paid calls still require the same authorization and budget, and source content cannot select providers or credentials. No live model calls are authorized by this change.

## Verification

Exercise both public assessment commands at all three depths with canonical profiles and existing host/depth-profile forms. Check selected model, reasoning, output cap, and forwarded assessment depth. Verify that the depth mapping can supply distinct models without a CLI change. Check the Claude path preserves preflight and model override forwarding. Reject conflicting hosts, unsupported profiles and gateway selection, legacy depth mismatches, missing explicit selection for `assess`, and incompatible overrides before retrieval or assessment. Check discovery and help, current documentation commands, the installed entry skill, and package inventory alongside existing offline provider and budget tests.

Run `make test-analyzer`, `python3 scripts/check_specs.py`, the checker and affected documentation/distribution tests, and Ruff lint and format checks on changed Python files. No live assessment quality or provider account access is established by offline checks.
