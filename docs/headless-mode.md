# Command-line and unattended operation

Use `appsec-analyzer export --assessment /path/to/assessment --output /path/to/new-export --formats markdown yaml sarif` to convert a completed saved assessment without model calls. Success emits JSON with artifact digests; invalid inputs or failed conversion return exit 2. The destination must be new. See [export prerequisites and limits](security-assessment.md#exports-and-compatibility).

Full assessments run a preflight before cloning or analysis; it makes no model call, and `--skip-preflight` skips it for one run. For a separate check, use `appsec-analyzer preflight --repo /checkout --profile claude --json`; it returns 0 when its supported checks pass, 2 on failure and 130 on cancellation, without running an assessment. Default checks perform no generation. Read the returned limitations: local CLI login and Bedrock TLS checks cannot establish server authentication or model access. `preflight --test-model` explicitly consumes money or plan allowance and requires its own explicit budget or call limit. See [preflight checks](security-assessment.md#preflight-checks).

For focused analysis in automation, use `appsec-analyzer analyze-threats "Question" --path src/api --non-interactive` or select an explicit change/MR/PR scope. Scope ambiguity and required unanswered questions return exit 2; no answer is invented. `--preview` performs no model call, but MR/PR resolution still uses the network. The focused analyst uses Claude CLI and `--max-budget-usd` per call, independently of full-assessment profiles and budgets. See [focused threat analysis](threat-analyst.md).

Install the package, then invoke the same public program locally or in CI:

```sh
appsec-analyzer assess --repo /checkout --budget 20 --output /private/assessment
appsec-analyzer scan-sources --repo /checkout --output /private/source-scan
appsec-analyzer score /checkout --json
appsec-analyzer assess --repo /checkout --profile claude \
  --budget 20 --output /private/assessment --non-interactive
appsec-analyzer assess --repo /checkout --profile codex \
  --assessment-depth standard --budget 20 --output /private/openai-assessment
appsec-analyzer status --output /private/assessment
appsec-analyzer progress --output /private/assessment
appsec-analyzer stop --output /private/assessment
appsec-analyzer results --output /private/assessment
```

The `claude` and `codex` scan profiles use a USD 20 spending limit; user scan profiles can set another budget. `audit-requirements` defaults to USD 5. `--budget USD` overrides the default, and `--hard-budget` remains a compatible alias. The CLI prints the selected limit to stderr before starting. Use an explicit budget in automation when its spending limit should be visible in the command.

Full assessments show monetary console costs by default only with API billing. Add `--show-costs` to enable them for subscription runs too; unavailable amounts remain unavailable. This changes no accounting or spending limits, and `--quiet` still suppresses live progress. See [cost display](security-assessment.md) for Claude CLI billing selection.

The `lite` and `bedrock` profiles also default to USD 20. Configure their separate operator connection and external credential first, then use `--model "lite claude"` or `--profile bedrock` with `--non-interactive`. See [provider setup](providers.md). These profiles run full assessments with offline protocol coverage; live quality remains unqualified.

A [scan profile](profiles.md) selects the model profile, depth, USD budget, exports, and report attributes. A model profile supplies the connection and model settings, including optional per-role overrides. Without a selection, `assess` uses the operator's scan profile `default` if it exists, otherwise `--profile claude`, at standard depth; with `--non-interactive`, an explicit profile or legacy host is required. Configure a Claude login or external Anthropic credentials for `claude`, or `OPENAI_API_KEY` for the experimental `codex` profile. Existing `--host` commands remain supported; see [profile compatibility](model-selection.md).

For ChatGPT plan usage on a trusted local machine, install the supported Codex CLI 0.163.0, sign in with `codex login`, and use `appsec-analyzer assess --repo /checkout --profile codex-cli --max-calls 1000 --max-duration 14400 --output /private/subscription-assessment --non-interactive`. This uses existing CLI authentication and sends selected context to OpenAI. It rejects USD budget flags, defaults to at most two concurrent components, and stops on allowance exhaustion. It does not provision a CI login or share your credentials with a runner. See [Codex CLI prerequisites, recovery, and limits](profiles.md#use-your-chatgpt-plan-with-codex-cli).

Create `/private/source-scan` before running `scan-sources`. It prints readable scanner observations, or versioned JSON with `--json`. `--output` also saves `scan-result.json`.

`assess` shows progress and creates a private default destination if you omit `--output`. A stop request preserves accepted work for `--resume`, which reuses the steps that still match. `--rebuild` starts over.

Provider rate limits pause new calls and can pause the run with exit code 3. Accepted work stays saved. Wait for capacity, then repeat the command with `--resume`; the original deadline still applies. See [retry rules and recovery](security-assessment.md#rate-limits-and-connection-failures).

Persistent connection failures pause required work with exit code 3; optional jobs record a coverage gap. Login, quota, certificate, configuration, and request errors are not retried. See [connection failure recovery](security-assessment.md#rate-limits-and-connection-failures).

Status and results distinguish scanner-only output, completed assessments, interrupted runs, and failures. After cleanup removes the event feed, `progress` returns the final state with `feed_available: false` and no events. `status` and `results` remain available.

`score REPO` needs no model or result directory. Progress goes to stderr; stdout contains only the text, JSON, or YAML result. Redirected progress is plain text, and JSON/YAML contain no styling codes. A low computed score still exits 0; there is no score-threshold CI gate.

Exit 2 means insufficient coverage (`undetermined`) or invalid arguments; exit 1 means an operational error or incomplete scan; Ctrl+C returns 130 without a traceback or result. Git URLs use temporary checkouts. See [security scoring](security-score.md) for checks, output, comparison limits, and recovery.

Normal progress output records skipped optional model jobs immediately as `Coverage gap` warnings, without requiring `--verbose`. Within a phase, only the first job of a kind skipped for the budget reserve gets its own warning; the phase's done line counts the others, and `--verbose` lists each one. Architect Review and abuse-case phase totals show actual review coverage separately from planned candidates. The final summary retains omitted work. `--quiet` suppresses live progress; see [assessment coverage and limits](security-assessment.md).

For troubleshooting, add `--verbose` to correlate model messages with their jobs and calls. Private per-attempt diagnostics are saved for every full-assessment provider under the output's `.assessment-work/diagnostics/` directory, including when `--quiet` suppresses progress. Compatible resume preserves earlier attempt files. See [assessment diagnostics and limits](security-assessment.md) for recorded fields, size limits, and privacy.

Use `--non-interactive` to explicitly prevent budget questions in CI. Without it, a terminal session outside recognized CI environments may ask for a higher total USD limit when money prevents further work. Piped input or stderr, `--quiet`, and recognized CI markers also prevent questions. Examples of detected markers include `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, and `TF_BUILD`; explicit `--non-interactive` also covers CI systems that set none of them. Declining keeps the configured limit and normal fallback behavior. Compatible `--resume` retains an increase explicitly approved earlier for the same run; a fresh run uses its configured budget.

Run a separate requirements audit with `appsec-analyzer audit-requirements --repo /checkout --requirements /catalog.yaml --output /private/audit --host claude-cli --budget 5`. Its result records `assessment_status: not_run`. Add `--gate` to return exit 1 for qualifying failures. The [historical guide](history/advisor/headless-mode.md) retains the earlier `scripts/run-headless.sh` instructions.

Use `appsec-analyzer authnz-review --repo /checkout --budget 5 --json` for a separate AuthN/AuthZ review through Claude CLI. It needs no prior assessment and never waits for interactive input. `--yaml` prints the same result as YAML. `--save --pentest-tasks --pentest-output-format both` retains reports and the legacy pentest plan as JSON and YAML in a fresh private application subdirectory. The command sends masked scanner signals and explicit catalog context to the model, defaults to a USD 5 limit, and performs no dynamic testing. Exit 1 means a selected gate failed, 2 means incomplete or invalid execution, and 130 means cancellation. See [AuthNZ coverage, exports and recovery](authnz-review.md).
