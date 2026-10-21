# Command-line and unattended operation

Use `appsec-analyzer export --assessment /path/to/assessment --output /path/to/new-export --formats markdown yaml sarif` to convert a completed saved assessment without model calls. Success emits JSON with artifact digests; invalid inputs or failed conversion return exit 2. The destination must be new. See [export prerequisites and limits](security-assessment.md#exports-and-compatibility).

Full assessments run a preflight before cloning or analysis. For a separate check, use `appsec-analyzer preflight --repo /checkout --profile claude --json`; it returns 0 when its supported checks pass, 2 on failure and 130 on cancellation, without running an assessment. Default checks perform no generation. Read the returned limitations: local CLI login and Bedrock TLS checks cannot establish server authentication or model access. `preflight --test-model` explicitly consumes money or plan allowance and requires its own explicit budget or call limit. See [preflight checks](security-assessment.md#preflight-checks).

For focused analysis in automation, use `appsec-analyzer analyze-threats "Question" --path src/api --non-interactive` or select an explicit change/MR/PR scope. Scope ambiguity and required unanswered questions return exit 2; no answer is invented. `--preview` performs no model call, but MR/PR resolution still uses the network. The focused analyst uses Claude CLI and `--max-budget-usd` per call, independently of full-assessment profiles and budgets. See [focused threat analysis](threat-analyst.md).

Install the package, then invoke the same public program locally or in CI:

```sh
appsec-analyzer assess --repo /checkout --budget 20 --output /private/assessment
appsec-analyzer assess-sources --repo /checkout --output /private/source-scan
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

The `lite` and `bedrock` profiles also default to USD 20. Configure their separate operator connection and external credential first, then use `--model "lite claude"` or `--profile bedrock` with `--non-interactive`. See [provider setup](providers.md). These profiles run full assessments with offline protocol coverage; live quality remains unqualified.

A [scan profile](profiles.md) selects the model profile, depth, USD budget, exports, and report attributes. A model profile supplies the connection and model settings, including optional per-role overrides. The default for `scan` is `--profile claude --assessment-depth standard`; with `--non-interactive`, an explicit profile or legacy host is required. Configure a Claude login or external Anthropic credentials for `claude`, or `OPENAI_API_KEY` for the experimental `codex` profile. Existing `--host` commands remain supported; see [profile compatibility](model-selection.md).

For ChatGPT plan usage on a trusted local machine, install the supported Codex CLI 0.163.0, sign in with `codex login`, and use `appsec-analyzer assess --repo /checkout --profile codex-cli --max-calls 1000 --max-duration 14400 --output /private/subscription-assessment --non-interactive`. This uses existing CLI authentication and sends selected context to OpenAI. It rejects USD budget flags, defaults to at most two concurrent components, and stops on allowance exhaustion. It does not provision a CI login or share your credentials with a runner. See [Codex CLI prerequisites, recovery, and limits](profiles.md#use-your-chatgpt-plan-with-codex-cli).

Create `/private/source-scan` before running `scan-sources`. That command prints
readable scanner findings to stdout; `--json` prints its versioned JSON instead.
With `--output`, the complete JSON is saved as `scan-result.json`. The full `assess`
command shows live progress and creates its private default destination if `--output` is omitted. A `stop` request preserves
accepted assessment work for a compatible `--resume`. `--rebuild` starts over.

On a provider rate limit, all new model calls in the assessment wait together; already running calls may finish. Free failures allow up to three retries with delays of 15, 60, and 180 seconds; valid HTTP `Retry-After` delays are respected. Paid failures retain their stricter retry limits. CLI hosts without structured reset metadata use those fallback delays. A wait over three minutes, insufficient remaining time, or exhausted retries pauses the run with exit code 3, including when the affected job is optional. Accepted work is kept. Wait for provider capacity, then rerun the same command with `--resume`; the original deadline and compatibility checks still apply.

When a provider connection drops or cannot be opened, Analyzer repeats the call after 15 seconds. A failed call without a cost report, such as a Codex subscription call or a failed API call, is repeated at most once, and these paid repeats count toward the stricter retry limits. If the connection stays down for a required job, the run pauses with exit code 3 and keeps accepted work; check connectivity, then rerun the same command with `--resume`. An optional job records a coverage gap instead. Login, quota, certificate, configuration, and request errors are never repeated.

The result and status contracts distinguish scanner-only output from completed,
interrupted, and failed assessments. After normal cleanup removes the event
feed, `progress` reports the final state with `feed_available: false` and no
events; `status` and `results` remain available.

`score REPO` runs without model calls or a result directory. It immediately shows three phases on stderr: repository preparation, security checks, and the result, with separate persistent status lines and durations for runtime loading, repository preparation, each scanner, and result validation. Interactive terminals refresh the running step while retaining completed steps; redirected stderr receives plain step start/completion lines. The final summary shows total time. Status labels use the shared terminal colors based on stderr; text results choose colors independently from stdout. `NO_COLOR` and `FORCE_COLOR` follow the shared policy, and JSON/YAML remain free of styling codes. Git cloning remains visible when needed. Stdout contains only the limited scanner-based indication as text, JSON (`--json`), or YAML (`--yaml`), without excluded-file lists or counts. Exit 0 means a score was computed, 2 means coverage was insufficient (`undetermined`) or the arguments were invalid, 1 means an operational error or incomplete scan, and 130 means cancellation by Ctrl+C. Cancellation ends the status without a traceback; an interrupted analysis publishes no result. A low computed score still exits 0; this command has no score-threshold CI gate. Explicit Git URLs use temporary checkouts. See [security scoring](security-score.md) for source admission, comparison limits, scanner coverage, and error recovery.

Normal progress output records skipped optional model jobs immediately as `Coverage gap` warnings, including budget reservations, without requiring `--verbose`. Architect Review and abuse-case phase totals show actual review coverage separately from planned candidates. The final summary retains omitted work. `--quiet` suppresses live progress; see [assessment coverage and limits](security-assessment.md).

For troubleshooting, add `--verbose` to correlate model messages with their jobs and calls. Private per-attempt diagnostics are saved for every full-assessment provider under the output's `.assessment-work/diagnostics/` directory, including when `--quiet` suppresses progress. Compatible resume preserves earlier attempt files. See [assessment diagnostics and limits](security-assessment.md) for recorded fields, size limits, and privacy.

Use `--non-interactive` to explicitly prevent budget questions in CI. Without it, a terminal session outside recognized CI environments may ask for a higher total USD limit when money prevents further work. Piped input or stderr, `--quiet`, and recognized CI markers also prevent questions. Examples of detected markers include `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, and `TF_BUILD`; explicit `--non-interactive` also covers CI systems that set none of them. Declining keeps the configured limit and normal fallback behavior. Compatible `--resume` retains an increase explicitly approved earlier for the same run; a fresh run uses its configured budget.

The separate requirements audit uses `appsec-analyzer audit-requirements
--repo /checkout --requirements /catalog.yaml --output /private/audit
--host claude-cli --budget 5`. Its versioned result reports
`assessment_status: not_run`. Use `--gate` to make qualifying findings return
exit status 1. The old `scripts/run-headless.sh` instructions are retained only
in the [historical guide](history/advisor/headless-mode.md).

Use `appsec-analyzer authnz-review --repo /checkout --budget 5 --json` for a separate AuthN/AuthZ review through Claude CLI. It needs no prior assessment and never waits for interactive input. `--yaml` prints the same result as YAML. `--save --pentest-tasks --pentest-output-format both` retains reports and the legacy pentest plan as JSON and YAML in a fresh private application subdirectory. The command sends masked scanner signals and explicit catalog context to the model, defaults to a USD 5 limit, and performs no dynamic testing. Exit 1 means a selected gate failed, 2 means incomplete or invalid execution, and 130 means cancellation. See [AuthNZ coverage, exports and recovery](authnz-review.md).
