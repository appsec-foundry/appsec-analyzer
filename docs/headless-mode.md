# Command-line and unattended operation

This guide covers running Analyzer in scripts and CI: which commands to use, how spending limits work, and what the exit codes mean. Install the package first. Then call the same program locally or in CI:

```sh
appsec-analyzer assess --repo /checkout --profile claude \
  --budget 20 --output /private/assessment --non-interactive
appsec-analyzer assess --repo /checkout --profile codex \
  --assessment-depth standard --budget 20 --output /private/openai-assessment
appsec-analyzer scan-sources --repo /checkout --output /private/source-scan
appsec-analyzer score /checkout --json
appsec-analyzer status --output /private/assessment
appsec-analyzer progress --output /private/assessment
appsec-analyzer stop --output /private/assessment
appsec-analyzer results --output /private/assessment
```

## Questions and spending limits

Use `--non-interactive` in CI. Without it, a terminal session can ask for a higher total USD limit when money prevents further work. Piped input or stderr, `--quiet`, and recognized CI markers (such as `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, and `TF_BUILD`) also prevent questions. `--non-interactive` covers CI systems that set none of these. Declining keeps the configured limit. `--resume` keeps an increase you approved earlier for the same run. A new run uses its configured budget.

`--non-interactive` also requires an explicit `--repo` and `--profile` (or the older `--host`), so the command shows its provider.

The `claude`, `codex`, `lite`, and `bedrock` profiles stop at USD 20 by default. `audit-requirements` and `authnz-review` stop at USD 5. `--budget USD` changes the limit, and `--hard-budget` is an alias. The CLI prints the selected limit to stderr before it starts. State the budget in the command, so the limit is visible in the CI configuration.

Console costs appear by default only with API billing. `--show-costs` shows them for subscription runs too. It changes no accounting or limits. See [security assessment](security-assessment.md#output-and-continuation).

## Profiles and providers

A [scan profile](profiles.md) selects the model profile, depth, USD budget, exports, and report attributes. Without `--profile`, `assess` uses your scan profile `default` if it exists, otherwise `claude`, at standard depth. Configure a Claude login or external Anthropic credentials for `claude`, or `OPENAI_API_KEY` for the experimental `codex` profile. Existing `--host` commands still work; see [model selection](model-selection.md).

The experimental `lite` and `bedrock` profiles need a separate operator connection and external credentials first. See [provider setup](providers.md).

For ChatGPT plan usage on a trusted local machine, install Codex CLI 0.163.0 or newer, sign in with `codex login`, and run:

```sh
appsec-analyzer assess --repo /checkout --profile codex-cli \
  --max-calls 1000 --max-duration 14400 \
  --output /private/subscription-assessment --non-interactive
```

This uses the CLI's existing login and sends selected context to OpenAI. It rejects USD budget flags and stops when the allowance is used up. It does not set up a login for a CI runner. See [Codex CLI prerequisites, recovery, and limits](profiles.md#use-your-chatgpt-plan-with-codex-cli).

## Running and resuming an assessment

`assess` shows progress and creates a private default destination if you omit `--output`. A stop request keeps accepted work. `--resume` reuses the steps that still match, and `--rebuild` starts over. Rate limits and connection failures pause the run with exit code 3. Wait, then repeat the command with `--resume`. See [rate limits and connection failures](security-assessment.md#rate-limits-and-connection-failures).

Normal progress shows skipped optional model jobs at once as `Coverage gap` warnings. The final summary lists omitted work. `--quiet` hides live progress. Add `--verbose` to match model messages to their jobs and calls. Private diagnostics for every attempt are saved under the output directory in `.assessment-work/diagnostics/`, also with `--quiet`. See [progress and diagnostics](security-assessment.md#progress-and-diagnostics).

`status` and `results` tell scanner-only output, completed assessments, interrupted runs, and failures apart. After cleanup removes the event feed, `progress` returns the final state with `feed_available: false` and no events.

Exit codes of `assess`:

| Exit code | Meaning |
| --- | --- |
| `0` | The assessment completed and the selected gate passed. |
| `20` | The assessment completed, but the findings gate failed. Keep the reports. |
| `3` | The run paused or stopped before completion. Keep the output and resume. |
| `130` | Interrupted by an operator or signal. |
| `1` or `2` | Operational, configuration, or invocation error. |

## Commands without an assessment

- **`preflight`** checks repository access and provider setup without running an assessment: `appsec-analyzer preflight --repo /checkout --profile claude --json`. It returns 0 when the checks pass, 2 on failure, and 130 on cancellation. It makes no model call unless you add `--test-model`, which uses money or plan allowance and needs its own budget or call limit. See [preflight checks](security-assessment.md#preflight-checks).
- **`export`** converts a completed assessment without model calls: `appsec-analyzer export --assessment /path/to/assessment --output /path/to/new-export --formats markdown yaml sarif`. It prints JSON with artifact digests. Invalid inputs or a failed conversion return 2. The destination must be new. See [exports](security-assessment.md#exports-and-compatibility).
- **`scan-sources`** needs an existing output directory. It prints readable observations, or versioned JSON with `--json`. `--output` also saves `scan-result.json`.
- **`score REPO`** needs no model and no result directory. Progress goes to stderr, and stdout holds only the result as text, JSON, or YAML. A low score still exits 0, so there is no score threshold for CI. Exit 2 means too little coverage (`undetermined`) or invalid arguments. Exit 1 means an operational error or incomplete scan. Ctrl+C returns 130. See [security score](security-score.md).
- **`analyze-threats`** answers a focused question. Example: `appsec-analyzer analyze-threats "Question" --path src/api --non-interactive`, or select a change, MR, or PR. An unclear scope or an unanswered required question returns 2. `--preview` makes no model call, but resolving an MR or PR still uses the network. It uses Claude CLI and `--max-budget-usd` per call, independently of assessment profiles. See [focused threat analysis](threat-analyst.md).
- **`audit-requirements`** checks a catalog: `appsec-analyzer audit-requirements --repo /checkout --requirements /catalog.yaml --output /private/audit --host claude-cli --budget 5`. Its result records `assessment_status: not_run`. `--gate` returns exit 1 for qualifying failures. See [requirements audit](security-requirements-audit-skill.md).
- **`authnz-review`** reviews authentication and authorization through Claude CLI: `appsec-analyzer authnz-review --repo /checkout --budget 5 --json`. It needs no assessment and never waits for input. `--yaml` prints YAML. `--save --pentest-tasks --pentest-output-format both` keeps reports and pentest plans in a new private directory. Exit 1 means a selected gate failed, 2 means incomplete or invalid execution, and 130 means cancellation. See [AuthNZ review](authnz-review.md).
