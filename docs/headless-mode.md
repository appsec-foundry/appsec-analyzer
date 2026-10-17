# Command-line and unattended operation

Install the package, then invoke the same public program locally or in CI:

```sh
appsec-analyzer scan --repo /checkout --budget 20 --output /private/assessment
appsec-analyzer scan-sources --repo /checkout --output /private/source-scan
appsec-analyzer assess --repo /checkout --host claude-cli \
  --budget 20 --output /private/assessment --quiet
appsec-analyzer scan --repo /checkout --host openai \
  --profile codex-standard --budget 20 --output /private/openai-assessment
appsec-analyzer status --output /private/assessment
appsec-analyzer progress --output /private/assessment
appsec-analyzer stop --output /private/assessment
appsec-analyzer results --output /private/assessment
```

`scan` and `assess` default to a USD 20 spending limit; `audit-requirements` defaults to USD 5. `--budget USD` overrides the default, and `--hard-budget` remains a compatible alias. The CLI prints the selected limit to stderr before starting. Use an explicit budget in automation when its spending limit should be visible in the command.

Create `/private/source-scan` before running `scan-sources`. That command prints
readable scanner findings to stdout; `--json` prints its versioned JSON instead.
With `--output`, the complete JSON is saved as `scan-result.json`. The full `scan`
command uses the same assessment controller as `assess`, shows live progress, and
creates its private default destination if `--output` is omitted. A `stop` request preserves
accepted assessment work for a compatible `--resume`. `--rebuild` starts over.
After a rate-limit interruption, wait for provider capacity and rerun with
`--resume` in place of `--rebuild`.
The result and status contracts distinguish scanner-only output from completed,
interrupted, and failed assessments. After normal cleanup removes the event
feed, `progress` reports the final state with `feed_available: false` and no
events; `status` and `results` remain available.

The separate requirements audit uses `appsec-analyzer audit-requirements
--repo /checkout --requirements /catalog.yaml --output /private/audit
--host claude-cli --budget 5`. Its versioned result reports
`assessment_status: not_run`. Use `--gate` to make qualifying findings return
exit status 1. The old `scripts/run-headless.sh` instructions are retained only
in the [historical guide](history/advisor/headless-mode.md).
