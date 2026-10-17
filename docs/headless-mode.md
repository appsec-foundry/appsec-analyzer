# Command-line and unattended operation

Install the package, then invoke the same public program locally or in CI:

```sh
appsec-analyzer scan --repo /checkout --output /private/scan
appsec-analyzer assess --repo /checkout --host claude-cli \
  --hard-budget 20 --output /private/assessment --quiet
appsec-analyzer status --output /private/assessment
appsec-analyzer progress --output /private/assessment
appsec-analyzer stop --output /private/assessment
appsec-analyzer results --output /private/assessment
```

Create `/private/scan` before the first command. A scan without `--output`
prints its versioned JSON to stdout. The assessment command creates its
private default destination if `--output` is omitted. A `stop` request preserves
accepted assessment work for a compatible `--resume`. `--rebuild` starts over.
The result and status contracts distinguish scanner-only output from completed,
interrupted, and failed assessments.

The old `scripts/run-headless.sh` instructions are retained only in the
[historical guide](history/advisor/headless-mode.md). An independent
requirements audit cannot currently be launched by this public command; a
requirements check inside an assessment is selected with `--requirements`.
