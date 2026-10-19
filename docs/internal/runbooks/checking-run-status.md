# Inspect and recover an Analyzer run

Use the output directory of the full assessment. The default location is in the user's private Analyzer data directory, not `docs/security` in the analyzed repository. The CLI prints the selected location.

```sh
appsec-analyzer status --output /private/assessment
appsec-analyzer progress --output /private/assessment
appsec-analyzer results --output /private/assessment
```

`status` returns the run identity, lifecycle state, accounting, and deliverable names. `progress` returns bounded recent events. After successful cleanup the feed may be absent; `feed_available: false` with the final state is expected. `results` requires completion and verifies every recorded deliverable digest. A changed or symlinked artifact is rejected.

To request a stop:

```sh
appsec-analyzer stop --output /private/assessment
```

The controller observes cancellation at its next checkpoint. Do not infer immediate termination from the request alone. Check status before taking another action.

Resume an interrupted run using the same selected source and compatible options:

```sh
appsec-analyzer scan --repo /path/to/project --host claude-cli \
  --budget 20 --output /private/assessment --resume
```

The budget shown is an example requiring authorization. Changed source, incompatible settings, expired state, or unresolved cost accounting may prevent resume. Follow the reported reason; do not edit state files to bypass it. A deliberate `--rebuild` starts over and must respect existing user edits.

These operations apply to full-assessment state. A source scan has a standalone JSON result; a requirements audit cannot resume. Focused analyst jobs use `analyst answer` and `analyst cancel`. The retained `runtime/appsec_status.py` depends on excluded Advisor modules and is not the current status interface.
