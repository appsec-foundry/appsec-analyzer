---
reason: Allow operators to save assessment parallelism in scan profiles and override it per invocation.
affected_ids: [REQ-018, REQ-023]
compatibility: Adds optional max_parallel to scan profile schema version 1 and --max-parallel to scan, assess, and profile inspection; the default remains two. Changed parallelism or older snapshots without the setting require a new run; existing reports remain readable.
verification: Offline tests cover profile and CLI precedence, strict integer limits, worker admission and ordering, per-run isolation, time reservations, snapshot incompatibility, public help, and packaged profile examples; no live model calls.
---

# Configurable assessment parallelism

The operator requested both a profile setting and a CLI override for the number of components analyzed concurrently. `max_parallel` and `--max-parallel N` use a default of 2 and accept integers from 1 to 16. The CLI takes precedence over the selected scan profile, and inspection exposes the resolved value and its origin without model calls.

The worker pool and required-analysis time estimate read the same per-assessment budget value. The setting cannot come from an analyzed repository or alter spending authority, accepted-job validation, cancellation, or publication gates. The run header shows the effective limit. Existing lifecycle identity checks reject incompatible configuration, including changed parallelism and snapshots that predate this setting, with instructions to start a new run.
