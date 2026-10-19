---
reason: scan and assess ran the same assessment and differed only in defaults, so users had to choose between two commands for one workflow. The explicit-provider check that assess gave scripts belongs to unattended scan runs.
affected_ids: [REQ-011, REQ-018]
compatibility: The assess command is removed; calls fail with an invalid-choice error and must use scan. scan --non-interactive now requires --repo and an explicit --profile or legacy --host, except where an organization distribution supplies the profile, so an unattended run never starts on the default provider. Interactive scan and all other options are unchanged. The internal controller subcommand of the same name is not a public command and is unchanged.
verification: Offline tests cover scan --non-interactive refused without --repo, without a provider selection, and with neither, before host preflight; the removed assess command rejected by the parser; and the scan variants of the profile, budget, parallelism, abuse-case-file, source-preflight and organization-distribution tests. The specification gate runs against the base commit. No live model call was made.
---

# Remove the assess command

`assess` required `--repo` and an explicit `--profile` and otherwise matched `scan`. `scan --non-interactive` now enforces the same requirement, so CI jobs choose their provider deliberately, and `assess` is removed from the CLI, the organization composition command list, the guides, the installed entry skill and the helper scripts.
