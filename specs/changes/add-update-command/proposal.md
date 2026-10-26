---
reason: Updating the installed Analyzer was only offered after a result from a newer version failed to open. The user asked for an update command that works at any time.
affected_ids: [REQ-043]
compatibility: Adds the command `update` and extends REQ-043 by one sentence and its title ("Update Analyzer"). No existing command, exit code, or saved artifact changes. Organization distributions do not get the command.
verification: Offline tests in tests/test_public_update_cli.py cover the upgrade after a yes with the source shown, no installation after no, other input, or end of input, a failed upgrade, no question in CI, without a terminal, outside pipx, or without a pipx executable, rejection of a `--yes` option, and the absence of the command in an organization command. The upgrade command is replaced by a stub in every test. No test runs a real update.
---

# Add an update command

The user approved the wording in conversation as an extension of REQ-043 instead of a new requirement, chose that `update` installs after an explicit yes, chose no option that skips the question, and asked for the implementation directly on `main`.

Risks raised before approval:

- After a yes, Analyzer installs code from the network, as in REQ-043. The explicit yes is the only safeguard, and the source is shown first.
- The source is a GitHub repository, because the package is not on PyPI. Without access to it, the update fails.
- An organization distribution is often pinned to a version, so it gets no update command.
- A skip-the-question option would allow unattended installs, for example from a cron job. It was left out.
- The command makes no model call and sends no assessment data.

Found after the first implementation: `pipx upgrade appsec-analyzer` does nothing for an installation from a Git source while the version number stays the same, because pipx reports "already at latest version". A test with a temporary pipx installation (pipx 1.0.0, a local Git repository as source) showed that `pipx upgrade --pip-args=--force-reinstall` installs the newest commit in place, while `pipx upgrade --force` did not, and `pipx install --force` returned an older commit twice. `pipx reinstall` also worked but removes the installation first, so a network failure would leave none. Both `update` and the offer from REQ-043 use the working command. This was not run against GitHub.

Simpler variant that was not chosen: a command that only shows the `pipx upgrade` command to run.
