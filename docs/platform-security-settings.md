# Platform security settings

`appsec-analyzer platform-settings URL` checks security settings of a repository on github.com, gitlab.com, or a self-hosted GitLab without model calls. It sends read requests to the platform API. It sends no source code and writes nothing to the repository or the platform.

```sh
appsec-analyzer platform-settings https://github.com/your-org/your-project
appsec-analyzer platform-settings https://gitlab.com/your-group/your-project --token-env GITLAB_READ_TOKEN --yaml
GITLAB_HOST=gitlab.example.com appsec-analyzer platform-settings https://gitlab.example.com/your-group/your-project
```

Replace the example URLs with your own repository. `--json` and `--yaml` are mutually exclusive. The URL must be an HTTPS or SSH URL of a repository on one of these hosts. Local paths and other hosts are rejected.

## Self-hosted GitLab

Set the environment variable `GITLAB_HOST` to the host name of your instance, such as `gitlab.example.com`. Analyzer treats only that host as GitLab, because a host name does not show which platform runs there. It never takes the host from repository files.

Requests go to port 443 of that host, so URLs with their own port are rejected. A self-hosted host passes the same checks as Git retrieval before every request: `APPSEC_URL_ALLOWLIST` applies, and addresses such as loopback or link-local are refused. Private addresses are allowed. If your proxy settings apply to the host, the proxy reaches it and only the allow-list applies. For a private certificate authority, add it to the certificates your system trusts.

Settings your version or license does not offer or return are reported as `not checkable`. The reason can read `missing permission`, because Analyzer cannot always tell a missing feature from missing access.

## Token

Without `--token-env`, only publicly readable data is checked. Many settings need more access, so expect `not checkable` results for them.

`--token-env NAME` reads the token from the environment variable `NAME`. Use a read-only token. The command fails if the variable is unset or empty. Analyzer sends the token only to the platform host, refuses redirects to another host, and does not write it to results, logs, or diagnostics. It never takes a token from repository files or from an existing command-line login.

For GitHub, a fine-grained token with read access to `Metadata` and `Administration` covers the Actions and branch protection checks. Secret scanning and push protection are visible only with repository admin or organization security manager access. GitLab roles are not yet confirmed; see the open points in the [check catalog](internal/contracts/platform-security-settings.md#open-points).

## Results

Each check reports one state:

| State | Meaning |
| --- | --- |
| `set` | The setting is configured. It does not show that the setting works or that no bypass exists. |
| `not set` | Every source for the check was readable and none enforces it. |
| `not checkable` | Analyzer could not read the setting. The reason is `missing permission`, `feature not offered by the platform or plan`, or `platform error`. |

A setting that cannot be read never counts as `set` or `not set`. A missing field and an empty answer count as unreadable when the platform also returns them to callers with too little access.

The checks, their IDs, and what counts as `set` are listed in the [check catalog](internal/contracts/platform-security-settings.md). The result names the platform, repository, visibility, access level, and check time. It describes the settings at that time, not the code, and is not a release approval.

## In a scan

`assess` runs the same checks as the Platform Security Settings phase, after the context is captured and before the architecture analysis. It checks every repository you selected as a URL on github.com, gitlab.com, or the host in `GITLAB_HOST`. A local checkout is shown as skipped and sends no request, even if its Git remote points to GitHub or GitLab. Add `--platform-token-env NAME` to use a read-only token from an environment variable; without it only public data is checked. A token goes to one host only, so a run with repositories on several hosts stops at the start; leave out the option to check them with public data only. A check that fails is recorded as unknown and does not stop the scan.

Before the first request, the phase prints the platform host. It saves results in the private working directory and reuses them on resume.

Control analysis and the survey receive only fixed fields: check ID, state, reason, repository, access level, and check time. Platform free text does not reach a model. These roles must treat unreadable or unchecked settings as unknown. Settings alone cannot prove a finding or control. Other roles receive no platform results. In a combined scan, the summary lists all checked repositories without assigning them to components.

The report shows the result in an unnumbered section, Platform Security Settings, below Trust Boundaries, and the model stores it in `meta.platform_security_settings`. A local checkout appears there as skipped, so the report shows that the check did not run. Reports from earlier scans have no such section.

## Limits

Administrator access, webhooks, and deploy keys are not checked. Only github.com, gitlab.com, and a self-hosted GitLab named by `GITLAB_HOST` are supported; GitHub Enterprise is not. The self-hosted check has been tested offline only.
