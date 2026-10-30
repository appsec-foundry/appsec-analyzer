---
reason: Teams that run their own GitLab could not check its security settings, because the platform check accepted only github.com and gitlab.com. No recorded decision required that limit, and the GitLab API paths the checks use are the same on a self-hosted instance.
affected_ids: [REQ-038]
compatibility: Repositories on github.com and gitlab.com are checked as before, and saved results stay valid. A URL on the host named by `GITLAB_HOST` is now checked instead of skipped. An `assess` run that combines `--platform-token-env` with repositories on several hosts now stops at the start; before, the same token went to each host. The skipped reason in new results and reports says how to name a host.
verification: Offline tests cover a named host in the command and the scan phase, a host that was not named, `GITLAB_HOST` values with a scheme or a path, a host name with invalid characters, a URL with a port, one token for several hosts, resolved addresses that are prohibited, an address that changes between requests, the connection to the checked address, a redirect, `APPSEC_URL_ALLOWLIST`, a configured proxy, and a host name that stays out of model context and the report. No request to a real instance was made.
---

# Self-hosted GitLab in the platform check

Extends REQ-038. Analyzer checks the security settings of a repository on a self-hosted GitLab instance that the user has named, in `platform-settings` and in `assess`. Every other host stays unsupported.

## Decisions

The user approved the requirement wording and its five acceptance points in the conversation that drafted them, and asked for the implementation directly on `main`. These decisions were made there:

- Self-hosted GitLab is in scope and GitHub Enterprise is not. GitHub Enterprise would need its own way to name a host, and no instance was available to test it.
- `GITLAB_HOST` names the host. It already marks a GitLab host for `GITLAB_TOKEN`, so no new option is needed and Analyzer sends no probe to an unknown host.
- A run that would send one token to several hosts stops before any request. A token works on one platform only, so such a run gained little, and a token for a private instance must not reach a public host.
- URLs with their own port stay rejected, because requests go to port 443.

Implementation choices that follow from the acceptance rules:

- A self-hosted host passes the checks of Git retrieval for every request: `APPSEC_URL_ALLOWLIST`, the prohibited address ranges, and a connection to the checked address. Private addresses stay allowed, because a self-hosted instance usually has one.
- When the operator's proxy applies to the host, the proxy resolves and reaches it, as for Git retrieval, so the address check does not apply and only the allow-list does.
- The stop happens in the command-line validation, next to the check for an unset token variable, so it comes before Git retrieval.

## Risks raised

- **Credentials:** The token goes to a host the user names instead of one of two fixed hosts. The stop for several hosts and the destination checks limit this.
- **Data sent to other hosts:** Requests reveal the repository and, with a token, the account to the instance. No source code is sent. There are no model costs, and the host name stays out of model context and the report.
- **Existing commands:** A token run across github.com and gitlab.com now stops, as described under compatibility.
- **Live behavior:** All tests are offline. The live check of REQ-038 was still open for github.com and gitlab.com, and it now also covers a self-hosted instance. Settings an older version does not return are reported as `not checkable`.
