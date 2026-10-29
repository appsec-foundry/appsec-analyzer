---
reason: Analyzer read a Git token only from APPSEC_GIT_TOKEN, so a token already held in GIT_TOKEN or GITLAB_TOKEN was ignored and a failed access did not say which variable it needed.
affected_ids: [REQ-045]
compatibility: Existing setups with APPSEC_GIT_TOKEN, a credential helper or SSH keep working and keep precedence. Runs that also have GIT_TOKEN or GITLAB_TOKEN set now use them when no earlier variable applies, and the new --git-token-env option selects any other variable. Commands, result formats and exit codes are unchanged.
verification: Offline tests cover the search order, empty fallback variables, GITLAB_TOKEN for GitLab hosts and other hosts, a named variable that is unset or invalid, the option on every command that takes a URL, the merge and pull request API headers, and failure messages without token values.
---

# Git token selection

The user asked for a default search over GIT_TOKEN and GITLAB_TOKEN plus an option that names another variable. The requirement wording and risks were shown in the conversation before the change, and the user then asked for the change to be implemented and pushed.

New requirement REQ-045 covers the outcome. The search order is the named variable, APPSEC_GIT_TOKEN, GIT_TOKEN, then GITLAB_TOKEN. The option and the equivalent APPSEC_GIT_TOKEN_ENV variable take a variable name, never a token.

Risks raised and decisions: the new defaults read variables that may hold tokens meant for other tools, and GIT_TOKEN is sent to any Git host the user selects, as APPSEC_GIT_TOKEN already was. GITLAB_TOKEN is therefore limited to gitlab.com and the host in GITLAB_HOST. A simpler variant with only the option was offered and not chosen. The token reaches the merge and pull request API through the same selection as Git retrieval. Analysis processes still inherit the caller's environment as before.
