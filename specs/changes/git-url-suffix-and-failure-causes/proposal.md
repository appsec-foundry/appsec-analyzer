---
reason: An HTTPS Git URL without .git failed on GitLab with a message about tokens, and every failed Git access showed one general message, so users could not tell a rejected token from an unreachable host.
affected_ids: [REQ-002, REQ-045]
compatibility: URLs that work today are used unchanged. A URL without .git that used to fail on a redirect, a missing repository, a missing login or refused access now gets one more attempt with .git on the same host. Failure messages change their wording; commands, result formats and exit codes stay the same. Git runs with LC_ALL=C.
verification: Offline tests run a stand-in Git process that answers with output recorded from real hosts. They cover each failure cause, host text that imitates a cause, output above the size limit, the second attempt and the failures that skip it, and the destination checks of both attempts. Plain Git against gitlab.com, github.com, codeberg.org, bitbucket.org and badssl.com supplied the recorded output. A manual run of the access check and clone against those hosts, without user credentials, confirmed the second attempt on gitlab.com and the causes for a rejected token, a missing login, a missing repository and rejected certificates. HTTP 403, 429 and 5xx answers, the SSH login and host key failures, and a proxy were not exercised against a real service.
---

# Git URL suffix and failure causes

The user asked whether Analyzer should add .git itself to a URL that lacks it, and later asked that the preflight check show the exact cause of a failure, such as a wrong token or an unreachable URL.

REQ-002 gains the approved sentence on the second attempt. The user approved its wording after seeing the options and their risks. REQ-045 changes one sentence: a message that named token variables for every failure would mislead when the cause is a network error, so it now names the cause, and the variables only for a login problem. The user's request for exact causes prompted that sentence, and the user approved its wording.

Options raised: always adding .git was rejected because it changes URLs that work today. Allowing redirects was rejected because it would drop the control that stops a host from sending Git to another destination. Keeping the hint alone was rejected because a first run on GitLab failed, and a proxy hid the redirect, so the message pointed at tokens.

Risks raised and decisions: the token now goes to a second path on the same host. A host that keeps `a` and `a.git` as separate repositories could deliver the wrong one, so the output shows the URL used. The risk of one more failed login was raised too. The implementation removes it: no second attempt follows a rejected token. Connection, certificate, proxy, request limit and server failures also skip the attempt, because the suffix cannot change them.

Causes come from Git's error output, read in the C locale and limited to its last 8 KiB. Only a fixed class leaves that step, so no text from Git or the host reaches a message. Git and the hosts decide what they report: GitHub, GitLab and Bitbucket answered a missing public repository with a login request, so the message says that a private and a missing repository can both cause it. The redirect request now runs only after Git reported a redirect, also for URLs with .git, so a moved repository can be named and other failures send no extra request.
