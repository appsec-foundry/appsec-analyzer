---
reason: The repository URI already names the destination host, but platform checks skipped self-hosted GitLab unless GITLAB_HOST repeated it; Git credential hints also confused an unselected token with a rejected token.
affected_ids: [REQ-038, REQ-045]
compatibility: GITLAB_HOST remains an explicit platform assignment and keeps its existing Git-token host binding. Without it, platform checks try the selected URI host anonymously before any explicitly supplied platform token. Unknown checks remain unknown, saved results retain their format, and no model calls or new destinations are added.
verification: Offline tests cover URI host selection, anonymous project detection, explicit token access, unrelated and malformed responses, prohibited destinations, one platform token for several hosts, credential hints, and unknown Git failures; run the standalone offline gate and Ruff checks.
---

# Use the repository URI for the platform host

The user requested clearer Git preflight messages and a commit on main, then asked to take the host from the repository URI when GITLAB_HOST is unset. This simplifies the existing REQ-038 platform check and clarifies REQ-045 diagnostics without adding a new user outcome or changing the requirement catalog.

The platform check tries the selected host's GitLab project API anonymously. A positive project ID and matching namespace identify a project response. An explicitly supplied read-only platform token can read a private project after an anonymous authorization or not-found response. Detection alone never selects an ambient Git token. Hosts without an identifiable or readable project fail the check and remain unknown in an assessment rather than being skipped for missing configuration.

The change can add anonymous API reads to URI hosts that previously had no platform check. They are the same user-selected destinations, under the existing transport, address, allow-list, redirect, and response limits. Unconfirmed hosts count toward the existing rule that one platform token cannot go to several hosts. No live qualification or model-backed assessment is authorized by this change.
