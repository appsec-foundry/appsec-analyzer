---
reason: The operator requested an action-oriented score heading that identifies the repository being analyzed.
affected_ids: [REQ-036]
compatibility: Change only the initial stderr heading under interface version 1; retain progress phases, timings, result formats, source policy, and exit codes. Show the selected local path or a Git host/project without credentials or URL parameters.
verification: Run public score and installed-package tests, documentation/specification checks, and changed-file Ruff checks. Cover immediate piped startup, local and relative paths, HTTPS/SSH/SCP selections, credential and parameter omission, malformed URLs, terminal injection, and bounded labels.
---

# Identify the repository in the score heading

Begin with `Calculating security score for ...` and the operator-selected repository. Expand local paths without reading repository contents and keep Git host/project identity while removing user information, query parameters, and fragments. Reject unsafe control, formatting, or surrogate characters and bound the visible label to 240 characters. Invalid selections receive a generic label and still fail through normal source admission; formatting the heading does not authorize retrieval or relax validation.

Display the heading before importing the scoring runtime so an immediately visible startup message remains available even when stderr is piped. Keep detailed status lines fixed and leave structured stdout unchanged. This explicitly permits the selected repository identity in progress, superseding the earlier restriction against any path or URL in status messages; other filenames, source contents, and credentials remain excluded.

Verification completed: 42 public score cases and eight installed-package/documentation cases passed, including immediate piped startup with the selected path, successful remote checkout with a credential-free heading, malformed and credential-bearing URLs, control-character rejection, and unchanged structured output. The revised relative-path case also passed with a control character in the working directory. Specification change coverage validates against `69c2501f14f59746f4d96409135abbff9d30a256`; changed Python files pass Ruff lint and format checks and changed documentation links resolve. No live model calls or external repository retrieval were needed.
