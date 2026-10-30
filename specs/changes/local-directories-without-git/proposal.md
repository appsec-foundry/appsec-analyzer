---
reason: A local directory without Git could not be assessed, although analysis reads source from the file system and identifies it by file hashes. A sandbox had also left an empty .git in one such directory, which stopped the run with "Git metadata validation failed".
affected_ids: [REQ-002, REQ-036]
compatibility: Git checkouts and Git URLs behave as before and keep their source identity. A directory that was rejected as not being a Git checkout is now accepted by the commands that take Git URLs. Saved results are unaffected.
verification: Offline tests cover a directory with and without .gitignore, an empty .git, a damaged .git, a subdirectory of a checkout, an output inside the directory, nested selections, a nested repository, links, secret-named files, size limits, cleanup after the run, and an identical source identity for unchanged content.
---

# Local directories without Git

The user asked why a run failed and said that a plain directory should be scannable. The requirement wording and the risks below were shown in the conversation, and the user approved them.

Analyzer turns such a directory into a private temporary checkout, the same way it already handles a Git URL, and removes it after the run. `assess`, `scan-sources`, `score`, and `audit-requirements` share that step, so all four accept such a directory; this is why REQ-036 changes too. `authnz-review` and `analyze-threats` stay Git-only. The analysis steps need no change. The file list comes from Git with a private Git directory outside the selected directory, so nested `.gitignore` files apply and nothing is written there.

Options considered: removing Git from the pipeline was rejected because several steps call Git and the schemas expect a commit hash. A better error message alone was rejected because the user would still have to write Git data into the directory. A fixed exclusion list without `.gitignore` was rejected after a check on the user's directory: it would have sent `runtime/documents/finance.txt` to a model.

An empty `.git` counts as no Git, because a sandbox can leave one behind. A `.git` with content that Git cannot read is rejected, because treating it as a plain directory would silently change which files reach a model.

Risks raised and decisions:

- Without a `.gitignore`, nearly every readable file reaches the model, which raises cost and data use. Only the list of secret-named files still applies. Analyzer says so before any model call.
- The temporary copy lies in the same private location as Git URL checkouts and is removed after the run. After a hard stop it stays, and the next run reports it. Secret-named files are not copied.
- Changes made during a run do not reach it, because the run works on the state at its start.
- The temporary commit exists only for the run. The report therefore names the source as a directory without Git and shows no commit.
- Limits stay as for checkouts: 20,000 files and 64 MiB of captured source.
