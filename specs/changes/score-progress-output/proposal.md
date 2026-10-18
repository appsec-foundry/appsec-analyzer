---
reason: The operator reported a silent startup and an unreadable excluded-file listing in the public score command, and requested immediate progress and removal of that listing.
affected_ids: [REQ-036]
compatibility: Keep public interface version 1, score arithmetic, source-policy identity, and exit codes. Progress is now flushed to stderr while stdout remains the result stream. New text and structured results omit excluded-file counts and lists; the schema still accepts the optional field in earlier saved results.
verification: Run public score, retained calculation, package installation, documentation contract, and specification tests plus changed-file Ruff checks. Verify startup is readable through a pipe before runtime preparation, cloning and scanner progress precede their work, structured stdout remains parseable, and sensitive files remain excluded internally without being listed.
---

# Visible score progress and concise output

Print a startup message before loading the score runtime. Report Git cloning for explicit remote selections, source reading and preparation, each of the four scanners, score calculation, and final source consistency validation. Each message is flushed to stderr so terminal users and callers that pipe stdout can see work begin. Use fixed messages without repository URLs, file paths, source contents, or credentials. The retained scanner collector accepts an optional progress callback; existing direct-script callers keep their behavior.

Remove the excluded-file listing and its count from the human-readable score and omit `source.excluded_files` from newly generated JSON and YAML. Keep the schema field optional for earlier saved results. Internal exclusions, secret masking, symlink rejection, and source consistency checks continue to enforce the same boundary. Finding counts excluded by the severity policy describe scoring rather than files and retain their existing behavior.

Verification completed: 141 public-score and retained calculation tests passed, including piped startup progress before runtime preparation, progress before real Git cloning and every scanner, clean JSON/YAML stdout, and omission of excluded-file details. Another 119 package, runtime-documentation, and specification tests passed, including the installed wheel's console entry. Specification change coverage validates against `69c2501f14f59746f4d96409135abbff9d30a256`; changed Python files pass Ruff lint and format checks, 61 local documentation links resolve, and `git diff --check` passes. No live model calls or external network retrieval were used.
