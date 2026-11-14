---
reason: Finding the root cause of a failed analysis job means assembling the shared diagnostic feed, host event streams, and job files by hand. The attempt trail names only the first failing check, and only the Claude CLI host records model answers, so failures on other hosts cannot be traced to a cause.
affected_ids: [REQ-050, REQ-032]
compatibility: Adds a requirement without changing behavior yet. REQ-032 now allows the private debug file to hold requests, model answers, and cited source lines. Existing assessments, saved results, and commands stay unchanged. The implementation will add one line to the final message, record rejected answers for every host, and add an offline rerun command.
verification: make check-specs against the base commit and tests that read the changed specification files. The implementation needs intended and negative cases for every host, stopped runs and runs finished with missing checks, secret masking, private file permissions, no shortened requests or answers, no model calls during the rerun, and a refused rerun when the file no longer fits the Analyzer version.
---

# Find the cause of a failed run

The user asked whether Analyzer can write a debug file with all relevant information when an error occurs, so a model can check the error. The goal is to identify and fix the root cause as reliably as possible.

## Approved wording

The user approved REQ-050 with this wording and acceptance:

1. Every failed job is included, whether the run stopped or finished with missing checks. The final message names the file.
2. For each failed job, the file holds the exact request, every model answer, each rejection with the Analyzer check and its code, and the correction that followed.
3. For stopped calls, it holds failure code, timing, retries, and the sanitized host message. This works for every model host.
4. It names the Analyzer version, profile, models, and analyzed commit, and masks secrets. Analyzer sends it nowhere.
5. Analyzer can rerun the checks of a failed job from the file without model calls, also on a newer version, and says when the file no longer fits that version.

REQ-032 gains the sentence that the private debug file of a failed run may contain requests, model answers, and cited source lines.

## Decisions

The user chose a self-contained file over an index that only points to existing files. An index would leave REQ-032 unchanged, but it works only with an assistant that can read local files, and it cannot show answers that a host never recorded.

The file is written automatically when a job fails, not through a separate command. This costs no model calls, and the data is still complete; `--rebuild` later removes the working directory.

Runs that finish with missing checks are included, because their failed jobs have causes just as stopped runs do.

The file includes the exact request, not only the answers. Without it, a reader cannot tell whether the model answered wrongly, the instruction was unclear, or the check was too strict. The check's code is included because the installed Analyzer is often a copy without a checkout.

The offline rerun belongs to the same requirement because it proves a cause and tests a fix: the rerun should fail on the old version and pass with the fix. Implementation proceeds in two steps, first the file (points 1 to 4), then the rerun (point 5). The requirement is recorded on `main`; the implementation happens on a separate branch in its own worktree.

## Risks raised and accepted

The request contains source excerpts, so the file contains real code. It stays private in the output directory. Giving it to a model provider other than the one used for the assessment sends that code to a new recipient; that is the user's decision under REQ-034.

A rerun needs the complete request, so the size bound must not shorten it. Content beyond the bound stays complete in private files next to the debug file.

Covering every host means Analyzer keeps a job's answers until the job succeeds. Every run therefore holds more private data while it runs.

A rerun on a newer version can fail because schemas or request identities changed. The requirement asks Analyzer to report that rather than show a pass that checked nothing.

There are no model costs. The rerun adds a public command with help, README, and packaging updates.
