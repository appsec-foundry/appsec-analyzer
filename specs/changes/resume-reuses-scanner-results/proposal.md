---
reason: A resumed or taken-over run spent about three and a half minutes before its first new model call, because every phase ran its deterministic scanners again although source and Analyzer were unchanged, and the start header did not say that the run was a resume.
affected_ids: [REQ-016]
compatibility: Results and exit codes are unchanged. A run that continues an unfinished run reuses scanner output of identical source, depth and Analyzer runtime from its private work directory, and the header names the resume and its cause. A changed source or Analyzer recomputes everything.
verification: Offline tests cover reuse of an identical snapshot, recomputation after changed files, depth, architecture depth or runtime, rejection of altered, damaged and linked result files, no cache without configuration, the work directory keeping the results for a new run and dropping them on rebuild, and the Resumed header rows.
---

# Faster, clearer resume

The user asked for a clearer console and a faster return to the point where the run stopped. The header shows a `Resumed` row; when `--resume` runs as a new run, a second line names the cause. Scanner results are kept per source, depth and runtime fingerprint, so a plugin or source change never returns an older answer. The results are neither written nor read when the output lies inside the analyzed checkout, which a repository controls. The model-job validation of taken-over steps is not changed here.
