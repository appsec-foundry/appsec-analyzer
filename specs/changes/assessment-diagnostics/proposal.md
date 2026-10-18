---
reason: Verbose assessment output discarded scanner and CLI failure context, shortened correction reasons, lacked concurrent job identities, and reused host-event filenames on resume.
affected_ids: [REQ-016]
compatibility: Existing flags, exit codes, budgets, receipts, provider isolation, and publication gates remain unchanged. Full assessments add private bounded per-attempt diagnostic files and correlated verbose messages; resumed Claude host-event streams use separate attempt directories. Rebuild still discards the owned work directory.
verification: Offline diagnostic, scanner, host, job, API, controller, and CLI tests cover correlation, corrections, replacements, resume retention, safe classifications, secret and control-character omission, bounded logs, and link rejection; Ruff and specification checks verify the changed files.
---

# Assessment diagnostics

Keep provider-independent diagnostic events under the assessment work directory. Each process attempt gets a private directory and every model exchange gets a call identity tied to the job's existing receipt identity. Failed and optional jobs retain their classification without persisting source or model payloads. Controller rejection detail is sanitized and bounded with explicit truncation.

Classify bounded CLI stderr in memory and retain safe exit status metadata. Scanner failures identify the scanner, safe failure class, and available exit code. Existing raw Claude host streams remain private intermediate artifacts, separate from the shared sanitized diagnostic feed, and no longer overwrite a previous attempt's stream.
