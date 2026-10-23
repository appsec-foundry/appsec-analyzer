---
reason: Users want to find leaked credentials in their sources with maintained open-source detection rules and their own rules, and want a model to separate real credentials from test values, explain exposure and fixes, point out credentials the rules miss, and propose rules for them, without any secret value reaching a model or a result.
affected_ids: [REQ-042, REQ-018]
compatibility: Adds the requirement and its acceptance rules, and adds to the REQ-018 acceptance rules that organization profiles can supply secret rules for secret scans. Nothing is implemented yet; existing commands, schemas, and saved results are unchanged. The planned scan-secrets command is new, and assess, scan-sources, and score keep their behavior. The organization profile gains an optional secret_rules field, so existing profiles stay valid; a distribution's bundled profile then also applies to scan-secrets. Gitleaks becomes a user-installed prerequisite of the new command only.
verification: The specification check validates the catalog entry, binding, acceptance section, and this proposal. The binding is advisory because no test covers the requirement yet. The implementation must add the intended and negative cases that the acceptance rules list, run offline with recorded model replies; no live model call is made without explicit authorization.
---

# Secret scan

Adds REQ-042. A new `scan-secrets` command finds credentials with Gitleaks and Analyzer's maintained rules plus the user's own rules, without model calls. With `--review`, a model reviews each hit in masked code context, points out credentials the rules missed, and proposes rules that the user can adopt.

## Decisions

The user approved the requirement wording in the conversation that drafted it. These decisions were made there:

- Gitleaks (MIT) runs as an external binary that the user installs. Two variants were rejected. Extending Analyzer's own detector would mean maintaining provider token formats in a pattern set of about 15 rules that was built to mask reports. Porting the Gitleaks rules to Python would rebuild the engine they depend on (keyword prefilter, entropy, allow-lists, decoding), swap the linear-time RE2 engine for backtracking, lose the rule fixtures that live in the Gitleaks generator, and need syncing with every upstream release. TruffleHog was not chosen because of its AGPL-3.0 license and because its strength is live validation, which is excluded.
- There is no fallback to Analyzer's own detector when Gitleaks is missing; a much weaker silent fallback would make a scan without hits misleading.
- The command is called `scan-secrets`, matching `scan-sources`, and the model review is selected with `--review`. `--verify` was rejected because it suggests live validation.
- The model reviews hits, points out missed credentials, and proposes rules. Model-generated rules never take effect at runtime, because model output must not supply executable patterns (REQ-040 acceptance rules) and a prompt injection in the repository could otherwise hide hits. A proposal becomes active only when the user adds it to their own rules.
- Users can add their own regular expression rules in the Gitleaks format. Own rules only add hits and cannot contain allow-lists.
- Own rules come from three sources, following the pattern of scan profiles: `secret-rules/` in the XDG configuration directory, `--rules FILE` for a single run, and a new `secret_rules` field in the organization profile for team rules. The organization profile was chosen over a separate entry in the distribution manifest because it also works without a distribution through `--org-profile`, and `organization validate` already checks the files a profile references. The REQ-018 rule that bundled defaults apply only to full assessments is extended for these secret rules.
- Found credentials are never validated against their providers: that would use credentials without authorization and send them to third-party hosts.
- The model sees only masked literal values. The alternative of sending code as `assess` does would find more missed credentials but would send undetected secrets to the model host.
- The requirement text was shortened; implementation details moved to the acceptance rules.

Still open: whether Git history can be scanned on request (not part of REQ-042 for now), whether `assess` uses the results, and whether users can suppress false positives with a recorded reason, which would be a separate feature.

## Risks raised

- **New external dependency:** Gitleaks is a Go binary outside the Python packaging. The user installs it, Analyzer checks a minimum version and records it, and nothing is downloaded automatically. A pinned download with checksum would be more convenient but adds a download path to maintain.
- **Data sent to models:** With `--review`, context windows around hits and selected candidate code go to the model host. Literal values are masked, but variable names, paths, and host names are still sent.
- **Model cost:** Repositories with many hits make reviews expensive. Deterministic prefiltering, batching, and the shown call or spending limit bound the cost.
- **Model judgement is not proof:** A real production key can sit in a test file, and a comment such as "test key only" can sway the model. A review therefore only labels a hit and never removes it.
- **Lower hit rate for missed credentials:** Masking every literal value means the model judges structure, such as a literal passed as a password argument, rather than the value itself.
- **User-supplied regular expressions:** Own rules run in the scanner's linear-time engine and are validated before the scan; an invalid rule stops the scan instead of silently reducing coverage.
- **Rules that apply without being chosen per run:** Rules from the XDG directory and from a distribution's bundled profile apply automatically, so two machines can produce different results. The result lists every active own rule with its source, and `--no-org-profile` disables the team rules for a run.
- **Repository-controlled suppression:** Gitleaks honors configuration, ignore files, and inline allow markers from the scanned source. Analyzer ignores the first two and reports hits with inline markers as marked allowed by the repository.
- **Existing commands and saved results:** None change.
