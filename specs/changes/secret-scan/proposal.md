---
reason: Users want to find leaked credentials in their sources with maintained open-source detection rules and their own rules, and want a model to separate real credentials from test values, explain exposure and fixes, point out credentials the rules miss, and propose rules for them, without any secret value reaching a model or a result. A follow-up changed how the rules run, because users would have had to install the Gitleaks program themselves, and left out the generic rule, because the user wants reliable rules rather than many false positives.
affected_ids: [REQ-042, REQ-018]
compatibility: Adds the requirement and its acceptance rules, and adds to the REQ-018 acceptance rules that organization profiles can supply secret rules for secret scans. Nothing is implemented yet; existing commands, schemas, and saved results are unchanged. The planned scan-secrets command is new, and assess, scan-sources, and score keep their behavior. The organization profile gains an optional secret_rules field, so existing profiles stay valid; a distribution's bundled profile then also applies to scan-secrets. The new command needs an optional installation extra that adds google-re2, and tomli on Python 3.10; installing Analyzer without the extra is unchanged.
verification: The specification check validates the catalog entry, binding, acceptance section, and this proposal. The binding is advisory because no test covers the requirement yet. The implementation must add the intended and negative cases that the acceptance rules list, run offline with recorded model replies; no live model call is made without explicit authorization.
---

# Secret scan

Adds REQ-042. A new `scan-secrets` command finds credentials without model calls. It uses the provider-specific rules of Gitleaks, Analyzer's maintained rules, and the user's own rules, evaluated by Analyzer's own scanner on the RE2 engine. With `--review`, a model reviews each hit in masked code context, points out credentials the rules missed, and proposes rules that the user can adopt.

## Decisions

The user approved the requirement wording in the conversation that drafted it. These decisions were made there:

- The command is called `scan-secrets`, matching `scan-sources`, and the model review is selected with `--review`. `--verify` was rejected because it suggests live validation.
- The model reviews hits, points out missed credentials, and proposes rules. Model-generated rules never take effect at runtime, because model output must not supply executable patterns (REQ-040 acceptance rules) and a prompt injection in the repository could otherwise hide hits. A proposal becomes active only when the user adds it to their own rules.
- Users can add their own regular expression rules in the Gitleaks format. Own rules only add hits and cannot contain allow-lists.
- Own rules come from three sources, following the pattern of scan profiles: `secret-rules/` in the XDG configuration directory, `--rules FILE` for a single run, and a new `secret_rules` field in the organization profile for team rules. The organization profile was chosen over a separate entry in the distribution manifest because it also works without a distribution through `--org-profile`, and `organization validate` already checks the files a profile references. The REQ-018 rule that bundled defaults apply only to full assessments is extended for these secret rules.
- Found credentials are never validated against their providers: that would use credentials without authorization and send them to third-party hosts.
- The model sees only masked literal values. The alternative of sending code as `assess` does would find more missed credentials but would send undetected secrets to the model host.
- The requirement text was shortened; implementation details moved to the acceptance rules.

A follow-up conversation, after the user asked how Gitleaks would be installed, replaced the first plan of running the Gitleaks program, which users would have installed themselves:

- Analyzer runs its own scanner on the RE2 engine through the `google-re2` package (BSD-3-Clause, maintained by Google) and packages the Gitleaks default rules (MIT) as base rules. A probe with google-re2 1.1.20251105 compiled all 222 rules and 306 patterns of Gitleaks v8.30.1; Python's own `re` rejected five of them. The earlier argument against a Python solution, that it would replace RE2 with a backtracking engine, was wrong once google-re2 is used.
- Alternatives that were checked and rejected: no maintained Python package ships Gitleaks. detect-secrets is widely used but had its last release in May 2024, has 26 detectors against 222 Gitleaks rules, and accepts own rules only as Python code, which an organization profile must not distribute. ggshield sends content to the GitGuardian API. trufflehog3 and whispers have had no release since 2024, and Nosey Parker is archived. TruffleHog was not chosen because of its AGPL-3.0 license and because its strength is live validation, which is excluded. Keeping the Gitleaks program with an install command that downloads a pinned release would need a maintained download per platform, for releases that are checksummed but not signed.
- google-re2 is an optional installation extra, because it has no prebuilt packages for Alpine Linux or macOS before version 13, and a required dependency would break the whole installation there. The extra also adds tomli, so that Python 3.10 can read own rules in the Gitleaks format.
- There is no fallback to Analyzer's own detector or to Python's own regular expression engine when google-re2 is missing. A weaker silent fallback would make a scan without hits misleading and would run own rules in a backtracking engine.
- The generic rule `generic-api-key` is left out. In this repository and in OWASP Juice Shop it produced about 70 percent of the hits, and a masked sample of 44 of them found almost only test values, configuration keys, and translation strings. The provider-specific rules matched only real token formats, and the rules that look for a provider name next to a fixed-form value matched nothing in either repository. The user wants reliable rules rather than many false positives and agreed to leave credentials without a recognisable format to the model review.
- Licenses fit: Analyzer is Apache-2.0, the packaged rule copy keeps its MIT license text and copyright notice, and google-re2 is only a declared dependency that Analyzer does not ship.

Still open: whether Git history can be scanned on request (not part of REQ-042 for now), whether `assess` uses the results, and whether users can suppress false positives with a recorded reason, which would be a separate feature.

## Risks raised

- **Own scanner to maintain:** Analyzer reimplements how a rule is evaluated (keywords, entropy, secret groups, allow-lists, stop words) and can drift from Gitleaks. Base rule updates are manual copies of a reviewed release, checked by compiling every rule and running the fixtures. Gitleaks keeps its per-rule test values in its rule generator, so Analyzer needs its own fixtures.
- **Lower coverage than Gitleaks:** Values encoded as Base64 or hex are not decoded, and the generic rule is left out. Credentials without a recognisable format are found only with `--review`.
- **Rules with a provider name:** About 100 base rules look for a provider name next to a value of fixed form. They matched nothing in two repositories, so their precision is not established; every hit names its rule, so a noisy rule can be removed later.
- **Compiled dependency:** google-re2 contains compiled code, including a statically linked copy of Abseil (Apache-2.0) whose license text the package does not ship. Someone who redistributes installed packages, for example in a container image, should add it.
- **Data sent to models:** With `--review`, context windows around hits and selected candidate code go to the model host. Literal values are masked, but variable names, paths, and host names are still sent.
- **Model cost:** Repositories with many hits make reviews expensive. Deterministic prefiltering, batching, and the shown call or spending limit bound the cost.
- **Model judgement is not proof:** A real production key can sit in a test file, and a comment such as "test key only" can sway the model. A review therefore only labels a hit and never removes it.
- **Lower hit rate for missed credentials:** Masking every literal value means the model judges structure, such as a literal passed as a password argument, rather than the value itself.
- **User-supplied regular expressions:** Own rules run in RE2 and are validated before the scan; an invalid rule stops the scan instead of silently reducing coverage.
- **Rules that apply without being chosen per run:** Rules from the XDG directory and from a distribution's bundled profile apply automatically, so two machines can produce different results. The result lists every active own rule with its source, and `--no-org-profile` disables the team rules for a run.
- **Repository-controlled suppression:** Gitleaks honors configuration, ignore files, and inline allow markers from the scanned source. Analyzer ignores the first two and reports hits with inline markers as marked allowed by the repository.
- **Existing commands and saved results:** None change.
