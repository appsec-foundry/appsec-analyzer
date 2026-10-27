---
reason: The user asked for a review of the requirement catalog for wording, length, and implementation detail, and approved the proposed changes. Several catalog entries repeated rules of the acceptance contract, named flags or commands, used unexplained terms, or stood in the wrong section.
affected_ids: [REQ-001, REQ-002, REQ-004, REQ-011, REQ-016, REQ-021, REQ-023, REQ-024, REQ-025, REQ-026, REQ-036, REQ-038, REQ-039, REQ-040, REQ-041, REQ-042, REQ-043, REQ-044]
compatibility: No command, behavior, saved artifact, or acceptance rule changes. Every detail removed from the catalog is already stated in the acceptance contract, which stays normative. REQ-044 takes over the AuthN/AuthZ review from REQ-024 with its unchanged acceptance paragraph and its bindings; REQ-024 keeps the focused question. REQ-043 moves to "Run and maintain assessments" with its unchanged contract section. No ID is retired.
verification: make check-specs BASE=bd5820f6 checks the catalog, the acceptance sections, the bindings, and this proposal. tests/test_check_specs.py::test_shipped_catalog_and_bindings_are_valid and tests/test_check_specs.py::test_shipped_acceptance_matches_every_active_requirement read the shipped catalog, bindings, and contract. A review of the diff confirmed that each removed catalog detail has a matching contract rule.
---

# Shorten the requirement catalog

The user asked whether the requirements make sense in wording and length and whether some contain implementation detail that does not belong in the catalog. The user approved all proposed changes, including the split of REQ-024, and asked for the change directly on `main`.

Catalog details removed because the acceptance contract already states them:

- REQ-040: live progress, the outcome counts of the completion summary and the report, how combined findings merge their parts, and the link from each finding to its verification items and rules. The catalog now says that the report shows the outcome of each item. The entry shrinks from 201 to 135 words.
- REQ-038: that a separate command runs the check, the phase order in an assessment, and the skipped check for a local repository.
- REQ-002: how the depth question describes each choice.
- REQ-016: the `--resume` flag and the sentence it repeated.
- REQ-043: the command name `appsec-analyzer update`.
- REQ-023: the default cost display and the option to enable it, including the unexplained term "API mode".
- REQ-004: that scanner rules work at single locations and across the application.
- REQ-021: that integrity is checked when results are listed.
- REQ-041: output validation and the disclosure of data transfer and usage limits, which REQ-021, REQ-023, and REQ-033 state for every provider.
- REQ-001: the sentence that repeated the separation from the assessment.

Wording corrected:

- REQ-011 and REQ-026 say "abuse case" instead of "misuse case", as README, guides, and the CLI do.
- REQ-024 no longer mentions Markdown as a document format, and "Choosing an analysis method" became "it does not certify compliance or authorize further actions", because users do not know methodology profiles.
- REQ-025 explains what "established requirements" and "proposed changes" mean.
- REQ-036 says "still shows its findings when it cannot compute a score".
- REQ-039 says "update the engine version it depends on" instead of "align the engine pins".
- REQ-042 said that the model proposes rules for missed credentials. The contract says the model only names the location, provider, and keywords, and Analyzer derives the rule. The catalog now says that Analyzer proposes the rules.

Structure:

- REQ-044 "Review authentication and authorization" is new and holds the AuthN/AuthZ review that REQ-024 mentioned in one sentence. Its catalog text states two existing contract rules: deterministic scanner signals stay when the model leaves them out, and an incomplete review never passes as clean. The bindings for `authnz_review.py`, the scanner execution, source preflight, artifact publication, the AuthNZ guide, and the three AuthNZ guards moved from REQ-024 to REQ-044; `engine.py` stays in both, because `analyze-threats` also uses it.
- REQ-043 moved from "Decide what to fix" next to REQ-019 under "Run and maintain assessments", in the catalog and in the contract.

Not changed: the acceptance contract also holds detail that may belong in guides or tests, such as the terminal colors of REQ-036 and the preflight and diagnostics rules under REQ-016. That was mentioned and left for a separate decision.
