---
reason: The completion summary's Verification line listed seven outcome counts and became too long to read at a glance, although only some of them ask the reader to act.
affected_ids: [REQ-040]
compatibility: The completion summary leads with the counts of items with a finding, a control, a partial result and an undecidable result, and leaves the counts of items with no finding, that do not apply, or are disabled to the report, unless the run has none of the four. The report and saved results keep every outcome per item.
verification: Closing line tests for each combination of outcomes, including a run with only outcomes that need no action; the report appendix tests that state every outcome; requirements checks.
---

# Shorter verification line in the completion summary

REQ-040 named all outcomes for the completion summary. It now names the four that ask for a look, and the report keeps stating all of them. The line therefore reads `39 findings · 3 controls · 4 partial · 34 undecidable`.
