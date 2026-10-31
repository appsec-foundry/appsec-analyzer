---
reason: A verification item decided by rules reported a confirmed control when its rules found no violation, even when nothing in the repository could carry the control. The Juice Shop run of 2026-10-31 reported "Coding agents run sandboxed and with approvals" as a control although no workflow starts a coding agent, and "Data and admin services are not publicly exposed" although the compose file holds no data service and publishes no port.
affected_ids: [REQ-040]
compatibility: The REQ-040 outcome stays, and its acceptance rule becomes stricter. A rules item now reads control only when at least one rule found the control itself; otherwise it reads no finding, or undecidable when other rules have no recorded result. Structured checks count as proof only when they are named in the code, so some real controls read no finding until their check records what it found. New assessments can report fewer controls than earlier runs. Saved assessments keep their results until they run again, and findings are unaffected.
verification: Unit tests in `tests/test_case_outcomes.py` cover a rule that only found no violation, also beside rules without a result and beside a violated rule, the classification of rules from the shipped checks, and a control that a rule found itself.
---

# A control needs positive evidence

A rule such as "automation must not run a coding agent without a sandbox" passes when the bad flag is absent. That also holds for a repository that runs no agent, so the pass says nothing about a control.

The change separates two kinds of pass. A rule that requires a setting and finds it shows a control. A rule that looks for a bad pattern and finds none shows only that no violation was found, so the item reads no finding.

The user decided on 2026-10-31 to make this correction part of the compact report tables work, as a separate commit.
