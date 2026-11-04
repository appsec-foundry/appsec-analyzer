---
reason: The report anatomy contract that tests/test_report_anatomy.py reads was not carried over when the Analyzer was extracted, so thirteen anatomy tests errored and the composed-report export test could not run. The copy in the Advisor described the report before the table and section decisions made since.
affected_ids: [REQ-013]
compatibility: No report, renderer or saved-result format changes. The contract now describes the report the current renderer produces; the anatomy test additionally reads the header row of HTML tables, so tables the composer emits as fixed-layout HTML are checked too.
verification: tests/test_report_anatomy.py passes against both frozen runs; check_report reports no difference for a current standard-depth assessment (VulnerableSpringApp3). No model calls.
---

# Restore the report anatomy

The user asked to fix the open offline check failures, which included the missing anatomy contract. This restores `report-anatomy.md` from the Advisor and brings it to the report the Analyzer renders today. It changes no report.

The contract now names the Changelog, Top Threats, Operational Strengths, Identified Actors, Trust Boundaries, §2.3 Components, §4 Assets and §5 tables in their current form. It adds the Platform Security Settings subsection, §5.3 for entry points whose authentication could not be determined, the §6 verdict legend and mechanism table, the abuse-case overview tables, business abuse cases, Not verified and Business-case coverage, the Verification Findings chapter, the Verification Items appendix, and the current run statistics tables. A finding card lists Development only, Found by, the two contradiction notes and Reliability in rendering order. Architecture evidence in a weakness entry appears only when a missing control was recorded.

The anatomy test takes over the Advisor's reading of `<thead>` header rows, so Remediation Priorities, §2.3 and other fixed-layout HTML tables are compared with the contract instead of being invisible to it.

Limits: the frozen runs still contain no §6 content, abuse-case scenario, verification result or stage statistics. Those parts were compared with one current assessment report, not by the test.
