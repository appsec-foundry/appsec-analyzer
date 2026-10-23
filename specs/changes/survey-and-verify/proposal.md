---
reason: Four pilot runs on Juice Shop showed that the two analysis methods complement each other but stay unconnected, and that the requirement texts named neither method. Readers could not tell which method a requirement means, the term "test case" was confused with software tests, and the pilot rule left no way to choose the verified aspects per depth or to combine the findings of both methods.
affected_ids: [REQ-004, REQ-018, REQ-040]
compatibility: REQ-004 names the survey, the existing open review per component that uses the six STRIDE categories as its checklist; its outcome is unchanged. REQ-040 replaces "test case" with "verification item" and "test catalog" with "verification catalog" without changing the rules that used them, replaces the pilot selection rule with a setting per assessment depth, and adds the merge of findings that both methods report. REQ-018 names the new per-depth setting. Catalog IDs such as TC-AUTHZ-01, saved results, and the scan profile key test_cases keep their names until a later change renames them. Standard depth gains verification of authorization by default, which adds model calls and cost; operators can change it in a scan profile.
verification: The specification check validates the catalog entries, bindings, acceptance sections, and this proposal. The implementation must test that each depth runs the configured aspects, that a scan profile changes them, that an organization profile's mandatory aspect cannot be removed, that an insufficient budget is reported before the first model call, that an aspect cut short by the budget is marked incomplete, that findings of both methods at the same location and CWE become one finding naming both, that a survey finding at a location verification evidenced as protected stays visible and is marked contradicted, and that survey findings at unexamined locations stay unchanged.
---

# Survey and verify

Names the two analysis methods in the requirements and connects them. The survey (REQ-004) reviews every component openly and labels its findings with a STRIDE category. Verification (REQ-040) checks selected security aspects against the verification catalog. The [implementation status](../../../docs/internal/analysis/aspect-test-cases-implementation-status-2026-10-19.md) records the four pilot runs and the analysis behind these decisions.

## Decisions

The product owner approved the wording on 2026-10-23 in the conversation that drafted it. These decisions were made there:

- The methods are called "Survey" and "Verify" in console and requirement texts. "STRIDE-based" remains a valid description of the survey. The names fit the console's progress grid.
- "Test case" becomes "verification item" in the requirements, as chosen on 2026-10-22. Code, console, catalog IDs, and saved results follow with the implementation.
- Which aspects each depth verifies is a setting, not a requirement. The shipped defaults are configuration and documented in the guides: quick runs the survey only, standard adds verification of authorization, thorough adds verification of every catalog aspect with model review. A scan profile can change them, and an organization profile can make aspects mandatory.
- The survey keeps running for all aspects. Verification does not replace it: it covers only catalog aspects, cost as much as the survey for four of fourteen aspects, and missed weaknesses that the survey found in every run.
- Findings of both methods at the same location and CWE become one finding that names both. A location that verification evidenced as protected marks the survey finding as contradicted and never removes it. Survey findings are not sent to verification as candidates, because an independent second finding is stronger evidence than a model asked to confirm a presented claim, and because it would add calls.
- Authorization alone is verified at standard depth. In the third and fourth runs verification found 8 of 9 authorization challenges against 6 to 7 for the survey, it has deterministic post-checks, and the fourth run's verification found about ten authorization weaknesses beyond the survey; five of them were checked in the code and hold. Input validation is the next candidate: its advantage was measured in one run only, and standard depth with both would exceed the USD 20 standard limit already on Juice Shop.

## Risks raised

- **Cost:** standard depth costs about USD 4.50 more on Juice Shop (USD 18.30 instead of 13.80). Verification cost grows with the number of routes, so larger applications can exceed the standard limit; the assessment then says so before the first model call.
- **Data sent to models:** standard depth sends more source code to the model, about nine additional calls with about 90,000 tokens of context each.
- **Changed results:** standard runs report more findings, so results before and after the change are not directly comparable.
- **Evidence base:** four runs on one intentionally vulnerable repository at standard depth. The defaults stay configuration so that a run on a second repository can change them without code.
- **Order:** the merge must ship with or before the new standard default, or standard runs report authorization weaknesses twice.
