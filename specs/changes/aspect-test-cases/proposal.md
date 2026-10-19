---
reason: The full assessment presents its model analysis as STRIDE per component, but it works as an evidence-based code review whose findings receive a STRIDE category afterwards. Users cannot see which security questions a run asked and answered, model claims receive no deterministic follow-up, and most source-scanner findings default to Tampering.
affected_ids: [REQ-040, REQ-018]
compatibility: Adds the requirement and its acceptance rules, and adds a cross-reference to the REQ-018 acceptance rules. Nothing is implemented yet; existing commands, schemas, and saved results are unchanged. The planned implementation adds optional fields to threat-model.yaml and SARIF, and its output stays opt-in through a scan profile setting until the pilot ends, so default runs keep their current output. REQ-004 keeps its text during the pilot, because the STRIDE step keeps running for all aspects.
verification: The specification check validates the catalog entry, binding, acceptance section, and this proposal. The binding is advisory because no test covers the requirement yet. The implementation must add fixtures with and without the weakness for every catalog test case, an offline replay of the deterministic parts, and a recorded-response evaluation per test case. Negative cases must show that a fixture with a seeded weakness never yields control, partial coverage never yields control, a comment or an external control never counts as control evidence, repository content cannot define or disable test cases, and a disabled test case never hides a finding.
---

# Aspect test cases

Adds REQ-040. A full assessment is to check security aspects through named, versioned test cases with deterministic pre-checks and post-checks, plus an open review for weaknesses outside the catalog. The [analysis](../../../docs/internal/analysis/aspect-test-cases-proposal-2026-10-19.md) describes the design, the catalog of 45 test cases in 14 aspects, the rollout, and the open questions.

## Decisions

The user approved the requirement wording in the conversation that drafted it. These decisions were made there:

- The rebuild follows the analysis: the catalog and rule-backed results first, then a model pilot beside the STRIDE step. A simpler variant was considered: correct the STRIDE mapping, run post-checks on current STRIDE findings, and add a structured checklist to the existing STRIDE call before deciding on separate model calls per test case.
- A test case reports a control only when every candidate location has an evidenced control; otherwise it reports partial coverage with counts. No finding is a separate outcome and never counts as a control.
- Control results feed the existing control catalog and its control posture instead of creating a second control view.
- The cost limit is set after a measurement run with the pilot configuration. That run needs separate authorization of its model spending.
- The pilot covers IAM, SessionMgmt, AuthZ, InputVal, and DataProt.
- The pilot is measured against the documented Juice Shop vulnerability list together with the saved STRIDE assessments, not against a single STRIDE run.
- Findings that match a disabled test case stay visible with the disable reason, including the rule findings of a disabled rules test case, as REQ-018 requires.
- The Figure 1 legend that claims STRIDE-per-element analysis and the Tampering default for unmapped source-scanner rules are corrected before the rebuild, in a separate change.

The rule that comments, documentation, and controls outside the examined sources are not control evidence was added during the revision and approved with the requirement wording.

## Risks raised

- **Fewer weaknesses found:** Narrow test cases could miss logic flaws that open prompting finds. Starting points are not limits, the open review has its own budget share, and the STRIDE step keeps running during the pilot.
- **False assurance:** A wrong control outcome claims protection that is absent. Controls need enforcing evidence at every candidate location, and controls without deterministic confirmation are labelled model-evidenced.
- **Model cost:** Pilot runs cost more than the current assessment, because the STRIDE step keeps running while test cases and the open review are added. The amount is unknown until the measurement run.
- **Data sent to models:** Providers and destinations stay the same; some source excerpts may be sent more than once.
- **Repository content in prompts:** Candidate lists and application-specific test cases carry text from the analyzed code into model input. Candidates are passed as data, post-check parameters are validated, and repository content cannot define, select, or disable catalog test cases.
- **Existing commands and saved results:** New output stays opt-in until the pilot ends. Saved results gain optional fields, and older results stay readable.

REQ-004 changes only when the STRIDE step stops for an aspect after a positive pilot decision. REQ-003, REQ-006, REQ-008, REQ-013, REQ-014, and REQ-016 keep their text; the REQ-040 acceptance rules define how test case results relate to them.
