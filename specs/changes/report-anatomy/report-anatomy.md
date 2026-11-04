# Report anatomy

This document describes the shape of the assessment report (`security-assessment.md`): which chapters it has, what each chapter covers, which subsections and tables it contains, and how a finding, a mitigation, and a weakness are built. A change to that shape is a product change and needs the maintainer's approval.

It does not describe wording, ranking, limits, diagram geometry, or how content is produced. Those live in the sections contract (`data/sections-contract.yaml`), the code that renders the report, the prompts that write its prose, and the schemas.

## Overview

A report has these chapters, in this order. Chapters in *italics* appear only under a condition.

1. Front matter: info box, *Changelog*, *quick-mode notice*, Table of Contents
2. Management Summary
3. *Critical Findings by Root Cause*
4. §1 System Overview
5. §2 Architecture Diagrams
6. *§3 Attack Walkthroughs*
7. §4 Assets
8. §5 Attack Surface
9. *§6 Security Architecture*
10. *§7 Weakness Register*
11. *§7b Requirements Compliance*
12. §8 Findings Register
13. §9 Abuse Cases
14. §10 Mitigation Register
15. §11 Out of Scope
16. *Verification Findings*
17. Appendices: *Verification Items*, Run Statistics, *Composition Notes*, Attack Vector Taxonomy

Section numbers are fixed, so links such as `#8-findings-register` stay the same from run to run. When a numbered chapter is absent, its number is skipped.

## How to read this document

- **always** means the part appears whenever the part above it appears. **only when** names the condition under which it appears. A list introduced with "always appear" marks all its items always. An absent part leaves no empty heading, field, or column.
- Text in `code` is exact: headings and table headers must appear in the report as written, and the test checks them. Text in **bold** describes content that the test does not check.
- In headings, `N` and `NNN` stand for a number, `(n)` for a count, and `<...>` for free text.

## Front matter

Covers the identity of the assessed project and how to navigate the report.

- Info box with project name, version, repository, and license — always.
- `## Changelog` — only when the model records assessment runs.
  - Table: `| Version | Date | Scan | Model | Δ Threats | Note |`
- Quick-mode notice — only when the run used quick depth.
- `## Table of Contents` — always.

## Management Summary

Covers the overall verdict, the systemic weaknesses, the most important threats, what to do first, and what already works. A reader who stops here knows how bad it is and what to fix first.

- `## Management Summary` — always. Its blocks appear in this order:
  - `### Verdict` — always. A 🟢, 🟡, or 🔴 rating with a highlighted statement citing at least two findings, then **About this assessment**, **Method and limits**, **Risk distribution**, and the security concerns behind the rating.
  - `### Remediation Priorities` — always. What to fix first: one row per mitigation, grouped under the top root causes. The root-cause cell spans its group's rows and names the lasting fix. Every mitigation that fixes a Critical finding is listed; one without a root cause appears under *No root cause linked*.
    - Table: `| Root cause → lasting fix | Do first | Resolves | Effort |` The HTML root-cause cell spans its group's rows.
  - `### Open Questions for the Team` — only when a decision is open that only the team can settle. At most three questions.
  - `### Security Posture & Top Threats` — always. **Figure 1a** (runtime architecture and threats), **Figure 1b** (supply chain and build, only when a build is evidenced), **Figure 2** (attack routes and impact), and the threat actors behind the routes. Every route in Figure 2 has exactly one table row, and every row links its findings into §8.
    - Table: `| # | Threat Description | Findings (→ Component) | Risk & Impact | Primary Measures |`
  - `### AI / LLM Exposure` — only when the system has an LLM or AI surface. One bullet per affected OWASP LLM Top 10 category with its findings.
  - `### Requirements Compliance` — only when a requirements catalog was checked. The overall result: **Baseline**, **Overall status**, and **Result**. The per-requirement detail is in §7b.
  - `### Operational Strengths` — always, closing with a **Bottom line**.
    - Table, only when no strength has an open gap: `| Strength | What's in Place | Effectiveness |`
    - Table, only when a strength has open gaps: `| Strength | What's in Place | Effectiveness | Open gaps |`

## Critical Findings by Root Cause

Covers which weakness each Critical finding traces back to and which structural fix closes it.

- `## Critical Findings by Root Cause` — only when there are at least two Critical findings. One diagram linking each Critical finding to its weakness records, with Critical findings that have none in a separate node, followed by the list of **Structural fixes**.

## §1 System Overview

Covers what the system is, what was analyzed and what was not, who interacts with it, and where trust changes.

- `## 1. System Overview` — always.
  - `### Scope` — always. Number of components, how many were analyzed, what is out of scope, and the basis of the assessment.
  - `### Identified Actors` — only when actors were identified.
    - Table, only when actor roles were resolved: `| Actor | Type | Access | Findings |`
    - Table, only when no actor role was resolved: `| Actor | Role | Reach | Findings | Components |`
  - `### Trust Boundaries` — only when trust boundaries were derived.
    - Table: `| Crossing | Required condition | Control | Status and findings |`
  - `### Platform Security Settings` — only when the hosting platform's settings were checked, or skipped, for a selected repository.

## §2 Architecture Diagrams

Covers the system from outside in: context, containers, and components. The diagrams are generated from the model, not written by the analysis.

- `## 2. Architecture Diagrams` — always.
  - `### 2.1 System Context` — always. One diagram.
  - `### 2.2 Container Architecture` — always. One diagram.
  - `### 2.3 Components` — always. One table with each component's findings by severity, its weakest controls and top findings, closing with a **Key takeaway**.
    - Table: `| Component | 🔴 | 🟠 | 🟡 | Weakest controls and top findings |`

## §3 Attack Walkthroughs

Covers how the Critical and High findings are exploited step by step, alone and chained.

- `## 3. Attack Walkthroughs` — only when the run did not use quick depth.
  - `### 3.1 Attack Chain Overview` — only when findings form a chain. One diagram per chain, each closing with a **Key takeaway**.
  - `### 3.N <title>` — always, one per walked-through finding, each with a sequence diagram.

## §4 Assets

Covers what is worth protecting, how sensitive it is, and which findings threaten it.

- `## 4. Assets` — always.
  - Table, only when assets were identified: `| Asset | Sensitivity (assumed) | Findings |`

## §5 Attack Surface

Covers every entry point an attacker can reach, split by whether authentication is required. Entry points without Critical or High findings fold into a second table of the same form.

- `## 5. Attack Surface` — always.
  - `### 5.1 Unauthenticated Entry Points (n)` — always.
    - Table, only when there are entries: `| Entry point | Findings |`
  - `### 5.2 Authenticated Entry Points (n)` — always.
    - Table, only when there are entries: `| Entry point | Findings |`
  - `### 5.3 Authentication Not Determined (n)` — only when the analysis could not establish whether an entry point requires authentication.
    - Table: `| Entry point | Findings |`

## §6 Security Architecture

Covers, for each control family, which controls exist, how well they work, and which findings show their gaps. The unit is the control, not the finding.

- `## 6. Security Architecture` — only when the run did not skip it. Otherwise a one-line note says that it was skipped. It opens with the number of cataloged controls and a legend of the verdicts. All thirteen subsections always appear, in this order:
  - Table: `| Status | Meaning | What to do |`
  - `### 6.1 Security Control Overview`: only the overview table, one row per family.
    - Table: `| Control category | Verdict | Findings | Weakest controls |`
  - `### 6.2 Identity and Authentication Controls`
    - Table, only when an authentication mechanism is evidenced: `| Mechanism | Status | Findings |`
  - `### 6.3 Session and Token Controls`
  - `### 6.4 Authorization Controls`
  - `### 6.5 Query Construction and Data Access Controls`
  - `### 6.6 Input Boundary Validation Controls`
  - `### 6.7 Output Encoding and Rendering Controls`
  - `### 6.8 Browser and Cross-Origin Controls`
  - `### 6.9 Cryptography Secrets and Data Protection`
  - `### 6.10 File Parser and Outbound Request Controls`
  - `### 6.11 Operations Runtime and Supply Chain Controls`
  - `### 6.12 Real-time and Not Applicable Controls`
  - `### 6.13 Defense-in-Depth Summary`: a **Verdict** and two short lists, what holds and what to repair first. No table.

Each family from 6.2 to 6.12 has the same block. A family whose verdict is Not applicable has only the verdict.

1. **Verdict**: Adequate, Partial, Weak, Unsafe, Missing, or Not applicable.
2. **Controls covered**: links to every control below.
3. **Implemented controls**: what exists.
4. **Assessment**: the architectural conclusion for the family.
5. One subsection per assessed control, each with a short intro, **Security assessment**, and **Relevant findings** as a list. The login and session-token flows in 6.2 and 6.3 add a sequence diagram.

The analysis writes this block. The quality checks of every run hold it to the contract, so the test checks only the list of subsections.

## §7 Weakness Register

Covers the systemic control gaps behind the findings, each with its findings, affected components, and a structural and tactical remedy.

- `## 7. Weakness Register` — only when at least one weakness was derived. A list of all weaknesses ordered by severity, then one entry per weakness.
  - `### W-NNN — <title>` — always, one per weakness. The title names the missing or misused control.

Each weakness entry has these fields, in this order:

| Field | Content | When |
|---|---|---|
| **severity line** | Severity, confirmed or design risk, and the number of findings. | always |
| **description** | The control gap. | always |
| `**Architectural anti-pattern - <name>.**` | The anti-pattern behind the gap. | only when one applies |
| `**Confirmed findings:**` | The findings that confirm the gap. | only when there are any |
| `**Practice sites:**` | Code locations that show the unsafe practice without a confirmed finding. | only when there are any |
| `**Architecture evidence:**` | The missing controls and the sources the assessment rests on. | only when a missing control was recorded |
| `**Affected components:**` | The affected components. | only when there are any |
| `**Remediation:**` | A structural change and, when they exist, the mitigations that fix individual findings. | always |

## §7b Requirements Compliance

Covers, per requirement of the checked catalog, whether it is met, violated, or not assessable.

- `## 7b. Requirements Compliance` — only when a requirements catalog was checked.
  - `### Requirement Scope` — only when the catalog resolution was recorded.
  - `### Requirements Traceability` — always.
    - Table: `| Requirement | Status | Risk | Findings | Mitigations | Guidance |`

## §8 Findings Register

Covers every finding with location, attack, evidence, and fix.

- `## 8. Findings Register` — always. An intro, **Risk Distribution**, **STRIDE Coverage**, and a **Findings index**, then the findings grouped by severity.
  - `### 🔴 Critical (n)` — only when there are Critical findings.
  - `### 🟠 High (n)` — only when there are High findings.
  - `### 🟡 Medium (n)` — only when there are Medium findings.
  - `### 🟢 Low (n)` — only when there are Low findings.

Each finding is a card `#### F-NNN · <title>`. The title names the weakness, not the file. Its fields appear in this order:

| Field | Content | When |
|---|---|---|
| `**Severity:**` | Severity, component, and source location on one line. An unproven finding is marked as unproven. | always |
| `**Development only:**` | The file serves only local development, so the finding does not raise the verdict. | only when no build or deployment definition refers to the file |
| `**Found by:**` | The analysis methods that found it, with the verification items behind it. | only when verification found it or more than one method did |
| `**Contradicted by verification:**` | A control that verification evidenced at the finding's location. | only when verification evidenced one |
| `**Contradicted by the evidence review:**` | Why the evidence review contradicts the finding. | only when the review contradicted it |
| `**Reliability:**` | High, Medium, or Low, and the reason. | always |
| `**Violates:**` | The violated catalog requirements. | only when a checked requirement is violated |
| `**Weakness:**` | The weakness this finding belongs to. | only when it belongs to one |
| `**Trust boundary gap:**` | The trust boundary whose assumption fails. | only when one applies |
| `**Instances (n):**` | Further locations, grouped by file. | only when there is more than one location |
| `**Issue:**` | What the attacker does and achieves. | always |
| `**Root cause:**` | Why the code allows it, specific to this finding. | only when the analysis wrote one |
| `**Evidence:**` | The verification result and what the code shows. | only when evidence was recorded |
| **code excerpt** | The source lines, secrets redacted. | only when the finding is Critical or High, or marked as important, and a source excerpt is available |
| `**Fix:**` | The required change and its mitigation. | always |
| `**Classification:**` | Weakness class, STRIDE category, CWE, OWASP Top 10, and the walkthrough link. | always |

## §9 Abuse Cases

Covers which abuse scenarios were checked against the code and with what outcome. When the check did not run or no scenario applied, a one-line note replaces the content.

- `## 9. Abuse Cases` — always. When scenarios were checked, an overview lists the open ones, the unresolved ones, and those checked without finding, followed by a legend.
  - Table, only when a checked scenario is open: `| Scenario | Risk | Verdict |`
  - Table, only when a scenario stayed unresolved: `| Case | Findings | Where it stands |`
  - Table, only when a scenario was checked without finding: `| Case | Result | Reason |`
  - `### Not verified` — only when abuse-case verification did not finish. The outcome of these cases is unknown, not negative.
    - Table: `| Case | Reason |`
  - `### AC-<kind>-NNN — <title>` — only when a scenario was confirmed or partly confirmed. `T` marks a technical case, `B` a business case. A summary line with **Source**, **Actor**, **Combined Risk**, and **Verdict**, then **Goal**, **Prerequisite** when one exists, **Attack chain**, and **Scenario impact** and **Blocking mitigations** when they exist.
    - Table: `| Step | Finding | Outcome |`
  - `### Technical abuse cases — evaluated, not applicable` — only when technical abuse cases were ruled out.
    - Table: `| Scenario | Source | Why not applicable |`
  - `### Business-case coverage` — only when business abuse cases did not apply, were not performed, or a repository case file was rejected.

## §10 Mitigation Register

Covers every mitigation, ordered by urgency, with the steps to implement it and a way to verify it.

- `## 10. Mitigation Register` — always. A legend and a **Mitigations index**, then four priority groups. An empty group shows a one-line note.
  - `### P1 — Immediate` — always.
  - `### P2 — This Sprint` — always.
  - `### P3 — Next Quarter` — always.
  - `### P4 — Backlog` — always.

Each mitigation is a block `#### M-NNN — <title>`. The title names the action. Every finding has at least one mitigation. The fields appear in this order:

| Field | Content | When |
|---|---|---|
| `**Addresses:**` | The findings it resolves. | always |
| `**Weaknesses addressed:**` | The weaknesses it addresses. | only when it addresses a weakness |
| `**Prevents CWEs:**` | The CWEs it prevents. | only when known |
| `**Requirements at stake:**` | The catalog requirements involved. | only when a catalog was checked |
| `**Priority:**` | Priority, effort, and the main file on one line. | always |
| `**Why:**` | Why it is needed. | only when the analysis wrote it |
| `**How:**` | Ordered steps, optionally followed by an example implementation. | only when written; every P1 or P2 mitigation that changes code has it |
| `**Verification:**` | How to confirm that the fix works. | only when written; every P1 or P2 mitigation that changes code has it |
| `**Blueprint:**` | The organization's implementation blueprint. | only when one is configured |
| `**Reference:**` | An external guide. | only when one applies |

## §11 Out of Scope

Covers what this method cannot see, what was excluded, and which components were not analyzed in depth.

- `## 11. Out of Scope` — always.
  - `### Not Covered by This Method` — always.
  - `### Excluded from This Assessment` — always.
  - `### Components Not Individually Analyzed` — only when components were left out.
    - Table: `| ID | Component | Reason not analyzed |`
  - `### Accepted Risks (Team-Provided)` — only when the team recorded accepted risks.
    - Table: `| ID | Title | Severity | Component | STRIDE | Justification |`

## Verification Findings

Covers the findings that verification reported but the survey did not report at the same location.

- `## Verification Findings` — only when verification reported findings. They do not count in the totals of the findings register; a verification finding that matches a survey finding with the same CWE at the same location appears in §8 instead.
  - Table, only when a verification finding has no survey finding at its location: `| ID | Verification items | Component | Finding | Risk | Location |`

## Appendices

Covers the outcome of each verification item, how the run went, and the attack-vector vocabulary used in the findings.

- `## Appendix: Verification Items` — only when verification ran.
  - `### Results that need attention` — always. Items that failed or partly failed, by risk; results without Critical or High findings fold into a second table of the same form.
    - Table, only when an item failed or partly failed: `| Verification item | Where | Result | Findings |`
  - `### Not decided` — only when an item has no result for a component.
    - Table: `| Verification item | Where | Why it stayed open |`
  - `### Controls evidenced` — only when verification evidenced a control.
    - Table: `| Verification item | Where | Result |`
  - `### Other items` — only when further items were not applicable or disabled.
- `## Appendix: Run Statistics` — always.
  - Table: `| Field | Value |`
  - `### Per-Stage Breakdown` — only when stage statistics were recorded. A column whose values were not recorded is left out.
    - Table, only when one model ran: `| Stage | Calls | Tokens | Cost (≈ USD) | Model time |`
    - Table, only when several models ran: `| Stage | Model | Calls | Tokens | Cost (≈ USD) | Model time |`
  - `### Tokens by model` — only when token usage per model was recorded.
    - Table, only when costs were recorded: `| Model | Calls | Uncached | Cache write | Cache read | Output | Cost (≈ USD) |`
    - Table, only when no cost was recorded: `| Model | Calls | Uncached | Cache write | Cache read | Output |`
  - `### Contribution of analysis steps` — only when the run compared what each analysis step added.
    - Table: `| Step | Additional locations | Repeated locations | New distinct problems | Stronger evidence | Contradictions | Recorded cost (USD) |`
  - `### Per-Phase Duration Breakdown` — only when phase timings were recorded.
    - Table: `| Phase | Description | Agent (Model) | Duration |`
  - `### Agent Dispatch Log` — only when agent dispatches were recorded.
    - Table: `| Agent | Model | Role | Phases |`
- `## Appendix: Composition Notes` — only when the previous rendering reported warnings.
  - `### Soft Warnings` — only when there are warnings.
    - Table: `| Section | Category | Detail |`
  - `### Section Retries` — only when a section had to be composed again.
    - Table: `| Section | Compose Attempts | Final |`
  - `### Skill-Level Auto-Retries` — only when the run retried automatically.
- `## Appendix A — Attack Vector Taxonomy` — always.
  - `### <vector>` — always, one per attack vector used.

## Glossary

- **F-NNN, M-NNN, W-NNN, C-NN, AC-T-NNN, AC-B-NNN**: identifiers of a finding, mitigation, weakness, component, and technical or business abuse case. They stay the same within one model.
- **P1 to P4**: mitigation priority, from before the next deployment (P1) to backlog (P4).
- **✓, ◌, ↻**: evidence verified, ambiguous, or carried over unverified from an earlier, deeper run.
- **Confirmed** or **design risk**: a weakness backed by confirmed findings, or one shown only by unsafe practice or a missing control.
- **Unproven**: a finding whose insecure state is observed but whose exploitability is not established.
- **Quick depth**: the fastest assessment depth, which skips §3, §6, and abuse-case checks.

## Changing the report's shape

The approved version of this document is `specs/changes/report-anatomy/report-anatomy.md`. A change follows these steps:

1. Propose the new wording under `specs/changes/<name>/` and get it approved.
2. Update this document, the contract, and the renderer together.
3. Run `python3 -m pytest tests/test_report_anatomy.py`. It fails until all three agree.

Write new entries in the same form as the existing ones, because the test reads them:

- A heading is followed by ` — always` or ` — only when <condition>`, unless its list was introduced with "always appear".
- A table line starts with `Table:` or `Table, only when <condition>:`.
- The **When** cell of a field table is `always` or starts with `only when`.

The test names the line when one of these forms is missing. It checks only the parts in `code`:

- Every level-2 and level-3 heading in a rendered report must be listed here, in the listed order. A heading marked always must appear when its parent appears.
- Every table must be listed under its heading. A table without "only when" must appear when its heading appears.
- The fields of a finding, mitigation, or weakness must follow the order of its field table, and every field marked always must appear.
- The chapter order and the §6 subsections must also match the contract, so a chapter that no test report renders is still checked.

The test renders two frozen runs: `tests/fixtures/report-anatomy/quick-run` for most chapters and `tests/fixtures/e2e/frozen-run` for §3.

The test does not catch everything:

- Level-4 headings are checked only in §8 and §10, where every one must be a finding card or a mitigation block.
- A field is seen only when its label starts a line. A label added inside the severity or priority line goes unnoticed.
- The frozen runs contain no §6 content, abuse-case scenario, accepted risk, composition warning, verification result, stage statistics, root cause, or why field, so those parts are described here but not yet checked against a rendered report.
