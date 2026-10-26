# Requirements for AppSec Analyzer

AppSec Analyzer helps developers, architects, and security reviewers find security problems and decide what to fix. It examines code, configuration, and the context supplied by the team. That can reveal weaknesses in both implementation and design, but it cannot establish how a system behaves in production or approve a release.

The requirements below describe what people should be able to do with Analyzer and what they should be able to rely on. Some capabilities are still incomplete. See the [README](README.md) for what is available today.

The [acceptance contract](docs/internal/contracts/requirement-acceptance.md) gives the detailed rules behind these requirements. The [requirement bindings](data/requirement-bindings.yaml) point to the relevant code and tests. A listed test does not establish that the whole requirement is met.

Each requirement keeps its `REQ-NNN` ID when it moves or is reworded. Retired IDs are never reused. Earlier IDs are listed in the [migration table](specs/changes/plain-requirement-ids/proposal.md).

## Understand the system

- **REQ-001:** **Scan without an AI account.** A source scan runs without an AI account or any model calls. It is separate from the model-backed assessment scan. Its output explains what the scanners checked, marks observations as unverified, and makes clear that a full assessment has not been run.

- **REQ-036:** **Get a quick security indication.** A repository can receive a deterministic security score without model calls. The result explains its coverage and limits, retains visible findings when it cannot score, and identifies when scores can be compared across commits of the same repository.

- **REQ-038:** **Check platform security settings.** Analyzer checks security settings of a GitHub or GitLab repository, such as branch protection and secret scanning, without model calls. A separate command runs only this check. A scan runs it before the threat analysis and uses the results. Each setting is reported as set, not set, or not checkable, with the reason. A setting Analyzer cannot read never counts as set, and the analysis treats it as unknown. Without a read-only token supplied by the user, only public data is checked. For a local repository, the scan shows the check as skipped.

- **REQ-042:** **Find leaked secrets.** A secret scan finds credentials in the selected source without model calls, and users can add their own detection rules. On request, a model reviews each hit in its code context: whether it is likely real or a test or example value, what it could give access to, and what to fix. The model also points out credentials the scanner missed and proposes rules for them, which apply only after the user adds them to their own rules. Secret values never appear in results or reach a model, and a review never removes a hit.

- **REQ-002:** **Choose what to assess.** An assessment can cover one repository or several that belong to the same system, supplied as local Git repositories or supported Git URLs. The user chooses the depth and result directory. If the user gives no depth in an interactive terminal, Analyzer asks which depth to use and describes each choice briefly by cost limit, relative runtime, and what it covers. If Analyzer cannot honor a restriction to specific components or directories, it rejects the request instead of analyzing a different scope.

- **REQ-003:** **Know what was examined.** The report names the source versions and context used, along with anything excluded or left unchecked. Its conclusions apply to that examined source, not to later changes.

- **REQ-004:** **Find relevant security risks.** The survey reviews every component for weaknesses in how it is built and in the design it relies on. It uses the six STRIDE threat categories as its checklist and labels each finding with one of them. The report shows which kinds of threats were considered and where the analysis is incomplete. Deterministic scanner rules also look for known weakness patterns, both at single code locations and across the whole application, such as permissive cross-origin settings or cleartext transport. A rule hit becomes a finding only after the same evidence review as a survey finding.

- **REQ-040:** **Verify security aspects item by item.** Verification checks selected security aspects, such as authorization, against a fixed catalog of verification items. Each item states what must hold, for example that every request that returns a user's data checks that the data belongs to the caller. After the items, verification looks for weaknesses that no item covers, such as insecure business logic. The live progress shows verification progress. The completion summary counts the verification items that found a weakness, confirmed a protecting control, confirmed one only at some locations, or could not decide; the report shows for each item whether it also found neither, did not apply, or was disabled. Findings of the survey, the scanners, and verification appear together in the findings register. A weakness that several methods found appears there once, names each method, and combines what they found about it. A weakness that only verification found passes the same evidence review as a survey finding, unless an automatic check already confirms it. Each finding names the verification items and scanner rules behind it, or is marked as found outside the verification catalog. Teams can disable individual items with a recorded reason; a disabled item never counts as a confirmed control and never hides a finding.

- **REQ-005:** **Understand the architecture.** The report explains what needs protecting, who uses the system, and how its components and external services exchange data. It shows where those exchanges cross access or trust boundaries.

- **REQ-006:** **Understand security controls.** For each relevant control, the report explains whether the evidence supports it, shows a problem, or leaves its effectiveness uncertain. Missing and inapplicable controls are identified separately. A claim in documentation or an absence of findings does not prove that a control works.

- **REQ-007:** **Keep repository origins clear.** In a combined assessment, findings and connections can be traced back to their repositories and evidence. Imported reference models are clearly labelled so readers can tell them apart from source examined during this assessment.

## Decide what to fix

- **REQ-008:** **Show the evidence behind each finding.** Every finding explains the problem and points to the affected code and supporting evidence. Grouping similar problems must preserve each affected location. Unproven claims are labelled and left unscored.

- **REQ-009:** **Explain severity.** A finding's severity is justified by evidence of the harm it could cause. The report states what is uncertain or unknown. Business context can inform the assessment, and an explicit absence of business harm can lower business impact. It cannot change priority tiers, hide technical findings, or override the severity rules.

- **REQ-010:** **Include business context.** Teams can supply information about their business and organization, or ask Analyzer to skip stored business context. The report explains how that information affected the analysis and what relevant facts are still missing.

- **REQ-011:** **Look for misuse of business features.** Teams can choose misuse cases for the analysis to examine. The results show which cases are confirmed, unproven, mitigated, unresolved, inapplicable, or unchecked.

- **REQ-012:** **Explain what to fix.** Findings describe how an attack could work, what damage it could do, and what developers need to change. Recommendations address this system and show what to tackle first. Urgent fixes include concrete steps and a way to check the result.

- **REQ-013:** **Make the report easy to follow.** Architecture diagrams are readable, and finding references stay consistent throughout the report. Supporting detail is easy to find, and the most important open decisions are highlighted without hiding the rest. The report does not leave finding verification to the reader.

- **REQ-014:** **Use results in other tools.** Results come in Markdown and structured YAML, with optional HTML, PDF, SARIF, Threat Dragon, and penetration-test task exports. Exports retain the relevant evidence references and conclusions. Analyzer explains any format limitations or missing export tools.

- **REQ-015:** **Export without running the analysis again.** A saved, validated assessment can be exported without repeating the analysis or paying for new model calls.

- **REQ-037:** **Work with an assessment using AI.** Users can open a saved assessment in a coding assistant with the context and guidance needed to discuss findings and prepare remediation. Analyzer offers this next step after completion and defaults to the assistant used for the assessment when available. Starting a review does not repeat the analysis or authorize changes.

## Run and maintain assessments

- **REQ-016:** **Follow, stop, and resume a run.** Progress is visible while an assessment runs. A run can be stopped and resumed when its source and settings are still compatible. If something fails, Analyzer explains the cause and how to recover. Interrupted or unfinished work is never reported as complete.

- **REQ-017:** **Reassess without losing work.** Running another assessment preserves the history of earlier results and protects edits made since the last run. Starting over is an explicit choice, with a clear explanation that rebuilding can reset results and history.

- **REQ-018:** **Use team settings.** Analyzer accepts documented settings and organization profiles, and reports conflicting or unsupported options. Repository content cannot choose provider credentials, weaken required analysis, or suppress findings supported by evidence.

- **REQ-019:** **Handle version changes clearly.** Public interfaces carry a version, and incompatible changes to saved results or organization profiles are versioned too. When saved work is incompatible, Analyzer provides an explicit migration or explains why it cannot use it.

- **REQ-039:** **Build your own command on Analyzer.** An organization can create the files for its own Analyzer distribution, with its profiles and without copying engine code, and align the engine pins when it adopts a new engine version. Both steps use local files only: no model calls, no network, no build or publication, and nothing existing is overwritten. Building, testing, and releasing stay the organization's own steps.

- **REQ-020:** **Show which providers have been tested.** Analyzer distinguishes available model connections from provider configurations that have passed real assessment tests. Being able to connect to a provider is not proof that its results are reliable.

- **REQ-041:** **Use GitHub Copilot CLI for assessments.** Users can select GitHub Copilot CLI as an experimental provider for full security assessments, with its model output validated before Analyzer uses it and its data-transfer and usage limits made clear.

- **REQ-021:** **Check results before publishing them.** Required inputs, analysis, and output must pass validation before an assessment is marked complete. Analyzer publishes only the selected report files and checks that those files have not changed when listing the results.

- **REQ-022:** **Run unattended.** Assessments can run without waiting for answers from a person. Automation can tell a completed run from an interruption, an operational error, or a failed policy gate. Advisory results do not become blocking failures unless a gate was explicitly selected.

- **REQ-023:** **Control time and spending.** Model calls run within documented spending or subscription-use limits and execution limits. The user can set the applicable spending or call limit, which Analyzer shows before a full assessment or separate audit starts. If the limits prevent completion, it keeps validated progress and clearly reports what remains unfinished. Console output shows monetary costs by default only in API mode. Users can explicitly enable cost display in any mode.

## Ask focused security questions

- **REQ-024:** **Ask a focused security question.** Users can ask a security question directly and clarify its scope and missing facts in a dialogue. A focused analysis can use existing threat models, requirements and specifications, including Markdown documents, without requiring a full assessment. A separate authentication and authorization review is also available without a full assessment. Focused analysis leaves existing threat models and other running assessments alone. Choosing an analysis method does not certify compliance or authorize further actions.

- **REQ-025:** **Understand what a code change affects.** Users can select local changes, a commit comparison, or a merge or pull request. The review shows which problems the change introduces, makes worse, or mitigates, and distinguishes established requirements from proposed changes to them. It also identifies problems that were already present and says when their relationship to the change is unclear.

- **REQ-026:** **Check a suspected security problem.** A hypothesis check examines a specific concern within the chosen source paths and revision. A selected misuse case can be previewed before the check runs. The answer explains whether the evidence supports the concern, does not confirm it within that scope, or leaves it unresolved. Not confirming a problem does not prove safety.

- **REQ-027:** **Review a design before writing code.** A design review works from a supplied design without requiring implementation evidence. It describes possible attacks, assumptions, recommendations, and open questions, and names any code or earlier assessment used as context.

- **REQ-028:** **Choose which answers to save.** Answers are saved only when requested, and the user can remove them later. Analyzer checks them again before reuse. It never automatically commits answers or copies them into a threat model or stored business context.

## Check security requirements

- **REQ-029:** **Check a supplied set of requirements.** A requirements audit can run on its own using a local catalog. It records where the catalog came from, which code was examined, and the evidence behind each verdict. Requirements are reported as pass, partial, fail, unverifiable, or not applicable.

- **REQ-030:** **Decide whether an audit should block CI.** Requirements results are advisory unless the user explicitly chooses a blocking CI gate based on verdicts and requirement priorities. An unfinished audit is reported separately from a failed policy check. Unverifiable requirements never count as passing.

## Protect sources and results

- **REQ-031:** **Treat repository content as data.** Files in a repository cannot activate their own instructions, hooks, or tools, or send the analysis outside the selected sources. Analyzer rejects paths and links that escape the permitted source boundary.

- **REQ-032:** **Keep secrets out of results.** Analyzer blocks publication of generated files containing unmasked secrets. Reports and diagnostics avoid exposing credentials or sensitive code details. Intermediate data kept during analysis stays private.

- **REQ-033:** **Explain what leaves the machine.** Before using a model, Analyzer explains what code, context, and answers it will send and which selected host receives them. It distinguishes this from fetching a Git repository and does not claim provider retention guarantees it cannot verify.

- **REQ-034:** **Do only what was authorized.** Analysis stays within the agreed task, resources, and permissions. Asking for an analysis does not authorize code changes, commits, publication, or acceptance of a risk. Sharing diagnostics requires approval of the actual content to be shared.

- **REQ-035:** **Protect local results.** Assessment results are kept outside the analyzed repositories. Results and working data are readable only by the current user. Concurrent runs and untrusted paths cannot overwrite another run's work or unrelated files.
