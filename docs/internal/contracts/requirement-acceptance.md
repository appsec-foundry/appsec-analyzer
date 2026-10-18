# Requirement acceptance contract

This contract contains the detailed acceptance rules for the [user requirements](../../../requirements.md). Both documents are normative: shortening the user catalog does not relax these rules. The rules describe intended behavior, not proof of implementation or live qualification. The [bindings](../../../data/requirement-bindings.yaml) identify relevant producers, consumers, and partial test evidence.

Keep these rules aligned when changing a user outcome. Record semantic changes in a proposal and update its bindings. Existing schemas and domain contracts still govern their respective implementation boundaries. The [ID migration](../../../specs/changes/plain-requirement-ids/proposal.md) records the origin and redistribution of these rules.

## REQ-001: Scan without an AI account

Offer a deterministic source scan that needs no model account or model budget. Show its coverage, exclusions, and unverified observations, and clearly state that a complete security assessment was not run.

## REQ-036: Get a quick security indication

Offer `score REPO` for one top-level local Git checkout or explicitly selected supported Git URL, without model calls or writes into the target. Reuse Analyzer source admission, private redacted snapshots, source-change detection, and bounded remote retrieval. Treat repository content as data and sanitize diagnostic and terminal fields. Record source revision, captured state, public interface version, and source-policy identity in structured results. Omit excluded-file lists and counts from the score output in every format; retain source admission and exclusions internally.

Use the retained version-2 scoring calculation over route inventory, architecture coverage, configuration/IaC, and source-auth scanners. Report per-indicator scores and applicable coverage; keep findings from unscored indicators visible and identify excluded severities. A headline requires at least five applicable coverage rules and complete, validated results from every required scanner. Otherwise return `undetermined` or `incomplete` with a null headline score and visible findings and warnings. Report scanner observations as unverified and state that this is a limited quick check without exposure context, not a full assessment or security approval.

Offer readable text and mutually exclusive JSON/YAML output conforming to the score schema. Organize the text summary into an overall score and coverage, an aligned area table, numbered top findings with example locations, warnings, and a short examined-source footer. Highlight the headline score in a separated block while retaining the limited-check qualifier next to it. Reuse the shared Analyzer terminal palette for score bands, severity labels and totals, headings, and secondary finding metadata. Apply color to progress status tokens: cyan running, green done, red failed/invalid, and yellow missing/cancelled, while keeping descriptions and durations neutral. Auto-detect color independently for stdout results and stderr progress, honor the shared NO_COLOR/FORCE_COLOR policy, and always keep JSON/YAML free of styling codes. Separate findings with blank lines, wrap complete check titles to the available width, and put the example location and repetition count below each title. Public finding titles are not truncated to the retained script's legacy 50-character display limit; keep the direct script's default unchanged. Rank areas weakest first only for scored runs; incomplete or undetermined runs show every area as unscored. Keep unscored findings and excluded severities prominent, and retain detailed control signals and comparison fingerprints in structured output. Start with an immediate, flushed `Calculating security score for ...` header naming the operator-selected repository before runtime preparation, grouped into repository preparation, security checks, and the result. Give runtime loading, repository reading and snapshot preparation, every required scanner, calculation, and source validation separate persistent status lines under the three phase headings. Interactive stderr refreshes only the running step with elapsed time; completed steps retain their status and measured duration, and a final summary shows total time. A scanner line must distinguish complete validated output from failed execution, missing output, and invalid output; do not mark a failed scanner done or equate completed execution with absence of vulnerabilities. Redirected stderr and terminals without cursor support receive plain step start/completion lines without animations or control characters. Keep Git cloning visible when applicable. Stop the live display on success, incomplete scans, errors, and interruption; label incomplete or stopped work accordingly without implying that security checks passed. Send progress only to stderr and reserve stdout for results, including when either stream is piped. Only the explicitly selected repository identity may appear in progress: show its expanded local path or Git host/project, strip URL user information, queries and fragments, reject control or formatting characters, and bound the displayed label. Keep that identity on the existing heading or repository line; emphasize the project segment with bold accent text and mute its prefix without removing or rearranging the sanitized identity. Do not echo source contents, other filenames, or credentials. Exit 0 for a computed score regardless of value, 2 for insufficient coverage or invalid arguments, 1 for incomplete execution or operational errors, and 130 for user cancellation. Ctrl+C during preparation, scanning, or source validation must finish the status with a cancellation message, publish no result, and unwind temporary source and checkout cleanup without a traceback. Invalid local source selections and incomplete scanner output must identify the failure and a recovery action without raw exception, scanner, credential, or source details. Contain unexpected score runtime and rendering errors with a safe operational diagnostic; serialize the result before declaring completion and publishing it. A closed output pipe exits 1 without a traceback; already delivered output cannot be withdrawn. Invalid arguments and operational errors can omit the result document. Do not introduce an implicit score-based CI gate. Scores are comparable only across commits of one repository with matching scoring version, catalog fingerprint, applicable-coverage fingerprint, and source policy. Preserve the retained direct script's result shape and distinguish it from public results captured through the Analyzer boundary.

## REQ-002: Choose what to assess

Let users select local Git repositories or supported Git URLs, combine repositories into one assessment, choose analysis depth, and select a separate result directory. Reject unsupported scope restrictions instead of silently analyzing a different scope.

## REQ-003: Know what was examined

Record source revisions, captured source state, context sources, exclusions, and coverage gaps. Keep conclusions within the examined snapshot and reject source changes that would invalidate its evidence.

## REQ-004: Find relevant security risks

Examine every assessed component for all six STRIDE threat categories at every depth. Include applicable identity, authorization, input, cryptography, secrets, browser, deployment, supply-chain, and AI security concerns; make incomplete coverage visible. Help developers, architects, and security reviewers understand risks in a system from its code and configuration. Cover implementation weaknesses and insecure design assumptions; explain that source analysis cannot prove production behavior or approve a release.

## REQ-005: Understand the architecture

Describe valuable assets, actors, components, interfaces, data flows, and trust boundaries.

## REQ-006: Understand security controls

Distinguish evidenced, broken, missing, uncertain, and inapplicable controls. Declarations or an absence of findings must never establish that a control works.

## REQ-007: Keep repository origins clear

Retain repository provenance in combined results and require evidence from both sides for cross-repository connections. Clearly identify imported reference models as context; importing one must not imply that its repository was scanned.

## REQ-008: Show the evidence behind each finding

Explain each concrete security problem with target-source evidence, affected scope, and distinct instances. Group shared weaknesses without losing individual findings. Keep unproven claims visibly unproven and unscored; revalidate imported known threats or record mitigation, declared acceptance, or skip reasons.

## REQ-009: Explain severity

Base severity and scores on supported security impact and policy limits. Business context may clarify impact and order findings within a priority tier, but must not invent findings, raise likelihood, change tiers, or relax caps. Distinguish unknown impact from an explicit absence of business harm without hiding technical findings or independent obligations.

## REQ-010: Include business context

Accept validated business and organization context as data, identify its source and influence, and allow unattended use without questions. Honor a request to skip stored business context. Explain when relevant business or deployment facts remain unknown.

## REQ-011: Look for misuse of business features

Let users configure abuse-case sources. Include enabled business cases at standard and thorough depth, with at most three model-derived cases at thorough depth. Distinguish confirmed, unproven, mitigated, unresolved, inapplicable, and unchecked cases; create findings only when supported by evidence.

For a single repository, accept repeatable `--abuse-case-file` selections through `scan` and `assess`, and saved selections through the scan profile's `abuse_case_files` list. CLI selections replace that list. Resolve bounded YAML paths against the admitted repository root without requiring a documentation directory or granting access to host files. Retain automatic discovery at earlier repository locations for compatibility. Explicitly selected files request their enabled cases at every depth, including when the file is also automatically discovered, without loading the cases twice. Preserve case limits and report omissions. Reject unsupported multi-repository file selection and files outside the admitted source boundary.

## REQ-012: Explain what to fix

Explain each finding in developer language: affected location, attack mechanism, harm, and required change. Provide prioritized, system-specific mitigations; urgent actions need concrete steps and verification criteria. State unresolved decisions explicitly.

## REQ-013: Make the report easy to follow

Provide a readable report with consistent finding references, legible architecture diagrams, and detailed catalogs for omitted connections. Show evidenced build-time risks separately, using a table when needed. Surface up to three unresolved business, design, or deployment decisions without delegating finding verification to the reader.

## REQ-014: Use results in other tools

Publish Markdown and structured YAML and offer requested HTML, PDF, SARIF, Threat Dragon, and pentest-task exports. Preserve applicable references, requirements results, abuse outcomes, and bounded context provenance. Explain unsupported content and missing export tools.

## REQ-015: Export without running the analysis again

Allow users to export an existing validated model without rerunning analysis. Apply the format, reference-preservation, and missing-tool rules of REQ-014 to these exports as well.

## REQ-016: Follow, stop, and resume a run

Let users inspect status, stop a run, and resume compatible interrupted work. Preserve accepted work when resuming and identify stale or incompatible state. Store the effective operator profile with the run. On resume, preserve resolved OpenAI alias targets and revalidate their models, options, and prices against the installed catalog; changed definitions or incompatible runtime state require a new run. Expose progress, actionable failure reasons, and recovery steps. Never describe interrupted or incomplete work as complete.

For full assessments, retain bounded private diagnostics across compatible resume attempts. Correlate model calls, corrections, accepted or reused jobs, replacements, and failures with the run, attempt, role, job, and call identities independently of the selected provider. Verbose output identifies the job and retains bounded sanitized correction reasons beyond a short preview. Identify failed scanners and host failures through safe classifications and available exit or HTTP status codes. Do not record prompts, source excerpts, model answers, raw provider errors, or raw stderr in this shared diagnostic feed. Diagnostic storage failure must warn without changing analysis or publication decisions.

On provider rate limits, pause admission of all new model calls in the assessment, including other roles and providers sharing its budget; already running calls may settle. Use bounded retries and valid HTTP `Retry-After` delays without shortening the provider's wait or extending execution limits. Stop with paused exit code 3, retained accepted work, and `--resume` guidance when retries are exhausted or the cooldown exceeds three minutes or the remaining execution time. Optional jobs cannot replace a persistent rate limit with a coverage gap and continue publication. Resume remains subject to the original deadline and compatibility checks; CLI hosts without structured reset metadata use the bounded fallback delays.

## REQ-017: Reassess without losing work

Let users deliberately rebuild. Preserve accepted work and earlier-result history across reassessment; a deliberate rebuild may reset the model and history. Protect intervening user edits. Identify stale or incompatible state and the review status of findings.

## REQ-018: Use team settings

Accept documented and validated operator settings and organization profiles. Report conflicting or unsupported options. Repository declarations cannot choose provider credentials or weaken required analysis inputs, and configuration must not suppress evidence-supported findings.

For full assessments, accept built-in or operator-owned scan profiles and model profiles in schema-versioned YAML. Scan profiles define model-profile selection, depth, USD budget, outputs, and bounded literal report attributes. Model profiles define a provider adapter or one built-in base, defaults, and role/depth overrides. Explicit CLI values override scan defaults. Provide offline listing, resolution with provenance, and validation. Resolve user files from the documented XDG configuration directories or an explicitly selected external scan path, never from analyzed repositories. `scan` defaults to the Claude profile and standard depth; `assess` requires an explicit profile or compatible legacy host selection. Preserve documented legacy host and depth-profile calls, reject conflicting selections before host preflight or repository retrieval, and keep model profiles separate from organization settings. Repository content cannot define or select a model profile. Reject unknown fields, unsupported models/options, links, unsafe YAML, and conflicting reserved names. Profiles cannot supply credentials, endpoints, prices, tools, or permission grants. Preserve organization restrictions. Record actual role settings in the result; report attributes cannot become analysis instructions or evidence references.

Full-assessment scan profiles may set `max_parallel`, an integer from 1 to 16 with a default of 2. `--max-parallel N` on `scan`, `assess`, and offline profile inspection or validation overrides the profile value. Reject malformed and out-of-range values before host preflight or source retrieval. Show the effective limit in the run header and retain it in the saved configuration and profile snapshot; changing it requires a new run. Older snapshots without this setting receive an explicit incompatibility explanation.

For full assessments, support `lite` and `bedrock` adapters through operator-owned `providers.yaml` with schema version 1, outside every analyzed repository. This separate connection file may specify bounded model aliases, output maxima, conservative USD rates, price and route revisions, an HTTPS LiteLLM endpoint and deployment IDs, or a standard-partition AWS Region and exact model/profile IDs. It cannot contain credentials, commands or tool permissions. Keep scan/model profiles unable to supply endpoints or prices. Require `lite MODEL` and `bedrock MODEL` in the corresponding role profiles; accept those strings as CLI model selections or built-in profile shorthands. Preserve explicit provider selection, role configuration, organization model restrictions and offline inspection. Unknown model families must fail an organization Opus restriction. Reject unsupported reasoning settings and cross-provider role choices. The new adapters apply only to full assessments, not the separate audit or focused analyst.

## REQ-019: Handle version changes clearly

An independently packaged organization distribution may pin the engine and ship scan/model/org defaults through an explicit installed launcher. Resolve those resources from its package, never from the assessed checkout or by automatic plugin discovery. Require an exact engine and public-interface match, validate bounded data files and referenced profiles before dispatch, reject missing files, links, unsafe YAML, unsupported Advisor integration blocks and escaping paths, and fail without upstream fallback. Preserve explicit operator profile choices and existing organization restrictions. Expose model-free inspection and validation of the installed defaults, and test the wheel from outside the source checkout. Document that bundled defaults apply to full assessments and are not mandatory organization-wide enforcement.

Version public interfaces and incompatible artifact or organization-contract changes. Provide explicit migration or rejection for incompatible state.

## REQ-020: Show which providers have been tested

Distinguish available adapters from providers and profiles whose live assessment quality has been qualified.

Expose LiteLLM Responses and Bedrock Converse as available but unqualified adapters. Offline transport, controller and distribution tests cannot establish model quality, upstream retention or cost accuracy. Retain the legacy generic gateway route's unavailable public status.

## REQ-021: Check results before publishing them

Validate required inputs, model responses, evidence, and deliverables before use or publication. Missing or invalid required work must block a complete result. Publish only the selected report artifacts. Verify published result integrity when listing deliverables.

## REQ-022: Run unattended

Run without interactive responses when unattended operation is selected. Return distinguishable completion, policy-gate, interruption, and operational-error outcomes. Finding severity must not silently change an advisory command into a blocking gate.

For full assessments, `--non-interactive` explicitly disables budget questions. Missing input or diagnostic terminals, recognized CI environments, `--quiet`, and machine-readable controller output also disable them. Unattended execution never raises its spending limit automatically.

## REQ-023: Control time and spending

Apply documented finite default spending limits for full assessments and separate audits, allow explicit overrides, show the selected limit before starting, and explain limits for focused analysis. Profile `budget` values are always USD. Do not impose a default OpenAI output-token cap; omit the API parameter unless explicitly configured. Reserve each request against bounded input and the selected output cap or catalog model maximum. A role may need a larger per-call reservation without increasing the total authorized budget. Enforce finite work, retry, and time bounds. Reserve required completion work before optional model calls; when budget cannot cover required assessment work, preserve validated progress in a clearly incomplete result.

An interactive full assessment may ask for a higher total USD limit before a monetary budget gap prevents further work. Settle running calls and prevent new admission while waiting. Only an explicitly entered higher finite amount authorizes the increase; blank input, EOF, invalid input, cancellation, and elapsed time never authorize it. Persist authorization for the same run before spending, and retain it on a compatible resume with the original configuration. Keep call and time limits, per-call reservations, source authority, and publication gates unchanged. Declining preserves normal optional-work fallbacks or required-work interruption. Bound invalid attempts and the number of increases.

For the explicitly selected `codex-cli` ChatGPT subscription profile, replace monetary admission with finite exchange and elapsed-time limits using the existing required-completion reserves. Default to 1,000 exchanges including failed attempts, corrections, and retries, four hours, and one component at a time; allow operator overrides within the engine bounds. Reject USD budget options and configured output-token caps. Force ChatGPT login without API-key fallback; stop on quota exhaustion and preserve validated work. Report unavailable monetary cost as null, never as zero or an API-price estimate. Subscription lifecycle states and receipts use schema version 2; monetary states and receipts retain version 1 and their existing strict accounting. Do not reuse a receipt across accounting modes. Resume keeps the original deadline, call limit, source authority, and model settings. A new compatible run may reuse accepted jobs with their calls retained. The call limit does not promise a bound on tokens, credits, or the account's shared plan allowance.

Use the effective `max_parallel` setting for both component worker admission and the required-analysis time reserve. Keep each run's limit independent of other assessments in the same process. Changing parallelism cannot raise spending, call, retry, or execution-time limits or bypass cancellation and result validation.

For LiteLLM, disable upstream retries and fallbacks in each request, reserve against configured token bounds and conservative prices, require the returned deployment ID to match the selected deployment, and require a finite nonnegative per-request USD cost header within the call ceiling. Never accept absent charges as zero or silently substitute another provider's prices. For native Bedrock, authenticate with an externally supplied Bedrock API key, enforce bounded Converse requests and output, require completed tool-less text responses and integer token usage, and account using configured regional rates. Reject truncation, tool use and unexpected cache usage. Neither adapter may bypass existing source, response, completion, retry, cancellation or accounting gates. Bind connection, deployment, price and role settings into resume identity; changed connections require a new run.

## REQ-024: Ask a focused security question

Offer explicitly invoked design analysis, change review, and hypothesis checks separately from a full assessment. Keep existing threat models, finding IDs, and concurrent assessments unchanged. Methodology profiles guide analysis without proving findings, certifying compliance, or granting permissions.

## REQ-025: Understand what a code change affects

For change reviews, identify whether each finding is introduced, worsened, mitigated, pre-existing, or of unknown relationship to the selected change.

## REQ-026: Check a suspected security problem

Keep a hypothesis check within its selected revision and paths. Allow users to preview and check selected abuse cases with their origins visible. Distinguish supported, not confirmed in scope, and unresolved outcomes; lack of confirmation must not be presented as proof of safety.

## REQ-027: Review a design before writing code

Accept a supplied design without requiring implementation evidence. Report scenarios, assumptions, recommendations, and open questions, and identify any existing model or source context used.

## REQ-028: Choose which answers to save

Save analysis answers only on request and revalidate them before reuse. Never automatically commit them or copy them into the threat model or persistent business context. Provide job cancellation and explicit removal of saved answers.

## REQ-029: Check a supplied set of requirements

Audit a validated local requirements catalog independently of a full assessment, recording its source and inspected scope. Distinguish pass, partial, fail, unverifiable, and not applicable. Link findings to requirements only with explicit evidence; conclusive verdicts require evidence from inspected source.

## REQ-030: Decide whether an audit should block CI

Offer advisory requirements results and explicitly selected CI gates based on verdict and requirement priority. Distinguish a policy failure from incomplete execution; never interpret unverifiable controls as passing.

## REQ-031: Treat repository content as data

Repository content must not activate its own instructions or hooks, select executable tools, or redirect analysis outside admitted sources. Enforce source and path boundaries outside the model; reject escaping links and invalid scope.

## REQ-032: Keep secrets out of results

Block publication of generated artifacts containing unmasked secrets. Avoid copying credentials or sensitive source details into reports and diagnostics; keep retained intermediate data private.

## REQ-033: Explain what leaves the machine

Before a model-backed operation, explain which source excerpts, context, and answers leave the machine and which selected host receives them. Distinguish model transmission from explicitly selected Git retrieval. Do not equate a request to disable provider storage with a verified retention guarantee.

## REQ-034: Do only what was authorized

Constrain model requests to the authorized task, resources, and permissions. Source exploration must be explicitly enabled, interactive, organization-permitted, and confined to a redacted read-only snapshot without execution or network tools. Analysis grants no permission to remediate code, commit, publish, or accept risk. Sharing diagnostics or publishing an external issue requires approval of the concrete content.

## REQ-035: Protect local results

Store assessment results outside analyzed checkouts and make managed state readable only by the current user. Prevent concurrent runs or untrusted paths from overwriting another run or unrelated files.
