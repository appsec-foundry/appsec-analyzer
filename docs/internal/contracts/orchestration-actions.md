# Assessment Controller Contract

`analyze-threats` is a deterministic front end to the separate analyst controller. Scope selection, document discovery and MR/PR metadata retrieval happen outside the model; remote responses can supply only validated commit identities, never new execution destinations. The controller retains ownership of source admission, model calls, evidence validation, question checkpoints and cancellation. Terminal answers are submitted through the existing answer operation and never accepted on timeout or EOF. Additional document citations do not authorize source expansion or publication to a forge.

`scripts/orchestrator/orchestration_controller.py` runs the security assessment. `assess` executes every phase in-process through tool-less structured model exchanges, validates each result, and renders and publishes the report; no session orchestrates it and no action protocol is exchanged. The launch helpers `assess-context-preview`, `assess-context-save` and `assess-stop` each print one JSON object for the `appsec-analyzer` skill.

## Business-context dialog

`assess-context-preview` builds `.business-context-preview.json` through `contexts/business_context_preview.py`, which owns the local discovery limits; its excerpts are untrusted preliminary evidence, never a complete inventory. It returns the plugin-owned instruction file `skills/appsec-analyzer/business-context.md`. The session asks at most two questions, the use case and the worst-case business harm, without further discovery or agent dispatch; technical attack mechanisms are not business-harm choices. Headless and skip-context runs bypass the dialog.

`assess-context-save` accepts `answered`, `skip` or `unchanged`. Only the fixed, bounded `.business-context-raw.md` supplies answers; the controller validates it and saves substantive answers in `docs/security/business-context.md`, preserving repository context and never persisting explicit run-only imports. Repository context uses that path first and the legacy `docs/business-context.md` only when it is absent; saving carries effective legacy context into the new file without modifying the legacy file. An invalid answer is rejected. Later runs read the saved context before formulating questions.

## Ownership

- `runtime/resolve_config.py` resolves organization settings, flags, paths, and depth behavior. For public scans, `appsec_analyzer/profiles.py` resolves operator scan/model files and applies role models and export selection before lifecycle identity is computed. Explicit CLI settings take precedence; organization restrictions remain enforced. The stored operator profile records actual role settings and keeps OpenAI alias targets fixed on compatible resume.
- `orchestrator/orchestration_controller.py` owns admission, phase order, job acceptance, the deterministic replacements listed below, and publication.
- Registered agent definitions supply role instructions; the controller validates every returned artifact against its output contract before accepting it.

## Agent call lifecycle and budget telemetry

Full-assessment exchanges use `runtime/assessment_diagnostics.py` separately from the retained Agent-tool lifecycle described below. After state admission, each execution attempt creates a private `.assessment-work/diagnostics/attempt-*/events.jsonl` feed. Job IDs match receipt identities; call IDs are unique within the attempt and concurrent component views share the same writer. Events distinguish returned answers from accepted, reused, rejected, or replaced work and retain the selected host/model and available exit or HTTP status metadata. Claude call records identify their separate host-event attempt and filename.

The Codex CLI adapter supplies a native structured output schema under `payload`, with explicit presence wrappers for optional fields and entry arrays for dynamic object members. It rejects malformed or ambiguous wire values before canonical schema validation, source verification, or action authorization. It does not parse a JSON document hidden in an output string. The generated wire schema and trusted instructions count against request capacity; the full canonical schema is not duplicated in the instructions.

Each semantic job permits at most six exchanges, including source requests and corrections. Every packet states the remaining exchanges; the final exchange permits only a complete artifact and serves no further source requests. The controller retains a rejected draft and its validation reason across subsequent source-read feedback. A completed artifact still passes all source, schema and semantic checks. Exhaustion reports source-read rounds and rejected-result counts without extending the call limit or accepting incomplete work.

Trust-boundary classification groups up to twelve deterministic signals per job, ordered by crossing endpoints with client origins grouped alongside external ingress. Combined context above 64 KiB or half the host's available context capacity is split further; a single signal retains the normal host limits. Each projection contains only the selected signals, their flows, endpoint components and permitted relay context. Known evidence from the projection is preloaded in bounded source windows, including route evidence for placement-derived signals. The model classifies crossings and required assumptions before the separate control and threat analyses, and may reference one candidate from several signals describing the same enforcement point. Every signal still requires exactly one disposition, and the existing source, fingerprint, coverage and candidate validation runs for each batch and the combined result. A candidate's endpoints must belong to each signal it covers; its evidence and flows must belong to those signals' projections, even when another crossing in the batch exposes additional sources. Batch identities namespace candidate keys and bind resume receipts; neither batching nor fewer initial calls changes the run's spending or execution limits.

Discovery quotation rejections carry controller-generated evidence positions separately from their safe diagnostic text. A targeted correction call receives at most 24 affected references and bounded windows from the task's existing source slices. It returns only known citation IDs, line numbers inside those windows, and quotations that occur literally on those lines. Only the corresponding line and quote fields can change; files, repository identities and interface claims stay fixed. The controller validates the complete corrected artifact and reruns its review before accepting it. These calls count against the same exchange, budget and time limits; malformed answers, out-of-window lines and invented quotations cannot produce an accepted artifact. Unavailable or oversized correction context falls back to ordinary correction without extending source authority.

Diagnostic records exclude prompts, source excerpts, model answers, provider bodies, raw stderr, and arbitrary exception text. Controller validation reasons pass through secret masking, quoted-value and location removal, and printable single-line normalization; reasons beyond the safe input limit are omitted with an explicit marker. Each feed is limited to 8 MiB. A write failure disables only that feed and emits a fixed warning. Compatible resume creates new feed and host-event directories without replacing earlier attempt files; rebuild retains its existing work-directory reset behavior.

The following lifecycle rules apply to agents other skills dispatch through the Agent tool; the assessment's own model exchanges are tool-less and use none of them.

Every Agent tool invocation uses the host `tool_use_id` as its immutable
`agent_call_id`. `scripts/runtime/agent_lifecycle.py` persists the schema-v1 lifecycle
under `.active-tool-calls/agent-lifecycle.json` and permits only
`AGENT_SPAWN -> AGENT_RUNNING -> AGENT_DONE | AGENT_FAILED`. Replayed terminal
events are no-ops; missing, reordered, or conflicting transitions emit
`AGENT_LIFECYCLE_REJECTED`. The host `agent_id` binds SubagentStart and
SubagentStop usage to the call. SubagentStop reads the child-specific
`agent_transcript_path` and retires the budget; a missing or later Agent
PostToolUse cannot reopen the call. A child's own `SubagentHandback` ends its
turns and every join once it came on the last allowed turn, when no
SubagentStop can follow, or the child stayed silent after it (OR-29). The common `transcript_path` belongs to the
parent session. A headless session persists neither transcript: SubagentStop
then defers the outcome instead of recording a failure, and the Agent
PostToolUse terminalizes the call and supplies its usage. A run or session ID
alone never assigns a role, usage record, or turn counter.

`scripts/runtime/budget_watchdog.py` opens one schema-v2 counter at call admission and
retires it with the terminal call. Budget markers retain the compatible JSON
list envelope but each new entry must validate against
`schemas/agent-call-budget-marker.schema.json`. Entries without a current
`agent_call_id + action_id + job_id + component_id + attempt` identity are
inert.

Terminal cleanup first emits `AGENT_FAILED` for any
remaining calls, retires their counters and markers, then removes
`.active-tool-calls/`.

A run that does not finish cleanly still reaches one terminal state.
`scripts/runtime/terminate_run.py` is that single terminator: it records `RUN_ABORTED`
unless a controller verdict already stands, closes the checkpoint, terminalizes
remaining calls, removes live markers, aggregates run issues, and releases the
lock when the run owns it. All of that is scoped to the run that owns the
directory: when the lock is held by a live run under a different run ID, the
terminator changes nothing there — not the lock, and not the checkpoint, live
markers or run issues that are the holder's state. The headless wrapper calls
it when the operator interrupts a requirements audit.

## Semantic architect review

When `architect_review` is enabled, the assessment reviews canonical findings after evidence handling and before triage; `scripts/analyzers/architect_review_runtime.py` plans the packets, collects the proposals and applies them in one transaction.

The controller persists `.architect-review.json` under `schemas/architect-review-runtime.schema.json`. The transaction binds the run, original canonical input, analyst context, scoring profile, policy, admitted packets, proposals and accepted output. Every consumer reconstructs the application with the correction core and the recorded scoring profile, including after transient configuration cleanup. A scoring-profile change during an in-flight review blocks publication. Completed transactions recover publication without dispatching again. Re-entered boundaries retain already returned results and never dispatch a returned or missing job again.

The YAML builder projects accepted fixes after mitigation grouping and before requirement annotation. Changed ratings rederive priorities on linked fix cards through their existing deterministic policy; unrelated authored priorities and separate review or investigation tasks remain intact. Old override cards have no source-bound exception proof and cannot override a changed rating or replace an accepted fix. Shared cards retain unrelated members. Enrichment rejects lost corrections; a finding legitimately below the configured report floor remains in the audit.

## Assessment controller failure policy

The deterministic assessment controller (`assess`) requires accepted architecture, component inventory, trust boundaries, controls and every component's STRIDE analysis before publishing a complete result. A resource-budget interruption may instead publish the separate incomplete snapshot described below; other failures before those foundations are accepted stop the run.

After that point, a failed model job or optional stage does not stop the run. The stage supplies a deterministic replacement, the gap is published as a run warning that names the replaced job, and the job writes no receipt, so a later run retries it. Replacements:

- an abuse case becomes not checked;
- a failed abuse-case derivation proposes no case;
- an evidence-review batch leaves its findings `ambiguous`;
- a merge-review batch keeps its findings separate;
- unanswered architect-review packets stay unreviewed;
- root-cause synthesis falls back to the title-derived tier view;
- the Management Summary keeps the deterministic verdict floor;
- a failed export is a warning.

A model read proposal for a well-formed relative filename outside the task selection is refused before retrieval and may be corrected within the existing exchange, read, time and accounting limits. Refused proposals consume the read allowance; no file is admitted or guessed from imports. Missing evidence must remain unresolved. Unsafe paths, unknown repository IDs, and paths paired with the wrong repository remain fatal, even after the read allowance is spent; every batch is checked before any of its reads is served. Only served authorized ranges enter acceptance receipts.

The Security Architecture section remains required: its contract requires a sequence diagram per flow, which only its author can write. At any point, the run stops on a violated trust boundary (a read outside the admitted scope, a changed or foreign receipt, or source changed during the run), on a model that still violates its output contract, provenance or the secret gate after every deterministic repair, on an inconsistent register after the integrity steps, or on unsettled call accounting.

### Completion budget

Each structured job reserves its remaining correction allowance inside the existing six-exchange ceiling. When the remaining exchanges equal one draft plus the unused correction allowance, the host requires complete and disallows further model-selected source requests in that exchange. An early valid draft returns immediately; a rejected draft still passes full schema, source, identity and semantic validation on every correction. Exhausting the allowance never accepts an invalid draft. Failure diagnostics distinguish exchange use, source-read rounds and rejected drafts.

`AssessmentBudget` owns resource admission under the same lock as concurrent call reservations. The controller plans the required Security Architecture job and outstanding STRIDE batches. Optional jobs protect all planned work; required analysis protects report completion. Cost estimates use the average accepted job cost for each role under the run's fixed model selection, with correction headroom, so one expensive job is not multiplied across every outstanding batch; time estimates use the largest accepted job duration. Roles without observations use conservative call allowances. Exact constants and the parallel-work calculation live in `runtime/assessment_jobs.py`. Reused, revalidated jobs reduce outstanding work and contribute measured cost, while their previous costs remain charged to the run. The plan is reconstructed during resume, never taken from model output.

Every exchange and retry rechecks the reserve before dispatch. An optional job that cannot fit returns its existing deterministic replacement, records a budget-specific gap and writes no acceptance receipt. While STRIDE batches are outstanding, such a gap does not ask the operator for more budget; the controller retries deferred evidence reviews once that reserve is released, and a shortfall then may ask. User cancellation, a stale or foreign receipt, source drift and unavailable accounting never take this fallback. A completed result still passes all existing report gates.

`max_parallel` is an operator-owned scan setting with a default of 2 and a validated integer range of 1–16. `--max-parallel` on `scan` overrides the profile; profile inspection and validation accept the same override. Each assessment budget owns this limit, and both the component worker pool and required-work time reserve use it. Repository configuration cannot choose it. The effective value is shown in the run header and included in the configuration identity and profile snapshot; changing it requires a new run. Snapshots predating the setting are explicitly rejected through the profile path.

STRIDE source batches share already included source windows between targets, including a related template that later becomes a primary target. Batch sizing includes UTF-8 target metadata, unique source windows and the first job's reserved context; a large group of targets sharing one window is split when its metadata would exceed the budget. Route-handler targets receive compact registration excerpts covering their resource's route lines, with earlier guards and middleware retaining separate source anchors and authorized reads. No investigation target is discarded to reduce the job count. Component jobs remain sequential within each component; `max_parallel` controls concurrent components.

Each replacement emits an immediate controller-owned coverage-gap event to normal progress output, including without `--verbose`; budget skips name the completion reserve. The event uses fixed role labels and validated case IDs, never raw host exception text. A later successful retry remains possible. Architect Review reports accepted, unreviewed, and unresolved finding counts; abuse-case completion counts come from the validated canonical export, with missing candidates counted as unchecked and partial checks separate. These totals remain in phase completion lines. `--quiet` suppresses live progress, while the existing final summary retains omissions. Progress reporting does not change required work, spending admission, publication gates, or exit codes.

Stage 2 completes Security Architecture before Management Summary and requirements commentary. An already filled architecture scaffold releases its unused planned reservation. After the required renderer completes, the Management Summary may use the remaining funds below its full job estimate; every exchange and correction still obeys the actual remaining USD allowance, minimum call amount, host admission, call count and finalization time reserve. Other optional jobs retain their estimated-job admission threshold. The summary's existing deterministic fallback and validation gates remain in force.

For an eligible interactive terminal, full-assessment monetary admission may ask for an increased total USD limit. `runtime/interactive_budget.py` excludes explicit `--non-interactive`, quiet or JSON output, missing terminals, and recognized CI markers. Admission holds the shared budget lock only after in-flight calls settle; no new call starts during the question. The operator must supply a higher literal amount. `AssessmentState.approve_budget_increase` validates and persists a bounded authorization history before the live limit changes. Compatible resume retains the original identity and validates the monotonic authorization chain before restoring its last limit. Required-source scope, call and time limits, per-call ceilings, cancellation, and unsettled-accounting failures remain authoritative. Separate discovery and requirements audits never enable this prompt.

If required work cannot fit, `BudgetExhausted` interrupts the lifecycle and exits `3`. While it still owns the lock and after workers have joined, the lifecycle may write `.assessment-work/budget-report.md` from results accepted or revalidated in this session. The optional `partial_report` field of `schemas/multi-repo-state.schema.json` defines its structured projection, bounds and omission counts. Source verification, redaction against captured sources, inert rendering and the secret check precede the write. The snapshot identifies preliminary candidates and missing work, never claims completed analysis, and never enters the normal model/export publication path. Cancellation, unknown accounting or source/contract violations block it. A successful continuation removes the snapshot; a fresh attempt with changed limits reuses compatible accepted jobs through the existing cache.

### Verification jobs

Verification (REQ-040) runs after every survey job of the threat analysis phase and before the merge. Its model jobs are optional: one per component and verified aspect, or several that share the candidates by location when a component has more than 40. The verified aspects are the run's `test_cases` setting, resolved for its depth from `data/assessment-depths.yaml`, the organization profile's `depths`, and the scan profile's `depths` and `test_cases`, and extended by the organization profile's `test_cases.required_aspects`; repository content cannot select them.

A component gets a job for an aspect only when one of the aspect's items has a starting candidate there or the aspect's goal item applies; otherwise its items record undecidable without a model call. A job runs on the survey's model and receives the component's starting candidates from the route inventory and the scanner rules, together with the code of the middlewares and guards their routes run, answers each candidate, and may add its own. Several jobs share the candidates by location, so each route is examined in one of them for every item that names it, and only the first job adds candidates of its own. Role checks and privileged fields start from every route that changes state, whatever its guards. Owner checks also start from every route that takes a request body, because the body can carry the object identifier, and role checks also from authenticated reads without one, such as user lists. The candidates include the routes that finale-rest and epilogue resources generate from data models; only verification sees them, so the route inventory, the survey, and the other commands do not list them. Input validation, data protection, and language model items start from code sites that the fixed patterns of `data/code-sites.yaml` mark, such as raw queries, commands, HTML output, model calls, or sensitive fields in data models: a route whose handler reaches such a site is the candidate and names the site, and a site no route reaches is a candidate of its own. Each aspect's goal item asks for an attacker goal, such as changing data beyond one's rights, by any path and adds its own candidates. Fixed post-checks over the route inventory and the code sites test the job's claims; a code site confirms only the mechanism of a weakness, never a control.

Each item records one outcome per component: finding, control, partial, no finding, undecidable, not applicable, or disabled. An item that examined no location records undecidable; only a goal item records no finding when its search across the component found nothing beyond the other items. A control requires evidence at every candidate location, and the reason says where only model review supports it. Partial, no finding, and undecidable never count as a control, and comments, documentation, and controls outside the examined sources are not control evidence. A finding may lie in a shared file that belongs to no component, such as a helper that a handler calls, when the job read that file. A finding that still breaks an evidence, trace, or rating rule after the job's last correction is dropped with a warning, its candidates record undecidable, and the job's other answers stand. A failed or unaffordable job makes its candidates undecidable with a warning, and the run continues.

The controller decides the jobs from the catalog, the architecture and the scanner findings before the survey and states their number then, so the live progress weighs them from the phase's start. Before the first one runs, it states their number and estimated cost and whether `AssessmentBudget.available_usd` covers them. Each job reports its start and its end, including an end without a result, with its component's number and its part of that component's jobs. The plan and start lines name the components and end with the job count, which the console uses only to weigh the step; it shows one step per component. Until a verification job has been accepted, `AssessmentBudget.job_usd` takes the reserve of a survey job, which carries the same component context. A run that cannot cover them records a note and continues: a job that cannot fit becomes a budget gap, its candidates record undecidable with the fixed budget reason, and its aspect is listed in `incomplete_aspects` of the sidecar and of `test_case_results`. A subscription run states the job count and that its call and time limits apply.

`AssessmentBudget.hold` and `release` keep a share of the optional budget for one group, such as the planned open review. Required work outranks a hold, and other optional jobs see less while it is active. Holds are never persisted; a resumed run recomputes them.

After the model is built, `case_outcomes.combine_methods` links a verification finding with a survey threat when one of the threat's locations has the same file, line, and CWE family by the survey merge's identity (`merge_threats._evidence_identity_key`), and marks a survey threat as contradicted on a line where a verification item with its CWE evidenced a control. Neither step removes or rescores a survey threat.

### Depth settings

`resolve_config.resolve_depth_settings` runs after the organization profile is applied. It layers the organization's and then the scan profile's `depths` over `data/assessment-depths.yaml` and records `depth_settings` with the origin of each value. The architect review and the abuse case stage follow these values unless a command-line flag decides them; the stage is skipped when a depth checks neither optional nor model-derived cases and no case is named. The matcher and the deriver read the counts from `.skill-config.json`, actor discovery reads its switch there, and the Claude Code dialogue entry takes its budget from the same layers before the run starts. Before the first model call the controller refuses a scan profile that checks an abuse case the organization switched off, or a shipped `AC-T`/`AC-B` ID that does not exist.
