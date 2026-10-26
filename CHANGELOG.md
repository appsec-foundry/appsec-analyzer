# Changelog

Notable changes, including development history inherited from AppSec Advisor. Historical entries retain their original command names; see the [README](README.md#commands) for current Analyzer commands.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

<!-- Add entries here as work lands; promote them into a dated heading at release. -->

### Added

- Standard and thorough assessments verify authentication, authorization, input validation, and language model use alongside STRIDE analysis; thorough also checks data protection and authentication on every route. Verification adds model cost, shown in advance, and produces item-level results with linked findings and explicit contradictions. Profiles can also record scanner-linked verification items without model calls; see [verification configuration](docs/security-assessment.md#configure-verification).
- Assessment depths and business abuse cases are configurable through organization and scan profiles. Standard and thorough runs check business abuse cases; thorough adds application-specific cases. `appsec-analyzer abuse-cases` lists definitions and saved results without model calls.
- `appsec-analyzer platform-settings` checks GitHub and GitLab repository security settings through read-only API requests, without model calls.
- `appsec-analyzer distribution init` creates an organization's own Analyzer distribution; `distribution update-engine` aligns its engine pins. Both work on local files only.
- `appsec-analyzer repo-profile` shows local repository size, languages, and build manifests without model calls.
- Experimental: the headless runner accepts repeated `--repo` options to assess several checkouts as one system, with cross-repository evidence and attribution. Replacing a combined report requires `--rebuild`.
- Threat Analyst supports code hypotheses, selected abuse cases, change-specific questions (`--question`), and read-only design exploration (`--explore`).
- Headless assessments accept HTTPS and SSH Git URLs with authenticated access and automatic temporary checkout cleanup.
- `python -m appsec_analyzer` starts the public CLI from a checkout or when the command is not on `PATH`; `python -m appsec_analyzer.cli` remains supported.

### Changed

- `assess` no longer sends a test prompt to a low-cost model before the run. The access and provider checks remain; a rejected login, key or quota now shows at the first model call in Reconnaissance.
- `appsec-analyzer scan` is renamed to `assess`. `assess --non-interactive` requires `--repo` and an explicit `--profile` (or legacy `--host`). Starting without a command shows examples and help guidance, with exit code 2.
- Standard and thorough runs prioritize built-in business abuse cases not already covered by verification; team-supplied and explicitly requested cases keep their place.
- Management summaries group remediation by root cause and severity. Critical Findings by Root Cause replaces the Critical Attack Tree.
- Headless controller assessments analyze up to four components concurrently within the budget and retain an explicitly incomplete snapshot when required work cannot finish.
- Headless findings count as confirmed exploitable only with source evidence of insecure code, attacker reachability, and no stopping control. Reports identify unresolved checks and coverage gaps.
- Architecture diagrams distinguish network and build trust boundaries, unauthenticated requests, and client-to-route calls more precisely.
- Threat Analyst uses existing threat-model context unless `--isolated` is passed; reviews follow relevant imports and earlier finding references.
- `scripts/run-headless.sh` uses the controller for single-repository assessments and rejects `--incremental`, `--rerender`, and `--pr-mode`. `--audit-requirements` uses the repository named by `--repo`.
- Headless output shows component progress and delivered files, with detailed diagnostics under `--verbose` and wrapping controlled by `--width`.
- Repository abuse cases move to `docs/security/abuse-cases/`; `.appsec/abuse-cases/` remains supported.
- Trust-boundary review and abuse-case checks run up to `max_parallel` jobs at once instead of one after another. A run paused by provider rate limits names a smaller `--max-parallel` value for a new run that reuses the accepted jobs.
- `max_parallel` defaults to 4 instead of 2, or 3 for a run on the default whose components divide by three, and stays 2 for Codex and Copilot subscriptions.
- A component's evidence-review batches run side by side, and the run caps all simultaneously running model calls at `max_parallel`.
- The completion summary's Verification line counts findings, controls, partial and undecidable items only, and names the other report formats by short name.

### Fixed

- Hardcoded secrets, including keys passed as arguments, are masked in all report outputs; the secret gate fails if one remains.
- Threat Analyst honors organization Opus bans.
- Authentication checks follow more JavaScript middleware and imported handlers; ownership controls count only when they protect every recognized handler registration.
- Abuse-case verification excludes unrelated findings, distinguishes confirmed and unresolved results, and rejects invalid case files without dropping valid ones.
- Trust-boundary detection covers varied layouts, separate deployments, build channels, and outbound calls, including request-chosen URLs.
- Source analysis excludes archived reports as code evidence, avoids false wildcard-CORS findings without credentials, and detects OAuth implicit-flow tokens read from `location.hash`.
- Reports handle empty registers and repair or stop on broken links. STRIDE mappings follow weakness classes, and the Figure 1 legend no longer claims per-element STRIDE coverage.
- AI / LLM Exposure lists verification findings under the OWASP LLM categories of their verification items and no longer files a user role set from the request body under prompt injection.
- Verification no longer asks the model to correct a finding anchored at a route registered in another component's file; it may anchor there, and the instructions tell it to cite data models and guards as the trace.

## 0.6.0-beta.4 (2026-10-06)

### Added

- Experimental [Threat Analyst](docs/threat-analyst.md) checks planned features and selected code changes through `/appsec-advisor:analyze-threats` and `scripts/appsec-analyst-cli`.
- Figure 1b maps build inputs, release artifacts, evidenced attacks, and controls, with GitHub Actions and GitLab CI support.
- `scripts/analyzers/repo_scan.py` lists findings, endpoints, and technologies without a threat model. It and Security Score accept HTTPS GitHub/GitLab URLs and YAML or JSON output.
- `.appsec/actors.yaml` accepts `legitimate_roles` whose login is outside the repository.
- Report figures support dark mode.
- `export-threat-model` and `authnz-review` accept `--slug` for named exports.

### Changed

- Malicious insiders and attackers holding a user's device require explicit opt-in and otherwise appear as not assessed.
- Interactive runs confirm application purpose and worst plausible business impact, saving answers in `docs/security/business-context.md` with legacy-path fallback.
- `--stride-cap` and quick assessments retain all Critical and High findings.
- `create-threat-model` uses `auto` and `bypassPermissions` mode without a separate `Bash(*)` allow-list and reports unreadable settings.
- Management summaries identify the system and use case, distinguish confirmed from unverified findings, and avoid claims of exploitability or release readiness.
- Reports consolidate architecture and control coverage, link attack routes to prerequisites and impact, and simplify finding and remediation tables. Figure 1 adds technology and authentication labels, detail views, and a PDF appendix; older models need reassessment for authentication evidence.
- Configuration scans cover secrets and exposed data ports in Kubernetes, Helm, Terraform, and Compose, with workload attribution and explicit coverage limits. Supply-chain controls rely on repository and CI evidence; tools that may run elsewhere appear as not evidenced.
- LLM and agentic assessments report coverage for each applicable OWASP Top-10 item.
- Thorough assessments include more source evidence within the same token budget.
- Architect review checks ratings and mitigations, removes refuted and below-threshold findings, and retains accepted corrections across report rebuilds.
- Completion summaries prioritize grouped fixes and unresolved team decisions. Run Issues flag duplicate findings, missing evidence, incomplete reviews, and sharp drops in severe findings.
- `/appsec-advisor:report-error` prepares anonymised issue drafts for explicit publication approval; `--bundle-only` keeps diagnostics local.
- Baseline installations load verified modules on demand; updates use compatible signed installers and preserve installation scope and mode. The bundled baseline advances to `aiscb-0.1.19`.
- `/appsec-advisor:help` starts with a quick guide; `--all` shows the full reference.

### Fixed

- Private keys are fully redacted, and pentest exports are checked for leaked secrets.
- Config/IaC findings reach reports with correct categories and components; checks respect Git ignores, tracked agent settings, and valid workflow permissions.
- Authorization checks detect object-level gaps and mass assignment without stale results or read-only-field false positives. Route guards apply only to the handlers they protect.
- HTTP handlers remain in scope even in internal components; large components retain source coverage and prioritize severe scanner evidence.
- `authnz-review` retains scanner findings, checks unresolved permissions and disabled JWT validation, and fails its gate on incomplete analysis.
- Finding merges preserve risk, evidence, and scenario references while keeping distinct JWT failures separate. Ratings respect policy limits and verified attack-chain impact.
- Confirmed business impact reaches all runtime components; prior findings count as verified only when explicitly referenced.
- LLM analysis retains component-specific RAG and agent evidence; AI / LLM Exposure includes only relevant OWASP-tagged findings.
- Supply-chain findings account for repository-wide control coverage and identify searched files.
- Architecture diagrams distinguish endpoint controls from host controls and in-process calls from separate services.
- Reports retain assessed controls and handle free-text control domains without aborting.
- Security Score withholds ratings when required scanners fail or return invalid output.
- Large inventories, out-of-range evidence lines, and metadata no longer abort runs; omitted context and exhausted analysis budgets appear as coverage gaps.
- Retries resume saved work without duplicate attempts; interrupted runs release their locks, and rerendering preserves other runs' locks.
- Logs retain prior events, and cost totals avoid duplicate sub-agent usage while flagging missing measurements. Run plans warn when requested exports cannot complete.
- Plugin update checks advertise released versions only; error-report prompts exclude known defects.

## 0.6.0-beta.3 (2026-09-14)

### Added

- Summaries suggest up to three concrete questions for manual threat modeling, linked to findings.
- `--soft-budget` and organization profiles provide cost budgets, spending warnings, and per-phase headless totals.
- `/appsec-advisor:repo-profile` shows repository size, languages, and build manifests without model calls or network access.

### Changed

- Figure 1 groups attack scenarios, data flows, actors, and severe findings; scenario tables show verification status.
- Actor grouping recognizes self-registration and public access while preserving login and privilege requirements.
- `fix-run-issues` requires a diagnosis and gives manual remediation guidance.
- Examples move to `appsec-advisor-examples`.
- Baseline installations and updates verify release signatures and checksums.

### Fixed

- Headless runs handle asynchronous agents, interruptions, and lock conflicts; progress and tracing settings reflect the active run.
- Cost reports use actual model rates, retain stopped-agent usage, and flag missing measurements.
- Unattended runs no longer prompt for context. Discarding completed analysis with `--full` or `--rebuild` requires confirmation or `--force`.
- Deeper scans reuse unchanged reconnaissance; rebuilds preserve model details.
- Injection checks cover more NoSQL, code, and template sinks and distinguish stored, reflected, and DOM-based XSS.
- Reports retain controls and editorial work, merge duplicates, exclude refuted chains from open questions, and avoid formatting and masking corruption. Completion summaries list all requested exports.

## 0.6.0-beta.2 (2026-09-04)

### Added

- Findings and mitigations link to requirements and blueprint guidance. Summaries list failed requirements; audits identify the catalog and its age.
- Blueprint sources support separate catalogs through `catalog_file`. YAML and Threat Dragon exports retain requirements provenance and applicable assessment traces.
- `/appsec-advisor:status` reports installed versions, skills, and active profiles; `--check-updates` checks baseline and core updates.
- `/appsec-advisor:security-score` rates repositories from scanner results without a threat model.
- Scanners flag unchecked LLM output reaching rendering, interpreters, or privileged actions.
- `/appsec-advisor:update-baseline` updates an installed baseline, including organization-defined sources.
- Headless runs accept an environment-configured Claude Code wrapper.
- `authnz-review` supports pentest-task exports and organization defaults.
- Run Issues flag inconsistent agent counts, missing source context, and requirements results absent from YAML.

### Changed

- Enforcing baseline checks distinguish outdated installations from foreign ones and reject both.
- Final editing polishes prose while preserving findings, ratings, evidence, links, and numbers.
- Missing lockfiles, image digests, workflow permissions, and action pins are rated Medium rather than High.
- `--context` records its source and stops on unreadable input.
- Help and completion guidance remove unsupported options and clarify next steps.

### Fixed

- Hooks use the run's output directory; stale locks and asynchronous agent completion no longer block later work.
- Plain HTTP URLs in comments no longer cause transport findings for bundled third-party files.
- Skipped abuse-case verification appears as a coverage gap. Release gates write the failed chains and ranking before stopping.
- Disabled requirements checks ignore empty catalogs and stale counts; harvesting retains complete sections, unbracketed IDs, and declared formats without duplicates.
- Stored business context containing credentials is withheld. `--skip-context` is honored, context cannot leak between runs, and unmatched context produces a run issue.
- Reports preserve complete code references; `--slug` also names PDF and HTML exports. Run statistics, failure diagnostics, and temporary-file cleanup reflect the outcome.

## 0.6.0-beta.1 (2026-08-23)

From this release, `-beta.N` identifies a numbered prerelease of the upcoming version; in 0.4 and 0.5, `-beta` named the release line.

### Added

- Scans assess committed coding-agent permissions, approvals, hooks, and tool trust for Claude Code, Codex, Copilot, Gemini CLI, and Kiro.
- Requirements harvesting exports selected functional requirements as OpenSpec and SpecDD files.
- Optional business context, supplied interactively or with `--context`, guides scope and impact; `--skip-context` omits it.
- LLM analysis checks prompt-only restrictions, action auditability, data permissions, and approval gates, with organization policy through `llm_policy`.
- Alpha OWASP Threat Dragon v2 export supports Threat Dragon and ThreatAtlas.
- Stable trust-boundary IDs link declarations and findings across Markdown, YAML, query, and SARIF output.
- Baseline install, verification, and removal skills include `verify-baseline --enforce` for CI. Organization profiles can ship skills, baselines, and banners or disable shipped skills.
- Help shows active configuration.
- `/appsec-advisor:report-error` creates a local anonymised diagnostic bundle without sending it.

### Changed

- Reference runs cost 39.8% less at quick depth and 26.8% less at thorough depth.
- Progress identifies active steps and components; summaries explain code-derived assessment limits and reporting thresholds.
- Attack walkthroughs cover more threat categories. Verified findings at confirmed internet entry points may rise one severity level, up to High.
- Findings remain separate across trust boundaries and show STRIDE categories. `show-threat-model` includes the saved verdict, worst-case scenarios, severity counts, and stale-model warnings.

### Removed

- Runs support only full, rebuild, and rerender. Incremental, resume, PR mode, assessment dry runs, baseline restore, `--max-wall-time`, `--max-cost`, and `APPSEC_LIVE_PHASE=1` are rejected; use `--full` to reassess while preserving report history.
- The retired `--qa-scan-repo` option is rejected.

### Fixed

- Scope mismatches narrow analysis without losing cited evidence; large repositories retain required sections and report partial source coverage.
- Diagrams honor component tiers and counts, include LLM endpoints, and avoid treating browser code as a trust zone.
- Finding tables preserve references, categories, locations, and consistent severity without duplicate workflow findings.
- Long, interrupted, and malformed runs retain completed work or terminate cleanly; lock conflicts offer recovery, and cost summaries flag incomplete accounting.
- Abuse-case selection works at every depth, and verification cannot be silently skipped before rendering.
- Prompt text alone no longer counts as an injection control. Other repositories and earlier reports cannot stand in for target-source evidence.
- Supply-chain checks assess tools actually run and retain PHP dependencies. Reconnaissance detects predictable OAuth-derived and bundled client credentials.
- Requested exports are written and listed; invalid YAML cannot replace the last valid artifact. Report gates and rendering accept the same valid output.

## 0.5.1-beta (2026-07-26)

### Added

- Authentication scans detect security-question resets and password policies allowing fewer than eight characters.
- `ask-threat-model` filters by severity, component, and evidence state.
- Headless runs report per-model token usage and cost from Claude Code accounting.
- Smaller-budget screening for internal components is enabled at quick and standard depth, configurable with `--cheap-stride` and `--no-cheap-stride`.
- Agentic assessments check Claude Code permissions and hooks.

### Changed

- Large assessments use resumable component batches. Evidence checks and report review take less time and cost; supply-chain scoring better recognizes Python and npm safeguards.
- Attack walkthroughs clarify action order and technical details; preflight summarizes STRIDE depth and screening.

### Fixed

- Long runs preserve evidence and completed work, resume after analysis, and isolate concurrent runs. Component analysis no longer runs serially by mistake.
- Findings retain locations, sources, and consistent severity; stored XSS requires evidence of persistence and unsafe HTML output.
- Attack chains count as fully viable only when every step is confirmed; control assessments use verifier evidence.
- Report diagrams and control sections handle large models without broken links. Secret masking preserves unsigned-token and SQL-injection reproduction payloads.
- Packaged plugins support custom namespaces in headless mode.

## 0.5.0-beta (2026-07-18)

### Added

- `/appsec-advisor:ask-threat-model` answers questions about saved models with finding references.
- `/appsec-advisor:review-threat-model` supports bulk triage, saves a remediation plan, and retains decisions across reassessments.
- A Weakness Register groups systemic and design weaknesses by evidence and control implementation, including supply-chain risks and committed secrets.
- Access-control, cryptography, and mass-assignment scanners extend beyond JavaScript/TypeScript to Java, Python, Go, PHP, C#/.NET, Ruby/Rails, and mobile.
- Headless runs accept Claude subscription authentication through `CLAUDE_CODE_OAUTH_TOKEN`.
- Abuse cases can be selected from repository signals, paths, or source probes and gated on verified chains.
- Organization profiles can package MCP servers, requirements and severity gates, remote-fetch allowlists, Security Coach rules, and event hooks. Per-run gate options remain available.
- Agentic applications gain OWASP Agentic Top-10 coverage and linked finding tags.
- Architecture diagrams show missing tiers as placeholders.

### Changed

- OWASP Top-10 mappings and coverage checks target the 2025 edition.
- Management summaries use plain language; Security Architecture precedes the Weakness Register, with shorter tables.

### Fixed

- Refuted findings are removed; merging preserves locations and scenarios, and scanner findings receive remediation guidance.
- Abuse-case verification avoids weak matches and marks incomplete chains provisional.
- npm install-script checks exclude non-JavaScript images.
- Interrupted runs explain failures and retain context across retries and compaction.
- `--slug` names pentest-task exports to prevent overwrites.

## 0.4.0-beta (2026-07-07)

First public release, intended for guided use rather than unattended CI.

### Added

- `/appsec-advisor:create-threat-model` generates STRIDE models with architecture diagrams, trust boundaries, risk-ranked findings, and remediation guidance at quick, standard, or thorough depth.
- Markdown, YAML, PDF, HTML, SARIF, and pentest-task exports; findings link to reachable threat actors, and abuse cases combine findings into attack scenarios.
- Incremental scans reuse unchanged analysis. Business context, related repositories, and organization profiles guide assessments.
- Standalone security-requirements audits and publication of reviewed reports; generated reports are git-ignored by default.

### Known limitations

- Run `/appsec-advisor:check-permissions --update` after installation.
- Large repositories (roughly 8–10 or more components) are slower and not yet parallelized.
- Supply-chain assessment covers posture, not known CVEs; use a dedicated dependency scanner.
