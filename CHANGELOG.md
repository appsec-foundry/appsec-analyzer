# Changelog

Notable changes, including development history inherited from AppSec Advisor. Historical entries retain their original command names; see the [README](README.md#commands) for current Analyzer commands.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

<!-- Add entries here as work lands; promote them into a dated heading at release. -->

### Added

- `assess`, `scan-sources`, `score`, and `audit-requirements` accept a local directory without Git. A `.gitignore` applies as in a checkout, nothing is written into the directory, and the report shows no commit. See [Directories without Git](docs/security-assessment.md#directories-without-git).
- `--requirements` of `assess`, `audit-requirements`, `authnz-review`, and `analyze-threats` also reads OSCAL catalogs in JSON or YAML. Analyzer detects the format from the content, assigns the priority MUST to every control, leaves out withdrawn controls, and records the format and the checksum of the supplied file. Profiles, XML, and catalogs above a command's limit are refused before any model call; see [catalog formats](docs/security-requirements-audit-skill.md#catalog-formats).
- Figure 1 shows OAuth 2.0 and OpenID Connect sign-ins step by step for any provider product, including a provider that runs inside the system: the sign-in, the token request with its grant, and requests that carry the provider's access token to the application. Common client libraries and token checks are recognized, and fetching public discovery documents or signing keys no longer appears as missing authentication.
- Private HTTPS Git URLs and merge or pull request URLs can use a token from `GIT_TOKEN` or `GITLAB_TOKEN` (GitLab hosts only), or from any variable named with `--git-token-env`; a failed access now names the variables it looked for.
- Standard and thorough assessments verify authentication, authorization, input validation, and language model use alongside STRIDE analysis; thorough also checks data protection. Verification adds model cost, shown in advance, and produces item-level results with linked findings and explicit contradictions. Profiles can also record scanner-linked verification items without model calls; see [verification configuration](docs/security-assessment.md#configure-verification).
- Assessment depths and business abuse cases are configurable through organization and scan profiles. Standard and thorough runs check business abuse cases; thorough adds application-specific cases. `appsec-analyzer abuse-cases` lists definitions and saved results without model calls.
- `appsec-analyzer platform-settings` checks GitHub and GitLab repository security settings through read-only API requests, without model calls.
- `appsec-analyzer distribution init` creates an organization's own Analyzer distribution; `distribution update-engine` aligns its engine pins. Both work on local files only.
- `appsec-analyzer repo-profile` shows local repository size, languages, and build manifests without model calls.
- Experimental: the headless runner accepts repeated `--repo` options to assess several checkouts as one system, with cross-repository evidence and attribution. Replacing a combined report requires `--rebuild`.
- Threat Analyst supports code hypotheses, selected abuse cases, change-specific questions (`--question`), and read-only design exploration (`--explore`).
- Headless assessments accept HTTPS and SSH Git URLs with authenticated access and automatic temporary checkout cleanup.
- `appsec-analyzer update` updates a pipx installation of Analyzer with `pipx upgrade --pip-args=--force-reinstall` after an explicit yes. It makes no model call.
- `appsec-analyzer --version` prints the release version, or the commit and its date when the build is not a release.
- `python -m appsec_analyzer` starts the public CLI from a checkout or when the command is not on `PATH`; `python -m appsec_analyzer.cli` remains supported.

### Changed

- `appsec-analyzer update` and the update that `review` offers for a result of a newer Analyzer show the installed version before they ask and the newly installed version afterwards, as release version or commit and date, so you can see which version you run.
- When the repository's `docs/security` still holds a finished assessment from an earlier release, `assess` starts without it instead of stopping, and names it at the end of the run. Only `--migrate-legacy` imports it, and only before the first run into the destination. `--ignore-legacy` is still accepted but no longer needed.
- `assess` refuses a requirements catalog that needs more than 32 context rows per component before the first model call, instead of silently leaving the later requirements out of the analysis. A remote catalog is read only up to 16 MiB and its redirects are checked against the URL policy.
- Pipeline helpers that validate the threat model and read run costs now start with the interpreter of the running Analyzer instead of the first `python3` on `PATH`, so an environment-managed install no longer fails on a different Python's older libraries.
- The start check of `assess` and `preflight` stops with the `pip install` command when `jsonschema` is older than 4.20, instead of failing in the middle of a run.
- The scanner line of the `assess` console lists the hits of each deterministic scanner (source auth, authz confirm, mass assignment, config/IaC, architecture), including scanners with none.
- The `assess` header shows the model host (Claude CLI, Codex CLI, GitHub Copilot CLI, LiteLLM gateway, Amazon Bedrock API) in a `Host` row before the billing row; Claude CLI also names the gateway host (from `ANTHROPIC_*BASE_URL`) or cloud provider it is routed through.
- Discovery now serves a missing serving unit's entry file with its correction, so a model that omitted the frontend or API component can model it instead of repeating its answer.
- API billing is detected from `ANTHROPIC_AUTH_TOKEN` and from the Claude CLI's own credential source (settings key, key helper, Bedrock, Vertex), not only from `ANTHROPIC_API_KEY`; such runs no longer show as subscription usage.
- Git URL preflight honors `HTTPS_PROXY` and `NO_PROXY`, announces the host it is checking, and names the host in a timeout message.
- The remaining time in the `assess` console follows phase durations measured on quick and standard runs. Quick no longer starts with about 30 minutes for a run of about 22, and standard no longer shows too little time during threat analysis and finalization. The estimate accounts for the depth's quality checks and the architect review of thorough.
- A resumed run, or a new run that takes over an unfinished one, shows a `Resumed` row in its header with the reason, and skips repeating the deterministic scanners when source and Analyzer are unchanged. Scanner results are kept in the output's work directory, never inside the analyzed checkout.
- `assess --resume` no longer refuses an unfinished run whose source, settings, limits or time limit changed. It continues as a new run that reuses the accepted steps that still match, with the limits of the command, and the run header names the cause. A completed run still needs a start without `--resume`.
- Assessment reports name the tool as AppSec Analyzer instead of appsec-advisor and show the Analyzer version of the run. A report rendered again later keeps the version that ran the assessment.
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
- The start line of each phase says what the phase does and names the models of its agents in parentheses, for example `(Sonnet 5.5)`, instead of only the model. In the threat analysis, the start line names the methods from the run header, such as `Scanners, Survey and Verify`, and the start lines of Survey and Verify name their models.
- The Opus roles of the `opus` and `opus-cheap` reasoning models run on `claude-opus-5-5` instead of the `opus` alias, so the console and the cost estimate name the version that ran. Haiku roles still use the `haiku` alias, which follows the host. `--no-opus` still applies.
- Repository abuse cases move to `docs/security/abuse-cases/`; `.appsec/abuse-cases/` remains supported.
- Trust-boundary review and abuse-case checks run up to `max_parallel` jobs at once instead of one after another. A run paused by provider rate limits names a smaller `--max-parallel` value for a new run that reuses the accepted jobs.
- `max_parallel` defaults to 4 instead of 2, or 3 for a run on the default whose components divide by three, and stays 2 for Codex and Copilot subscriptions.
- A component's evidence-review batches run side by side, and the run caps all simultaneously running model calls at `max_parallel`.
- The completion summary's Verification line counts findings, controls, partial and undecidable items only, and names the other report formats by short name.
- With a Claude subscription, USD limits and budget prompts say that they count subscription usage at API prices. The limits themselves are unchanged.
- The Verification Items appendix starts with the results that need attention: findings and partial protection, then undecided items and evidenced controls, each with its title, component, reason, and findings. Not-applicable, not-examined, and disabled items share one line per aspect, and only items with a result get a detail section. Before, the appendix listed every item for every component, mostly as not applicable, with internal candidate counts.
- A thorough assessment examines every program file of each component, in extra survey jobs after the others; files the budget does not reach are named as unexamined (REQ-004). Client code gains its own security signals at every depth, such as raw HTML bindings, HTTP interceptors, route guards, and browser storage. Thorough runs send more source code to the model host and cost more; the run header says so.

### Fixed

- A cited ignore-file pattern such as `*.env` or `**/node_modules` in `.dockerignore` or `.gitignore` counts as configuration, not as a block-comment line. Before, a control that rested on such a file could never cite valid evidence, and the Controls step stopped the assessment after three attempts.
- A configuration rule hit is rated insecure practice instead of confirmed exploitable, and a hit in a file that serves only local development, such as `compose.dev.yaml`, is marked "Development only" and does not raise the verdict (REQ-009). A file that the repository's CI, Dockerfile, or Makefile names is not development only.
- Remediation Priorities names a measure to do first when no measure has priority P1 or P2; it then shows the best priority present. A root cause without any measure of its own says that its lasting fix applies. Before, an assessment with only Medium findings showed every row with empty cells.
- A finding that only verification reported and that the evidence review refuted no longer supports the verdict, the risk distribution, a weakness, or a fix recommendation. It stays in the findings register with the review's reason and its manual review task (REQ-040).
- `assess --resume` without a depth option continues at the depth of the saved run. Before, it fell back to `standard`, so a resumed thorough run silently became a new standard run.
- The route inventory recognizes administrator guards such as `requireAdmin()`, guard lists passed as `router.use(...guards)`, and routes whose path is a constant or a configuration value, such as an OIDC callback registered with `router.get(config.oidc.callbackPath, …)`, and each method of a chain such as `router.route('/items/:id').get(…).patch(…)`. Before, admin routes showed unknown authorization and the sign-in callback was missing from the attack surface.
- A route with a detected guard is no longer listed as public by design because of its name, and `refresh` and `status` mark a route as public only as a token refresh or a top-level probe. Before, `POST /backoffice/refresh` behind an admin guard appeared as public.
- A control outside the identity and session sections, such as a registry credential helper in the build pipeline, no longer counts as password sign-in. Before, an OIDC-only application received a "Password Reset: Missing" control.
- A finding whose evidence lies in a route file takes its attack vector from the route registered just before the evidence line. Before, a shared file name token could match an unauthenticated login route, and a session finding was reported as reachable without sign-in.
- Finding titles keep a clause such as "using a withdrawn right" when it names the object of the sentence. Before, the title "User keeps using a withdrawn right" was shortened to "User keeps".
- When an architecture result cites a comment or blank line as evidence for a flow's authentication or an external service's role, Analyzer now asks the model to fix only those lines, as it already did for threat analysis. Before, the model had to regenerate the whole result, often repeated the citation, and the assessment stopped.
- Flows to an identity provider's public discovery document or signing keys no longer stop an assessment at the trust-boundary step with `Additional properties are not allowed ('public' was unexpected)`. Two internal schemas had not been updated for the provider fields `public` and `issuer`; a schema test now compares nested fields of these schemas.
- A stop that is not a model rejection now shows the Analyzer check that raised it. A schema violation names the field, the rule and the schema rule path instead of printing the whole schema.
- When an analysis job stops after rejected results, the message names the Analyzer check that rejected each result and the correction that followed, so the cause can be traced from the message alone.
- A Claude model call whose answers keep failing the output schema now stops after three attempts and runs once more, instead of using up its spending limit and stopping the assessment.
- A stopped assessment now names the host's actual limit or error, such as a model call's spending limit, instead of `transport; check the selected host`.
- Every program file and server-side template now belongs to a component, so the survey also covers code that discovery did not read. Before, only files that discovery's model had read belonged to a component, unless Analyzer recognized the framework's routes. Most of the code of PHP, Go, Ruby, ASP.NET MVC, Razor Pages and Java servlet applications went unanalysed, as did the services and data access of recognized applications. A Spring application in the default `com.example` package was not recognized as an application at all. Assessments now send more code to the survey model, so they cost more and take longer. Code that still belongs to no component is counted in the final summary without `--verbose`.
- An assessment no longer stops with `KeyError: 'jobs'` after verification when a component had no verification item to check.
- A report with exactly one Critical finding is published again. Its attack walkthroughs linked to Critical Findings by Root Cause, a section that appears only with two or more Critical findings, and the quality check stopped the report.
- When report composition stops at a quality check, the message names the failed checks and their issues instead of the check's raw JSON output.
- An unexpected internal error now ends a command with a short message instead of a Python traceback. The message names the error and the line in Analyzer's code where it happened; `assess` keeps its finished steps, and once an update fixes the error, `--resume` continues the run. `.run-issues.json` records the same details. With `APPSEC_PLUGIN_DEV=1`, the traceback follows the message.
- With API profiles (OpenAI, Bedrock, LiteLLM), a failed model call no longer uses up its whole call allowance. A request the provider refuses, including a rate limit, costs nothing and is repeated as intended; a rejected answer counts the tokens it used; any other failure counts at most the request's worst case. When too little budget is left for a call, Analyzer sends nothing and asks for a higher limit or keeps the finished work in an incomplete result, and the report keeps a reserve for one worst-case call.
- The warning about repeated model calls names what the failed attempts cost, and the verification aspects' costs add up to the step's cost. A Claude CLI result that reports no cost for used tokens counts as unknown cost instead of free.
- Reports of applications whose sign-in runs through an SSO or identity provider now show the people who use the browser client as a legitimate role, instead of showing attackers only.
- OAuth and OIDC client registration endpoints such as `/connect/register` no longer count as open user self-registration, which had grouped authenticated users with anonymous attackers.
- A `GET` login route that redirects to an SSO or identity provider, and the `POST` callback of a SAML or OIDC sign-in, no longer count as password authentication, so reports no longer list User Registration and Password Reset as missing controls for such applications. An unrelated control whose name contains "reset" no longer hides a missing password reset.
- Mitigations for exposed ports, storage or namespaces (CWE-668) and for untrusted build components (CWE-1357) get titles that describe their fix, instead of "Scope real-time events to authorized recipients" and "Set least-privilege CI workflow permissions".
- Shared workspace packages of a monorepo that an API or client imports (`@acme/shared`), also transitively, now belong to that component and are analysed.
- Discovery gets one correction for a client application or API it left out; if the model still omits it, the assessment models the component from the code itself instead of stopping.
- A MongoDB, PostgreSQL, MySQL or Redis database that application code connects to now appears as a data component with the connection to it, also in monorepos, even when the discovery model left it out. Before, the data layer and its flows depended on that model.
- An API component now comprises its whole package (route files, services, configuration) instead of only the files the discovery model happened to read. Before, the rest stayed unowned and no analysis step examined it, so sign-in code, routers and the data flows they implement could be missing from the report.
- TypeScript imports written with a `.js` extension (ESM/NodeNext style) now resolve to their `.ts` source, so mounted routers, their guards and handler code are found in such projects.
- An assessment no longer stops in discovery when the model models a client application but leaves out its entry file; the one client component below the app's folder carries it and receives the entry file.
- Express and Koa routers mounted with `use`, from the same file or imported from another one, now appear in the route inventory with their full path and take the authentication of a guard at the mount. Client requests to such routes become data flows with their authentication instead of `?`, and these routes no longer read as unauthenticated.
- A handler that checks an express-session session (`req.session`) now shows cookie authentication instead of `other`.
- SSO verification now starts on applications that sign in with the functional `openid-client` 6 API (`discovery`, `buildAuthorizationUrl`, `authorizationCodeGrant`); before, it ended as undecidable without a verification job.
- Protection-mechanism findings (CWE-693), such as a weak CSP or an architecture finding without its own CWE, no longer appear as an outdated dependency in the weakness register.
- A weakness whose CWE several mechanisms share takes the narrative of the one the finding describes, so an OIDC callback state gap no longer reads as a cookie CSRF weakness.
- Input-validation design weaknesses no longer cite whitespace `.trim()` calls as deny-list validation.
- A scanner rule finding at a location where verification evidenced a control now shows "Contradicted by verification", as a survey finding already did. The report card also shows this note for findings that several methods found; before, it was missing there.
- An abuse case no longer takes a documentation file, such as a Markdown file outside `docs/`, as source evidence for a step.
- The abuse case for exposed secret material binds its first step to a key that signs the application's tokens, when one is reported, instead of an unrelated secret with the same weakness type.
- A run stopped by an exhausted Claude usage allowance says so and names the reset time. It no longer reports a rate limit or advises a lower `--max-parallel`, which does not shorten that wait.
- Hardcoded secrets, including keys passed as arguments, are masked in all report outputs; the secret gate fails if one remains.
- Threat Analyst honors organization Opus bans.
- Authentication checks follow more JavaScript middleware and imported handlers; ownership controls count only when they protect every recognized handler registration.
- Abuse-case verification excludes unrelated findings, distinguishes confirmed and unresolved results, and rejects invalid case files without dropping valid ones.
- Trust-boundary detection covers varied layouts, separate deployments, build channels, and outbound calls, including request-chosen URLs.
- Source analysis excludes archived reports as code evidence, avoids false wildcard-CORS findings without credentials, and detects OAuth implicit-flow tokens read from `location.hash`.
- Reports handle empty registers and repair or stop on broken links. STRIDE mappings follow weakness classes, and the Figure 1 legend no longer claims per-element STRIDE coverage.
- AI / LLM Exposure lists verification findings under the OWASP LLM categories of their verification items and no longer files a user role set from the request body under prompt injection.
- Verification no longer asks the model to correct a finding anchored at a route registered in another component's file; it may anchor there, and the instructions tell it to cite data models and guards as the trace.
- An assessment no longer stops after the merge with "Merged finding anchor is outside its component ownership" when verification anchored a finding at a route registered in another component's file. The model build and check accept such an anchor in a repository of the finding's component.
- The remaining time (LEFT) of a resumed assessment, or one that takes over an earlier run's results, no longer drops below a minute while work is still ahead. Steps taken over from the earlier run no longer count toward the measured speed.

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
