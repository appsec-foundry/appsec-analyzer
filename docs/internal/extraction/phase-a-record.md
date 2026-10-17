# Phase A extraction record

Status: in progress, 2026-10-17. Phase B is outside this assignment. All
implementation, tests, documentation, and commits belong to this repository;
`appsec-advisor` is a read-only source. No push or publication is authorized.

## Frozen source and history

- Source: `https://github.com/appsec-foundry/appsec-advisor`, development branch
  commit `d21eaac102cea6b8878ba0837e40c7a8fd47358d`. Its checkout contained
  five unrelated uncommitted file changes; none entered the clone or import.
- Destination before import: unborn `main`, no tracked or untracked project
  work. The destination remote advertised no branch heads when checked. The
  filtered history was imported to local `dev` without touching `main`.
- Source lineage: 2,353 commits. Filtered lineage: 1,980 commits; 373 commits
  touched only excluded paths and disappeared. Filtered tip:
  `ca16392f389eb55a84cfcb0b680bf5c6adf61e49`.
- Full original-to-filtered [commit map](commit-map.txt), [ref map](ref-map.txt),
  and [selected current and historical paths](filter-paths.txt). The 1,693
  selected paths include 380 historical-only names. `git filter-repo` does not
  follow renames automatically, so those names were added from Git rename
  records before filtering.
- Tool: upstream `newren/git-filter-repo` 2.47.0, installed from the PyPI
  distribution with that version and homepage; local executable
  `/home/mrohr/.local/bin/git-filter-repo` reported version `a40bce548d2c`.
  The upstream [release](https://github.com/newren/git-filter-repo/releases/tag/v2.47.0)
  and [PyPI version](https://pypi.org/project/git-filter-repo/2.47.0/) were
  checked before filtering. Filter command, run **only** in a disposable full
  clone of the frozen source bundle: `git filter-repo --force --refs refs/heads/dev --paths-from-file
  /tmp/appsec-analyzer-filter-paths.txt`.
- A complete source `dev` bundle was verified at
  `/tmp/appsec-analyzer-source-backup-20261017.bundle`. This is a local recovery
  copy, not a release artifact.

Filtering changes commit hashes and removes signatures from rewritten commits.
The source's nine Advisor release tags were not imported as Analyzer tags.
Authorship, author dates, committer names and dates, and commit messages were
preserved for sampled historical commits: the earlier
`docs/threat-modeler.md` to `docs/security-assessment.md` transition, the
root-to-`scripts/analyzers/` scanner move, the earlier `plugin/scripts/` path,
and the assessment launcher. Use the original source repository to inspect
original signatures.

## Selection and consumers

The path list is the exact filter input. These groups explain ownership and
the planned current-tree treatment. A selected historical file may contain
legacy code; cleaning its present form does not erase its earlier evolution.

| Source area | Treatment | Reason and consumer |
| --- | --- | --- |
| `scripts/{orchestrator,runtime,contexts,analyzers,model,shared,validators,renderers,exporters,repairs,requirements}/` and historic root or `plugin/scripts/` predecessors | Import and adapt | Controller, source admission, scanner findings, source grants, semantic jobs, validation, budget, status, cancellation, rendering, exports, and requirements audit consume these paths. Mixed runtime modules require consumer-level cleanup. |
| `agents/`, selected `skills/`, `schemas/`, `data/`, `templates/`, `types/`, `scripts/assets/` | Import and adapt | The controller reads semantic role instructions and schemas; deterministic scanners use catalogs; renderers and supported consumers use templates, style, and data. Keep role descriptions distinct from executable model tools. |
| `tests/` selected paths and fixtures, `scripts/threat_fixture.py`, development metadata | Import and adapt | Preserve affected scanner, controller, contract, status, and consumer regressions; retarget wrapper tests to the public CLI. |
| `README.md`, `CONTRIBUTING.md`, `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, selected user guides, technical contracts, runbooks, plan, and provider/product concepts | Import and adapt | Explain actual behavior, operating limits, provenance, and migration. Concepts remain historical until implemented and qualified. |
| `scripts/baseline/`, `data/baselines/`, baseline lifecycle skills, `.claude-plugin/`, `.github/`, `hooks/`, `scripts/package_internal_plugin.py` | Exclude at import | Independent baseline installation, Claude plugin hosting, CI publication, and marketplace assembly are Advisor responsibilities. Any security check still required by a direct CLI call must be retained or moved before deleting a mixed implementation. |
| Plugin-only help, marketplace, installation, and retired publish/update skills | Exclude at import | They have no supported standalone Analyzer consumer. The current `appsec-analyzer` entry skill is retained and must be rewritten as a thin CLI entry. |
| Mixed plugin status, metadata, configuration, wrappers, and older tests | Investigate then remove or adapt | Direct imports are insufficient to decide liveness. Search runtime calls, dynamic loading, subprocesses, skills, tests, and documented interfaces first. |

`docs/security-assessment.md` describes the complete assessment. The distinct
`docs/threat-analyst.md` describes focused threat analysis. The former's
historical path was `docs/threat-modeler.md`; no current
`docs/threat-analyzer.md` exists. Both histories are selected.

### Assessment launcher inventory

`scripts/run-headless.sh` currently dispatches one or several `--repo` inputs
to the controller for a full assessment, with resume, rebuild, budget, depth,
source trust, progress, and export options. A separate `--audit-requirements`
path invokes the requirements audit skill through Claude; it is not a full
assessment. Its callers include the Analyzer skill, README and headless guide,
Makefile spot checks, fixture wrappers, `live_canary.py`, remote repository
provisioning, and launcher/consumer tests. Some Advisor-only CI dispatch and
plugin packaging callers remain in the source and are not imported. The target
CLI will replace the launcher in this repository only: `scan`, `assess`, and a
distinct documented requirements-audit entry, plus versioned status, stop,
results, and export operations. A deterministic scan must never report full
assessment completion.

## Verification and open items

- Every selected current source-tip blob matched the filtered tip: 1,313 files,
  no missing, extra, or differing blobs. Sampled renamed commits retained
  their author, committer, dates, and messages. The filter's full commit map
  records all changed hashes and pruned commits.
- A redacted pattern scan traversed 12,881 reachable blobs. It found 555
  pattern matches, concentrated in secret-detection code, example prose, and
  synthetic tests; no candidate was an independently stored credential file.
  A `.env` fixture exists under `tests/fixtures/e2e/ci-pipeline/` and must be
  reviewed before packaging. No matched secret value was printed. This is a
  scoped pattern review, not a guarantee that all sensitive data is absent.
- A historical PDF example is a Git LFS pointer whose server object was not
  available during checkout. The branch was checked out with LFS smudging
  skipped. The current PDF pointer and its user-guide link were removed after
  checking their only retained consumer; the Markdown and JSON examples remain.
  The PDF pointer remains part of selected historical commits.
- `types/progress.d.ts` was removed from the current tree after a reference
  search found no runtime, type-check, build, or documented consumer. Its
  historical predecessor remains in the filter selection.
- Provider access, concrete model/depth qualification, gateway route evidence,
  and paid-run budget are not supplied. The operator requested offline work;
  no paid provider calls are permitted. Provider support must remain marked
  unqualified until complete authorized live assessments establish it.
- A versioned public CLI now has deterministic `scan`, Claude-compatible
  `assess`, `status`, `progress`, `stop`, `results`, and a focused `analyst`
  delegation. `scan` does not read provider credentials. API transports have
  offline wire, budget, destination, and failure tests but no approved public
  model profile. A distinct bounded requirements-audit controller replaces
  the old plugin-skill audit for local catalogs; the historical remote catalog
  and resume modes remain unimplemented. The temporary shell file in this
  repository only delegates to `appsec-analyzer assess`.
- Default assessment and analyst state paths now use `appsec-analyzer`. The
  old Advisor data directory is not silently reused; historical data import
  behavior still needs installed-artifact verification.
- A first path list omitted the focused-analysis and reviewer CLI programs and
  several fixture-development drivers. A new filter run from the frozen source
  bundle added their historical paths. The first local import and its two
  follow-up commits remain on `import-v1`; their changes were cherry-picked
  onto the corrected `dev` history. The source checkout's `dev` branch advanced
  externally during this work; that later commit was not imported.
- A complete offline controller replay exposed one more omitted historical
  path, `scripts/auto_emitter_pass.sh`. A separate full bare clone of the same
  frozen bundle was filtered for that path alone, with `git-filter-repo` 2.47.0
  in `/tmp/appsec-analyzer-emitter-bare-20261017.git`. Its 11 retained source
  commits were merged without squash as the second parent of local merge
  `03a3e9c4`. The original source-tip blob hash and imported blob hash both
  equal `14f08a26c59333bd1d07f09185e6501449ddbaaf`. The
  [supplemental commit map](emitter-commit-map.txt) and
  [ref map](emitter-ref-map.txt) identify rewritten and pruned commits. No
  Advisor release tag was added. The old shell current-tree file was then
  removed because the same ordered deterministic pass now runs through the
  controller's engine-owned Python script dispatcher; its history remains.
- The first complete fake-Claude CLI assessment stopped at the missing
  enrichment receipt, proving publication stayed blocked. After moving the
  ordered pass, single- and two-repository fake-host assessments completed and
  published schema-valid assessment models. Existing tests that expected old
  `threat-model.*` names were updated to `security-assessment.*`. The
  `test_auto_emitter_pass.py` regression now checks the active Python path,
  including order, fail-closed receipt, refuted findings, and idempotence.
- Local wheel and sdist smoke builds succeeded outside the source trees. The
  second build has 585 wheel entries and 687 sdist entries. Inventory checks
  found neither the temporary `run-headless.sh`, old plugin metadata/gates,
  reviewer launcher, nor test runner in either artifact. The isolated wheel
  installed after downloading declared dependencies. Its `scan` succeeded with
  all model credentials unset and Claude pointed to a nonexistent executable;
  installed status/progress/results operations read a valid local fixture.
  `stop` correctly rejected a completed fixture. A complete installed-wheel
  assessment remains to be tested with an offline fake host.
- The plugin-only `appsec-reviewer-cli` shell launcher and its direct tests
  were removed from the current tree after confirming they depended on the
  excluded `verify-requirements` plugin skill and broad host tools. This is
  distinct from the focused Threat Analyst and independent Requirements Audit.
  Plugin metadata and read/write hooks have no Analyzer runtime consumer and
  were removed; direct CLI source and output boundaries have their own tests.
- A standalone `audit-requirements` entry now handles one local validated
  catalog and one admitted checkout. It uses bounded model-directed reads,
  accepts conclusive verdicts only with citations to served source lines,
  applies the existing deterministic summary and gate, and publishes its
  versioned result only after schema and source-state checks. It cannot resume
  an interrupted audit or fetch Advisor's remote catalog sources. A fresh
  output directory avoids mistaking an earlier verdict for the current run.
  Its Markdown output escapes model-authored text. Offline fake-host tests
  cover the successful gate and missing-evidence, invalid-source, stale-output,
  and invalid-model failures; no live audit was charged or qualified.
- The active deterministic scanners now choose packaged data independently of
  `CLAUDE_PLUGIN_ROOT`. Affected scanner regression tests found three tests
  that asserted the retired plugin override; they now assert the bundled-data
  behavior. A fourth test expected an older controller function and was
  aligned with the current deterministic render stage without reducing its
  scanner-wiring check.

## Milestones

| Milestone | State | Evidence and next step |
| --- | --- | --- |
| A1–A2 inventory and history | Imported, verification ongoing | Primary and supplemental filtered lineages, maps, blob comparison, historical samples above; finish scoped secret triage and current-tree exclusions. |
| A3–A5 provider boundary | Offline adapter in progress | Responses/gateway transport and negative offline tests exist; qualification, complete pipeline replay, and public API routing remain open. |
| A6 standalone CLI and package | In progress | Scan and assessment CLI, state operations, private state paths, focused analyst delegation, independent bounded requirements audit, and wheel smoke checks exist; some launcher development consumers, installed assessment, and resume checks remain open. |
| A7 local release preparation | Open | Build and inspect wheel and sdist; record unresolved qualification and compatibility limits. No source-repository correction, push, or publication. |
