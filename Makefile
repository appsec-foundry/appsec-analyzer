# Makefile — minimal entry points for maintainer workflows.
# This is development tooling; the package is built through Python packaging.
#
# Run `make help` for an overview.

.DEFAULT_GOAL := help

# Use .venv if present, otherwise fall back to system python3
PYTHON ?= $(if $(wildcard .venv/bin/python3),.venv/bin/python3,python3)

# Absolute path to this Makefile's directory, stable even
# when make is invoked from a different working directory.
PLUGIN_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# ─────────────────────────────────────────────────────────────────────────────
# Manual E2E full-run
#
# Triggered ONLY manually — after a non-trivial refactor or before a release.
# Never wired into PR / push / cron hooks. See README "Manual full-run check".
#
# An explicit BUDGET is required. These targets are never part of offline gates.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: e2e-full
e2e-full:  ## Run the full E2E pipeline + assertions against the synthetic-repo fixture
	@test -n "$(BUDGET)" || { echo "ERROR: set BUDGET=<USD> for this live run"; exit 2; }
	@./tests/e2e/run-full.sh --depth quick --budget "$(BUDGET)"

.PHONY: e2e-full-standard
e2e-full-standard:  ## Standard depth with Stage-3 QA enabled (slower, higher fidelity)
	@test -n "$(BUDGET)" || { echo "ERROR: set BUDGET=<USD> for this live run"; exit 2; }
	@./tests/e2e/run-full.sh --depth standard --budget "$(BUDGET)"

.PHONY: e2e-full-thorough
e2e-full-thorough:  ## Thorough depth with Stage-3 QA and Stage-4 architect review
	@test -n "$(BUDGET)" || { echo "ERROR: set BUDGET=<USD> for this live run"; exit 2; }
	@./tests/e2e/run-full.sh --depth thorough --budget "$(BUDGET)"

.PHONY: e2e-fixture-suite
e2e-fixture-suite:  ## Run all six external language/architecture fixtures and their recall oracles
	@./tests/e2e/run-fixture-suite.sh

.PHONY: ci-triage
ci-triage:  ## Fetch a dispatched run's artifacts (fixture E2E or threat model) and summarise failures: make ci-triage RUN_ID=<id> [INTO=.appsec-ci]
	@test -n "$(RUN_ID)" || { echo "ERROR: set RUN_ID=<github run id>. List runs with: gh run list --workflow fixture-e2e-dispatch.yml -L 10"; exit 2; }
	@./scripts/ci_triage.sh --run-id "$(RUN_ID)" --into "$(or $(INTO),.appsec-ci)"

.PHONY: analyze-verify
analyze-verify:  ## Manual live assessment: make analyze-verify REPO=<path> BUDGET=<USD> [DEPTH=quick|standard|thorough]
	@test -n "$(REPO)" || { echo "ERROR: set REPO=<path to repo to verify>, e.g. make analyze-verify REPO=/home/mrohr/juice-shop"; exit 2; }
	@test -n "$(BUDGET)" || { echo "ERROR: set BUDGET=<USD> for this live run"; exit 2; }
	@./tests/e2e/run-full.sh --repo "$(REPO)" --depth "$(or $(DEPTH),quick)" --budget "$(BUDGET)"

# ─────────────────────────────────────────────────────────────────────────────
# Test groups and full-suite gates (no LLM)
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: test-analyzer
test-analyzer:  ## Current standalone CLI, audit, provider, state, and completion contracts (offline)
	@PYTHONPATH="$(CURDIR):$(CURDIR)/scripts" $(PYTHON) -m pytest -q \
		tests/test_public_scan_cli.py \
		tests/test_public_export_cli.py \
		tests/test_module_boundaries.py \
		tests/test_public_score_cli.py \
		tests/test_score_summary.py \
		tests/test_security_score.py \
		tests/test_public_assessment_operations.py \
		tests/test_requirements_audit_cli.py \
		tests/test_authnz_review_cli.py \
		tests/test_threat_analysis_cli.py \
		tests/test_analyst_documents.py \
		tests/test_review_sources.py \
		tests/test_analyst_isolation.py \
		tests/test_api_hosts.py \
		tests/test_startup_preflight.py \
		tests/test_remote_repositories.py::test_preflight_reads_remote_head_without_checkout \
		tests/test_remote_repositories.py::test_preflight_git_failure_is_safe \
		tests/test_remote_repositories.py::test_preflight_rejects_empty_repository \
		tests/test_remote_repositories.py::test_preflight_timeout_stops_child_group \
		tests/test_remote_repositories.py::test_preflight_dns_denial_prevents_git_connection \
		tests/test_codex_cli.py \
		tests/test_profiles.py \
		tests/test_provider_backends.py \
		tests/test_auto_emitter_pass.py \
		tests/test_full_run_e2e_driver.py \
		tests/test_render_completion_summary.py::TestNextSteps \
		tests/test_render_completion_summary.py::TestExportDeliverablesBackstop

.PHONY: check-specs
check-specs:  ## Validate requirements and changes: make check-specs BASE=<base-commit>
	@$(PYTHON) scripts/check_specs.py --changed-against '$(subst ','"'"',$(BASE))'

.PHONY: check-analyzer
check-analyzer: check-specs  ## Standalone offline gate: make check-analyzer BASE=<base-commit>
	@ruff check appsec_analyzer scripts tests setup.py
	@$(MAKE) --no-print-directory test-analyzer
	@PYTHONPATH="$(CURDIR):$(CURDIR)/scripts" $(PYTHON) -m pytest -q \
		tests/test_check_specs.py \
		tests/test_requirements_report.py \
		tests/test_context_routing.py \
		tests/test_runtime_doc_cli_contract.py \
		tests/test_active_stride_policy.py \
		tests/test_analyzer_distribution.py

.PHONY: release-check-analyzer
release-check-analyzer: check-analyzer  ## Offline distribution/controller gate: BASE=<base-commit> required
	@$(MAKE) --no-print-directory test-controller

.PHONY: test
test:  ## Run the standard pytest suite with coverage (no LLM)
	@$(PYTHON) scripts/run_tests.py all -v --tb=short --cov=scripts --cov-report=term-missing; \
		status=$$?; rm -rf .coverage-data; exit $$status

.PHONY: coverage
coverage:  ## Run the suite + write an HTML coverage report to htmlcov/index.html
	@$(PYTHON) scripts/run_tests.py all --tb=short --cov=scripts --cov-report=term-missing --cov-report=html; \
		status=$$?; rm -rf .coverage-data; exit $$status
	@echo "HTML report: htmlcov/index.html"

.PHONY: test-incremental
test-incremental:  ## Fast focused subset: incremental-scan reconciliation + 2-run main() E2E (no LLM)
	@$(PYTHON) scripts/run_tests.py incremental -q

.PHONY: test-controller
test-controller:  ## One offline controller run over a small web-application fixture: route inventory, client-to-API flows, architecture gate, abuse matching, publication (no LLM, ~80 s)
	@$(PYTHON) -m pytest tests/test_controller_fixture.py -q --tb=short

.PHONY: e2e-controller
e2e-controller:  ## Offline end-to-end runs through appsec-analyzer assess and a fake Claude CLI (no LLM)
	@$(PYTHON) -m pytest tests/test_controller_e2e.py -q --tb=short $$($(PYTHON) -c 'import xdist' 2>/dev/null && echo '-n auto')

.PHONY: e2e-controller-live
e2e-controller-live:  ## Live quick controller run with the real claude CLI (costs up to BUDGET USD, default 3): make e2e-controller-live [REPO=<path>] [DEPTH=quick] [BUDGET=3]
	@./tests/e2e/run-controller-live.sh $(if $(REPO),--repo "$(REPO)") --depth "$(or $(DEPTH),quick)" --budget "$(or $(BUDGET),3)"

.PHONY: test-full
test-full:  ## Run the complete pytest suite without coverage (no LLM)
	@$(PYTHON) scripts/run_tests.py all --tb=short

.PHONY: test-quick
test-quick:  ## Run shared base drift guards without coverage
	@$(PYTHON) scripts/run_tests.py quick -q

.PHONY: test-group
test-group:  ## Run a focused group: make test-group GROUP=<name> (see scripts/run_tests.py --help)
	@test -n "$(GROUP)" || { echo "ERROR: set GROUP=<test group>; see scripts/run_tests.py --help"; exit 2; }
	@$(PYTHON) scripts/run_tests.py "$(GROUP)" -q

.PHONY: test-changed
test-changed:  ## Run reviewed tests for branch and local changes: make test-changed BASE=origin/dev
	@$(PYTHON) scripts/run_tests.py --changed-against "$(or $(BASE),origin/dev)" all -q

.PHONY: test-for
test-for:  ## Run reviewed tests for this task's files only: make test-for FILES="scripts/a.py tests/test_a.py"
	@test -n "$(strip $(FILES))" || { echo "ERROR: set FILES=\"<changed files of this task>\""; exit 2; }
	@$(PYTHON) scripts/run_tests.py $(foreach f,$(FILES),--path "$(f)") all -q

.PHONY: test-plan
test-plan:  ## Explain changed-file selection without running pytest: make test-plan BASE=origin/dev
	@$(PYTHON) scripts/run_tests.py --list --changed-against "$(or $(BASE),origin/dev)"

.PHONY: audit-test-routes
audit-test-routes:  ## Verify source routes by measuring every test module under coverage (slow)
	@$(PYTHON) scripts/audit_test_routes.py

.PHONY: lint
lint:  ## Ruff check + format check
	@ruff check scripts/ tests/ hooks/
	@ruff format --check scripts/ tests/ hooks/

.PHONY: fix
fix:  ## Auto-repair the mechanical gate failures (ruff lint + format), then list what still needs a human
	@echo ">> ruff check --fix (safe lint fixes)"; ruff check --fix scripts/ tests/ hooks/ || true
	@echo ">> ruff format"; ruff format scripts/ tests/ hooks/
	@echo ""
	@echo "Auto-repair done. Stages 3-6 are NOT auto-fixable by design (fix the producer, not the symptom):"
	@echo "  - validators/validate_config.py        -> correct the offending config field"
	@echo "  - check_fragment_registry   -> align the registry maps (docs/internal/runbooks/adding-a-section.md)"
	@echo "  - check_target_specificity  -> make the rule generic, or move the target name into a comment"
	@echo "  - pytest / coverage         -> separate pre-existing from new failures; add tests, don't lower the floor"
	@echo "  - check_release_meta.py     -> reconcile pyproject version / git tag / CHANGELOG heading"
	@echo ""
	@echo "Re-run 'make check' (or 'make release-check') to see what remains."

# ─────────────────────────────────────────────────────────────────────────────
# Vendored content
#
# `baseline-sync` re-vendors data/baselines/ from the published baseline. It
# fetches over the network, so it is a maintainer command and never part of a
# gate: `check` and `release-check` stay deterministic and offline, and a
# release must not fail because a host is down.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: baseline-sync
baseline-sync:  ## Re-vendor data/baselines/ from the published baseline: make baseline-sync [DRY=1] [ACCEPT_ID=aisec-0.2]
	@$(PYTHON) scripts/baseline/sync_baseline.py \
		$(if $(DRY),--dry-run,) \
		$(if $(ACCEPT_ID),--accept-id "$(ACCEPT_ID)",)

# ─────────────────────────────────────────────────────────────────────────────
# Release gates
#
# `check`         — the continuous gate. Runs on every dev/main push & PR in CI.
#                   Must be green on EVERY commit (code health + drift guards).
# `release-check` — superset, for the release boundary only. Adds version/tag/
#                   changelog hygiene. Run it when PREPARING a release (version
#                   bumped + CHANGELOG entry written), not on routine dev commits.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: check
check:  ## Continuous gate: lint, format, config, drift, full test suite (no coverage)
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory validate
	@$(MAKE) --no-print-directory test-full

.PHONY: validate
validate:  ## Validate config, registry, target neutrality, and requirement bindings without pytest
	@$(PYTHON) scripts/validators/validate_config.py .
	@$(PYTHON) scripts/validators/check_fragment_registry.py
	@$(PYTHON) scripts/check_target_specificity.py
	@$(PYTHON) scripts/check_specs.py
	@$(PYTHON) scripts/run_tests.py --check-groups

.PHONY: release-check
release-check:  ## Release-boundary gate: `check` + version/tag/changelog consistency
	@mkdir -p .cache
	@bash scripts/run-interruptible.sh .cache/release-check.log \
		bash -c '$(MAKE) --no-print-directory check && python3 scripts/check_release_meta.py'

.PHONY: release-all
release-all:  ## Full pre-release sequence: release-check then a live e2e-full (quick)
	@$(MAKE) --no-print-directory release-check
	@$(MAKE) --no-print-directory e2e-full

# ─────────────────────────────────────────────────────────────────────────────
# Target-repo setup — write required Claude Code permissions into a target repo
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: setup-target
setup-target:  ## Write required CC permissions into a target repo (default: cwd): make setup-target [REPO=<path>] [OUTPUT=<path>] [SCOPE=local|project|user]
	@mkdir -p "$(or $(REPO),$(CURDIR))/.claude"
	@$(PYTHON) $(PLUGIN_ROOT)scripts/check_permissions.py \
		--repo-root "$(or $(REPO),$(CURDIR))" \
		$(if $(OUTPUT),--output-dir "$(OUTPUT)",) \
		--plugin-dir "$(PLUGIN_ROOT)" \
		--scope "$(or $(SCOPE),local)" \
		--update
	@echo "Restart Claude Code (or reload the session) for the new permissions to take effect."

# ─────────────────────────────────────────────────────────────────────────────
# Diagnostic bundle — anonymised user→maintainer error report
#
# Build a finding-free .tgz from a failed run's OUTPUT_DIR (versions, run shape,
# metadata-only inventory, scrubbed logs) and inspect one on the analysis side.
# Never contains threat-model results, evidence, or source. See CONTRIBUTING.md.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: diagnostic-bundle
diagnostic-bundle:  ## Build an anonymised diagnostic .tgz from a run: make diagnostic-bundle RUN=<repo>/docs/security [REPO_ROOT=<repo>] [INTO=.]
	@test -n "$(RUN)" || { echo "ERROR: set RUN=<run OUTPUT_DIR>, e.g. make diagnostic-bundle RUN=<repo>/docs/security"; exit 2; }
	@$(PYTHON) scripts/runtime/diagnostic_bundle.py collect --run "$(RUN)" --into "$(or $(INTO),.)" $(if $(REPO_ROOT),--repo-root "$(REPO_ROOT)",)

.PHONY: inspect-bundle
inspect-bundle:  ## Print a triage summary of a diagnostic bundle: make inspect-bundle BUNDLE=appsec-diag-<id>.tgz
	@test -n "$(BUNDLE)" || { echo "ERROR: set BUNDLE=<path to .tgz or unpacked dir>"; exit 2; }
	@$(PYTHON) scripts/runtime/diagnostic_bundle.py inspect --bundle "$(BUNDLE)"

# ─────────────────────────────────────────────────────────────────────────────
# Ad-hoc headless analysis against an arbitrary target repo
#
# Maintainer spot checks through the public Analyzer CLI.
# (e.g. juice-shop). Streams to the terminal AND a log file by default; set
# BG=1 to detach via nohup so this session is free to work in parallel.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: analyze
analyze:  ## Assessment against any repo: make analyze REPO=<path> [HARD_BUDGET=20] [BG=1] [EXTRA="--assessment-depth thorough"]
	@test -n "$(REPO)" || { echo "ERROR: set REPO=<path to repo to analyze>, e.g. make analyze REPO=/home/mrohr/juice-shop"; exit 2; }
	@log="$(or $(LOG),$(HOME)/appsec-$(notdir $(patsubst %/,%,$(REPO))).log)"; \
	cmd='appsec-analyzer assess --host claude-cli --hard-budget $(or $(HARD_BUDGET),20) --repo "$(REPO)" --max-duration $(or $(MAX_DURATION),9000) $(EXTRA)'; \
	if [ -n "$(BG)" ]; then \
		nohup sh -c "$$cmd" >"$$log" 2>&1 & \
		echo "▶ analyzing $(REPO) in background (PID $$!)"; \
		echo "  log:  $$log"; \
		echo "  tail: tail -f $$log"; \
	else \
		echo "▶ analyzing $(REPO) (log → $$log)"; \
		sh -c "$$cmd" 2>&1 | tee "$$log"; \
	fi

.PHONY: analyze-resume
analyze-resume:  ## Resume an interrupted analyze from its checkpoint — reuses .stride-*.json (no re-scan). Refuses if a run still holds the lock; kill it first, then: make analyze-resume REPO=<path> [BG=1] [LOG=<file>]
	@test -n "$(REPO)" || { echo "ERROR: set REPO=<path to repo to resume>, e.g. make analyze-resume REPO=/home/mrohr/juice-shop"; exit 2; }
	@$(MAKE) --no-print-directory analyze REPO="$(REPO)" BG="$(BG)" LOG="$(LOG)" MAX_DURATION="$(MAX_DURATION)" EXTRA="--resume $(EXTRA)"

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
