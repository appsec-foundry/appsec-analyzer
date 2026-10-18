# Script layout

Runtime modules are grouped by responsibility. The supported user entry is `appsec-analyzer`; direct script commands are internal or maintainer interfaces. The public package in `appsec_analyzer/` owns the application workflows and selects engine resources from the checkout or installed wheel.

| Directory | Responsibility |
|---|---|
| `orchestrator/` | Pipeline transitions, dispatch admission, waves and waiters. |
| `analyzers/` | Repository discovery, scanners and architecture checks. |
| `contexts/` | Bounded context construction and projection for analysis. |
| `model/` | Canonical model construction, enrichment, ranking and queries. |
| `renderers/` | Report composition, diagrams, fragments and console summaries. |
| `exporters/` | HTML, PDF, SARIF and Threat Dragon output. |
| `validators/` | Artifact validation, QA and publication gates. |
| `repairs/` | Contracted repairs and preservation of authored sections. |
| `runtime/` | Configuration, source admission, model hosts, lifecycle, telemetry, and cleanup; also retained hook-era helpers. |
| `requirements/` | Requirements retrieval, state, assessment and traceability. |
| `shared/` | Cross-domain parsing, paths, atomic IO and policy helpers. |

Run an internal command by its full path, for example `python3 scripts/orchestrator/orchestration_controller.py --help`. Direct entry points add the engine's `scripts/` directory to the import path. Imports use qualified domain names, for example `from shared._atomic_io import atomic_write_text`.

The Advisor baseline package, plugin metadata, and hook registration were excluded from the extraction. Some retained helpers still refer to them and are not usable standalone; see the [legacy review](../docs/internal/analysis/repository-review-2026-10-17.md). Existing schema identifiers and migration helpers may intentionally retain Advisor or threat-model names.

When moving a module, check imports, dynamic dispatch, subprocess paths, prompts, schemas, packaging, requirement bindings, and affected tests together. `scripts/run_tests.py` contains an inherited routing catalog with known stale references; it is not a complete current dependency graph. `setup.py` and `MANIFEST.in` select packaged resources and exclude some legacy files; they do not copy every checkout file.

## Application modules

`appsec_analyzer/score/` owns deterministic scoring: `service.py` coordinates admitted sources and validated scanner signals, `collection.py` selects the score scanners, `calculation.py` computes results from a loaded `ScoringPolicy`, and `render.py` and `progress.py` present them. Progress uses structured events; legacy text callbacks remain accepted by the presentation adapter.

`appsec_analyzer/analyze_threats/` separates the terminal adapter in `cli.py` from scope and document preparation in `preparation.py`. The analyst controller owns job state and exposes `waiting_job`, `run`, `answer`, and `cancel`; the terminal adapter does not read checkpoint files. Analyst jobs retain their separate lifecycle and state directory.

`appsec_analyzer/assessment/` owns the structured `AssessmentRequest` and the assessment console. The public CLI passes validated options directly to the retained controller; direct script callers can still use argument lists. The existing configuration resolver continues to receive its configuration arguments.

Shared application modules own artifact reads and exclusive publication (`artifacts.py`), requirements catalog admission (`catalogs.py`), terminal fields (`terminal.py`), export targets (`targets.py`), and scanner execution and validation (`scanners/execution.py`). Scanner selection, order, applicability, and failure policy stay with each workflow. Repository preflight is shared through `runtime/source_preflight.py`; configuration-surface detection belongs to `analyzers/iac_surface.py`.

The dependency direction is command adapter to application workflow to shared services. Shared services must not import the public CLI or an application controller. The previous `scoring.py`, `score_progress.py`, and `threat_analysis.py` module paths are compatibility imports; the retained score script still supports its direct command and original output presentation.

`appsec_analyzer/engine.py` owns the compatibility bootstrap for retained engine domain imports. The retained script directories and their relative resources remain in place; moving them requires coordinated changes to subprocess dispatch, resource lookup, packaging, prompts, and tests. New application Python files participate in assessment runtime fingerprints in both checkouts and installed wheels. A changed implementation invalidates earlier resume identities rather than silently reusing them.
