# Script layout

The engine groups modules by responsibility. Users start it through `appsec-analyzer`; direct script commands are for maintainers or internal use. The `appsec_analyzer/` package owns application workflows and locates engine resources in the checkout or installed wheel.

| Directory | Responsibility |
|---|---|
| `orchestrator/` | Runs pipeline phases, checks job admission, dispatches batches, and waits for results. |
| `analyzers/` | Repository discovery, scanners and architecture checks. |
| `contexts/` | Selects and prepares size-limited context for analysis roles. |
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

The [architecture overview](../ARCHITECTURE.md) describes the score, focused-analysis, and assessment modules, their shared services, dependency direction, compatibility adapters, and verification. Keep module ownership there and engine-domain descriptions in this script layout.
