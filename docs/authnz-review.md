# Authentication and authorization review

`appsec-analyzer authnz-review` reviews one local Git checkout without requiring a previous assessment. It inventories routes, scans authentication checks, confirms supported authorization patterns statically, and asks a specialized model to reason over those signals. It does not execute the application, make requests to a pentest target, or update an existing assessment.

## Prerequisites and data use

Install and authenticate Claude CLI as described in [configuration](configuration.md). This focused command currently supports only `claude-cli`, independently of full-assessment provider profiles and organization presets. It defaults to model `sonnet` and a USD 5 maximum; use `--model MODEL` and `--budget USD` to select another model or budget. The budget must be finite and at least USD 0.05. Authorize spending before starting a model-backed review.

The command sends masked scanner evidence, route metadata, and any explicitly selected requirements catalog to Claude CLI. Source files are scanned from a bounded, private snapshot; repository instructions, hooks and tools are not loaded by the model. A model receives no tools or direct repository access. The host uses the existing bounded exchange and budget accounting. Each scanner has a 120-second timeout; reasoning has a 600-second limit and at most six exchanges, including bounded corrections. Budget exhaustion can stop it earlier. Live quality and host isolation remain unqualified; offline tests establish pipeline behavior only.

## Run a review

Run from a local Git checkout, or select it explicitly:

```sh
appsec-analyzer authnz-review --repo /path/to/project --budget 5
appsec-analyzer authnz-review --repo /path/to/project --budget 5 --json
appsec-analyzer authnz-review --repo /path/to/project --budget 5 --yaml
```

Replace `/path/to/project` with the local checkout. Progress and the budget/data-use notice go to stderr. Stdout contains Markdown-style text by default; the mutually exclusive `--json` and `--yaml` flags print the same versioned result without terminal styling. Console-only reviews leave no persistent result files. Git URLs, multiple repositories, imported threat models, organization output defaults and resumable lifecycle commands are not supported by this focused entry.

Add `--requirements /path/to/catalog.yaml` to annotate findings with references from an explicitly selected local requirements catalog. The catalog uses the same `categories[].requirements[]` format as the [requirements audit](security-requirements-audit-skill.md). References must resolve to that catalog. No catalog is auto-detected and annotation is not a requirements audit or compliance certification.

Use `--save` to retain results under a fresh `authnz-reviews/review-*` subdirectory of the application's private assessment directory. `--output DIR` selects an existing, empty directory outside the checkout, owned by the current user with mode 0700. Concurrent claims, links and occupied destinations are rejected before model calls. Each saved file is private and is never written over another file.

```sh
mkdir -m 700 /private/authnz-review
appsec-analyzer authnz-review --repo /path/to/project --budget 5 --output /private/authnz-review
```

Replace `/private/authnz-review` with a fresh destination whose parent exists. Saving defaults to `authnz-review.md`, `authnz-review.json` and `authnz-review.yaml`. `--outputs markdown json yaml pentest-tasks` selects saved formats and implies saving even without `--save`. The hidden `.authnz-report.json` and `.route-inventory.json` files retain validated inputs for later pentest export. The public JSON and YAML share `interface_version: 1`, `kind: authnz-review`, source provenance, completion and gate status, limits, and the canonical report under `report`.

## Export the legacy pentest plan

The command reuses the pentest endpoint catalog and test plan from the former `create-threat-model` skill. Tasks contain finding references, objectives, test strategies, negative controls, required accounts, evidence requirements, success criteria and stop conditions. They retain AuthNZ evidence status, source locations and requirement references. They describe planned checks and do not authorize or execute a penetration test.

```sh
appsec-analyzer authnz-review --repo /path/to/project --budget 5 --save \
  --pentest-tasks --pentest-format generic --pentest-output-format both \
  --pentest-target https://staging.example.com
```

`--pentest-format generic|strix` selects the existing plan dialect. `--pentest-output-format yaml|json|both` selects serialization, defaulting to YAML. Files are named `pentest-tasks-authnz.yaml` and/or `pentest-tasks-authnz.json`. `--pentest-tasks` implies saving; `--outputs pentest-tasks` also enables it. The target URL is metadata only and must use HTTP(S) without embedded credentials. Every task retains the read-only safety block; the tool executing a later test must enforce its own scope and authorization.

Only findings on `data/pentest-eligible-cwes.yaml` with file and line evidence become tasks. The existing allowlist excludes some AuthNZ classes, including CWE-345 and CWE-640. The structured result names omitted finding IDs under `pentest_export`; their findings remain in the report. This focused path does not generate the architecture and baseline probes of a full threat-model export, or its Markdown Attack Walkthroughs section. The Strix dialect is a local compatibility shape, not a claim of current external integration qualification.

With a source checkout, re-export a saved report without new model calls:

```sh
python3 scripts/renderers/render_pentest_tasks.py \
  --authnz /private/authnz-review/.authnz-report.json \
  --route-inventory /private/authnz-review/.route-inventory.json \
  --output /private/authnz-review/reexport.json --output-format json --dialect generic
```

Run this command from the Analyzer source checkout with its runtime dependencies available. Choose a new output filename in the private result directory. This retained helper writes the selected destination directly and does not apply the focused runner's empty-directory admission. It accepts the saved canonical report, not the public envelope in `authnz-review.json`.

## Completion and recovery

Exit 0 means a completed advisory review, or a passing explicitly selected gate. `--gate` returns 1 for Critical/High findings. Incomplete results return 2 even without a gate; invalid inputs, scanner or host failures, exhausted budget, rejected model output and export failures also return 2. Ctrl+C returns 130. A partial or interrupted review is never reported as clean. Operational failures publish no new model result; a storage failure can leave already validated files, so select a fresh destination when retrying. This command does not resume interrupted work.

Findings retain `scanner`, `confirmed-instance` or `hypothesis` as their evidence status. Confirmation here is static scanner confirmation, not demonstrated runtime exploitability. Unknown authentication does not prove missing authentication, and absence of findings does not establish safety. Model reasoning is limited to extracted signals; unsupported frameworks, unresolved handlers and upstream controls can remain unknown.
