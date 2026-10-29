# Authentication and authorization review

`appsec-analyzer authnz-review` checks authentication and authorization in one local Git checkout. It needs no previous assessment. Scanners identify routes, login checks, and supported permission checks. A specialized model reviews those results. The command does not run the application, send requests to a pentest target, or change an existing assessment.

## Prerequisites and data use

Install and authenticate Claude CLI as described in [configuration](configuration.md). This focused command currently supports only `claude-cli`, independently of full-assessment provider profiles and organization presets. It defaults to model `sonnet` and a USD 5 maximum; use `--model MODEL` and `--budget USD` to select another model or budget. The budget must be finite and at least USD 0.05. Authorize spending before starting a model-backed review.

The command sends masked scanner evidence, route information, and any explicitly selected requirements catalog to Claude CLI. Scanners read a private source copy with size limits. The model receives no tools or direct repository access, and loads no repository instructions or hooks.

Each scanner has a 120-second timeout. The model step has a 600-second limit and at most six exchanges, including corrections. The budget can stop it earlier. Live quality and host isolation have not been verified.

## Run a review

Run from a local Git checkout, or select it explicitly:

```sh
appsec-analyzer authnz-review --repo /path/to/project --budget 5
appsec-analyzer authnz-review --repo /path/to/project --budget 5 --json
appsec-analyzer authnz-review --repo /path/to/project --budget 5 --yaml
```

Replace `/path/to/project` with the local checkout. Progress and the budget and data-use notice go to stderr. Stdout contains Markdown text by default. `--json` and `--yaml` (not together) print the same versioned result without terminal styling. A console-only review leaves no result files. This command does not support Git URLs, several repositories, imported threat models, organization output defaults, or resuming.

`--requirements /path/to/catalog.yaml` adds references from a local requirements catalog to the findings. The catalog is an Analyzer YAML catalog or an OSCAL catalog, as described under [catalog formats](security-requirements-audit-skill.md#catalog-formats), and may be up to 128 000 bytes after conversion. No catalog is picked up automatically. The annotation is not a requirements audit or a compliance check.

`--save` keeps the results in a new `authnz-reviews/review-*` subdirectory of the application's private assessment directory. `--output DIR` selects an existing, empty directory outside the checkout. It must be owned by you and have mode 0700. Links and occupied destinations are rejected before any model call. Saved files are private and never overwrite another file.

```sh
mkdir -m 700 /private/authnz-review
appsec-analyzer authnz-review --repo /path/to/project --budget 5 --output /private/authnz-review
```

Replace `/private/authnz-review` with a fresh destination whose parent exists. By default, saving creates `authnz-review.md`, `authnz-review.json`, and `authnz-review.yaml`. `--outputs markdown json yaml pentest-tasks` selects formats and enables saving without `--save`.

The hidden files `.authnz-report.json` and `.route-inventory.json` are used for a later pentest export. The public JSON and YAML contain `interface_version: 1` and `kind: authnz-review`, the source identity, completion and gate status, limits, and the validated report under `report`.

## Export the pentest plan

The export turns findings into planned pentest tasks. A task has finding references, an objective, a test strategy, negative controls, required accounts, evidence requirements, success criteria, and stop conditions, plus the evidence status, source locations, and requirement references of the finding. Tasks describe planned checks. They do not authorize or run a penetration test.

```sh
appsec-analyzer authnz-review --repo /path/to/project --budget 5 --save \
  --pentest-tasks --pentest-format generic --pentest-output-format both \
  --pentest-target https://staging.example.com
```

`--pentest-format generic|strix` selects the plan dialect. `--pentest-output-format yaml|json|both` selects the file format and defaults to YAML. The files are named `pentest-tasks-authnz.yaml` and `pentest-tasks-authnz.json`. `--pentest-tasks` also turns on saving, as does `--outputs pentest-tasks`. The target URL is only recorded. It must be an HTTP(S) URL without credentials. Every task carries a read-only safety block. The tool that later runs a test must enforce its own scope and authorization.

Only findings whose CWE is on the list in `data/pentest-eligible-cwes.yaml` and that have file and line evidence become tasks. The list leaves out some AuthNZ classes, including CWE-345 and CWE-640. The structured result names the omitted findings under `pentest_export`, and they stay in the report. The `strix` dialect has not been qualified against the external tool.

From a source checkout, you can re-export a saved report without new model calls:

```sh
python3 scripts/renderers/render_pentest_tasks.py \
  --authnz /private/authnz-review/.authnz-report.json \
  --route-inventory /private/authnz-review/.route-inventory.json \
  --output /private/authnz-review/reexport.json --output-format json --dialect generic
```

Run it in the Analyzer source checkout with its dependencies installed, and choose a new output filename in the private result directory. The script writes straight to that path and does not check that the directory is empty. It reads the saved report `.authnz-report.json`, not `authnz-review.json`.

## Completion and recovery

Exit 0 means the advisory review completed, or the gate you selected passed. `--gate` returns 1 for Critical or High findings. Exit 2 means an incomplete result (also without a gate), invalid input, a scanner or host failure, a used-up budget, rejected model output, or a failed export. Ctrl+C returns 130. A partial or interrupted review is never reported as clean. After an operational failure no new model result is published. A storage failure can leave files that were already validated, so use a new destination when you retry. This command cannot resume interrupted work.

Findings retain `scanner`, `confirmed-instance` or `hypothesis` as their evidence status. Confirmation here is static scanner confirmation, not demonstrated runtime exploitability. Unknown authentication does not prove missing authentication, and absence of findings does not establish safety. Model reasoning is limited to extracted signals; unsupported frameworks, unresolved handlers and upstream controls can remain unknown.
