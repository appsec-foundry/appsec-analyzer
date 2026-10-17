# AppSec Analyzer

AppSec Analyzer is a Python scanning and security assessment engine extracted from
[AppSec Advisor](https://github.com/appsec-foundry/appsec-advisor). It accepts local
Git checkouts, keeps a frozen source view for each run, and writes results outside
the analyzed checkout. The two central commands have different meanings:

```sh
appsec-analyzer scan --repo /path/to/project
appsec-analyzer assess --repo /path/to/project --host claude-cli --hard-budget 20
```

`scan` runs deterministic source authorization, authorization confirmation,
mass assignment, and applicable configuration/IaC scanners. It requires no
Claude installation, provider credentials, or model calls. Its JSON result says
`assessment_status: not_run`; a scanner finding is an observation, not a verified
exploit or complete component assessment.

`assess` runs the complete semantic workflow: source admission, component and
trust-boundary analysis, security controls, STRIDE, evidence review, consolidation,
validation, and publication. It uses an explicitly selected host. At this
pre-release stage the Claude CLI compatibility adapter is available; direct
OpenAI Responses and fixed gateway adapters have offline contract tests but no
qualified model/route/depth profiles and are refused by the public command.
No live provider test or paid call is part of this release preparation.

## Install locally

Python 3.10+ and Git are required. From this checkout, in an isolated environment:

```sh
python3 -m venv /tmp/appsec-analyzer-venv
/tmp/appsec-analyzer-venv/bin/pip install .
/tmp/appsec-analyzer-venv/bin/appsec-analyzer version
```

For a wheel built locally, install its exact path instead of `.`. This checkout
is a development extraction; no package has been published by this work.

## Quickstart

```sh
appsec-analyzer scan --repo /path/to/project --output /private/results
appsec-analyzer assess --repo /path/to/project --host claude-cli \
  --hard-budget 20 --output /private/assessment
appsec-analyzer status --output /private/assessment
appsec-analyzer progress --output /private/assessment
appsec-analyzer stop --output /private/assessment
appsec-analyzer results --output /private/assessment
```

For `scan --output`, create an output directory outside all selected checkouts
first. Without `--output`, the result is written to stdout. `assess` defaults to
a private directory under the user's `appsec-analyzer/assessments` data directory.
`--resume` continues an interrupted compatible assessment; `--rebuild` starts
again. Optional `--sarif`, `--threatdragon`, `--html`, `--pdf`, and
`--pentest-tasks` request exports. External PDF/HTML tools may be required.

The focused design/change/hypothesis analyst has a distinct entry under the same
program: `appsec-analyzer analyst design|review|hypothesis|answer|cancel|forget`.
See [Threat Analyst](docs/threat-analyst.md). A requirements check **within** a
full assessment is selected with `assess --requirements`; the independent
requirements audit remains a migration gap and is not represented as a full
assessment or a deterministic scan.

## Contracts and limits

- The JSON scan contract is [deterministic-scan-result.schema.json](schemas/deterministic-scan-result.schema.json).
  The assessment lifecycle is [multi-repo-state.schema.json](schemas/multi-repo-state.schema.json).
- `status`, `progress`, `stop`, and `results` use interface version 1. `results`
  verifies recorded hashes of published deliverables before listing them.
- Untrusted repository mode is the default. Repository-owned host configuration,
  escaping source links, source changes, invalid evidence, and incompatible
  resumed state stop a run rather than silently widening its scope.
- Source excerpts and supplied business context are sent to the selected model
  host during an assessment or focused analysis. A deterministic scan sends no
  source to a model host. Provider retention and gateway routing require
  operator review before use.
- The engine cannot observe production-only controls or prove runtime behavior.
  Review findings with the owning team before remediation or risk acceptance.

See [assessment operation](docs/security-assessment.md), [configuration](docs/configuration.md),
[model selection](docs/model-selection.md), [headless use](docs/headless-mode.md), and the
[Phase A extraction record](docs/internal/extraction/phase-a-record.md). Earlier
Advisor guides are retained as [historical reference](docs/history/advisor/INDEX.md);
their plugin commands are not Analyzer installation instructions.

## Development and provenance

Run focused checks with `python3 -m pytest tests/test_public_scan_cli.py
tests/test_public_assessment_operations.py tests/test_api_hosts.py`. Build local
wheel and source distribution with `python3 -m build --no-isolation --outdir
/tmp/appsec-analyzer-dist`, then inspect and install them in a separate
environment. See [the extraction record](docs/internal/extraction/phase-a-record.md)
for the committed source revision, filtered commit map, exclusions, and open
qualification work. This project preserves the original Apache 2.0
[license](LICENSE) and source history.
