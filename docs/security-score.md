# Security score

`appsec-analyzer score REPO` gives a quick deterministic indication from 0 to 100 using the existing Analyzer analysis engine, without a model account, model calls, or model charges. Install Analyzer and Git first. `REPO` must name one top-level Git checkout with a commit, a [directory without Git](security-assessment.md#directories-without-git), or an explicitly selected HTTPS or SSH Git URL. Run `appsec-analyzer score --help` for arguments and examples.

```sh
appsec-analyzer score /path/to/project
appsec-analyzer score /path/to/project --json
appsec-analyzer score /path/to/project --yaml
appsec-analyzer score https://github.com/your-org/your-project.git --json
```

Replace the example paths and repository URL with your own selection. `--json` and `--yaml` are mutually exclusive. There is no model profile, spending limit, output directory, or score-threshold gate for this command. To save the printed result, redirect stdout to a private file outside the selected repository.

The command runs Analyzer's deterministic scanners and scoring, without the model-backed stages of an assessment. Runtime depends on the repository size, the scanners, and any Git download.

Progress goes to stderr and runs through three phases: Repository, Security checks, and Result. Each step shows its status and duration, and the active step refreshes in an interactive terminal. A scanner marked `done` produced valid output. It does not mean that the scanner found no vulnerabilities. Redirected stderr and `TERM=dumb` terminals get plain lines without animation. Stdout contains only the finished text, JSON, or YAML result. For example, with illustrative durations:

```text
Calculating security score for /path/to/project

  [1/3] Repository
    [done]      Loading analysis runtime                       0.3s
    [done]      Reading repository sources                     1.2s
    [running]   Preparing source scan                          6.0s  /
```

## What is checked

The score runs route inventory, architecture coverage, configuration/IaC, and source-auth scanners. These differ from the scanner set used by `scan-sources`. It reports indicator scores, applicable check counts, finding counts, the ten most severe distinct checks with example locations, and warnings. Scanner observations are unverified. Use [a full assessment](security-assessment.md) for contextual findings, severity justification, and remediation.

The text result shows the overall score, the repository, check coverage, and severity totals. Areas are ordered from weakest to strongest, with check and finding counts. Areas without a scoring baseline show as `unscored`. The ten leading findings show severity, title, an example location, and how often they repeat. Warnings and incomplete work stay visible. The footer names the commit and the number of files captured. JSON and YAML add detailed control signals and comparison metadata.

Score colors are red below 25, orange below 50, yellow below 75, and green from 75. They describe scanner scores, not security approval. Redirected output and `TERM=dumb` have no colors. A nonempty `NO_COLOR` turns colors off. A nonzero, nonempty `FORCE_COLOR` turns them on unless `NO_COLOR` is set. JSON and YAML never contain styling codes.

Each area combines its architecture-coverage checks with deductions for its scanner findings. Low-severity checks do not count, and repeated configuration checks count less. An area without applicable checks stays unscored but keeps its findings. The overall score averages the weaker half of the scored areas. The scoring version is 2.

This is a limited quick check, not a risk rating or a full security analysis. It does not establish production exposure, asset importance, verified exploitability, or absence of vulnerabilities. Language coverage includes JavaScript/TypeScript, Python, Java/Spring, and parts of .NET. Fewer than five applicable coverage checks produces `undetermined` with no headline score. A failed, missing, or invalid required scanner result produces `incomplete` with no headline score. Findings and warnings remain visible in either case.

## Sources and data use

Analyzer admits the selected Git source under its usual limits for paths, file count, size, and secret redaction. Scanners read a frozen, private copy of regular files. Ignored files and earlier assessment results are not captured. Sensitive filenames, binaries, oversized files, internal links, submodules, and nested repositories are left out, and links that leave the repository are rejected. Repository hooks, instructions, and build scripts are not run. The source is checked again before the result is printed, and a change in the meantime stops the output.

The checkout receives no result files. Scanner files and source snapshots are temporary and private, and are deleted when the command ends normally or after a handled error. Killing the process can leave temporary files behind. Structured output records the source commit, whether the checkout had uncommitted changes, a fingerprint of the captured source, and the number of captured files. It does not list excluded files. Terminal output is redacted and stripped of control characters.

Only a Git URL you select allows network access. The command applies the same checkout, credential, destination, and TLS or SSH checks as the other commands and removes the checkout afterwards. Keep credentials out of URLs; see [Git repository access](configuration.md#git-repository-access). `score` never sends source to a model.

## Compare results and automate

Compare commits of the same repository only when `comparability.scoring_version`, `catalog_fingerprint`, `coverage_fingerprint`, and `source_policy` match. Changed applicable checks invalidate direct numerical comparison. The source policy `analyzer-admitted-redacted-v1` identifies the Analyzer snapshot boundary; results from the older direct script without this field are not directly comparable. Do not use the number to rank different repositories.

JSON and YAML follow the [score schema](../schemas/security-score.schema.yaml). Public CLI results add `interface_version: 1`, `assessment_status: not_run`, `evidence_status: unverified`, and source metadata; the schema also accepts the retained direct script's older shape. Exit codes are:

| Exit | Meaning |
| --- | --- |
| `0` | Score computed, including a low score. |
| `2` | `undetermined` because too few checks applied, or invalid command arguments reported on stderr. |
| `1` | Incomplete scan, rejected source, failed retrieval, or another operational error. |
| `130` | Cancelled by the user with Ctrl+C. |

`--help` exits 0 without reading source. An operational error can have no result document; distinguish it from an `undetermined` JSON/YAML document using the exit code and `verdict`. These codes report execution and coverage rather than a security approval.

## Errors and cancellation

Press Ctrl+C to cancel. The status ends with `Cancelled by user after ...` and exit code 130. No result is published, and the temporary source and scanner files are removed.

An invalid local selection says whether the path is missing, is a file, is a subdirectory of a checkout, has a `.git` that Git cannot read, or has no readable commit. Select an existing top-level Git checkout with a commit or a directory without Git, and check your Git installation and read permissions. Remote failures name the rejected URL, destination, access, or checkout limit. See [Git repository access](configuration.md#git-repository-access) for credentials, host authorization, and trusted SSH keys. Raw Git and scanner errors are not shown, because they can contain credentials or source details.

A scanner that times out, fails, or returns no valid result makes the score `incomplete`, with no overall score. The warnings name the scanner and the failure. Retry, or check the installation. Findings from completed scanners stay visible. If the source changes during the analysis, wait until the edits are done and run again. The outdated result is not printed.

If runtime resources are missing, check or reinstall Analyzer in the active Python environment. An unexpected failure exits with 1 and a short recovery message. When you report a persistent problem, include the Analyzer version, the last visible phase, and the error message.
