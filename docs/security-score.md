# Security score

`appsec-analyzer score REPO` gives a quick deterministic indication from 0 to 100 using the existing Analyzer analysis engine, without a model account, model calls, or model charges. Install Analyzer and Git first. `REPO` must name one top-level Git checkout with a commit, or an explicitly selected HTTPS or SSH Git URL. Run `appsec-analyzer score --help` for arguments and examples.

```sh
appsec-analyzer score /path/to/project
appsec-analyzer score /path/to/project --json
appsec-analyzer score /path/to/project --yaml
appsec-analyzer score https://github.com/your-org/your-project.git --json
```

Replace the example paths and repository URL with your own selection. `--json` and `--yaml` are mutually exclusive. There is no model profile, spending limit, output directory, or score-threshold gate for this command. To save the printed result, redirect stdout to a private file outside the selected repository.

The command reuses Analyzer's existing deterministic scanners and scoring calculation. It runs a limited quick check without the model-backed assessment stages. Runtime depends on repository size, source preparation, scanner work, and any Git download; the progress display identifies the current step and reports elapsed time.

Progress starts immediately on stderr with `Calculating security score for ...` and the selected repository, followed by three phases: Repository, Security checks, and Result. The header shows the expanded local path or Git host/project; URL credentials, queries, and fragments are omitted. Within the same line, the project name uses bold accent text and the parent path or URL prefix is muted; the summary uses the same treatment. Each runtime, repository-preparation, scanner, calculation, and validation step has its own persistent status line and measured duration under a phase heading. In an interactive terminal, the active step refreshes with an activity indicator while completed steps remain visible. Scanner lines distinguish done, failed, missing, and invalid results; done means that scanner output was validated, not that no vulnerabilities were found. Git cloning appears when needed. A final summary reports total time and identifies stopped or incomplete scans. Redirected stderr and `TERM=dumb` terminals receive plain step start/completion lines without animation or control characters. Messages are flushed even when output is piped. Stdout contains only the finished text, JSON, or YAML result.

For example, an interactive run retains completed steps while source preparation continues; the durations below are illustrative:

```text
Calculating security score for /path/to/project

  [1/3] Repository
    [done]      Loading analysis runtime                       0.3s
    [done]      Reading repository sources                     1.2s
    [running]   Preparing source scan                          6.0s  /
```

## What is checked

The score runs route inventory, architecture coverage, configuration/IaC, and source-auth scanners. These differ from the scanner set used by `scan-sources`. It reports indicator scores, applicable check counts, finding counts, the ten most severe distinct checks with example locations, and warnings. Scanner observations are unverified. Use [a full assessment](security-assessment.md) for contextual findings, severity justification, and remediation.

The text summary highlights the overall score in a separate block with its limited-check qualifier, followed by repository, coverage, and severity totals. An aligned table lists scored areas from weakest to strongest, with applicable-check and finding counts; areas without a scoring baseline remain visible as `unscored`. Numbered top findings have colored severity labels, complete check titles that wrap to the terminal width, and the example location and repetition count below the title. Blank lines separate finding entries. Unscored findings, excluded severities, incomplete execution, and warnings stay visible. The footer identifies the examined commit and captured file count. Detailed control signals and comparison fingerprints remain available through `--json` or `--yaml`.

Text output uses the same terminal palette as Analyzer assessments. The headline and area values use the retained visual bands: below 25 red, below 50 orange, below 75 yellow, and 75 or above green. These colors describe the scanner score, not security approval. Critical, high, and medium findings use the shared severity colors; source references and repetition counts are muted. Progress uses cyan for running, green for done, red for failed or invalid, and yellow for missing or cancelled. Descriptions and timing values remain neutral. Color is automatic and chosen independently for stdout results and stderr progress, disabled by a nonempty `NO_COLOR`, and normally absent on redirected streams or `TERM=dumb`. A nonzero, nonempty `FORCE_COLOR` explicitly enables text colors unless `NO_COLOR` is set. JSON and YAML never contain styling codes. Public finding titles are complete in every format; the retained direct script keeps its shorter default titles.

Each indicator combines its applicable architecture-coverage checks with deductions for its own scanner findings. Hypotheses receive at most one quarter of control credit. Low-severity checks are excluded from scoring; repeated configuration checks are damped. An indicator without applicable checks stays unscored and retains its findings. The headline averages the weaker half of the scored indicators. The bundled scoring version is 2.

This is a limited quick check, not a risk rating or a full security analysis. It does not establish production exposure, asset importance, verified exploitability, or absence of vulnerabilities. Language coverage includes JavaScript/TypeScript, Python, Java/Spring, and parts of .NET. Fewer than five applicable coverage checks produces `undetermined` with no headline score. A failed, missing, or invalid required scanner result produces `incomplete` with no headline score. Findings and warnings remain visible in either case.

## Sources and data use

Analyzer admits the selected Git source under its existing path, file-count, size, and secret-redaction rules. Scanners read a frozen, private copy containing regular files with unchanged source line numbers. Ignored files and prior assessment products are not captured. Sensitive filenames, binaries, oversized files, internal links, submodules, and nested repositories are excluded; links escaping the repository are rejected. Repository hooks, instructions, build scripts, and model tools are not executed. The source is rechecked before the result is printed; a relevant change stops publication.

The target checkout receives no result files. Scanner files and source snapshots are temporary and private, and are removed when the command exits normally or through a handled error. Unclean process termination can leave temporary files. Structured output records the source commit, dirty state, captured source fingerprint, and captured file count. Excluded-file lists and counts are omitted from every output format. Terminal fields are redacted and stripped of control and Unicode formatting characters.

Only selecting a Git URL authorizes network retrieval. The command uses the same bounded checkout, credential, destination, and TLS/SSH checks as the other Analyzer commands and removes the checkout afterwards. Keep credentials out of URLs; see [Git repository access](configuration.md) for operator configuration. Source is never sent to a model by `score`.

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

Press Ctrl+C to cancel. The status ends with `Cancelled by user after ...` and exit code 130, without a traceback. Cancellation during preparation, scanning, or final validation publishes no result and removes the run's temporary source and scanner files, including a temporary Git checkout.

Invalid local selections identify whether the path is missing, is a file, names a subdirectory, cannot be read as a Git checkout, or has no readable commit. Select an existing top-level Git checkout containing a commit and check Git installation and read permissions. Remote failures report the rejected URL policy, destination, access, or checkout limit; see [Git repository access](configuration.md) for credentials, host authorization, and trusted SSH keys. Raw Git and scanner errors are withheld because they can contain credentials or source details.

A scanner timeout, failed execution, missing result, or invalid result leaves the overall score `incomplete` with a null headline score. The warnings name the affected scanner, describe the failure, and suggest retrying or checking the installation. Findings from completed scanners remain visible. If the selected source changes during analysis, wait for edits to finish and rerun; the outdated result is not printed.

Missing runtime resources suggest checking or reinstalling Analyzer in the active Python environment. An unexpected runtime or rendering failure exits 1 with a short recovery message and no internal exception details. When reporting a persistent problem, include the Analyzer version, the last visible phase, and the sanitized error message. Closing an output pipe exits 1 without a traceback; bytes already delivered to another process cannot be withdrawn.
