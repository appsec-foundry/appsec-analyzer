# Focused threat analysis

Use `appsec-analyzer analyze-threats` to ask a security question, examine a design, or review a selected change. It uses the existing focused analyst, separately from a full [security assessment](security-assessment.md). Findings need source evidence; design documents and existing threat models describe expectations and assumptions. The result is advisory and never a security approval.

## Ask a question

Run the command in a local Git repository, or select one with `--repo`. In an interactive terminal, a question without scope prompts you to choose a design, staged changes, worktree changes or committed source paths. With no arguments it first asks for the question. It never silently expands a question into a full-repository audit.

```sh
appsec-analyzer analyze-threats "Can a normal user read another tenant's records?"
appsec-analyzer analyze-threats "Can a normal user read another tenant's records?" --path src/api
appsec-analyzer analyze-threats "Does this remove an authorization check?" --staged
appsec-analyzer analyze-threats --worktree
appsec-analyzer analyze-threats "How should we protect exports?" --design
appsec-analyzer analyze-threats --design-file /path/to/design.md
```

`--path` is repeatable and selects literal repository-relative files or directories at `HEAD`, or at `--revision REV`. It does not inspect uncommitted edits. Design mode reads the supplied design and document context, but no implementation source unless you explicitly select `--explore`. Exploration is available only for interactive design/change reviews and reads a redacted tracked-source snapshot. Design text, including a question combined with a design file, is limited to 20000 characters.

For a local commit comparison use `--base BASE_SHA --head HEAD_SHA`. The default comparison starts at their merge base; `--exact-base` compares the supplied commits directly. For a defined abuse case use `--abuse-case ID`, optionally repeated and combined with `--path` and `--revision`; its definition supplies the question. `--preview` shows the selected scope and document status without creating an analyst job or calling a model.

## Existing threat models, requirements and specs

The command looks for files named like a threat model or requirements document (for example `threat-model`, `security-assessment`, `requirements`) in the repository root, `docs/`, and `docs/security/`. It also reads documents under `specs/`, `docs/specs/`, `docs/architecture/`, and the business-context locations. Supported suffixes are `.md`, `.txt`, `.rst`, `.yaml`, `.yml`, and `.json`.

```sh
appsec-analyzer analyze-threats "Does this violate our tenant isolation requirements?" \
  --staged --context docs/security/threatmodel.md --context specs/tenant-isolation.md
appsec-analyzer analyze-threats "Can this endpoint bypass authentication?" \
  --path src/api --no-context --context requirements.md --preview
```

`--context FILE` selects a literal repository-relative document and can be repeated. `--no-context` disables automatic document and stored-assessment discovery while retaining explicit selections and the packaged requirements baseline. `--isolated` excludes existing threat models while preserving requirements and specs. Multiple candidate threat models require a selection in the terminal or an explicit `--context`/`--threat-model` choice; the tool does not decide which contradictory model is authoritative.

The context is limited to 24 document versions, 64 KiB per file and 192 KiB overall. A comparison can use two versions of each document. Automatic selection prioritizes explicit files, threat models and requirements over specs, and current specs over `specs/changes/`; omitted paths are counted. Select fewer documents when a byte limit is exceeded. Sensitive automatic documents are withheld visibly; unavailable or sensitive explicit documents stop the request before a model call. Symlinks, traversal and unsupported file types are refused. Discovery does not follow links or fetch links embedded in documents.

For each context document, the result records its path, hash, role, and revision. Hypothesis checks use the selected committed version. Staged and worktree reviews also include the corresponding index or current version.

The report lists these sources. Structured citations must match the delivered document and exact lines. A document can supply requirement or threat IDs, but cannot prove that code is vulnerable or that a control works.

`--threat-model FILE` and `--requirements FILE` select a structured YAML threat model or a requirements catalog (Analyzer YAML or an OSCAL catalog, see [catalog formats](security-requirements-audit-skill.md#catalog-formats); at most 300 requirements). Markdown and text files passed with these flags are read as ordinary documents. In commit and MR/PR reviews, a relative path refers to both selected revisions of the document, and an absolute YAML path selects an external catalog or model. Other relative paths are relative to `--repo`. `--design-file`, external YAML files, and output and state paths are relative to the directory you run the command in. Outside commit reviews, the command uses an existing Analyzer assessment when you selected no threat model, unless you pass `--isolated` or `--no-context`.

## Merge requests and pull requests

```sh
appsec-analyzer analyze-threats --mr https://gitlab.example/team/app/-/merge_requests/42 --preview
appsec-analyzer analyze-threats "Does this weaken tenant isolation?" \
  --pr https://github.com/team/app/pull/42 --non-interactive
```

`--mr` supports GitLab HTTPS URLs, including nested groups. `--pr` supports GitHub and GitHub Enterprise HTTPS URLs. The URL selects the repository, so do not combine it with `--repo`. Analyzer reads the metadata through the platform's API and fetches the commits into a private temporary checkout. It compares the merge-base source with the proposed head and keeps the documents of the target branch apart from the proposed ones. The result records the URL and commit IDs. A remote preview also uses the network but makes no model call.

For private repositories, set a token outside the repository, with API and repository read access. Analyzer reads it from `APPSEC_GIT_TOKEN`, `GIT_TOKEN`, or `GITLAB_TOKEN` (GitLab hosts only), or from the variable you name with `--git-token-env NAME`. GitLab takes a personal, project, or group access token. GitHub takes a bearer token. `APPSEC_GIT_USERNAME` optionally sets the HTTPS Git username. A Git credential helper can authenticate the fetch, but not the API calls. A token in a URL is rejected. GitHub.com uses `api.github.com` for metadata and `github.com` for Git. If you set `APPSEC_URL_ALLOWLIST`, include both. Enterprise instances must offer the standard API paths over HTTPS on port 443. Custom subpaths and redirects are not supported. Private-network hosts you name are allowed. Loopback, link-local, and metadata addresses are blocked.

The command does not follow repository URLs from API responses, run repository hooks or builds, change your checkout, or post comments. If the platform lacks the commits, rejects the credentials, or has not prepared its diff, the command fails before analysis. In that case fetch the history yourself and use `--base` and `--head`. Live compatibility with GitHub and GitLab has not been qualified.

## Questions, continuation and results

In an interactive terminal, required follow-up questions appear together with the controller's explanation and are answered in the same job. Blank input or EOF leaves the job waiting. No default answer or risk acceptance is invented. Resume a local job with its original repository and state directory:

```sh
appsec-analyzer analyze-threats --repo /path/to/project --resume JOB
```

Replace `JOB` with the printed `aj-` job ID. For a remote job, repeat its original `--mr URL` or `--pr URL` with `--resume JOB`. The temporary checkout is recreated, but the analysis continues with its stored frozen inputs. Ctrl+C cancels an active job; `appsec-analyzer analyst cancel --repo /path/to/project --job JOB` also supports explicit cancellation. The existing `analyst answer` command accepts answer files or explicitly saved feature answers; no answers are automatically copied into project documents.

Use `--non-interactive` for CI and agent calls. Ambiguous scope fails without a prompt; required unanswered questions leave the result incomplete. Exit 0 means completed analysis or preview, 2 means rejected, incomplete, or failed work, and 130 means cancellation. Findings alone do not change the exit code. Check the printed `State:`.

Private state stays under `$XDG_STATE_HOME/appsec-analyzer/analyst`, or the usual user state directory. `--output DIR` also writes `analyst-result.json` and `analyst-result.md` to an existing private directory outside the repository.

## Model, costs and compatibility

Claude CLI with a working external login or credentials is required for model-backed runs. The default model is `sonnet`; `--model` selects another permitted Claude CLI model. `--max-budget-usd` defaults to USD 1 per model call, with up to four calls under the current job limits. This is a per-call ceiling, not a total-job spending guarantee. The CLI shows the selected model and ceiling and says that source, design, documents, and your answers leave the machine. A preview costs nothing.

The older `analyst design`, `analyst review`, `analyst hypothesis`, `answer`, `cancel`, and `forget` commands still work. `appsec-analyzer analyst --help` lists them. `analyze-threats` does not use the provider profiles or budgets of a full assessment.
