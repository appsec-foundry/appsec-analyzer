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

The command discovers conventional threat-model and requirements filenames (`threat-model`, `threatmodel`, `threat_model`, `security-assessment`, `requirements`, `security-requirements`) in the repository root, `docs/` and `docs/security/`. It also discovers documents under `specs/`, `docs/specs/`, `docs/architecture/`, and the existing business-context locations. Supported document suffixes are `.md`, `.txt`, `.rst`, `.yaml`, `.yml` and `.json`.

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

The existing structured YAML adapters remain available through `--threat-model FILE` and `--requirements FILE`. Markdown/text files supplied through these flags enter the document adapter. In commit and MR/PR reviews, relative paths refer to both selected document revisions, including YAML files as document context; absolute YAML paths select an explicit external structured catalog/model. Other relative document paths are relative to `--repo`; `--design-file`, external YAML files, output and state paths use the invocation's filesystem context. Outside commit reviews, an existing structured Analyzer assessment is used when no document threat model was selected, unless `--isolated` or `--no-context` is given.

## Merge requests and pull requests

```sh
appsec-analyzer analyze-threats --mr https://gitlab.example/team/app/-/merge_requests/42 --preview
appsec-analyzer analyze-threats "Does this weaken tenant isolation?" \
  --pr https://github.com/team/app/pull/42 --non-interactive
```

`--mr` supports GitLab HTTPS URLs, including nested groups; `--pr` supports GitHub and GitHub Enterprise HTTPS URLs. The URL selects the repository, so do not combine it with `--repo`. Metadata is read through the [GitLab merge request API](https://docs.gitlab.com/api/merge_requests/) or [GitHub pull request API](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request); GitHub comparisons use its [commit comparison API](https://docs.github.com/en/rest/commits/commits#compare-two-commits). The adapter fetches immutable commit objects from that repository into a private temporary checkout. It compares merge-base source with the proposed head and supplies target-tip documents separately from proposed documents. The result records the URL and commit IDs. Remote preview also uses network access, but makes no model call.

For private forges, configure `APPSEC_GIT_TOKEN` externally with API and repository read access. GitLab uses a personal/project/group access token accepted by its `PRIVATE-TOKEN` header; GitHub uses bearer authentication. `APPSEC_GIT_USERNAME` optionally sets the HTTPS Git username. Existing operator Git credential helpers can authenticate the Git fetch, but do not supply API authentication. No token is accepted in a URL. GitHub.com uses `api.github.com` for metadata and `github.com` for Git; include both if `APPSEC_URL_ALLOWLIST` is configured. Enterprise instances must expose the standard API paths over HTTPS on port 443; custom subpath installations and redirects are not supported. Explicit private-network hosts are permitted, but loopback, link-local and metadata destinations are blocked.

The adapter does not follow repository URLs supplied by API responses, execute repository hooks/builds, mutate your checkout, or post comments. If a forge does not expose the required commit objects, rejects credentials, or has not prepared its diff metadata, the command fails before analysis; fetch the required history through your normal workflow and use local `--base`/`--head` as an alternative. Forge adapters have offline contract coverage; live forge compatibility has not been qualified.

## Questions, continuation and results

In an interactive terminal, required follow-up questions appear together with the controller's explanation and are answered in the same job. Blank input or EOF leaves the job waiting. No default answer or risk acceptance is invented. Resume a local job with its original repository and state directory:

```sh
appsec-analyzer analyze-threats --repo /path/to/project --resume JOB
```

Replace `JOB` with the printed `aj-` job ID. For a remote job, repeat its original `--mr URL` or `--pr URL` with `--resume JOB`. The temporary checkout is recreated, but the analysis continues with its stored frozen inputs. Ctrl+C cancels an active job; `appsec-analyzer analyst cancel --repo /path/to/project --job JOB` also supports explicit cancellation. The existing `analyst answer` command accepts answer files or explicitly saved feature answers; no answers are automatically copied into project documents.

Use `--non-interactive` for CI and agent calls. Ambiguous scope fails without a prompt; required unanswered questions leave the result incomplete. Exit 0 means completed analysis or preview, 2 means rejected, incomplete, or failed work, and 130 means cancellation. Findings alone do not change the exit code. Check the printed `State:`.

Private state stays under `$XDG_STATE_HOME/appsec-analyzer/analyst`, or the usual user state directory. `--output DIR` also writes `analyst-result.json` and `analyst-result.md` to an existing private directory outside the repository.

## Model, costs and compatibility

Claude CLI with a working external login or credentials is required for model-backed runs. The default model is `sonnet`; `--model` selects another permitted Claude CLI model. `--max-budget-usd` defaults to USD 1 per model call, with up to four calls under the current job limits. This is a per-call ceiling, not a total-job spending guarantee. The CLI displays the selected model and ceiling and explains that source, design, documents and supplied answers leave the machine. Preview has no model cost. No live model calls are part of offline verification; offline tests do not qualify model quality or host isolation.

`analyst design`, `analyst review`, `analyst hypothesis`, `answer`, `cancel` and `forget` remain compatible. `appsec-analyzer analyst --help` lists those operations. The question-first entry does not add full-assessment provider profiles or change their budgets. The [historical guide](history/advisor/threat-analyst.md) records the earlier package/feature contracts; its Advisor plugin commands are not current entry points.
