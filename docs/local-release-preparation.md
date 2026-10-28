# Local release preparation: 0.1.0a0

For a separate internal package that includes organization defaults and pins this engine, follow [organization distribution packaging](organization-distributions.md). The source and wheel include the complete example under `examples/organization-distribution/`.

This is an unpublished development preview. Later Advisor integration is outside this repository’s current scope. Build from the `dev` branch in a separate temporary clone to keep local files and test output out of the archive.

Run `make release-check-analyzer BASE=<base-commit>` before building. Replace `<base-commit>` with the commit before the release changes under review. That commit must exist in the checkout, and `HEAD` checks only uncommitted changes. The gate checks requirement changes and the public contracts, and inventories a wheel and a source archive, including incremental build cleanup and the links in the installed guides. The inherited whole-suite and test-route catalog still need separate reconciliation before you can call this a full release gate.

```sh
git clone --no-hardlinks -b dev /path/to/appsec-analyzer /tmp/analyzer-release-source
python3 -m build --no-isolation --outdir /tmp/analyzer-release-dist /tmp/analyzer-release-source
python3 -m venv /tmp/analyzer-install-test
/tmp/analyzer-install-test/bin/pip install /tmp/analyzer-release-dist/appsec_analyzer-0.1.0a0-py3-none-any.whl
/tmp/analyzer-install-test/bin/appsec-analyzer version
```

The wheel and source archive include the Apache-2.0 license; Git preserves source history. The wheel contains the CLI, engine, schemas, catalogs, templates, entry skill, and user documentation. The source archive also contains historical and technical documentation. Neither should include local assessment output or fixture data.

`appsec-analyzer --version` reports a release only if the built commit has a tag like `v0.1.0`; tag it before building, or the build reports its commit and date. The source archive carries the stamp, so a wheel built from it reports the same.

Runtime dependencies are PyYAML 6.x, jsonschema 4.x, and Jinja2 3.x. The optional requirements extra adds requests and BeautifulSoup for catalog tools. Git is required for local source checks. Document and diagram exports can need additional tools.

Inspect both archives before distribution. Exclude the temporary `scripts/run-headless.sh` wrapper, retired plugin metadata and gates, test runner, fixture `.env` files, and generated reports. Record hashes in a local `SHA256SUMS` file beside the artifacts. Pushing, tagging, uploading, and publication are separate steps.

## Qualification and compatibility limits

- `assess` runs the full assessment and makes model calls; `scan-sources` and `score REPO` are deterministic commands without a model provider. The separate [score](security-score.md) is a limited indication and does not establish security approval.
- `assess --host claude-cli` is a compatibility adapter with offline fake-host end-to-end tests. A real CLI session, model selection, and run cost have not been qualified.
- The OpenAI Responses profiles can be selected with `--host openai`. They have offline tests for the wire format, decoding, network egress, and budgets. Their assessment quality has not been qualified in a live run. Fixed gateway routes are not available through the public command.
- `codex-cli` supports Codex CLI 0.163.0 or newer with a ChatGPT login on Linux and macOS. It has offline tests, and the installed CLI passes a loopback-only wire test. Live assessment quality and plan consumption have not been qualified. See [setup and limits](profiles.md#use-your-chatgpt-plan-with-codex-cli).
- `audit-requirements` accepts one local catalog and one repository. Remote catalogs, PDF output, and resume from the earlier Advisor audit are not available. The audit is not a complete security assessment.
- Run directories from Advisor are not migrated. Resume needs compatible Analyzer state and an unchanged admitted source.

The [extraction record](internal/extraction/phase-a-record.md) lists the frozen source commit, the mapping from Advisor, the checks, and the open work.
