# Local release preparation: 0.1.0a0

This is an unpublished Phase A preview. Phase B Advisor integration is outside
this repository's current assignment. Build from the `dev` branch in a separate
temporary clone so checkout files and test artifacts cannot enter the archive:

```sh
git clone --no-hardlinks -b dev /path/to/appsec-analyzer /tmp/analyzer-release-source
python3 -m build --no-isolation --outdir /tmp/analyzer-release-dist /tmp/analyzer-release-source
python3 -m venv /tmp/analyzer-install-test
/tmp/analyzer-install-test/bin/pip install /tmp/analyzer-release-dist/appsec_analyzer-0.1.0a0-py3-none-any.whl
/tmp/analyzer-install-test/bin/appsec-analyzer version
```

The wheel and source distribution include the Apache-2.0 license and preserve
the source provenance in the Git repository. The wheel includes the CLI,
engine-owned code, schemas, catalog data, templates, the thin Analyzer skill,
and user documentation. The source archive includes historical and technical
documentation; it does not include local assessment output or fixture data.
Declared Python dependencies are PyYAML 6.x, jsonschema 4.x, and Jinja2 3.x;
the optional requirements extra adds requests and BeautifulSoup for retained
catalog-fetch tooling. Git is needed for local source admission. PDF, HTML,
and diagram exports may require separate external tools.

Inspect both archives before distribution. In particular, do not include the
temporary `scripts/run-headless.sh` compatibility wrapper, retired plugin
metadata and gates, test runner, source fixture `.env` files, or generated
reports. Check exact hashes in a local `SHA256SUMS` file beside the artifacts.
No push, tag, package upload, or release publication is part of this step.

## Qualification and compatibility limits

- `scan` needs neither Claude nor API credentials and makes no model calls.
- `assess --host claude-cli` is a compatibility adapter with offline fake-host
  end-to-end coverage. A real CLI session, model selection, and run cost have
  not been qualified here.
- Direct OpenAI Responses and fixed gateway transports have offline wire,
  decoder, egress, and budget tests. No model/depth/route profile is qualified;
  the public `assess` command refuses these hosts pending authorized live
  tests. Their prices must be reviewed against the actual billing route and
  fixed in a dated profile before use.
- `audit-requirements` accepts one local catalog and one repository. The
  historical Advisor plugin audit's remote catalog precedence, PDF output,
  and resume are not available at this boundary. This audit does not declare
  a complete security assessment.
- Historical Advisor run directories are not silently migrated. Resume needs
  compatible Analyzer state and an unchanged admitted source.

The [extraction record](internal/extraction/phase-a-record.md) identifies the
frozen source commit, historical mapping, checks, and current open work.
