# Prepare a requirements catalog

The standalone audit accepts a local YAML catalog. Start with [the demonstration catalog](../examples/appsec-requirements-example.yaml), adapt its requirements, then pass its file path to `audit-requirements --requirements`. This catalog is separate from the repository's [product requirements](../requirements.md), which describe Analyzer itself.

```sh
mkdir -m 700 /tmp/analyzer-catalog-audit
appsec-analyzer audit-requirements --repo /path/to/project \
  --requirements /path/to/catalog.yaml --output /tmp/analyzer-catalog-audit \
  --host claude-cli --budget 5 --md
```

Use a fresh output directory. The example budget must be authorized before running. The audit needs a catalog with at least one selected requirement; a blueprint-only document is insufficient. Remote catalog URLs and audit resume are not supported by this public command.

## Harvest existing pages

The retained maintainer tool `scripts/requirements/harvest_requirements.py` can extract a catalog from HTML pages. It runs from a source checkout with the requirements extra installed. It is not a public `appsec-analyzer` subcommand.

Copy [the configuration example](../scripts/harvest-config.example.json) to a private location, set the reviewed source URLs and an explicit output, and run:

```sh
python3 scripts/requirements/harvest_requirements.py \
  --config /private/harvest-config.json --dry-run --verbose
python3 scripts/requirements/harvest_requirements.py \
  --config /private/harvest-config.json --format yaml
```

A dry run still fetches remote pages. Configure authentication through the environment variable named by `request.auth_header_env`; keep tokens out of configuration, command-line arguments, and source control. The configured output path is relative to the configuration file. Without an output setting, the script uses `requirements.yaml` beside that file.

A minimal source configuration has this shape; replace the example URL with an authorized source:

```json
{
  "description": "Team security requirements",
  "output": "requirements.yaml",
  "request": {
    "timeout_seconds": 15,
    "auth_header_env": "HARVEST_AUTH_TOKEN",
    "verify_ssl": true
  },
  "sources": [
    {
      "id": "team-requirements",
      "type": "requirement",
      "mode": "structured",
      "title": "Team security requirements",
      "crawl_url": "https://requirements.example.com/security"
    }
  ]
}
```

The crawler reads static HTML and direct same-origin child links below the configured path, bounded by `max_pages`. It does not render a JavaScript application. Use explicit source entries for pages outside that navigation scope. Review the extracted requirements and provenance before using the catalog as an obligation.

## Validate and export

Validate the resulting YAML against the [catalog schema](../schemas/requirements-catalog.schema.yaml):

```sh
python3 scripts/requirements/requirements_state.py --validate /private/requirements.yaml --strict
```

Sources default to `outputs: ["catalog"]`. For sources that describe observable application behavior, you can also select `openspec` or `specdd`. The `--format openspec|specdd|all` option filters the configured outputs; it cannot enable a format the source does not declare. Only mandatory requirements enter functional-spec exports. See the [examples](../examples/README.md) for output formats.

The harvester also supports blueprint sources and per-source `catalog_file` outputs. Those files provide supporting guidance; they are not independent audit catalogs unless they contain requirements.

The mock server in the source checkout is for development with synthetic data. You do not need it for a local audit.
