# Nordlicht AppSec distribution

This is an installable example for a fictional organization. It uses the upstream Analyzer engine unchanged and installs a separate `nordlicht-appsec` command. Its profiles, context and abuse cases are included in the organization wheel.

The default assessment uses Claude, standard depth, a USD 20 limit, and Markdown, YAML and SARIF output. It makes model calls. The example does not include credentials or establish that a provider has passed live qualification.

## Build and install

Use Python 3.10 or later and Git. Start from a copy of this directory in your own organization repository. Build the matching Analyzer wheel from a reviewed upstream checkout first. The engine dependency and `src/nordlicht_appsec/organization.yaml` both select `0.1.0a0`.

Create a build environment and use your approved package index to install the pinned build tools:

```sh
python3 -m venv /tmp/nordlicht-build
/tmp/nordlicht-build/bin/python -m pip install -r requirements-build.lock
/tmp/nordlicht-build/bin/python -m build --no-isolation --outdir /tmp/nordlicht-dist .
```

Create a runtime environment. Place the reviewed Analyzer wheel in `/tmp/analyzer-dist` and the organization wheel in `/tmp/nordlicht-dist`. Download the exact runtime dependencies into a wheelhouse through your approved package index:

```sh
python3 -m venv /tmp/nordlicht-runtime
/tmp/nordlicht-runtime/bin/python -m pip download \
  --only-binary=:all: \
  --no-deps \
  --dest /tmp/nordlicht-wheelhouse \
  -r requirements-dependencies.lock
cp /tmp/analyzer-dist/*.whl /tmp/nordlicht-wheelhouse/
cp /tmp/nordlicht-dist/*.whl /tmp/nordlicht-wheelhouse/
/tmp/nordlicht-runtime/bin/python -m pip install \
  --no-index --find-links /tmp/nordlicht-wheelhouse \
  -r requirements.lock
/tmp/nordlicht-runtime/bin/python -m pip check
```

`requirements.lock` includes the pinned public dependencies from `requirements-dependencies.lock`. Private engine and organization wheels are copied from the reviewed builds; their names are never resolved against a public index. This is an example runtime lock for Python 3.10 on Linux. Review it and resolve a fresh lock for your supported runner platforms before releasing your own distribution. Review dependency advisories when updating. Build tools are pinned separately in `requirements-build.lock`.

## Check the installation without model calls

Run these commands from a directory outside both source checkouts:

```sh
/tmp/nordlicht-runtime/bin/nordlicht-appsec version
/tmp/nordlicht-runtime/bin/nordlicht-appsec organization show
/tmp/nordlicht-runtime/bin/nordlicht-appsec organization validate
```

The last command returns `valid: true` only when the installed engine version, manifest, default scan/model profiles and organization profile validate. Missing bundled files stop the command with exit code 2. The launcher never searches the assessed repository for its defaults.

## Assess a project

The following command sends selected source and context to the configured provider and may spend up to the default USD 20 limit. Run it only after authorizing that use and configuring the provider outside the package:

```sh
/tmp/nordlicht-runtime/bin/nordlicht-appsec scan \
  --repo /work/orders-service \
  --output /private/assessments/orders-service \
  --non-interactive
```

Choose a real Git checkout and an output directory outside it. For a scan without an AI account or model calls, use `nordlicht-appsec scan-sources --repo /work/orders-service`. Organization assessment defaults are applied only to `scan` and `assess`.

## Change the example

Rename the distribution in `setup.cfg`, rename the `nordlicht_appsec` package directory, and update the import and resource-package name in `cli.py`. Set the console command in both `setup.cfg` and `organization.yaml`. Edit the model/scan profiles and `org-profile.yaml` for your organization.

Keep the organization release version in `setup.cfg`, `requirements.lock`, `org-profile.yaml` and any report attributes aligned. To update the engine, change its exact dependency in `setup.cfg`, its entry in `requirements.lock`, and `engine_version` in `organization.yaml` together. Rebuild and retest both wheels. Never publish different wheel contents under the same version.

The organization profile is a default. Users may select another scan profile with `--profile`, another organization profile with `--org-profile`, or explicitly use `--no-org-profile`. The packaged default takes precedence over `APPSEC_ADVISOR_ORG_PROFILE`. Existing core controls remain enforced; this package is not an organization-wide enforcement boundary.

The bundled `requirements/orders.yaml` is a sample for a separate requirements audit. It is not automatically enabled in a full assessment. Context and abuse cases are declarations to assess, not evidence that the application implements a control.

## Run in CI

Install the approved wheelhouse into an isolated runner environment. Put that environment's `bin` directory on `PATH`, configure provider authentication through the CI secret store, and set absolute paths:

```sh
export PATH="/opt/nordlicht-runtime/bin:$PATH"
export ASSESSMENT_REPO=/work/orders-service
export ASSESSMENT_OUTPUT=/private/assessments/orders-service
sh ci/assess.sh
```

The job requires explicit approval to consume model allowance or budget. It runs noninteractively and preserves the engine exit status. Collect the private output directory on failure as well as success. Do not run a secret-bearing job on untrusted pull-request code. See the organization distribution guide shipped with Analyzer for the full packaging, integrity, update and CI procedures.

`ci/gitlab-ci.yml.example` is a concrete protected-runner job for the assessed application's pipeline. It expects an approved release mounted read-only on the runner, makes model-backed assessment a manual job on protected refs, and collects generated reports as maintainer-only artifacts. Review it with your CI administrator and validate it with your GitLab instance's CI Lint before use.
