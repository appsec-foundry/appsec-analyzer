# Package Analyzer for your organization

Your organization can ship its own command with its profiles already included. Users run `nordlicht-appsec assess`; they do not need to find a profile file or set a configuration environment variable. The Analyzer engine remains a separate dependency, so an engine update does not overwrite your organization's files.

This guide builds the fictional Nordlicht distribution from the [complete example](../examples/organization-distribution/README.md). All example names, addresses and business rules are fictional. The steps cover a local installation, an internal release and CI use. Nothing is uploaded or published by these commands.

## What you maintain

Keep an organization repository containing the following files:

```text
nordlicht-appsec/
├── pyproject.toml
├── setup.cfg
├── setup.py
├── requirements-build.lock
├── requirements.lock
├── requirements-dependencies.lock
├── ci/assess.sh
└── src/nordlicht_appsec/
    ├── cli.py
    ├── organization.yaml
    ├── org-profile.yaml
    ├── profiles/standard.yaml
    ├── profiles/release.yaml
    ├── model-profiles/nordlicht.yaml
    ├── context/organization.md
    ├── abuse-cases/orders.yaml
    └── requirements/orders.yaml
```

The engine repository contains the analysis code. Your repository contains configuration and a short launcher. There is no Git merge between these repositories. Your release selects an exact engine version and distributes the two wheels together.

The launcher is ordinary installed Python code:

```python
import sys


def main():
    try:
        from appsec_analyzer.organization import main as organization_main
    except ImportError:
        print("nordlicht-appsec: install the matching approved engine and dependency wheels", file=sys.stderr)
        return 2
    return organization_main("nordlicht_appsec")
```

The package name is supplied by your launcher. Analyzer does not search the application checkout for launchers or organization defaults, and it does not import arbitrary organization plugins.

## Before you start

Use Python 3.10 or later, Git, and a shell. The supplied dependency lock is for Python 3.10 on Linux. For another runner platform, resolve and review a lock for that platform. Build and runtime tools are installed into separate virtual environments.

You need a reviewed Analyzer source checkout. The current engine is an unpublished `0.1.0a0` preview, so this guide builds its wheel locally instead of assuming a public package release exists. Installation and the configuration checks below make no model calls. A full assessment requires provider setup and explicit approval to use model budget or plan allowance; see [provider configuration](profiles.md).

Run the commands in the following sections in one shell. Replace the two `/work` paths with your actual checkouts. Use your approved package index for dependency downloads; configure its authentication outside the repository.

## 1. Create the organization repository

To start under your organization's name, let the installed Analyzer create the files in a new or empty directory outside the engine checkout. The name is 2 to 30 lowercase letters and digits. The command writes only into that directory and makes no network request:

```sh
appsec-analyzer distribution init northstar /work/northstar-appsec
cd /work/northstar-appsec
git init -b main
```

The profiles, context, abuse cases and requirements it creates are sample content; replace them before a release. The later steps keep the fictional Nordlicht names, so replace `nordlicht` with your name when you follow them.

To keep the fictional names for a first installation, copy the example instead:

```sh
cp -R /work/appsec-analyzer/examples/organization-distribution /work/nordlicht-appsec
cd /work/nordlicht-appsec
git init -b main
```

`distribution init` already applies the following renames. Change them by hand only for a copy of the example:

| Name | Where to change it |
| --- | --- |
| Distribution name, such as `northstar-appsec` | `[metadata].name` in `setup.cfg`, and `requirements.lock` |
| Python package, such as `northstar_appsec` | The directory under `src/`, the package-data section and entry point in `setup.cfg`, and the resource package passed by `cli.py` |
| User command, such as `northstar-appsec` | The console-script name in `setup.cfg` and `command` in `organization.yaml` |
| Organization identity | `organization` in `org-profile.yaml`, plus any report attributes |

Keep credentials, source checkouts and assessment output out of this repository. The example `.gitignore` excludes local build output and virtual environments.

## 2. Set the defaults you want to ship

`src/nordlicht_appsec/organization.yaml` connects the installed files:

```yaml
schema_version: 1
engine_version: 0.1.0a0
interface_version: 1
command: nordlicht-appsec
scan_profile: profiles/standard.yaml
org_profile: org-profile.yaml
```

The engine and interface versions must match the installed Analyzer exactly. Resource paths must stay inside the package. Missing files, links, invalid profiles and incompatible versions stop the command with exit code 2; they do not select an upstream fallback.

The default scan profile contains the everyday assessment settings:

```yaml
schema_version: 1
description: Nordlicht standard assessment
model_profile: nordlicht
assessment_depth: standard
budget: 20
max_parallel: 2
outputs: [markdown, yaml, sarif]
```

The model profile named `nordlicht` is read from the sibling `model-profiles/nordlicht.yaml`, so a user's home-directory profiles cannot silently replace it. The [profile guide](profiles.md) explains the available model, scan and report settings. Put spending limits and exports in the scan profile; do not assume every inherited Advisor preset field controls the standalone CLI.

The org profile supplies the organization identity, report branding, context and organization abuse cases. The demo includes a question about reading another organization's order. Its context describes business assumptions; it does not establish that the assessed application enforces them.

The sample `requirements/orders.yaml` is for the separate [requirements audit](security-requirements-audit-skill.md). Shipping that file does not automatically enable it in a full assessment. There is no new remote catalog download in this example.

The installed launcher applies its defaults to `assess`. Other commands keep their documented behavior. The defaults are explicitly overridable:

```sh
nordlicht-appsec assess --repo /work/orders-service --budget 10
nordlicht-appsec assess --repo /work/orders-service --profile claude
nordlicht-appsec assess --repo /work/orders-service --no-org-profile
```

These are full assessments and may make model calls. A packaged org default takes precedence over `APPSEC_ADVISOR_ORG_PROFILE`; an explicit `--org-profile` or `--no-org-profile` takes precedence over the package. Existing engine controls remain enforced. This distribution mechanism does not make your defaults mandatory across every machine or prevent users from invoking the upstream command separately.

Advisor-only hooks, MCP declarations, added skills, skill toggles, banners, baseline installers, security-coach blocks and `llm_policy` are rejected in bundled profiles. They are not standalone Analyzer extension points.

## 3. Build the engine and organization wheels

Commit the organization files you intend to release. Build from clean clones so unrelated files and local edits cannot enter the release. The examples below use local repositories; a reviewed internal Git URL works as well.

```sh
git add .gitignore MANIFEST.in README.md pyproject.toml setup.cfg setup.py requirements.lock requirements-dependencies.lock requirements-build.lock src ci
git commit -m "Add organization assessment defaults"

ORG_REPO=/work/nordlicht-appsec
ENGINE_REPO=/work/appsec-analyzer
RELEASE_DIR="$(mktemp -d /tmp/nordlicht-release.XXXXXX)"

git clone --no-hardlinks "$ENGINE_REPO" "$RELEASE_DIR/engine-source"
git clone --no-hardlinks "$ORG_REPO" "$RELEASE_DIR/org-source"
git -C "$RELEASE_DIR/engine-source" rev-parse HEAD
git -C "$RELEASE_DIR/org-source" rev-parse HEAD
git -C "$RELEASE_DIR/engine-source" rev-parse HEAD > "$RELEASE_DIR/ENGINE_COMMIT"
git -C "$RELEASE_DIR/org-source" rev-parse HEAD > "$RELEASE_DIR/ORG_COMMIT"
```

Confirm that these are the reviewed commits before continuing. Two different engine commits can currently share the preview version `0.1.0a0`; keep the selected commit IDs with your release record and never mix their wheels under one approved release.

Build with the pinned tools:

```sh
python3 -m venv "$RELEASE_DIR/build-env"
"$RELEASE_DIR/build-env/bin/python" -m pip install \
  -r "$RELEASE_DIR/org-source/requirements-build.lock"
"$RELEASE_DIR/build-env/bin/python" -m build --no-isolation \
  --outdir "$RELEASE_DIR/engine-dist" "$RELEASE_DIR/engine-source"
"$RELEASE_DIR/build-env/bin/python" -m build --no-isolation \
  --outdir "$RELEASE_DIR/org-dist" "$RELEASE_DIR/org-source"
```

The organization build produces `nordlicht_appsec-1.0.0-py3-none-any.whl` and its source archive. Its metadata requires `appsec-analyzer==0.1.0a0`. The Python package includes both profiles and their referenced data; the organization profile is not an extra file that users must copy after installation.

## 4. Prepare and install the runtime release

Download only the public runtime dependencies into a dedicated wheelhouse. This step uses your configured package index. Copy the private engine and organization wheels directly from the reviewed builds; do not query a public index for internal package names. All packages must have wheels for the selected Python and platform; if one is missing, fix the lock or build and review the required wheel instead of allowing an unexpected source build on a runner.

```sh
"$RELEASE_DIR/build-env/bin/python" -m pip download \
  --only-binary=:all: \
  --no-deps \
  --dest "$RELEASE_DIR/wheelhouse" \
  -r "$RELEASE_DIR/org-source/requirements-dependencies.lock"
cp "$RELEASE_DIR/engine-dist/"*.whl "$RELEASE_DIR/wheelhouse/"
cp "$RELEASE_DIR/org-dist/"*.whl "$RELEASE_DIR/wheelhouse/"
cp "$RELEASE_DIR/org-source/requirements-dependencies.lock" "$RELEASE_DIR/requirements-dependencies.lock"
cp "$RELEASE_DIR/org-source/requirements.lock" "$RELEASE_DIR/requirements.lock"
cp -R "$RELEASE_DIR/org-source/ci" "$RELEASE_DIR/ci"
cd "$RELEASE_DIR"
sha256sum wheelhouse/*.whl requirements.lock requirements-dependencies.lock ci/assess.sh ENGINE_COMMIT ORG_COMMIT > SHA256SUMS
```

Review the archives, the resolved dependency versions and their advisories before approval. The example pins Jinja 3.1.6, whose upstream [release notes](https://github.com/pallets/jinja/releases/tag/3.1.6) describe its security fixes. A lock records a chosen set; it is not a guarantee that later advisories do not affect that set. Commit lock changes in the organization repository when preparing the next release.

Keep `wheelhouse/`, both runtime lock files, `SHA256SUMS` and the reviewed source commit IDs together as one approved internal release. Deliver the checksum file through the trusted release channel with the artifacts. A checksum supplied by an untrusted pull request does not establish approval.

Install into a new environment, with downloads and dependency resolution disabled:

```sh
sha256sum --check SHA256SUMS
python3 -m venv "$RELEASE_DIR/runtime-env"
"$RELEASE_DIR/runtime-env/bin/python" -m pip install \
  --no-index --no-deps --only-binary=:all: \
  --find-links "$RELEASE_DIR/wheelhouse" \
  -r "$RELEASE_DIR/requirements.lock"
"$RELEASE_DIR/runtime-env/bin/python" -m pip check
```

## 5. Check what users receive

Change to a directory outside both source checkouts. These checks run without provider credentials or model calls:

```sh
cd /tmp
"$RELEASE_DIR/runtime-env/bin/nordlicht-appsec" version
"$RELEASE_DIR/runtime-env/bin/nordlicht-appsec" organization show
"$RELEASE_DIR/runtime-env/bin/nordlicht-appsec" organization validate
```

`version` includes the organization ID and profile version. `organization show` identifies the installed default files. `organization validate` validates the manifest, engine/interface match, default scan and model profiles at all depths, and the organization profile with its referenced files. It does not contact a provider or establish assessment quality.

To check a real project without a model, run:

```sh
"$RELEASE_DIR/runtime-env/bin/nordlicht-appsec" scan-sources \
  --repo /work/orders-service
```

A full run needs approved provider use. The default example uses Claude and a USD 20 maximum:

```sh
"$RELEASE_DIR/runtime-env/bin/nordlicht-appsec" assess \
  --repo /work/orders-service \
  --output /private/assessments/orders-service \
  --non-interactive
```

Use a real Git checkout and an output directory outside it. Configure authentication outside the package through the supported provider mechanism. See [assessment operations](security-assessment.md) for source admission, outputs and resume limits.

## 6. Use the release in CI

Separate the checks that need no model from the job authorized to spend budget. An organization-package change can run `organization validate` and a deterministic `scan-sources` check without a provider secret. A full assessment should run only in a trusted job for which model use has been approved.

Give the runner read-only repository/package access. Install a release from a trusted internal artifact location, not from an untrusted pull-request branch. Verify the approved `SHA256SUMS`, install the locked wheelhouse as in step 4, run `pip check`, and place the runtime environment's `bin` directory on `PATH`.

The example includes `ci/assess.sh`. Configure these variables in the trusted job:

```sh
export PATH="/opt/nordlicht-runtime/bin:$PATH"
export ASSESSMENT_REPO=/work/orders-service
export ASSESSMENT_OUTPUT=/private/assessments/orders-service
sh /work/nordlicht-appsec/ci/assess.sh
```

The script validates the installed organization package and runs the assessment with `--non-interactive --fail-on high`. It preserves the exit status and never raises a spending limit by answering a prompt. Authentication comes from the runner's approved provider setup. For the OpenAI API adapter, use an appropriate bundled model profile and a secret-managed `OPENAI_API_KEY`. The default Claude adapter needs its supported credentials and executable on the runner. Do not put secrets in YAML, a wheel, shell arguments, or build logs.

Do not run this secret-bearing job on untrusted pull-request code. For forked contributions, run the secret-free checks first and require the organization's trusted approval path for a model-backed job. Analyzer's provider isolation does not make the surrounding CI workflow trustworthy.

Handle statuses explicitly:

| Exit code | Meaning | CI handling |
| --- | --- | --- |
| `0` | Assessment completed and the selected gate passed | Keep the reports |
| `20` | Assessment completed; the explicit findings gate failed | Fail the gate and keep the reports |
| `3` | Paused, incomplete, or refused before completion | Keep diagnostics; inspect the cause before a compatible resume |
| `130` | Operator or signal interruption | Keep diagnostics and accepted work |
| `1` or `2` | Operational, configuration or invocation error | Fail the job and inspect its diagnostic |

Without an explicit gate, findings remain advisory. The example's `--fail-on high` checks new findings at high severity or above according to the engine's existing gate. It does not convert an unfinished assessment into a passing result.

Collect output on failure as well as success. Reports and retained runtime state can contain proprietary source and analysis, so use private CI artifacts with restricted access and an appropriate retention period. Resume requires compatible sources, configuration, runtime and paths within the original deadline. Updating the engine or moving the installed profiles to another path can invalidate resume; do not promise that a different runner can resume an arbitrary saved directory.

### GitLab example

The example package contains `ci/gitlab-ci.yml.example`. Copy its job into the assessed application's reviewed pipeline configuration. It requires GitLab 18.4 or later for `artifacts:access: maintainer`, a protected shell runner tagged `appsec-trusted`, Python 3.10, Git, a supported Claude executable and authentication, and a read-only copy of the approved release at `/opt/appsec-releases/nordlicht-1.0.0`. Adjust these paths and the runner tag for your installation. No container image or external CI action is downloaded by the example.

The job is manual and restricted to protected refs outside merge-request pipelines. Configure the runner as protected and keep provider credentials in protected CI variables or the runner's approved credential mechanism. A manual button alone is not an authorization boundary; control who may change or run the protected pipeline. GitLab documents [merge-request secret exposure](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/) and the [pipeline rules and artifact settings](https://docs.gitlab.com/ci/yaml/).

Use a private project and restrict CI/CD visibility to project members. Review the job-token allowlist and downstream artifact forwarding: `artifacts:access` restricts UI/API downloads but does not replace those project controls.

The job verifies and installs the locked wheelhouse, validates the organization package, and runs the assessment. Its runtime and assessment directories are outside the assessed checkout. After the scan, it stages only generated `security-assessment.*` files into a newly created artifact directory. Artifact access is limited to maintainers, retention is one week, and collection runs on failed jobs too. Adjust retention to your policy. This published-report archive is not a portable resume bundle. Validate the YAML with your GitLab instance's CI Lint before enabling it; local tests do not exercise a hosted runner.

## 7. Release an update

For a configuration-only update, keep the engine pin and change the organization version in `setup.cfg`, `requirements.lock`, `org-profile.yaml` and any report-version attributes. Rebuild the org wheel and the approved wheelhouse. Test against the selected engine before distributing it.

For an engine update, select a reviewed upstream release or commit, install that engine, and run `appsec-analyzer distribution update-engine /work/nordlicht-appsec`. It sets these pins together to the installed engine and changes nothing if one of them is missing:

1. The `appsec-analyzer` dependency in `setup.cfg`.
2. The engine entry in `requirements.lock`.
3. `engine_version` and `interface_version` in `organization.yaml`.

It does not rebuild anything, and it cannot tell apart two engine commits that share a version.

Review the org profile's compatibility range as well. Build the new engine and organization wheels, validate the installed package, and run your reference projects before approval. Offline checks do not replace live provider qualification when model behavior or the provider changes. Keep the previous approved release for rollback.

## Troubleshooting

If `organization validate` reports an incompatible engine, install the matching engine and organization wheels together. Do not change only the manifest to silence the mismatch.

If a bundled file is missing, check the package-data entries in `setup.cfg` and inspect the wheel. Editing a file in the source checkout does not change an already installed wheel; rebuild with a new organization version and reinstall it.

If a scan profile names a custom model profile, keep `profiles/` and `model-profiles/` next to each other. A packaged profile does not resolve its model names from a user's home directory.

If an inherited org profile contains Advisor hooks, skill toggles or plugin packaging keys, remove those unsupported declarations from the standalone distribution and express supported settings through scan/model/org profiles. Their presence must not be mistaken for active enforcement.

<a id="engine-only-configuration-for-a-composed-score-plugin"></a>
## Engine-only configuration for a composed plugin

`organization-config` lets a host pass engine settings through the [organization-config schema](../schemas/organization-config.schema.json). It is separate from the installed distribution launcher. The file names the exact `engine_version`, the selected `advisor_core_version`, and an engine-only `profile`. `compatibility.core` applies to the Advisor version. Hooks, MCP declarations, banners, skills, and coaching do not belong in this file.

Use `organization-config validate --config /installed/plugin/org-profile/analyzer-config.yaml` or `organization-config show --config /installed/plugin/org-profile/analyzer-config.yaml --preset release` for model-free inspection. An explicit inspection `--assessment-depth quick` overrides the selected preset default without changing profile-wide policy. Missing or invalid profiles, unsupported fields, incompatible versions, source-owned configuration and unknown presets fail without upstream fallback. Files use the existing bounded, data-only YAML reader without links, duplicate keys or aliases.

Run a configured workflow with `organization-config run --config /installed/plugin/org-profile/analyzer-config.yaml -- score /source/repository --json`. Version 1 supports `score` and `assess` and declares `profile_source_validation: true`. It accepts base-mode presets plus `policy.disable_opus` and `policy.url_allowlist`.

Score makes no model calls and uses no assessment depth, exports, or branding. A preset depth is visible during inspection but does not change scoring. A nonempty URL allowlist restricts remote Git targets to an exact hostname or dotted subdomain before Git runs or credentials are used. Existing address and redirect checks still apply. Inner score arguments cannot weaken the policy. Output and exit status stay unchanged.

This interface rejects other profile fields and workflows. Use the assessment/distribution path for unsupported fields. Spend guidance does not become a hard limit, and agent instructions do not become executable policy. Organization restrictions apply only when this configuration is explicitly selected. Offline configuration checks do not verify real model or platform behavior.

For full assessments, use the same public envelope with `organization-config run --config /installed/plugin/org-profile/analyzer-config.yaml -- assess --repo /source/repository`. Running it may use models and requires separate authorization. Only the existing base-mode presets and the two policy fields are admitted. A selected preset supplies depth unless the inner CLI explicitly sets `--assessment-depth`; scan/model profiles and direct CLI budget/export options keep their existing behavior. Opus selections on the Claude path are clamped before host preflight and again by the existing controller; unknown or Opus-family provider models fail the restriction before credentials are used.

Inspect the same invocation without source access, credentials or models with `organization-config show --config /installed/plugin/org-profile/analyzer-config.yaml -- assess --repo /source/repository --assessment-depth quick`. Inspection resolves supported profile settings, checks policy and reports the effective `assessment_profile`; it does not execute an assessment. `validate` accepts the same optional workflow arguments. Invalid arguments and disallowed destinations fail instead of selecting a default workflow. Control option names must be exact; abbreviations are refused.

Hosts that copy an external Advisor profile must pass its original canonical path as outer `--profile-source FILE`, before `--`. Analyzer checks that path and the engine configuration against every selected repository. Inner profile or preset options cannot replace the outer selection. Advisor handles its explicit no-profile choice before dispatch.

CLI context and requirements destinations are checked against the URL policy before provider setup. Later context readers receive the effective-profile file. For composed configurations, `APPSEC_URL_ALLOWLIST` cannot widen the mandatory allowlist. Other organization-profile paths keep their earlier behavior.

The controller receives validated organization settings as data, with a content hash and no filesystem profile path. A temporary copied profile does not become a resume identity or an actor/abuse-case profile. Context capture saves supported policy in `.org-profile-effective.json`. Changing policy or preset changes session identity; moving an otherwise identical configuration does not. This handoff does not migrate hooks, UI, or saved-result workflows.
