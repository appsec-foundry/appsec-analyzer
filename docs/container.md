# Run Analyzer in a container

The container image runs one `appsec-analyzer` command and exits. Use it with Docker on your machine, or as a Job in OpenShift or Kubernetes. The image opens no network port and contains no credentials; you supply them when the container starts.

## What the image contains

- Analyzer from the checkout you build, with the version stamp of that checkout, as in an [installation from a checkout](../README.md#version).
- Python 3.12, Git, pandoc for HTML export, and Claude CLI 2.1.311 for the `claude` profile and for `analyze-threats`, `authnz-review`, and `audit-requirements`.
- The API profiles `codex`, `lite`, and `bedrock`, which need only their credentials and, for `lite` and `bedrock`, your [provider connections](providers.md).

The image leaves out:

- PDF export. It needs weasyprint, Mermaid CLI, and a browser, which would make the image several hundred MB larger. Create a PDF on another machine from the saved assessment with `appsec-analyzer export --assessment DIR --output NEW_DIR --formats pdf`.
- Codex CLI and Copilot CLI, so the `codex-cli` and `copilot-cli` profiles do not work in the container.
- Your Claude login. A login made with `claude login` on your machine does not carry into the container. Use Anthropic API credentials such as `ANTHROPIC_API_KEY`.

## Build the image

You need Docker or Podman and network access to Docker Hub, Debian, PyPI, and the npm registry. The build checks every download against a version and hash pinned in the [Dockerfile](../Dockerfile) and in [container/requirements.txt](../container/requirements.txt). The image supports `amd64` and `arm64`.

Run in the Analyzer checkout:

```sh
docker build -t appsec-analyzer .
```

To build with Podman, replace `docker` with `podman`; the run examples below are written for Docker. Uncommitted changes in the checkout go into the image, and `--version` then shows `+local changes`.

## Run with Docker

The user in the container must own the mounted checkout. Otherwise Git refuses it, and Analyzer stops with "The selected directory has a .git that Git cannot read". Which user that is depends on how Docker runs:

- Docker as a system service: your own user ID with group 0, `--user "$(id -u):0"`.
- Rootless Docker, where `docker info` lists `rootless` under security options: `--user 0:0`. Root in the container is then your own user and has no additional rights on your machine.

This command sets the right value for either case:

```sh
if docker info --format '{{.SecurityOptions}}' | grep -q rootless; then user=0:0; else user="$(id -u):0"; fi
```

Mount the source read-only and the result directory writable. Keep the result directory outside the analyzed repository. This example runs a standard assessment with the `claude` profile:

```sh
mkdir -p "$HOME/assessments"
docker run --rm --name appsec-assessment \
  --user "$user" \
  --env ANTHROPIC_API_KEY \
  --volume /path/to/project:/repo:ro \
  --volume "$HOME/assessments":/output \
  appsec-analyzer assess --repo /repo --output /output/project \
  --profile claude --standard --budget 20 --non-interactive
```

Replace `/path/to/project` with your checkout. `--env ANTHROPIC_API_KEY` without a value passes the variable from your shell, so the key does not appear in the command. The report is written to `$HOME/assessments/project`. Always pass `--output` on a mounted directory: without it, Analyzer writes into the container, and the results are lost when it exits.

Commands without model calls need no credentials:

```sh
docker run --rm --user "$user" \
  --volume /path/to/project:/repo:ro \
  appsec-analyzer score /repo
```

Further options:

- For a Git URL, pass it to `--repo` instead of mounting a checkout. For a private repository, also pass a read-only token with `--env APPSEC_GIT_TOKEN`. Never put a token into the URL.
- To use your [scan profiles](profiles.md) or provider connections, mount your configuration directory read-only: `--volume "$HOME/.config/appsec-analyzer":/home/analyzer/.config/appsec-analyzer:ro`.
- To pause a run, use `docker stop --time 60 appsec-assessment`. Analyzer keeps the accepted results and exits with code 3. Repeat the same command with `--resume` to continue. See [exit codes](headless-mode.md#running-and-resuming-an-assessment).

## Run as an OpenShift Job

The example [assessment-job.yaml](../examples/openshift/assessment-job.yaml) creates a volume for the results and a Job that runs one assessment of a Git repository. The pod runs with a random user ID, a read-only root file system, no added privileges, and no access to the Kubernetes API. It needs outbound HTTPS to the model provider and the Git host.

The Job does not retry a failed run, because a retry would start new paid model calls. Resume a paused run deliberately instead.

1. Build the image and push it to a registry your cluster can pull from:

   ```sh
   docker build -t registry.example.com/security/appsec-analyzer:1 .
   docker push registry.example.com/security/appsec-analyzer:1
   ```

2. Store the API key in a secret. The command reads the key from your shell variable, so it does not appear in your shell history:

   ```sh
   oc create secret generic appsec-analyzer-credentials \
     --from-literal=ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"
   ```

   For a private repository, add a read-only `APPSEC_GIT_TOKEN` to the same secret and remove the comment markers in the Job.

3. Copy the example and replace the image, the repository URL, the output directory, and the budget. Then start the Job:

   ```sh
   oc apply -f assessment-job.yaml
   oc logs -f job/appsec-assessment
   ```

4. Copy the results from the volume after the Job has finished. `oc debug` starts a copy of the Job's pod with a shell and the same volumes:

   ```sh
   oc debug job/appsec-assessment
   ```

   While that shell is open, run `oc rsync <debug-pod>:/output/project ./project-assessment` in a second terminal. `oc debug` prints the pod name when it starts.

If the run paused with exit code 3, delete the Job, add `--resume` to its arguments, and apply it again. The results on the volume remain.

Reports and intermediate files can contain sensitive code details. Restrict access to the namespace and its volume, and delete the volume when you no longer need it.
