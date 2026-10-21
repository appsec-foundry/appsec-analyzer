#!/bin/sh
# Explicit, manual live assessment of the bundled fixture through the public CLI.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REPO="$ROOT/tests/fixtures/e2e/synthetic-repo"
DEPTH=quick
BUDGET=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --repo) REPO=$2; shift 2 ;;
        --depth) DEPTH=$2; shift 2 ;;
        --budget) BUDGET=$2; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$DEPTH" in quick|standard|thorough) ;; *) echo "Invalid depth" >&2; exit 2 ;; esac
if [ -z "$BUDGET" ]; then
    echo "An explicit --budget USD is required for this manual live run" >&2
    exit 2
fi
command -v appsec-analyzer >/dev/null 2>&1 || { echo "Install appsec-analyzer first" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 2; }
[ -d "$REPO" ] || { echo "Repository does not exist: $REPO" >&2; exit 2; }

RUN_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/appsec-analyzer-e2e.XXXXXX")
OUTPUT="$RUN_ROOT/output"
mkdir -m 700 "$OUTPUT"
if [ "$REPO" = "$ROOT/tests/fixtures/e2e/synthetic-repo" ]; then
    cp -R "$REPO/." "$RUN_ROOT/repository"
    # Prior local runs may leave ignored output in the source fixture.
    rm -rf "$RUN_ROOT/repository/docs/security"
    git -C "$RUN_ROOT/repository" init -q
    git -C "$RUN_ROOT/repository" add -f .
    git -C "$RUN_ROOT/repository" -c user.name=appsec-e2e -c user.email=e2e@invalid commit -qm "E2E fixture baseline"
    REPO="$RUN_ROOT/repository"
fi

echo "Manual assessment output: $OUTPUT"
appsec-analyzer assess --host claude-cli --repo "$REPO" --output "$OUTPUT" \
    --hard-budget "$BUDGET" --assessment-depth "$DEPTH" \
    --requirements "$ROOT/examples/appsec-requirements-example.yaml" \
    --sarif --pentest-tasks
appsec-analyzer results --output "$OUTPUT" > "$RUN_ROOT/results.json"
python3 - "$RUN_ROOT/results.json" <<'PY'
import json
import sys

result = json.load(open(sys.argv[1], encoding="utf-8"))
required = {"security-assessment.md", "security-assessment.yaml",
            "security-assessment.sarif.json", "pentest-tasks.yaml"}
assert result["assessment_status"] == "complete"
assert required <= result["deliverables"].keys(), "missing expected deliverables"
PY
echo "Completed assessment and verified published results: $OUTPUT"
