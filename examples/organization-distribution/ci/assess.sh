#!/bin/sh
# Run only in a trusted job with explicitly approved model use.
set -eu
umask 077

: "${ASSESSMENT_REPO:?Set ASSESSMENT_REPO to the absolute checkout path}"
: "${ASSESSMENT_OUTPUT:?Set ASSESSMENT_OUTPUT to an absolute directory outside the checkout}"
case "$ASSESSMENT_REPO" in /*) ;; *) exit 2 ;; esac
case "$ASSESSMENT_OUTPUT" in /*) ;; *) exit 2 ;; esac

nordlicht-appsec organization validate

# exec preserves the engine's exit status, including paused runs and failed gates.
# Authentication is supplied by the runner's secret store, never by this file.
exec nordlicht-appsec scan \
  --repo "$ASSESSMENT_REPO" \
  --output "$ASSESSMENT_OUTPUT" \
  --non-interactive \
  --fail-on high
