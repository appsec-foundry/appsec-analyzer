#!/bin/sh
# Temporary compatibility delegate. The Analyzer CLI owns all assessment logic.
exec appsec-analyzer assess "$@"
