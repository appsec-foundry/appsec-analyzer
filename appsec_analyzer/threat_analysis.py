"""Compatibility import for the analyze-threats terminal adapter."""

import sys

from appsec_analyzer.analyze_threats import cli

sys.modules[__name__] = cli
