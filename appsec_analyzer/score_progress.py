"""Compatibility import for the score progress module."""

import sys

from appsec_analyzer.score import progress

sys.modules[__name__] = progress
