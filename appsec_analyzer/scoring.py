"""Compatibility import for repository scoring."""

import sys

from appsec_analyzer.score import service
from appsec_analyzer.score.render import render_text

service.render_text = render_text
sys.modules[__name__] = service
