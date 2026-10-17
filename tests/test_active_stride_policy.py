"""The Analyzer's STRIDE exchange receives analysis rules without legacy tools."""

from __future__ import annotations

from orchestrator.orchestration_controller import SEMANTIC_ROLE_REGISTRY, _assessment_role_instructions


def test_active_stride_prompt_has_evidence_rules_and_no_removed_tool_procedure() -> None:
    role = SEMANTIC_ROLE_REGISTRY["stride_analyzer"]
    prompt = _assessment_role_instructions("stride_analyzer", "Assess the supplied component.")
    assert role["tools"] == ()
    assert "all six categories" in prompt.lower()
    assert "source evidence served by the controller" in prompt
    assert "agent_progress.sh" not in prompt
    assert "stride_attempt_writer.py" not in prompt
    assert "CLAUDE_PLUGIN_ROOT" not in prompt
