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


def test_active_architecture_prompt_matches_the_toolless_finalized_component_job() -> None:
    role = SEMANTIC_ROLE_REGISTRY["architecture_analyst"]
    prompt = _assessment_role_instructions("architecture_analyst", "Analyze the supplied repository.")
    assert role["tools"] == ()
    assert role["output_contracts"] == ("schemas/multi-repo-architecture.schema.json",)
    assert "Components and their source ownership are already fixed" in prompt
    assert "Use only source evidence served by the controller" in prompt
    assert "sequence requires unique integer steps" in prompt
    assert "known, evidenced authentication methods" in prompt
    assert "same from, from_entity, to, to_entity, protocol, direction" in prompt
    for obsolete in (
        "DISCOVERY_TOOL_CALL_LIMIT",
        "PUBLICATION_TOOL_CALL_RESERVE",
        "reserve_ids.py",
        "AGENT_START",
        "AGENT_END",
        ".components.json",
        "maxTurns:",
        "tools:",
    ):
        assert obsolete not in prompt
