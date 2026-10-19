"""Bundled role metadata shared by profiles, context routing and orchestration."""

from typing import Any

from appsec_analyzer import resource_root

PLUGIN_ROOT = resource_root()

SEMANTIC_ROLE_REGISTRY: dict[str, dict[str, Any]] = {
    "abuse_case_deriver": {
        "agent": "appsec-abuse-case-deriver",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-abuse-case-deriver.md",
        "tools": ("Read", "Bash", "Write"),
        "output_contracts": ("schemas/abuse-case-deriver-output.schema.json",),
    },
    "abuse_case_verifier": {
        "agent": "appsec-abuse-case-verifier",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-abuse-case-verifier.md",
        "tools": ("Read", "Grep", "Bash", "Write"),
        "output_contracts": ("schemas/fragments/verdict.schema.json",),
    },
    "actor_discoverer": {
        "agent": "appsec-actor-discoverer",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-actor-discoverer.md",
        "tools": ("Read", "Glob", "Grep", "Bash", "Write"),
        "output_contracts": ("schemas/actors-discovered.schema.yaml",),
    },
    "architecture_analyst": {
        "agent": "appsec-architecture-analyst",
        "instruction": PLUGIN_ROOT / "data" / "architecture-analysis-policy.md",
        "tools": (),
        "output_contracts": ("schemas/multi-repo-architecture.schema.json",),
    },
    "control_analyst": {
        "agent": "appsec-control-analyst",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-control-analyst.md",
        "tools": ("Read", "Grep", "Bash", "Write"),
        "output_contracts": (
            "schemas/fragments/security-controls.schema.json",
            "schemas/stride-analyst-context.schema.json",
        ),
    },
    "architect_reviewer": {
        "agent": "appsec-architect-reviewer",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-architect-reviewer.md",
        "tools": ("Read", "Write"),
        "output_contracts": ("schemas/architect-review-proposals.schema.json",),
    },
    "evidence_verifier": {
        "agent": "appsec-evidence-verifier",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-evidence-verifier.md",
        "tools": ("Read", "Bash", "Write"),
        "output_contracts": ("schemas/evidence-verification.schema.json",),
    },
    "post_stride_synthesizer": {
        "agent": "appsec-post-stride-synthesizer",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-post-stride-synthesizer.md",
        "tools": ("Read", "Bash", "Write"),
        "output_contracts": (
            "schemas/fragments/mitigation-overrides.schema.json",
            "schemas/fragments/tier-root-causes.schema.json",
        ),
    },
    "recon_scanner": {
        "agent": "appsec-recon-scanner",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-recon-scanner.md",
        "tools": ("Read", "Glob", "Grep", "Bash", "Write"),
        "output_contracts": (
            "contract:recon-summary-markdown-v1",
            "schemas/recon-signals.schema.json",
        ),
    },
    "stride_analyzer": {
        "agent": "appsec-stride-analyzer-v2",
        "instruction": PLUGIN_ROOT / "data" / "stride-analysis-policy.md",
        "tools": (),
        "output_contracts": ("schemas/stride.schema.yaml",),
    },
    # REQ-040 pilot: the test cases of one aspect for one component, and the open review of one component.
    "test_case_investigator": {
        "agent": "appsec-test-case-investigator",
        "instruction": PLUGIN_ROOT / "data" / "test-case-investigation-policy.md",
        "tools": (),
        "output_contracts": ("schemas/test-case-investigation.schema.json",),
    },
    "open_reviewer": {
        "agent": "appsec-open-reviewer",
        "instruction": PLUGIN_ROOT / "data" / "open-review-policy.md",
        "tools": (),
        "output_contracts": ("schemas/open-review.schema.json",),
    },
    "threat_merger": {
        "agent": "appsec-threat-merger",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-threat-merger.md",
        "tools": ("Read", "Bash", "Write"),
        "output_contracts": ("schemas/merge-decisions.schema.json",),
    },
    "triage_validator": {
        "agent": "appsec-triage-validator",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-triage-validator.md",
        "tools": ("Read", "Glob", "Grep", "Bash", "Write"),
        "output_contracts": (
            "schemas/triage-flags.schema.yaml",
            "schemas/threats-merged.schema.yaml",
        ),
    },
    "trust_boundary_analyst": {
        "agent": "appsec-trust-boundary-analyst",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-trust-boundary-analyst.md",
        "tools": ("Read", "Grep", "Write", "Bash"),
        "output_contracts": ("schemas/fragments/trust-boundary-candidates.schema.json",),
    },
}

SEMANTIC_ROLE_MODEL_KEYS = {
    "abuse_case_deriver": "abuse_verifier_model",
    "abuse_case_verifier": "abuse_verifier_model",
    "actor_discoverer": "actor_discovery_model",
    "architecture_analyst": "orchestrator_model",
    "architect_reviewer": "architect_model",
    "control_analyst": "orchestrator_model",
    "evidence_verifier": "evidence_verifier_model",
    "post_stride_synthesizer": "triage_model",
    "recon_scanner": "recon_scanner_model",
    "stride_analyzer": "stride_model",
    "test_case_investigator": "stride_model",
    "open_reviewer": "stride_model",
    "threat_merger": "merger_model",
    "triage_validator": "triage_model",
    "trust_boundary_analyst": "orchestrator_model",
}

RENDERER_MODEL_KEYS = {"ms_renderer": "renderer_model", "secarch_renderer": "renderer_model"}

# Roles that run with another role's model settings. They are not profile roles:
# adding them to the scan profiles would change every profile's identity.
PROFILE_ROLE_ALIASES = {"test_case_investigator": "stride_analyzer", "open_reviewer": "stride_analyzer"}


def profile_role(role: str) -> str:
    """The role whose settings in a model profile apply to ``role``."""
    return PROFILE_ROLE_ALIASES.get(role, role)
