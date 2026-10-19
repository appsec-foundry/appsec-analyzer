"""Static guard for the explicitly invoked, potentially paid CLI smoke driver."""

from pathlib import Path

ROOT = Path(__file__).parent.parent
RUN_FULL = ROOT / "tests" / "e2e" / "run-full.sh"
RUN_FIXTURE_SUITE = ROOT / "tests" / "e2e" / "run-fixture-suite.sh"
MAKEFILE = ROOT / "Makefile"


def test_manual_full_driver_uses_public_cli_and_explicit_budget() -> None:
    text = RUN_FULL.read_text(encoding="utf-8")
    assert "appsec-analyzer scan --host claude-cli" in text
    assert 'if [ -z "$BUDGET" ]; then' in text
    assert '--hard-budget "$BUDGET"' in text
    assert "scripts/run-headless.sh" not in text
    assert "CLAUDE_PLUGIN_ROOT" not in text
    assert 'git -C "$RUN_ROOT/repository" init -q' in text
    assert "appsec-analyzer results --output" in text
    assert "security-assessment.yaml" in text


def test_manual_make_targets_require_cost_limit() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    for target in (
        "e2e-full",
        "e2e-full-standard",
        "e2e-full-thorough",
        "analyze-verify",
        "e2e-fixture-suite",
        "e2e-controller-live",
    ):
        assert f"\n{target}:" in text
        recipe = text.split(f"\n{target}:", 1)[1].split("\n\n", 1)[0]
        assert 'test -n "$(BUDGET)"' in recipe, target
    assert '--budget "$(BUDGET)"' in text
    assert 'APPSEC_FIXTURE_E2E_HARD_BUDGET="$(BUDGET)"' in text
    assert "$(or $(BUDGET)," not in text
    assert "e2e-full-repair:" not in text
    assert "e2e-full-eval:" not in text


def test_oracle_is_outside_scanned_fixture() -> None:
    fixture = (ROOT / "tests" / "fixtures" / "e2e" / "synthetic-repo").resolve()
    oracle = (ROOT / "tests" / "fixtures" / "e2e" / "oracle" / "expected-signals.json").resolve()
    assert fixture not in oracle.parents


def test_external_fixture_suite_covers_all_declared_languages() -> None:
    script = RUN_FIXTURE_SUITE.read_text(encoding="utf-8")
    assert "e2e-fixture-suite:" in MAKEFILE.read_text(encoding="utf-8")
    for fixture in (
        "spring-boot-threat-fixture",
        "python-threat-fixture",
        "rust-threat-fixture",
        "go-threat-fixture",
        "node-typescript-threat-fixture",
        "python-langchain-llm-threat-fixture",
        "aws-terraform-threat-fixture",
        "npm-supply-chain-threat-fixture",
        "fifty-service-threat-fixture",
    ):
        assert fixture in script
    assert "--clean-output" in script
