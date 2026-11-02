"""REQ-012/013: actionable mitigation cards without repeated or invented guidance."""

import shutil
from copy import deepcopy
from pathlib import Path

import pytest
from renderers import compose_threat_model as compose

from tests.test_compose_threat_model_cov import _mk_ctx


def _finding(identifier="T-001", **changes):
    return {
        "id": identifier,
        "title": "SQL injection in product search",
        "risk": "Critical",
        "cwe": "CWE-89",
        "evidence": [{"file": "routes/search.ts", "line": 23}],
        **changes,
    }


def _mitigation(identifier="M-001", **changes):
    return {
        "id": identifier,
        "title": "Parameterize product search",
        "kind": "fix",
        "priority": "P1",
        "effort": "Low",
        "threat_ids": ["T-001"],
        "steps": ["Bind the search term as a query parameter."],
        "verification": "Confirm injection input returns no account records.",
        "file": "routes/search.ts:23",
        **changes,
    }


def _render(tmp_path, mitigations, findings=None):
    model = {"mitigations": mitigations, "threats": [_finding()] if findings is None else findings}
    before = deepcopy(model)
    ctx = _mk_ctx(tmp_path, yaml_data=model)
    text = compose._render_mitigation_register(ctx, None, {"heading": "## 10. Mitigation Register"})
    assert model == before
    return text


def test_register_starts_with_priority_cards_and_preserves_every_link_target(tmp_path):
    cards = [
        _mitigation("M-003", priority="P3", title="Review the query layer"),
        _mitigation("M-001"),
        _mitigation("M-002", priority="P2", title="Add input boundary checks"),
    ]
    text = _render(tmp_path, cards)
    assert "Mitigations index" not in text
    assert "M-001" not in text.split("### P1 — Immediate", 1)[0]
    for card in cards:
        assert text.count(f'<a id="{card["id"].lower()}"></a>') == 1
        assert text.count(f"#### {card['id']} — {card['title']}") == 1
    assert text.index("#### M-001") < text.index("#### M-002") < text.index("#### M-003")
    assert text.count("[F-001](#f-001)") == 3


@pytest.mark.parametrize("cwe", ["CWE-89", "CWE-79", "CWE-639", "CWE-922"])
def test_a_weakness_category_never_invents_code_or_a_verification(tmp_path, cwe):
    text = _render(tmp_path, [_mitigation(verification="")], [_finding(cwe=cwe)])
    assert "Bind the search term" in text
    assert "```" not in text and "Generic CWE-" not in text
    assert "**Verification:**" not in text


@pytest.mark.parametrize(
    "example",
    ["return findProducts(term);", "```typescript\nreturn findProducts(term);\n```"],
)
def test_authored_examples_and_verification_remain_available(tmp_path, example):
    text = _render(tmp_path, [_mitigation(code_example=example, how_code_lang="typescript")])
    assert "return findProducts(term);" in text
    assert text.count("```typescript") == 1 and text.count("```") == 2
    assert "Example implementation in `routes/search.ts:23`" in text
    assert "**Verification:** Confirm injection input returns no account records." in text


def test_a_finding_can_supply_the_concrete_example_and_check(tmp_path):
    findings = [
        _finding(
            remediation={
                "code_example": "```typescript\nreturn findProducts(term);\n```",
                "verification": "Check both ordinary search and injection attempts.",
            }
        )
    ]
    text = _render(tmp_path, [_mitigation(verification="")], findings)
    assert "return findProducts(term);" in text
    assert "Check both ordinary search and injection attempts." in text


@pytest.mark.parametrize("marker", ["-", "*", "1.", "1)"])
def test_how_lists_and_steps_form_one_ordered_sequence(tmp_path, marker):
    text = _render(
        tmp_path,
        [
            _mitigation(
                how=f"{marker} Bind the search term.\n{marker} Validate the input type.",
                steps=["Bind the search term", "Validate the input type.", "Check ordinary search still works."],
            )
        ],
    )
    assert text.count("**How:**") == 1
    assert text.count("Bind the search term") == 1 and text.count("Validate the input type") == 1
    assert "1. Bind the search term." in text
    assert "2. Validate the input type." in text
    assert "3. Check ordinary search still works." in text


def test_shared_findings_contribute_each_distinct_instruction_once(tmp_path):
    findings = [
        _finding(remediation={"steps": ["Bind every request value.", "Check the product route."]}),
        _finding(
            "T-002",
            title="SQL injection in account lookup",
            remediation={"steps": ["Bind every request value", "Check the account route."]},
        ),
    ]
    text = _render(tmp_path, [_mitigation(steps=[], threat_ids=["T-001", "T-002"])], findings)
    assert text.count("Bind every request value") == 1
    assert "Check the product route." in text and "Check the account route." in text
    assert "[F-001](#f-001)" in text and "[F-002](#f-002)" in text


def test_how_prose_does_not_repeat_as_an_extra_step(tmp_path):
    text = _render(
        tmp_path,
        [_mitigation(how="Bind the search term.", steps=["Bind the search term", "Reject object input."])],
    )
    assert text.count("Bind the search term") == 1
    assert "1. Reject object input." in text and "2. " not in text


def test_a_deliberately_repeated_step_keeps_its_place_in_the_procedure(tmp_path):
    actions = ["Run the search regression test.", "Change the query binding.", "Run the search regression test."]
    text = _render(tmp_path, [_mitigation(steps=actions)])
    assert "1. Run the search regression test." in text
    assert "2. Change the query binding." in text
    assert "3. Run the search regression test." in text


def test_a_shared_fix_preserves_repeated_checks_from_its_findings(tmp_path):
    actions = ["Run the search regression test.", "Change the query binding.", "Run the search regression test."]
    text = _render(tmp_path, [_mitigation(steps=[])], [_finding(remediation={"steps": actions})])
    assert "1. Run the search regression test." in text
    assert "2. Change the query binding." in text
    assert "3. Run the search regression test." in text


@pytest.mark.parametrize(
    "actions",
    [
        ["Set `UserId` from the session.", "Set `userId` from the session."],
        ["Update `routes/search.ts`.", "Update `routes/Search.ts`."],
        ["Set `LABEL='a b'`.", "Set `LABEL='a  b'`."],
        ["Allow `GET /api/items`.", "Allow `DELETE /api/items`."],
    ],
)
def test_similar_instructions_with_distinct_identifiers_or_values_are_preserved(tmp_path, actions):
    text = _render(tmp_path, [_mitigation(steps=actions)])
    for action in actions:
        assert action in text
    assert "1. " in text and "2. " in text


def test_mixed_prose_and_fenced_code_remain_intact(tmp_path):
    how = "Keep this operation scoped.\n\n```typescript\n// The numbers are data.\n1.1;\n```"
    text = _render(tmp_path, [_mitigation(how=how, steps=["Reject object input."])])
    assert how in text and "1. Reject object input." in text


@pytest.mark.parametrize("kind", ["review", "investigate", "accept_risk"])
def test_non_fix_tasks_keep_uncertainty_without_inheriting_finding_fixes(tmp_path, kind):
    card = _mitigation(
        kind=kind,
        priority="P3",
        title="Check whether the query is reachable",
        how="The route guard was not available; confirm the caller requirements.",
        steps=[],
        verification="",
    )
    findings = [
        _finding(
            remediation={
                "steps": ["Bind every request value."],
                "code_example": "return findProducts(term);",
                "verification": "Check both ordinary search and injection attempts.",
            }
        )
    ]
    text = _render(tmp_path, [card], findings)
    assert "The route guard was not available" in text and "### P3 — Next Quarter" in text
    assert "```" not in text and "**Verification:**" not in text
    assert "Bind every request value" not in text and "findProducts" not in text
    assert "Check both ordinary search" not in text


def test_a_review_keeps_its_own_steps_and_check(tmp_path):
    card = _mitigation(
        kind="review",
        priority="P3",
        steps=["Read the route and trace its guard."],
        verification="Record whether the caller can reach the query.",
    )
    text = _render(tmp_path, [card])
    assert "Read the route and trace its guard." in text
    assert "**Verification:** Record whether the caller can reach the query." in text


def test_mitigation_register_matches_its_focused_golden(tmp_path):
    cards = [
        _mitigation(
            how="1. Bind the search term as a query parameter.",
            code_example="return findProducts(term);",
            how_code_lang="typescript",
        ),
        _mitigation(
            "M-002",
            title="Review the remaining query paths",
            kind="review",
            priority="P3",
            how="The remaining route guards were not examined.",
            steps=[],
            verification="",
        ),
    ]
    text = _render(tmp_path, cards)
    golden = Path(__file__).parent / "fixtures" / "golden" / "mitigation-register.md"
    assert text == golden.read_text()


def test_frozen_report_mitigation_chapter_matches_its_golden(tmp_path):
    root = Path(__file__).resolve().parents[1]
    fixture = root / "tests" / "fixtures" / "e2e"
    run = tmp_path / "run"
    shutil.copytree(fixture / "frozen-run", run)
    rendered, warnings = compose.render(root / "data" / "sections-contract.yaml", run)
    assert warnings == []
    golden = (fixture / "golden" / "threat-model.md").read_text()

    def mitigation_chapter(text):
        return text.split("## 10. Mitigation Register", 1)[1].split("## 11. Out of Scope", 1)[0]

    assert mitigation_chapter(rendered) == mitigation_chapter(golden)
