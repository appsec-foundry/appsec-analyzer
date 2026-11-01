---
reason: The product owner asked that a quick assessment can check business abuse cases on request. `assess` had no option for this, because `--abuse-cases` existed only in the internal configuration, where it ran technical cases and left the business limit of quick depth at 0.
affected_ids: [REQ-011]
compatibility: Runs without the option do not change, and neither do saved results. `assess --abuse-cases` is a new public option. It enables abuse cases at any depth. A depth setting of 0 then uses the highest allowed value, 16; a value above 0 stays the limit. `scripts/run-headless.sh` starts `assess` and accepts the option too. `--no-abuse-cases` stays internal to the configuration resolver.
verification: tests/test_depth_settings.py checks that the option raises a limit of 0, keeps a limit above 0, and that quick depth stays off without it. tests/test_match_abuse_cases.py checks that quick depth selects business cases under that limit. tests/test_resolve_config.py checks the resolved configuration, and tests/test_public_assessment_operations.py checks that `assess` passes the option on.
---

# Business abuse cases at quick depth on request

## Decision

The requirement sentence for abuse cases now names quick depth when `assess` is called with `--abuse-cases`. The wording was approved by the product owner on 2026-11-01. Quick depth still skips abuse cases by default.

## Risks raised and decisions

- **Cost:** on a run the size of Juice Shop, about 13 cases at about USD 0.05 each add about USD 0.65, measured on one standard run. The product owner accepted this, because it applies only when the option is used.
- **Severity on thinner evidence:** a confirmed chain can raise the severity of its findings, and quick depth has no verification beside it. Verdicts also varied between runs in the depth comparison. The product owner accepted this for runs that ask for the check.
- **New public option:** `assess` has one more option to keep in help, guides, and tests. A scan profile with `depths.quick.abuse_cases` already enabled the same check without code. The product owner chose the option anyway.
- **Quality at quick depth is not measured.** No run has checked abuse cases at quick depth. The default stays off until one has.
