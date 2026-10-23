---
reason: A wrong API key, a missing login, or an empty account showed up only at the first model call of an assessment, after cloning and scanning. The user asked for a quick, cheap model test before every assessment and for an option that skips the start checks for one run.
affected_ids: [REQ-016]
compatibility: The REQ-016 outcome is unchanged. For the Claude CLI, OpenAI and Codex CLI, `assess` now makes one synthetic model call before cloning, including on resume; it costs at most USD 0.05 or one plan exchange outside the run's limit, so a run's total spending can exceed its limit by that amount. LiteLLM, Bedrock and Copilot behave as before. `--skip-preflight` is new and changes no saved results; the run's limits and resume identity stay the same. The standalone `preflight` command is unchanged.
verification: tests/test_startup_preflight.py checks that `assess` tests haiku or gpt-luna with a synthetic prompt and its own limit before the run, that Copilot gets no model test, that rejected credentials, billing errors and exhausted quota stop the run before cloning without provider text, that rate limits, timeouts, a too small limit, unknown failures and invalid replies warn and let the run continue, and that `--skip-preflight` skips the access, provider and model checks while the clone and the controller arguments stay unchanged. tests/conftest.py keeps every other test from calling a real model.
---

# Model test before an assessment

Adds a low-cost model test to the checks that `assess` runs before cloning, and `--skip-preflight` to skip those checks for one run.

## Decisions

The product owner decided the points below on 2026-10-23.

- The test always uses a low-cost model: haiku for the Claude CLI, gpt-luna for OpenAI and the Codex CLI. Analyzer knows no low-cost model for LiteLLM, Bedrock and Copilot, so they get no model test, which keeps the check small.
- The test has its own limit of USD 0.05, or one exchange for Codex, outside the run's limit. Charging it to the run would change the run's limits at every start, and resume rejects changed limits.
- Only a failure that proves a setup problem stops the run: rejected credentials, a billing error, or exhausted quota. Every other outcome, such as a rate limit, a timeout, a limit too small for the model, or an invalid reply, warns, and the run continues.
- `--skip-preflight` skips the repository access, provider and model test checks. Source admission, clone and credential controls, the data-use notice and the host CLI checks that the run needs still apply.
- No new requirement: the REQ-016 outcome already covers explaining failures and how to recover. One sentence of its acceptance rule changes.

## Risks raised

- **Cost on every start and resume:** at most USD 0.05 per start, usually well below one cent, or one exchange from the ChatGPT plan for Codex. CI pipelines pay this on every run.
- **Low-cost model only:** a passed test does not show that the run's own, more expensive models answer, for example Opus at thorough depth on a Claude plan without Opus.
- **A 403 stops the run:** if an OpenAI project blocks only the test model, the run stops although its own models would work; `--skip-preflight` gets past it.
- **With `--skip-preflight`:** a wrong key or missing repository access shows up only at the clone or at the first model call.
