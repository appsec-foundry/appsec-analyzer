---
reason: The startup model test sent one synthetic prompt to Haiku or gpt-luna before every assessment. The product owner decided that it is not needed, because the first model call of the run finds the same login, billing and quota errors, and the test did not show that the run's own models answer.
affected_ids: [REQ-016]
compatibility: The REQ-016 outcome is unchanged. One sentence of its acceptance rule in the acceptance contract changes. `assess` makes no model call before the run, so no spending outside the run's limit and no request to Haiku or gpt-luna happens at start or on resume. Access and provider checks, `--skip-preflight`, and `preflight --test-model` are unchanged; the shown Provider note says that the first model call in Reconnaissance checks the login. A rejected login, key, billing or quota now stops the run at that call, after cloning and scanning, instead of before the clone. No saved result or resume identity changes.
verification: tests/test_startup_preflight.py checks that `assess` makes no model call and shows no Model test row, that Copilot gets no session, and that `--skip-preflight` still skips the access and provider checks. The checks for the removed behavior are deleted with it.
---

# Remove the model test before an assessment

Removes the low-cost model test that `assess-model-test` added. It reverses that change's decision of 2026-10-23 for the test and keeps `--skip-preflight`.

## Decisions

The product owner decided the points below on 2026-10-26.

- Only the model call is removed. Local Git roots, remote read access, provider metadata checks and `preflight --test-model` stay.
- The Provider note for a CLI login reads "not tested yet; the first model call in Reconnaissance checks it", as it did before the test existed.

## Risks raised

- **Late failure:** a wrong key, an empty account or a missing login shows up at the first model call, after cloning and scanning. On a large repository that costs minutes, not money.
- **Models behind the login:** the removed test never showed that the run's own models answer, so no protection is lost there.
