---
reason: A result written by a newer Analyzer cannot be validated by an older installation, for example a pipx installation beside a fresh checkout. The user asked whether Analyzer could offer the update in an interactive terminal.
affected_ids: [REQ-043]
compatibility: Adds one requirement and changes no existing outcome, command, or saved artifact. `review` keeps its exit code 2 for a result it cannot read, also after an accepted update. The diagnostic now names the state file and suggests updating the installation.
verification: Offline tests in tests/test_public_review_cli.py cover the offer for a state that fails the schema, no start of the review after a yes, a failed update, no installation after no, other input, or end of input, no offer in CI, without a terminal, outside pipx, or without a pipx executable, no offer for an incomplete result, and hiding credentials in the recorded source. The update command is replaced by a stub in every test. No test runs a real update or a pipx version other than 1.0.0.
---

# Offer an update for results from a newer version

The user approved the requirement wording in conversation and then asked for the implementation.

Risks raised before approval:

- After a yes, Analyzer would download and install code from the network, which is supply-chain exposure limited only by the explicit confirmation.
- Installation needs access to the source. The package is not yet on PyPI, so the GitHub repository must be reachable for the user's account.
- An update could bypass versions that an organization distribution pins. The offer is therefore withheld for those installations.
- `pipx upgrade appsec-analyzer` reinstalls from the source pipx recorded in the installation's `pipx_metadata.json`. Analyzer reads that record and shows it, without credentials, before asking. An installation without such a record, or with another package name such as an organization distribution, gets only the diagnostic. This was checked against pipx 1.0.0 only by reading its help and metadata; no update was run.
- The update makes no model call and sends no assessment data.

Simpler variant, already in place: the diagnostic names the state file as the cause and suggests updating the installation, without installing anything.
