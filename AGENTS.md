# Working on AppSec Analyzer

## Requirements

Read [requirements.md](requirements.md) before changing observable behavior. Use [data/requirement-bindings.yaml](data/requirement-bindings.yaml) to find affected code and tests.

Keep `REQ-NNN` requirement IDs stable when moving or reordering entries. The [acceptance contract](docs/internal/contracts/requirement-acceptance.md) contains normative detail rules; preserve them when editing short user outcomes. Record semantic changes to either document in `specs/changes/<change>/proposal.md`, including the reason, affected IDs, compatibility, and verification. An explicit user request to change requirements already authorizes that work; the proposal records it. Consolidated or removed IDs belong in `retired_ids` and must not be reused. Update bindings with the change. Keep implementation details in contracts and bindings.
