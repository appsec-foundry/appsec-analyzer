---
reason: Make custom abuse-case selection independent of inherited Advisor directory conventions through the standalone CLI and reusable scan profiles.
affected_ids: [REQ-011]
compatibility: Add an optional scan-profile field and repeatable CLI flag; preserve existing automatic case directories, schemas, organization settings, and source boundaries. Explicit selection of a compatibility file now requests its cases at quick depth too.
verification: Public CLI and profile tests cover forwarding, replacement, invalid paths and bounds; real matcher replay covers explicit selection at standard and quick depth in arbitrary and compatibility directories; existing source-boundary tests cover missing files, traversal and multi-repository refusal. Run standalone tests, specification gates, documentation contracts and packaging checks without paid model calls.
---

Custom cases are operator-selected analysis inputs. `scan` and `assess` accept repository-relative YAML paths through `--abuse-case-file`; scan profiles retain the list as `abuse_case_files`. CLI selections replace profile selections. Profiles stay outside the source repository and cannot change the engine's source grants. External organization cases continue to use the existing organization-profile mechanism.

The earlier `docs/security/abuse-cases/` and `.appsec/abuse-cases/` directories remain discoverable for compatibility. Selecting a file explicitly also marks already discovered cases as requested, preserving one definition per case. The current single-repository restriction, case limits, disabled IDs, budget and evidence requirements remain in force.
