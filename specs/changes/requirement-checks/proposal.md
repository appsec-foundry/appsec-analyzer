---
reason: The repository review found that proposal checks were absent from the standalone gate and acceptance sections and retirement history were not checked.
affected_ids: []
compatibility: Product requirements and runtime interfaces remain unchanged. Standalone maintainer gates now require BASE, and new or modified proposals require four YAML fields. Unchanged historical proposals retain their existing format.
verification: Run the checker tests with real temporary Git histories, negative proposal and acceptance cases, make check-specs BASE=HEAD, the standalone offline gate, and Ruff on changed Python files.
---

# Requirements checks in the standalone gate

The user approved strengthening the existing requirements workflow without introducing another specification framework. This change affects maintainer tooling, not the semantics of any product requirement or decision. No requirement IDs change or retire, so the existing implementation bindings remain unchanged.

The standalone gate compares the working tree against an explicitly selected commit and checks the current catalog in the same invocation. It verifies proposal fields and affected IDs, one nonempty acceptance section per active requirement, retirement of removed IDs, preservation of historical retirements, and rejection of reused retired IDs. A proposal records a change and does not establish approval, semantic completeness, or passing behavior.

Complex requirements can gain individually referenced acceptance criteria when they are next changed. The current work does not split all requirements or claim that partial evidence proves complete implementation. Reviewers remain responsible for semantic coverage and for selecting a comparison commit that includes the changes under review.
