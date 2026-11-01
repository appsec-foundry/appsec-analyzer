---
reason: The threat overview filled a fixed list with every structural threat, so lighter threats stood beside the ones that need attention first. The Juice Shop report of 2026-10-31 listed eight rows, two of them without Critical or High findings.
affected_ids: [REQ-012]
compatibility: The REQ-012 outcome changes. When any threat has a Critical or High finding, the overview, the figures, and the attack path list show only those threats, and the others are named below the table with their finding counts. Reports without such findings show all threats. New assessments can show fewer overview rows than earlier runs; every finding stays in the findings register. Saved assessments keep their reports until they run again.
verification: Unit tests in `tests/test_compose_threat_model.py` cover a report with Critical or High findings, one without, consistent numbering across the table, the figures, and the path list, and the line naming the other threats.
---

# Focus the threat overview on Critical and High

The user approved this wording on 2026-10-31: "When any threat has a Critical or High finding, the threat overview shows only those threats and names the others below it. Without such findings, it shows all threats."

The rule sits in the one function every consumer of the threats reads, so numbers and counts stay consistent.

## Raised effects and the user's decisions

The threat "Build Pipeline" carries the impact "Full Server Compromise", but its findings are Medium. It therefore moves to the line below the table.

The supply-chain attacker loses a numbered attack path. It stays in Figure 1b and in the actor table.

The user accepted both effects: lighter threats fall clearly behind and need not fill a fixed count.
