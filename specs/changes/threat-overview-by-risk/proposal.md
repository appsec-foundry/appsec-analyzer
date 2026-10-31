---
reason: The report's threat overview took its order from a list in a data file, so a High threat could stand above a Critical one. In Juice Shop run 1667, Hardcoded Secrets (High) stood above Broken Authorization (Critical), and Remote Code Execution (Critical) stood fifth.
affected_ids: [REQ-012]
compatibility: Reports list their threats by risk, and the numbers in the overview table, Figure 2, and the attack path list follow that order. One threat can therefore carry a different number in two reports. Saved reports stay as they are. Model use, costs, data sent, and credentials do not change.
verification: Offline renderer tests cover risk order, equal risks, independence from the authored order and from classes added later, and one numbering for all consumers. Re-rendering run 1667 shows the same number per threat in all places.
---

# Threat overview by risk

The attack class list in `data/attack-class-taxonomy.yaml` decides which class a finding belongs to. Its order also numbered the threats, although the renderer computes each threat's risk. The order was not even reliable: it applied only when the report had to add a class the model had left out. Otherwise the model's own order stayed.

REQ-012 already promises to show what to tackle first. It now says that the threat overview lists the most severe threats first.

Acceptance:

1. A threat with a higher risk never stands below one with a lower risk.
2. Among threats of equal risk, the one whose most severe findings weigh more comes first.
3. The same findings always give the same order, whatever a model answered.
4. A threat keeps one number in the overview table, Figure 2, and the attack path list.

Equal risks compare the sum of the three highest ranking scores. The score already combines severity, distance from the attacker, and the finding's role in attack chains. Three findings count breadth without letting many light findings outweigh a heavy one. In run 1667 this places Broken Authorization second, behind injection. With the single heaviest finding alone it would be third, by three points. Only the 50 highest findings have a score, so a class without one ends its risk level. The class list settles what is still equal.

## Decisions and risks

The user raised the sorting on 2026-10-31 and asked to adapt an existing report requirement instead of adding one.

- **No model call.** The user asked whether a model call could improve the order. It is not needed: the ranking exists and was not used here, and it matches the order the model wrote in run 1667. A model would add cost, make the order unrepeatable, and let repository text influence priorities. It could later reorder threats by business context within one risk level, never across levels.
- **Numbers can differ between reports.** One threat can carry a different number in two reports. This was already true, because the old order depended on whether a class had been added, but it is now the rule.
- **Simpler variant not taken.** Sorting by risk level and letting the class list settle ties needs less code, but then a data file would still decide among equal risks.
