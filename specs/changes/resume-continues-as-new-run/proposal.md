---
reason: "--resume refused a run whose settings or plugin had changed or whose time limit had passed, although a start without --resume would have reused its accepted steps; users who typed --resume wanted to continue where the run stopped."
affected_ids: [REQ-016]
compatibility: "--resume no longer ends with 'cannot resume' for an unfinished run. It starts a new run that reuses the accepted steps that still match, with the limits and deadline of the current command, and names the cause. A completed run, an exhausted budget of an unchanged run, a missing run and unreadable or altered state still refuse. Exit codes and artifacts are unchanged."
verification: "Offline lifecycle tests cover changed settings, limits, plugin together with settings, changed source, expired time limit and unreconciled cost taking the run over, and the refusals that remain (completed run, exhausted unchanged run, no run)."
---

# Resume continues as a new run

The user decided that `--resume` continues an existing run in the output folder instead of refusing it. The requirement sentence in REQ-016 no longer limits resuming to compatible runs.

Risks raised and accepted: the new run uses the budget and deadline of the current command, so the original deadline no longer bounds the total time; reused steps count toward the new budget; a changed source repeats most model steps and costs money, which the start line makes visible by naming the cause. No data goes to other models or hosts and no credential use changes. An unknown cost from an earlier call is not refunded: the new run starts its own accounting, as a start without `--resume` already does.
