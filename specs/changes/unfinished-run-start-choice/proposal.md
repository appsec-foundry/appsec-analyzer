---
reason: A start without --resume or --rebuild beside an unfinished run gave no way to choose between continuing, a new scan and starting over, and a failed reassessment deleted the earlier report before the new one existed. A run that stopped after moving its deliverables into place also left a directory that neither a new start nor --rebuild could clear.
affected_ids: [REQ-016, REQ-017]
compatibility: Interactive terminal starts outside CI now ask when the output holds an unfinished run; Enter and end of input keep the earlier default, a new scan that reuses compatible accepted steps. Noninteractive, quiet, JSON, CI and followed runs are unchanged. Earlier published results now stay until a new run completes instead of being removed at its start. The assessment state gains the optional fields publishing and superseded; states written before this change remain readable.
verification: Offline tests cover the answers that select continuing or rebuilding, Enter, end of input and repeated invalid answers keeping the default, a continue option withheld when the recorded limits differ, no question without an unfinished run or beside a completed one, --resume without a run, the earlier report surviving a failed new scan and a failed rebuild until a later run completes, removal of deliverables an interrupted publication moved into place, and an edited copy kept and named. Ruff and the specification gate run against the base commit. No live model call was made.
---

# Choose how to start beside an unfinished run

Without a flag, a start beside an unfinished run silently began a new scan that reuses accepted steps. That default stays. An interactive terminal now asks first, so continuing with the original limits or deliberately rebuilding is an explicit choice. Continuing is offered only while the recorded limits, deadline and accounting permit it; source, settings and runtime changes are still detected when the resume opens.

A new scan or rebuild previously removed the earlier report when it started. If that scan then failed, no report remained. Earlier unchanged results now stay in place, recorded as superseded, until a run completes; the completing run removes those it did not overwrite.

Publication records its deliverables before moving them into the output. A run that stops before completion therefore still owns them, and a later start or rebuild removes them. An edited copy is kept and named, as before.
