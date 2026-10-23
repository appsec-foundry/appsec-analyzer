---
reason: An Analyzer change made during a long assessment, even one that touches no prompt, made --resume refuse the interrupted run. The user then had to start a new run, which got a new deadline and an elapsed time starting at zero, although it reused the same accepted steps. The user asked for --resume to continue in this case, at the minute and deadline where the run stopped.
affected_ids: [REQ-016]
compatibility: --resume of an unfinished run whose only change is the Analyzer version now continues that run instead of refusing it. Deadline, limits, recorded costs and elapsed time stay; accepted jobs whose model request changed run again at additional cost, and the cost of their earlier answers stays counted. A completed run, changed source, settings or limits, an unreconciled cost reservation and an exhausted budget or deadline still refuse the resume. The start question offers continuing again in this case. Assessment states and receipts keep their format.
verification: Offline tests cover a resume after a plugin change that keeps run, deadline, accounting and elapsed time, reuses an unchanged job without a call or charge and repeats a changed one at additional cost; a changed artifact still stopping the run; a plugin change together with changed settings, an exhausted budget, an unknown cost reservation and a completed run still being refused without changing the state; and a new run without --resume still reusing only unchanged jobs. Ruff and the specification gate run against the base commit. No live model call was made.
---

# Resume after an Analyzer change

Since the verified review findings, --resume refused a run whose Analyzer fingerprint changed, because it had silently turned the resume into a new run with a new deadline and a new budget. A run without --resume already reused the compatible accepted jobs, but it started a new deadline and showed an elapsed time from zero.

--resume now continues the same run when the Analyzer version is the only change. The run keeps its deadline, limits, recorded costs and elapsed time, so nothing is reset. Each accepted job is checked against today's request: unchanged ones are reused without a call or charge, changed ones run again. A receipt of the run that no longer matches its request is replaced instead of stopping the run; an artifact that changed after acceptance still stops it. Platform settings are checked again with the current code instead of reusing the earlier result. The run header says that the plugin changed and only unchanged model steps are reused.

## Risks and decisions

- Cost: a job whose request changed costs again, and the earlier answer's cost stays counted, so less budget remains than for a new run, which does not count it.
- Deadline: the original deadline applies, as for every resume, and a pause counts against it. With little time left, a run without --resume remains the alternative.
- Integrity: only a receipt whose request no longer matches is redone, and only after a plugin change; a changed artifact still stops the run.
- Consistency: deterministic steps run with the current code; only model answers to identical requests are reused, and an answer that a changed validator rejects is redone.
- No additional data reaches models or other hosts, and credential use is unchanged.

The user chose this over keeping the refusal and asked that the elapsed time and deadline continue instead of restarting. The user asked to keep the acceptance rule short; implementation details stay in this proposal, the tests and the assessment guide.
