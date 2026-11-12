---
reason: A run stopped by a provider rate limit and resumed hours later kept its wall-clock deadline, so the pause used up the time limit and the reserve for the report then skipped every optional job, under a message that named the budget although money was left.
affected_ids: [REQ-016, REQ-023]
compatibility: The time limit now counts only the time a run worked; a resume continues with the time it had left. The state gains the optional field time_used_seconds, and expires_at becomes the deadline of the latest attempt. A state written before this change counts its worked_seconds. Request identities, receipts, and money and call limits are unchanged, so no accepted job runs again. Across stops, a run can take longer than its time limit in wall-clock time.
verification: Focused tests in tests/test_assessment_state.py (a resume after a three-hour pause keeps the unused time, with and without the new field; a used-up limit still takes the run over with a new limit; a negative record is refused as malformed state) and tests/test_assessment_jobs.py, tests/test_console_cost_display.py and tests/test_multi_repo_assessment.py for the report's time reserve and the skip wording. No live assessment.
---

# Resume keeps the time a run had not used

The Juice Shop standard run of 2026-11-12 stopped after 19 minutes at the Claude subscription's five-hour limit (HTTP 429). It was resumed 3 hours 16 minutes later. Its four-hour limit counted wall-clock time from the first start, so 25 minutes were left. The reserve for the report then held 900 seconds plus 120 seconds of finalization, because the resumed session had not measured the report yet. One verification call was stopped after 116 seconds. From then on, every optional job was skipped: the repeat of that call, merge review, five evidence reviews, text combination, actor discovery and all 14 abuse-case verifications. About USD 3.00 was left above the report's money reserve, but the console said "budget reserved for required completion work". The report then took 77 seconds.

A run whose limit had already passed got a new four-hour window on resume. A resume 25 minutes later would therefore have had more time than this one.

## Decision

The user approved this wording on 2026-11-12 and asked for the implementation on `main`:

- REQ-016 adds: "Time while a run is stopped does not count against its time limit."
- The REQ-016 acceptance rule changes from "the run keeps its deadline, limits, recorded costs and elapsed time" to "the run keeps its limits, recorded costs and worked time; its time limit counts only the time the run worked".

The two REQ-023 rules for the `codex-cli` and `copilot-cli` subscription profiles said "Resume keeps the original deadline". They now say that resume keeps the original time limit with the time already used, so they agree with REQ-016.

## Risks and side effects named before approval

- In wall-clock time, a run can last longer than its time limit across several stops. Money and call limits do not change.
- Existing state files get their deadline from the recorded working time. Accepted jobs do not run again.
- For the Codex and Copilot subscription profiles, where time is one of the main limits, the same rule applies.
- The user rejected the alternative of asking interactively whether to extend the time limit. That question would help only with a person at the terminal and would pause the run.

## Related fixes without a requirement change

- Until the report has its own measurement, its time reserve is twice the longest job of the session, at least 300 seconds and at most the 900-second call limit. In the eight runs from 2026-10-30 to 2026-11-12 that reached the report, it took 69 to 136 seconds. While a session has measured no job, the call limit remains the reserve.
- A job skipped because of the time reserve says "time reserved for required completion work". The phase summaries, the verification line and the closing summary also name time instead of budget. Saved results keep their existing cause value.
