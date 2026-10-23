---
reason: The product owner found the live progress line "Verify start · 9 jobs for AuthZ" and the per-job rows "Juice Shop Express Server (part 2 of 7)" confusing, because a user thinks in components, not in the jobs a component's places are split into. They asked to show authorization verification as one step per component, independent of the change that reduces further-read calls.
affected_ids: [REQ-040]
compatibility: Only the progress display and its documentation change. Verification still runs the same jobs with the same candidates, budget statement and results; saved assessments, reports, sidecars, receipts and resumed runs are unaffected. The plan and start lines now name the components and keep the job count at their end, which the console uses to weigh the step and leaves out of the shown line. A log reader that matched the old per-job texts must match the component texts instead.
verification: Console tests for a component checked in two jobs, one of them without a result, and a second component, checking that only finished components get a row, that a finished part advances the share without finishing its component, that the share never falls, and that a component verified for two aspects is one row; terminal status-line test; budget-statement tests for covered, uncovered and subscription runs; the authorization pilot controller test that pins the plan, start and job lines. Ruff on the changed Python files and the specification check against the base commit.
---

# Show verification progress per component

The acceptance contract of REQ-040 said that the assessment names the planned verification jobs before the survey. It now says that the assessment names the components it will verify, and that the live progress shows one step per verified component, however many jobs it needs.

The controller still reports every job's start and end. Each report names the component's number and the job's part of that component's jobs, so the console can wait for a component's last part before it shows the component as done. The plan and start lines end with the job count, because the console weighs the threat analysis by jobs; it shows these lines without that count.

A component whose jobs did not all produce a result is shown with a warning that names how many of its parts have no result and why.
