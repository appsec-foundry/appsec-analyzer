---
reason: The operator requested a clearer result summary in addition to the improved startup heading and progress display.
affected_ids: [REQ-036]
compatibility: Change only the public human-readable score summary under interface version 1; preserve score arithmetic, structured JSON/YAML, source policy, scanner behavior, and exit codes. The retained direct script keeps its existing renderer.
verification: Run public score and summary tests, retained scoring tests, installed-package/documentation/specification checks, and changed-file Ruff checks. Verify ranking and aligned counts, visible unscored critical findings, null scores and no numeric area values for incomplete or undetermined scans, warning retention, safe repository labels, and unchanged input results and structured output.
---

# Readable security score summary

Separate the overall score and coverage from the area breakdown and top findings. Keep the limited-check qualifier on the headline and the absence of full analysis and exposure context directly below it. Put repository identity, applicable-check coverage, completed-scanner coverage, and unverified severity totals together. Keep findings without a scored baseline and severity exclusions prominent before the area table.

List every area in an aligned table with score, applicable-check count, and finding count. Rank scored runs weakest first; when the run is undetermined or incomplete, show all areas as unscored in alphabetical order. Number the existing top findings and put each example location below its severity and title, retaining repetition counts. Keep warnings visible and identify the examined source with its short commit ID and captured file count. Avoid repeating internal source-policy labels in the text footer; structured output retains full source metadata, control signals, and comparison fingerprints.

Use the existing bounded repository label for display, avoid mutating the result object, and keep the public JSON/YAML serializer unchanged. A high number cannot hide unscored critical observations, and an absence of scored-severity findings must not imply safety.

Verification completed: the focused summary, public CLI, retained scoring, installed-package, runtime documentation, and specification test groups pass (306 cases across the final focused runs). A local Juice Shop run completed with all four scanners and the new summary. Ruff lint and format checks pass for the changed Python files.
