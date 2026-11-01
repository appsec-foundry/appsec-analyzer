---
reason: A combined assessment treats several repositories as one system, and nothing checks that they belong together. A wrong selection spends the run's budget on one combined report of unrelated code.
affected_ids: [REQ-002]
compatibility: This change records the requirement only, so behavior stays the same until the feature is implemented. Once implemented, `assess` with several repositories at a terminal can stop at one new question when no link is found. Single-repository runs, `--resume`, `--rebuild`, and `--skip-preflight` are not affected. Runs without a terminal continue and gain a warning. Report schemas and saved results do not change.
verification: Specification checks with `make check-specs` and the tests that read the changed files. Tests of the behavior follow with the feature. Offline probes without model calls informed the rule and are not part of the repository. No live model calls.
---

# Ask when selected repositories show no link

The user approved this wording on 2026-11-01 and added that it applies only to several repositories: "When several repositories are selected and Analyzer finds no link between them before the first model call, it names the unlinked repositories and, in an interactive terminal, asks whether to continue."

This change records the requirement. The feature is not implemented yet, so the guides, the CLI help, and the installed skill stay unchanged until it is.

## How the check decides

The existing connection review cannot serve here, because it works on the results of the paid discovery stage. The check compares free signals instead: hosts one repository names against service, package, and image names another declares; shared queue names; package dependencies; and routes one repository serves that another calls.

A repository counts as linked when it connects to the others directly or through another selected repository. In `tests/fixtures/multi_repo_system`, the browser client and the worker meet only through the API.

Routes stay in. Without them, a browser client that calls its API with relative paths looks unlinked.

Offline probes used that fixture, four hand-edited variants of it, and eight unrelated pairs, one of them hand-made. With routes, 4 of 5 related selections were linked and 6 of 8 unrelated pairs were flagged. Without routes, the results were 3 of 5 and 7 of 8. Only one of the related systems is an original fixture, so the rates in real use are unknown.

The check belongs directly after source capture and before the run session starts. A stop there is an ordinary refused start, leaves no unfinished run, and needs no second source capture. A separate route scan took 5 to 12 seconds on Juice Shop and `appsec-advisor`, so the implementation should reuse the scan result for the run.

## Raised effects and the user's decisions

The check adds no model cost, sends no data to models or other hosts, and uses no credentials. With Git URLs, the question comes after cloning.

A false alarm costs one question. It happens when addresses appear only in environment variables.

A missed case behaves like today: a shared queue name or route makes unrelated repositories look linked, and no question comes. Repository text can cause this on purpose, so the check is a cost hint and not a safety control.

Runs without a terminal warn and continue. Stopping them would be stricter but would break existing automated runs. The user accepted the warning.

Runs started by an assistant use `--non-interactive` and never see the question, although a person is present. When the feature is implemented, the installed skill must confirm several repositories with that person before it starts a run.

`--skip-preflight` already skips optional checks for one run, so this check needs no new option.

## Rejected variants

Asking at every start with several repositories would be simpler and free of detection errors. The user typed the list, though, so the question would add no new information and would soon be dismissed by habit. A rare question is more likely to be read. This is a judgement, not a measurement.

Asking after the paid discovery stage would cost money without helping the weakest case. By the code of the connection review, a caller without an address gets no identity there either. This was read from the code and not tested live.
