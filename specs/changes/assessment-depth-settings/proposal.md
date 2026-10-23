---
reason: What each assessment depth does was spread over code in five modules and two data files, so teams could not see or change it in one place. Teams also could not choose which of the shipped abuse cases a run checks, only add their own files.
affected_ids: [REQ-018, REQ-040]
compatibility: The shipped file reproduces today's behavior of every depth, so runs without new profile settings keep their results. data/verification-depths.yaml, added shortly before and never released, becomes part of the new file. Scan profiles gain optional per-depth settings and abuse case include and exclude lists; existing profiles stay valid. Changing a depth setting changes the run's saved configuration, so a started run needs a new run, as for other profile settings. Model selection per role stays in the model profiles.
verification: The specification check validates the acceptance sections and this proposal. The implementation must test that the shipped file yields today's values at every depth, that a scan profile overrides one depth without changing the others, that included and excluded abuse cases are honored, that a case the organization switched off cannot be included, that a mandatory aspect cannot be dropped, that repository content cannot set any of these values, and that internal limits are not accepted as settings.
---

# Assessment depth settings

Collects what each assessment depth does into one documented, shipped file and lets scan profiles change it per depth. The acceptance rules are in REQ-018; REQ-040 refers to them for the verified aspects.

## Decisions

The product owner approved the wording on 2026-10-23 in the conversation that drafted it, after asking for it to be clear for users. These decisions were made there:

- The file holds the settings that change cost and coverage: verified aspects, number of abuse cases and model-derived cases, architect review, actor discovery, trust boundary crossings examined in detail, and the default budget of an interactive start.
- Verified aspects are written as a plain list per depth (`verify: [AuthZ]`); an empty list runs the survey only. The rule-based verification items without a model stay available through `test_cases: true` in a scan profile.
- Which abuse cases a run checks is chosen in the scan profile, through lists of cases to always or never check, for every depth or single depths. The shipped file names only counts, because it does not know the application.
- The organization profile keeps its existing controls, switching off and adding abuse cases, and making aspects mandatory. Minimum values for the other settings were considered and left out: no current need, and they would add rules and conflicts for every value. They can be added for a single setting when one is needed.
- `max_parallel` stays a scan profile setting without a per-depth default, because it depends on the provider's rate limits and the machine, not on how thorough a run is.
- Model selection per role stays in the model profiles, because it depends on the provider. Internal limits such as turn budgets and quality-gate repairs stay out of the settings, as the context routing contract requires for implementation limits.

## Risks raised

- **Refactoring without a behavior change:** values move out of several modules. A test must show that the shipped file yields today's behavior at every depth.
- **Less coverage:** more settings give more ways to switch checks off. Only operator-owned profiles can set them, repository content cannot, and the organization profile keeps its existing controls.
- **Resuming:** a changed depth setting changes the run's identity, so a started run needs a new run.
- **Overlapping options:** `--only-abuse-case` and the include list both select cases; the command line option takes precedence, as for other settings.
- **Unchecked older values:** some depth-dependent values from the plugin era, such as phase time budgets, STRIDE turn budgets, and the evidence verifier limit, may no longer be read by the controller. They are checked before anything moves, and unused ones are recorded rather than moved.
