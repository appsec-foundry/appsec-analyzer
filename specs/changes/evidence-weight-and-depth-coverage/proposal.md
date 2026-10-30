---
reason: A thorough-labelled assessment of an Express and Angular application left most client and many API files unread, reported a finding that the evidence review had refuted in its verdict, and rated development-only and proxy-dependent configuration hits as confirmed exploitable. REQ-004 promised coverage of all program code that the survey never delivered.
affected_ids: [REQ-004, REQ-009, REQ-040]
compatibility: Thorough assessments read more source and cost more; quick and standard keep their file selection and now name it accurately. Reports of existing assessments change on the next run - contradicted verification findings leave the verdict, weaknesses, and fixes, and configuration hits move from confirmed exploitable to insecure practice, which also changes weakness grouping, SARIF, CVSS output, and golden fixtures. Saved artifact schemas are unchanged.
verification: Specification checks against the base commit. Implementation needs intended and negative cases for each rule - a refuted verification weakness that changes no verdict bullet, weakness, or fix, and a confirmed one that still does; a configuration hit without exploitation evidence as insecure practice and one with such evidence as confirmed; a development-only file and a release-used file of the same name pattern; a thorough survey that examines files without any signal, a budget stop that names unread files, and a standard survey whose file selection is unchanged; a cost preview that shows the thorough surcharge.
---

# Evidence weight and depth coverage

The user reviewed an assessment of an internal Express API with an Angular client. The run cost about USD 4 and reported 101 client files and 47 API files as unexamined. Its verdict cited a finding that the evidence review had contradicted, because a router-wide admin guard protected the route. A Helm ingress without TLS and a port in `compose.dev.yaml` were rated confirmed exploitable.

The user approved three requirement changes in the wording shown to them.

## REQ-040: contradicted verification findings

A weakness that only verification found and that the evidence review refuted stays visible with the reason. It no longer counts toward the verdict, the severity summary, weaknesses, or recommended fixes.

Risks raised: the review reads bounded source windows and can be wrong, so a real gap could lose weight; the finding stays in the register to limit that. Verdicts and counts of existing reports change on the next run. There is no model cost and no new data sent. The simpler variant, removing such findings only from the verdict, was offered and not chosen.

## REQ-009: configuration rule hits and development-only configuration

A configuration rule hit is an insecure practice unless evidence shows how it can be exploited where the system runs. Configuration that serves only local development is labelled as such and does not raise the verdict.

Risks raised: a development file can also be used in production and would then be underrated; the label states the assumption, and a file a release build uses is not development only. Configuration hits join weakness groups more often instead of standing alone, which changes golden fixtures, SARIF, and CVSS output. There is no model cost. The simpler variant, only labelling development files, was offered and not chosen.

## REQ-004: coverage by depth

The previous sentence that the survey covers all program code did not describe the implementation, which examines only files that a route, scanner lead, or security signal points to. Quick and standard keep that selection, and the report names what they left out. Thorough examines every program file and server-side template at least once, client code included, within the authorized budget, and names files the budget did not reach.

Risks raised: thorough costs more and takes longer; for the reviewed application about 156 more files would be read, and the surcharge must be measured on a fixture before release rather than estimated. More source code reaches the model provider, which the explanation of what leaves the machine (REQ-033) must show. A fixed budget can stop a thorough run earlier; unread files are then named. The simpler variant, correcting the text and adding client signals at every depth without reading every file, was offered and not chosen.

## Status

This change records the approved requirements, their acceptance rules, and their bindings.

REQ-040 is implemented through one finding-state predicate, `counts_toward_assessment`, which the verdict basis, the risk distribution, the weakness register, and the generated fix mitigations use. The register and the review mitigation keep the finding. Its guards are bound.

REQ-009 and REQ-004 are not implemented yet, and no guard covers their new rules.
