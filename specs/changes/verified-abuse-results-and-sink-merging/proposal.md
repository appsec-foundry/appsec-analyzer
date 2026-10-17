---
reason: The Juice Shop thorough run represented absent abuse-case verdicts as completed checks, linked a coupon finding to JWT authorization by CWE alone, described review tasks as chain-breaking fixes, and duplicated a verified template-injection sink across threat categories.
affected_ids: [REQ-008, REQ-011, REQ-012, REQ-013, REQ-014]
compatibility: Existing status values, case IDs, and artifact versions remain. The not_run status may retain entirely unchecked inconclusive cases. Consumers must inspect per-case verification flags; blocking_mitigation_ids contains only explicit fixes for confirmed steps and is not proof of an effective fix. Confirmed duplicate scanner observations can be retained as instances rather than separate findings.
verification: Regression tests first reproduced the four defects. Verify missing and partial verdicts, negative broad-CWE matches, fix kinds, category and provenance preservation, schema gates, consumer behavior, and offline replay of saved run 134. Compare golden replay drift with the unchanged base revision; no paid model calls are required.
---

# Verified abuse results and sink merging

This change implements the existing evidence, abuse-case, remediation, and report-clarity requirements. It changes no requirement outcome, spending limit, or model default.

## Abuse-case results

Missing verdicts, empty verdict stubs, unknown step verdicts, and pending steps remain unchecked. A genuinely decided inconclusive verdict stays distinct. `not_run` may preserve candidate definitions and step references only when every step is unchecked, the case verdict is inconclusive, and no blocking fixes are claimed. Partial verification retains `completed` as the processing status, with an incomplete reason and per-case step flags. Unchecked derived cases remain selectable for a later explicitly requested check.

Broad authorization CWEs require a mechanism match before a finding can bind to a technical chain step; an exact CWE or a shared file alone is insufficient. Fix suggestions must have `kind: fix` and address a confirmed step. The report does not promise that applying a suggested fix has blocked an attack.

Unexamined cases receive one coverage row each, with stable anchors. Examined inconclusive cases receive compact rows containing the unresolved evidence and questions. Confirmed and partially blocked scenarios retain detailed cards; mitigated or refuted cases remain compact.

## Merge scope

The deterministic reconciliation joins a reviewed scanner injection observation to a single confirmed mechanism trace at the exact same sink, while retaining source-specific evidence states and additional categories. It does not remove the general category guard from semantic merge decisions. Adjacent coupon findings without a shared trace remain separate: their apparent similarity is insufficient for a deterministic merge, and their saved run did not complete semantic merge review.

## Regression evidence

The initial focused regression run failed seven assertions covering absent verdicts, lost inconclusive reasons, broad-CWE false matches, and the duplicate scanner sink; six negative merge cases already passed. Offline replay of `/tmp/134` yields fourteen unchecked cases, zero completed case verifications, and a valid YAML export. The abuse section decreases from about 2,745 to 279 words while retaining all fourteen case IDs. The reviewed template-injection pair becomes one finding carrying both sources and categories. Original run artifacts are preserved.

The focused merger, matcher, renderer, resolver, and validator suite passed 758 tests. After the final renderer boundary cases were added, all 62 renderer tests passed. Additional schema, promotion, business-case, and specification tests passed 212 tests and failed one pre-existing documentation-example test: `test_documented_business_case_example_validates` expects a heading absent from `docs/org-profiles.md`. The same test fails on unchanged base `e91a1c5aedff1ce1179d117e10e9fa15cbe42e55`. The broader multi-repository integration diagnostic was interrupted before completion and is not a passed gate.

The Juice Shop golden replay reports drift in inherited product names, versions, and source-checkout metadata. Running the identical replay on that unchanged base produces byte-identical diagnostics; no golden fixture was replaced. Ruff lint and formatting, local documentation links, `git diff --check`, and the specification gate against the explicit base pass. No live model qualification was performed.
