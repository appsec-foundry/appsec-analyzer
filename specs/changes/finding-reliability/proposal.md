---
reason: Readers could not tell how sure the report is that a finding is a true positive. Three Juice Shop runs also showed a false Critical that a single abuse-case step had confirmed for nine locations, and the review's reason for leaving a finding open was lost.
affected_ids: [REQ-008, REQ-040, REQ-047]
compatibility: Findings gain a Reliability line on the card and the register a one-line note. Severity, verdict, counts and priorities do not change by the level. New results use the evidence basis post-check for findings a post-check confirmed, and evidence_review_unproven for the reason of an open review; both are additive. A saved result re-rendered with this version shows its post-check findings as low, because their older basis pointer-resolved also stands for a check that proves nothing, and shows low findings without a reason. A finding with several locations that an abuse-case step used to confirm stays unproven, also when the proven location is a true weakness.
verification: Focused tests of the level, the card, the kept reason, the failed review, the post-check basis and the promotion rule, negative cases included. The rule was checked offline against the three saved runs; its effect on a new run is not measured, because no assessment was run.
---

# Show how reliable a finding is

Every finding now says how sure the report is that it is real. The level answers true or false positive; severity remains a separate question. The evidence review never changed a rating, and the level does not either.

## Agreed requirement

The user asked for a value that shows the reliability of a finding, confirmed that it is about true or false positives, and approved implementing what the recommendation says after it was checked against the data. That check changed the first draft in three places, recorded below.

## What the check changed

The draft called a confirmed finding high when two methods found it. That would have rated a known false Critical as high: `scanners+survey` confirmed "client-supplied UserId used for wallet debit" in one run, although `app.use('/rest/basket', ...appendUserId())` overwrites the value. Scanner hits are starting points for the survey and for verification, and a scanner hit repeats by construction, so repeating says little about scanners. High therefore needs both the survey and verification. In the three runs this rule holds for 15 to 26 of about 156 findings, and none is a known false claim.

The draft treated a post-check as confirmation. A post-check tests one fixed property, such as whether a site is reached, and 64 percent of such findings were confirmed again elsewhere, against 92 percent for the survey and verification together. Such a finding reaches medium and is not counted as confirmed, which keeps the earlier behavior. It gets the basis `post-check`, because `pointer-resolved` also stands for a check that only found the cited line.

The draft put the level in the register as well. The report tables are agreed one by one and another session is changing them, so the level stands on the finding card, and the register gets one note below it.

## Measurements

All numbers come from the saved runs 1667, 1668 and 1669 of Juice Shop at standard depth, with the same source hash. Repeatability is not truth, and one deliberately vulnerable repository is a narrow base.

| Finding | Pairwise comparisons | Confirmed again at the same place |
| --- | ---: | ---: |
| Survey and verification, confirmed | 88 | 92 % |
| Verification only, confirmed | 168 | 73 % |
| Post-check | 70 | 64 % |
| Survey only, confirmed | 324 | 52 % |
| Survey only, unclear | 50 | 30 % |

The review decided 51 scanner claims that the route's middleware makes false: 30 refuted, 18 unclear and 3 wrongly confirmed. With the guard line in the review's source, 30 of 38 were refuted; without it, none of 13 was, and all 3 wrong confirmations fell there. The review refuted 86 of 246 scanner hits and none of 338 survey findings, so whether a confirmed survey finding is true remains unmeasured.

## Risks and decisions

The change adds no model call and sends no further data to a host. Reliability "high" can be read as proof, so the card says "probably real" and the register note says it is no probability. The approved recommendation leaves out a second review of Critical and High findings, because of its cost, and a percentage, which would need calibration on several repositories.

The reason of an open review is model text derived from repository content. It stays plain text on the card, like the reason of a contradicted finding. The reason of a failed review used to carry the raw exception and would have reached the report, so it is now a fixed sentence, and the recorded gap keeps the cause.

## Open points

Reviews with 13 to 15 findings do not read every guard, which causes most unclear verdicts. Changing the batch size or the source limits cannot be judged offline and needs a paid comparison run. An abuse-case step can still confirm a false claim at a finding's only location, because it reads only what it requests.
