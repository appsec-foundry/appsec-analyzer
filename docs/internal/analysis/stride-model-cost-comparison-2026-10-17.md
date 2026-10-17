# STRIDE model costs and business logic findings

On 2026-10-17, the Juice Shop thorough assessment cost USD 28.01 compared with USD 15.85 for standard. Most of the additional spending came from STRIDE using Opus instead of Sonnet. Thorough identified additional business logic problems, but Sonnet also identified business logic problems. This pair of runs does not establish that Opus is generally better: depth, model selection, verification limits, and completed downstream work changed together.

## Evidence and scope

The local evidence is the standard run in `/tmp/131` and the thorough run in `/tmp/134`. Both assessed Juice Shop commit `33518f5a0911e25d9df747b1e70fb7af279a755c` on `master`, reported engine version `0.6.0-beta.5`, and used a USD 30 hard budget. Their saved state has the same source-scope digest, `9c3d5cda4f71032d565d8782987b3389fd2f01380d0765911f6cd247f97abd83`, and runtime digest, `013625d8a9e3653bf74dbd23f73944dc25bc42eb173f6d74416dd14668cf896e`.

These are inherited Advisor-engine runs: their recorded plugin root is `/home/mrohr/appsec-advisor` and their invocations use the Advisor entry. They inform analysis of the extracted engine but do not qualify the current standalone package or establish its default model selection. The measured STRIDE models were `claude-sonnet-5-5` for standard and `opus` for thorough. The recorded evidence-verifier finding limits were 30 and 100 respectively.

For each run, `.assessment-state.json` supplies total calls and cost; `.assessment-work/jobs/*.receipt.json` supplies role, calls, and cost per accepted job; the corresponding job JSON contains raw model findings. `security-assessment.yaml` supplies final findings and abuse-case verdicts. `.assessment-work/summary.txt` records skipped work. `.assessment-work/render/.skill-config.json` records resolved settings, and `.assessment-work/render/.abuse-case-verdicts.json` distinguishes actual verifier output from missing verdicts. The temporary directories are local evidence, not durable repository fixtures; the aggregate measurements and selected job identifiers below preserve the basis of this analysis without copying source excerpts or entire reports.

## Measured costs and results

Costs are the controller's recorded USD amounts, not an independently reconciled provider invoice. The total receipt sums agree with state accounting: USD 15.8530618 for standard and USD 28.0053175 for thorough. Differences and percentages below use these unrounded amounts.

| Measurement | Standard | Thorough |
| --- | ---: | ---: |
| Total recorded cost | USD 15.85 | USD 28.01 |
| Rounded completion time | 35 minutes | 59 minutes |
| Total model calls | 134 | 109 |
| STRIDE jobs | 30 | 31 |
| STRIDE model calls | 33 | 40 |
| STRIDE cost | USD 8.35 | USD 21.91 |
| Evidence-verifier cost | USD 3.04 | USD 2.60 |
| Abuse-case-verifier cost | USD 0.58 | USD 0.00 |
| Final finding-register entries | 74 | 130 |
| Entries classified as `confirmed-exploitable` | 35 | 46 |
| Entries classified as `insecure-practice` | 39 | 84 |
| Weakness-register entries | 36 | 42 |
| Abuse cases | 10 | 14 |
| Abuse cases classified as `fully_viable` | 5 | 0 |
| Abuse cases classified as `inconclusive` | 5 | 14 |

The total increase is USD 12.15, about 77%. STRIDE alone increases by USD 13.56, about 162%, and accounts for about 78% of the thorough run's cost. The total increase is smaller because less downstream model work ran. The Angular frontend accounts for USD 10.70 of thorough STRIDE cost versus USD 4.89 in standard, with 17 jobs in each run. The Express server accounts for USD 6.98 versus USD 1.99, with seven versus six jobs. More calls alone do not explain the cost increase; model choice and the work within each call also differ.

The management-summary totals, 41 and 57, use a different counting basis from the finding register: they fold selected practice entries into weaknesses and include design-risk weaknesses. They must not be read as counts of unique confirmed vulnerabilities. The net increase of 56 register entries consists of 11 more confirmed-class entries and 45 more practice-class entries; it is not a matched set of 56 newly discovered vulnerabilities. These classifications are assessment outputs, not independent exploit validation.

## Business logic findings and apparent additions

Raw STRIDE output is the appropriate comparison for model detection. A final report also reflects severity filtering, merging, verification, and deterministic scanner findings. Both runs omit Low findings from the register.

| Topic | Observation from the two runs | Interpretation |
| --- | --- | --- |
| Negative basket quantities | Thorough reports F-074 at `routes/basketItems.ts:92`; no corresponding scenario was found in standard STRIDE output. | Additional business logic candidate in this thorough run. |
| Expired campaign discounts | Thorough reports F-072 at `routes/order.ts:201`, where the server accepts a client-supplied campaign date; no corresponding scenario was found in standard STRIDE output. | Additional business logic candidate in this thorough run. |
| Reusable CAPTCHA answers | Thorough reports F-060 at `routes/captcha.ts:38`; standard identifies other CAPTCHA weaknesses but no corresponding replay scenario. | Additional scenario, distinct from exposing the answer. |
| Unbounded metric labels | Thorough reports F-122 at `routes/metrics.ts:77`, using attacker-controlled MIME types as metric labels; no corresponding scenario was found in standard STRIDE output. | Additional availability candidate, not a business logic example. |
| Image CAPTCHA disclosure and missing-CAPTCHA bypass | Standard STRIDE already reports both as Low; thorough combines them in Medium F-063. | Visibility and severity differ; this is not new detection by Opus. |
| Review update with an operator selector | Standard's ownership-check finding already describes an operator object and `multi:true`; thorough separates the selector issue as F-030 and ownership issue as F-129. | More entries do not establish a newly detected attack. |
| Profile template injection | Standard's final F-027 records the unsafe template compilation as a practice finding; thorough STRIDE supplies an explicit input-to-sink trace and final F-011 is confirmed-class Critical. | More developed evidence in thorough, but the underlying issue was already in the standard assessment. |
| Wallet race condition at checkout | Both raw STRIDE outputs identify a non-atomic balance check and debit, at `routes/order.ts:149` and `:150`, as Low practice findings. Neither final report lists it. | Sonnet and Opus both detect this business logic concern; report absence is not model non-detection. |

Sonnet also identifies wallet top-ups without effective payment processing, a Deluxe upgrade without payment, and missing ownership checks on baskets and reviews. Business logic detection is therefore not exclusive to Opus. The additional thorough scenarios demonstrate useful marginal detection in this pair; they do not establish a reliable per-model recall advantage.

Selected raw artifact identifiers, relative to each run's `.assessment-work/jobs/`, make the comparison traceable:

| Run | Artifact | Relevant output |
| --- | --- | --- |
| Standard | `job-f7ed4b865995d1aea36c66b2.json` | Checkout wallet race condition, Low. |
| Standard | `job-00cb41e7cee5578ece41bf2f.json` | Missing image CAPTCHA accepted, Low. |
| Standard | `job-20bdf8ff34162a1444961eab.json` | Review ownership finding already includes the operator-selector attack. |
| Thorough | `job-8d7d920218a16b169a8707dc.json` | CAPTCHA reuse and negative basket quantities. |
| Thorough | `job-551c036bcd11e38fb532af89.json` | Unbounded MIME-type metric labels. |
| Thorough | `job-43fabd1e86160e91671ea5cd.json` | Client-supplied campaign date and checkout wallet race condition. |

## Budget pressure and report quality

The thorough run skipped 30 optional model jobs to preserve the report reserve. The summary names evidence review for the Express server, merge review, actor discovery, architect review, abuse-case derivation and verification, root-cause synthesis, and management summary. Deterministic replacements allowed report completion. Both merge-review jobs and all fourteen abuse-case-verifier jobs had zero model calls. No derived business abuse cases were admitted. The fourteen displayed cases comprise seven technical catalog cases and seven descriptive business cases; the descriptive cases have no linked findings.

This allocation explains why the more expensive run has fewer total model calls and no confirmed abuse chains. The abuse cases did not drive its higher cost. The budget mechanism in [assessment jobs](../../../scripts/runtime/assessment_jobs.py) protects pending required analysis and report completion; it does not ensure that all optional verification and synthesis will fit. Raising the budget might permit those jobs, but this pair does not establish the amount needed or the quality of their eventual results.

The saved final report contains concrete consolidation and status problems. The fixes below apply to the current engine; the original run artifacts remain unchanged:

- F-011 and F-031 describe the same template-injection sink at `routes/userProfile.ts:87`, once as confirmed-class Critical and once as a High practice. F-090 and F-091 substantially overlap on client-side campaign coupon validation. Merge review was skipped, but the run alone does not prove that executing it would remove these duplicates.
- Token storage is split across several thorough findings, including F-112 through F-116; standard F-005 groups seven instances. Relevant locations must remain traceable when findings are consolidated.
- Technical case AC-T-003 associates the coupon-tool finding F-058 with a step about trusting an admin role in a JWT. That pairing does not substantiate the stated step. The case remains inconclusive.
- The thorough YAML marks abuse-case verification complete despite the underlying verdict artifacts stating `no verifier verdict` with empty step verdicts. Use the run summary and verifier artifacts to interpret these saved results; the corrected renderer now distinguishes unexamined cases from reasoned inconclusive decisions.

## Verified fixes

The [change record](../../../specs/changes/verified-abuse-results-and-sink-merging/proposal.md) documents the regressions and compatibility details. Focused tests first reproduced seven failing assertions. The corrected engine treats empty verdict stubs as unchecked, requires mechanism evidence for broad authorization CWE matches, and offers only explicit fixes for confirmed steps without asserting that those fixes already block an attack. Compact tables retain unchecked case IDs and unresolved evidence. Derived unchecked cases remain available for an explicitly requested later check.

Offline replay of the saved thorough artifacts produces fourteen unchecked cases, zero completed case verifications, and a valid YAML export. The abuse section decreases from about 2,745 to 279 words without dropping case IDs. The F-058 coupon finding no longer matches the JWT-role step in AC-T-003. The verified F-011/F-031 template-injection pair consolidates into one finding with both evidence instances and both categories. This requires a single confirmed model trace and a reviewed scanner observation at the exact same injection sink and source scope; the general category guard remains in place.

The nearby coupon findings and token-storage groups are not automatically collapsed by this fix. Their apparent overlap does not establish a shared mechanism trace. Semantic review and verification budget allocation remain separate improvements to evaluate. No paid model calls were used for this verification, and these fixes do not measure a reduction in model spending.

## Conclusions and next evaluation

Standard is a reasonable starting point for cost-conscious assessments, including business logic analysis. This comparison supports neither “Sonnet cannot detect business logic” nor “Opus reliably finds everything Sonnet finds.” One run per configuration cannot separate model capability from sampling variation, changed depth limits, or incomplete downstream processing. There is no independently labeled ground truth here, so precision and recall cannot be calculated from report counts.

A Sonnet first pass with targeted Opus review of complex business rules or unresolved evidence is a candidate optimization, not a measured improvement or an implemented automatic escalation policy. Before changing defaults, compare the models at fixed depth with identical admitted source, role inputs, verification limits, and downstream processing. Repeat runs, distinguish unique actionable causes from additional locations, and assess evidence quality against an independently reviewed reference set. Track cost per accepted independent finding and completed verification, rather than raw finding count. Any new paid runs require separate spending authorization.

Prioritize preserving budget for verification and consolidation and evaluating targeted model use before adopting Opus for every STRIDE job. Relevant existing outcomes are REQ-008 for evidence, REQ-011 for abuse cases, REQ-013 for report clarity, and REQ-023 for spending. The fixes change result handling as recorded above; they change no requirement, acceptance rule, spending limit, or model default.
