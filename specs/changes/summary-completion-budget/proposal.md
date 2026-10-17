---
reason: Management Summary was skipped against a full Security Architecture reservation and its own cold-role estimate, leaving spendable funds unused after the required renderer completed.
affected_ids: [REQ-023]
compatibility: Existing spending limits, receipt contracts and deterministic fallbacks remain unchanged; Stage 2 now authors Security Architecture before Management Summary and requirements commentary.
verification: Offline Stage-2 regression at USD 28 of 30 spent, already-filled scaffolds, reduced call allowances, minimum cost, correction, call-count and time boundaries, plus controller and specification checks.
---

# Use the remaining report budget for the Management Summary

Previously, the summary ran first and needed both its own estimated job cost and the required renderer's full reserve. With a USD 2 call allowance it could be skipped with less than USD 4 remaining, even when the required renderer later left enough funds for a summary. The controller never returned to the skipped job.

Complete the required Security Architecture job first and release its reservation when the scaffold needs no model work. Then let the Management Summary use the actual remaining allowance without requiring a full estimated job cost. Keep its model response validation, deterministic fallback, per-call spending ceiling, aggregate budget, call limits and local finalization time. Ordinary optional analysis retains the existing reserve policy. This improves admission without guaranteeing that a provider can finish a summary in the remaining allowance.

The regression executes real assessment job admission and fragment validation with an offline host. It verifies that USD 28 spent out of USD 30 still allows the required renderer and then a summary under the reduced allowance. Boundary tests verify that corrections and exhausted cost, time and call limits stop further dispatch.
