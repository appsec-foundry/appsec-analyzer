---
reason: A live Codex CLI assessment of Juice Shop stopped after 40 minutes because one STRIDE call lost its provider stream after 21 seconds. The retry policy listed only four transient failure codes, so dropped connections and every other unlisted code ended the run as a failure without a repeat.
affected_ids: [REQ-022, REQ-023]
compatibility: Public commands and artifacts are unchanged. Dropped or unopened provider connections are now repeated under the existing delays and paid-retry limits, and a connection that stays down for a required job pauses the run with exit code 3 instead of failing with exit code 1. Optional jobs keep their coverage-gap fallback. API hosts now report a failed send as connection_failed or tls_failed instead of transport. The runtime fingerprint changes, so a run started with earlier code needs a new output directory rather than --resume.
verification: Offline tests repeat each network failure code once without a cost report, stop after one repeat when the connection stays down, never repeat account, certificate or unknown failures, pause the controller with exit code 3 only for network failures, classify API send failures, and require every produced failure code to belong to exactly one retry class. Ruff, the specification gate and the standard offline gate run against the base commit. No live model call was made.
---

# Repeat dropped provider connections

The retry decision depended on a list kept apart from the code that produces failure codes. Any code missing from that list, including `stream_disconnected`, `connection_failed` and `connection_timeout`, was final. With hundreds of calls over several hours, a single dropped connection is likely.

Every host failure code now belongs to exactly one class: transient provider failure, network failure, or fatal. Network failures follow the existing transient retry rules. A test collects the documented failure codes and the literal codes raised by the hosts and rejects any unclassified or doubly classified code. An unclassified code remains fatal at run time.

When the connection stays down for a required job, the controller pauses the run like an exhausted rate limit: exit code 3, accepted work kept, and `--resume` guidance. Login, quota, certificate, configuration, request and unknown failures are still never repeated. The paid-retry limit per run is unchanged.
