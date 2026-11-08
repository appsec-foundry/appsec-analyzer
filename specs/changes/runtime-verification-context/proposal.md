---
reason: Runtime verification needs the evidenced input processing and controls to choose meaningful experiments instead of generic payloads.
affected_ids: [REQ-049, REQ-014]
compatibility: Optional version-1 verification_context on findings and pentest tasks. Existing assessments remain readable; engine and interface versions stay unchanged. New request schema fingerprints may require rebuilding unfinished analysis jobs.
verification: Focused context-schema, source-admission, merge, assembler and pentest-export tests, then the standalone offline gate. No live assessment or target requests.
---

# Prepare targeted runtime checks

The user approved the requirement wording “Gezielte Laufzeitprüfungen vorbereiten. Zu prüfbaren Befunden erhalten Nutzer die belegte Eingabeverarbeitung, vorhandene Kontrollen, Voraussetzungen und erwarteten Beobachtungen, damit sie einen passenden Laufzeittest planen können.” and chose implementation directly on main. REQ-049 records that outcome in the catalog's English language.

The approved acceptance covers source-cited query construction and filter order where known, visible assumptions and missing information, control experiments and decision criteria, compatibility with old assessments, and no Analyzer target requests. Additional context can increase token use in existing calls; this disclosed cost was accepted with the wording. There are no additional model calls or execution permissions. The simpler legacy prose remains available to older consumers but does not provide this structured handoff.
