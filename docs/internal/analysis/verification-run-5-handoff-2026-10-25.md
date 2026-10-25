# Fünfter Messlauf (REQ-040): Übergabe

Stand 2026-10-25, Abend. Diese Übergabe ersetzt die zum vierten Lauf ([verification-run-4-handoff-2026-10-25.md](verification-run-4-handoff-2026-10-25.md)); ihre Arbeitskopie liegt unter `/home/mrohr/appsec-reports/verify-runs/HANDOFF.md`.

## Stand

Das Messprogramm zu Survey und Verify ist abgeschlossen. Ergebnis und Reihenfolge stehen im [Statusdokument](verification-cost-open-points-2026-10-23.md), Punkte 11 und 12.

- Lauf 5 (`/home/mrohr/appsec-reports/juice-verify-cost-5`, Code d1429c36) ist fertig und ausgewertet: USD 15,59, davon USD 8,24 übernommen aus Lauf 4. Verify kostet bei standard etwa USD 6 pro Lauf.
- Die Korrekturen aus Lauf 4 wirken: Combiner-Texte nennen keine falschen Anzahlen mehr (22f10c00), der Preload liefert die meistgebrauchten Datenmodelle zuerst (eb1e49c4), die Token-Zeile nennt ihre Aufrufe (db8ca15e).
- Behoben, aber noch nicht live gemessen: Funde in Dateien einer anderen Komponente werden entfernt statt an eine falsche Zeile verschoben, und Ablehnungen sind im Diagnoseprotokoll wieder lesbar (80ca6d1d).
- Die Abschlusszeile nennt neben der Kopfzahl das Register nach Schweregrad, wenn beide abweichen (f4692241).
- Routenketten wie `app.route(path).get(a).put(b)` liefern ihre Guards jetzt je Methode (0e9aed1d). Vorher sahen auf Juice Shop PUT und DELETE `/api/Users/:id` ungeschützt aus, obwohl `denyAll()` sie sperrt. Verify-Jobs bekommen diese Guards nun in den Preload; die Verify-Anfragen ändern sich dadurch.
- Schritt 13 ist gebaut (8593ac3e), nach dem freigegebenen Wortlaut für REQ-040 (83955aea, Proposal `specs/changes/verification-findings-evidence-review/proposal.md`). Funde, die nur Verify gemeldet hat und die kein Post-Check bestätigt, gehen nach Verify pro Komponente durch die Evidenzprüfung (Selektor `evidence-verification:<Komponente>`). Bestätigt wird bewertet und gezählt; abgelehnt bleibt unbewertet im Register mit `evidence_review_contradicted` und der Begründung; offen oder ohne Budget bleibt „model review only“. Ein Verify-Punkt, dessen Funde alle bestätigt sind, zeigt im Anhang „review“ statt „model“. Noch nicht live gemessen.
- Aus Punkt 10 gebaut, offline getestet, nicht gemessen: whoami-Routen sind Startpunkte von TC-DATA-01 (auf Juice Shop kommt nur `GET /rest/user/whoami` dazu), und AI-Verify greift auch, wo die Architektur einen Fluss zu einem `llm-inference`-Dienst zeigt; in solchen Komponenten zählen auch Modellaufrufe in Java, Go, C#, PHP, Bedrock und LiteLLM und die Belegzeilen der Architektur (beides 1896b8e8). Zwei Survey-Funde mit gleicher CWE und gleichem Prüfurteil an einer Zeile sind über Kategorien hinweg ein Fund (ca02dded).
- Aus Punkt 10 bewusst nicht gebaut: Datenabfragen als Sinks für TC-AUTHZ-01 (zurückgestellt, die Anweisung aus 3515cf86 hat den Auslöser schon behoben). Der Fund auf der auskommentierten Zeile `server.ts:370` ist kein Fehler: Ein Fund über eine fehlende Kontrolle darf die abgeschaltete Kontrolle zitieren (MR-20), und T-055 beschreibt eine echte Lücke.
- Gepusht ist bis 04a72309. `main` ist dem Remote voraus, von 83955aea bis zum Commit dieser Aktualisierung. Gepusht wird nur auf Anweisung.

## Nächste Schritte (Reihenfolge im Statusdokument)

13. Erledigt: reine Verify-Funde gehen durch die Evidenzprüfung (8593ac3e). Die enge Regel für generierte Routen ohne Guard wurde verworfen: Sie hätte in Lauf 5 nur 3 der 13 neuen AuthZ-Funde bestätigt und kennt als Generatoren nur finale-rest und epilogue. Geschätzt kostet die Prüfung etwa 4 Aufrufe und USD 0,30 bis 0,50 pro Lauf auf Juice Shop.
14. Ein Messlauf auf einer zweiten Anwendung, die nicht absichtlich verwundbar ist. Er misst Schritt 13, die Punkte aus Schritt 15 und 80ca6d1d mit. Zu prüfen: Kosten der neuen Evidenzprüfung, wie viele reine Verify-Funde sie bestätigt oder ablehnt, und ob abgelehnte Funde berechtigt abgelehnt sind.
15. Erledigt bis auf die Datenabfragen als Sinks, die zurückgestellt sind (Statusdokument, Reihenfolge Punkt 15).
16. Pooling nach Größe mit einem thorough-Lauf.

Außerhalb der Reihenfolge:

- Die Anforderung zu Quelländerungen während eines Laufs wartet auf die Freigabe ihres Wortlauts (Entwurf in der Übergabe zu Lauf 4, „Offene Punkte“, Punkt 2).
- Die Schätzung bei `Verify start` ist zurückgestellt (Statusdokument, Punkt 11).

## Hinweise für Läufe

- Vorlage: `verify-runs/run5.sh` und `run5.yaml`. Übernommene Jobs zählen mit ihren alten Kosten ins Budget; Lauf 5 brauchte deshalb Budget 25, obwohl nur etwa USD 7,35 neu anfielen.
- Juice Shop hat den Fingerabdruck `9c3d5cda…`; `run5.sh` prüft ihn vor dem Start. Die Dateien in `verify-runs/juice-shop-aside` liegen weiter dort, sonst passen die Belege der Läufe 4 und 5 nicht mehr.
- Neue Werkzeuge in `verify-runs/tools`: `verify_benefit.py OUTPUT` (Nutzen pro Aspekt), `rejected_anchors.py OUTPUT…` (abgelehnte Antworten mit Ankern außerhalb der Komponente), `watch_run5.py OUTPUT` (Beobachtung: Phasen, Fehler, Ende).
- Eine Sitzung, die in einem Worktree unter `.claude/worktrees/` arbeitet, darf in der Sandbox nur dort schreiben; Merges und Commits im gemeinsamen Checkout laufen dann außerhalb der Sandbox. Nach einem Wechsel in einen Worktree setzt die Sitzung ihr Arbeitsverzeichnis auch nach dessen Löschung dorthin zurück; ein Neustart im Hauptcheckout behebt das.

## Vorbestehend rote Tests

Auf `main` auch ohne die Änderungen dieses Tages rot:

- `tests/test_decision_register.py`: 10 Tests, das Register verweist auf fehlende Dateien.
- `tests/test_run_path_guard.py`: 5 Tests, fehlende Skripte; `tests/test_stride_outputs.py::test_baseline_hashes_only_components` (fehlendes Modul `baseline`).
- `tests/test_gate_preconditions.py::test_no_resolution_set_rejects_everything_when_its_authority_is_absent` (`render_pentest_tasks.py:239`).
- `tests/test_summarize_threat_model.py::test_render_text_names_the_ask_and_review_lanes` (erwartet `/appsec-advisor:triage-security-assessment`).
- Aus der Übergabe zu Lauf 4: `test_compose_threat_model.py::test_classification_line_links…`, `test_figure1_dfd.py::test_readme_example…`, `test_portable_model_readers.py` (5), die Budget-Stop-Tests in `test_multi_repo_assessment.py`.
- Der volle Lauf von `tests/test_multi_repo_assessment.py` überschritt 15 Minuten; einzelne Tests daraus laufen normal.
- `tests/test_analyzer_distribution.py::test_reused_build_drops_retired_resources_and_keeps_guide_links` scheitert in der Sandbox, weil es den Checkout samt gesperrter Dateien kopiert; außerhalb der Sandbox ist er grün.

## Auftrag für die nächste Sitzung (zum Einfügen)

Weiterarbeit an Survey und Verify (REQ-040) im appsec-analyzer. AGENTS.md beachten. Keine Modellaufrufe und keine Live-Läufe ohne Freigabe. Nur erforderliche Tests. Vor der ersten Änderung an einer versionierten Datei fragen, ob Feature-Branch oder main. Committen nur auf Nachfrage.

Zuerst lesen: `docs/internal/analysis/verification-run-5-handoff-2026-10-25.md` und `docs/internal/analysis/verification-cost-open-points-2026-10-23.md` (Punkte 11 und 12, Reihenfolge). Dann Schritt 14 der Reihenfolge vorbereiten: mit dem Nutzer eine zweite Anwendung wählen, die nicht absichtlich verwundbar ist, und einen Lauf nach dem Muster von `verify-runs/run5.sh` vorbereiten, den der Nutzer selbst startet. Budget und Kosten vorher mit ihm klären. Auszuwerten sind die neue Evidenzprüfung reiner Verify-Funde (8593ac3e), die neuen Startpunkte (1896b8e8), die Zusammenlegung doppelter Survey-Funde (ca02dded) und 80ca6d1d.
