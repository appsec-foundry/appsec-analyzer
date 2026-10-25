# Fünfter Messlauf (REQ-040): Übergabe

Stand 2026-10-25, Nachmittag. Diese Übergabe ersetzt die zum vierten Lauf ([verification-run-4-handoff-2026-10-25.md](verification-run-4-handoff-2026-10-25.md)); ihre Arbeitskopie liegt unter `/home/mrohr/appsec-reports/verify-runs/HANDOFF.md`.

## Stand

Das Messprogramm zu Survey und Verify ist abgeschlossen. Ergebnis und Reihenfolge stehen im [Statusdokument](verification-cost-open-points-2026-10-23.md), Punkte 11 und 12.

- Lauf 5 (`/home/mrohr/appsec-reports/juice-verify-cost-5`, Code d1429c36) ist fertig und ausgewertet: USD 15,59, davon USD 8,24 übernommen aus Lauf 4. Verify kostet bei standard etwa USD 6 pro Lauf.
- Die Korrekturen aus Lauf 4 wirken: Combiner-Texte nennen keine falschen Anzahlen mehr (22f10c00), der Preload liefert die meistgebrauchten Datenmodelle zuerst (eb1e49c4), die Token-Zeile nennt ihre Aufrufe (db8ca15e).
- Behoben, aber noch nicht live gemessen: Funde in Dateien einer anderen Komponente werden entfernt statt an eine falsche Zeile verschoben, und Ablehnungen sind im Diagnoseprotokoll wieder lesbar (80ca6d1d).
- Die Abschlusszeile nennt neben der Kopfzahl das Register nach Schweregrad, wenn beide abweichen (f4692241).
- Routenketten wie `app.route(path).get(a).put(b)` liefern ihre Guards jetzt je Methode (0e9aed1d). Vorher sahen auf Juice Shop PUT und DELETE `/api/Users/:id` ungeschützt aus, obwohl `denyAll()` sie sperrt. Verify-Jobs bekommen diese Guards nun in den Preload; die Verify-Anfragen ändern sich dadurch.
- Schritt 13 ist entschieden: Funde, die nur Verify gemeldet hat und die kein Post-Check bestätigt, gehen durch die Evidenzprüfung. Der Wortlaut für REQ-040 ist freigegeben und eingetragen (83955aea, Proposal `specs/changes/verification-findings-evidence-review/proposal.md`). Gebaut ist es noch nicht.
- Gepusht ist bis 04a72309. `main` ist dem Remote mit 83955aea und dem Commit dieser Aktualisierung voraus. Gepusht wird nur auf Anweisung.

## Nächste Schritte (Reihenfolge im Statusdokument)

13. Reine Verify-Funde bestätigen, damit konkrete Routenfunde bewertet werden. In Lauf 5 sind alle 13 neuen AuthZ-Funde unbestätigt und fallen deshalb aus der Kopfzahl. Ein Offline-Test zeigte, dass ein Check, der aus einem fehlenden Guard auf eine Schwäche schließt, nur so gut ist wie die Guard-Auflösung: Routenketten fehlten (inzwischen behoben), und am Code eines Guards lässt sich eine Authentifizierung nicht von `denyAll()` unterscheiden. Vertretbar ist nur eine enge Regel: generierte Route ganz ohne Guard und ohne Hook vor dem Schreiben (auf Juice Shop PUT `/api/Products/:id`, PUT `/api/Hints/:id`, POST `/api/SecurityAnswers`). Entschieden ist stattdessen: Reine Verify-Funde ohne bestätigenden Post-Check gehen durch die Evidenzprüfung. Die enge Regel hätte in Lauf 5 nur 3 der 13 Funde bestätigt (T-056, T-072, T-115), und sie kennt als Generatoren nur finale-rest und epilogue, wirkt also auf anderen Anwendungen kaum. Die Regeln stehen im Acceptance contract unter REQ-040: Ein bestätigter Fund wird bewertet und gezählt, ein abgelehnter bleibt als widersprochen und unbewertet im Register. Bei offenem Urteil oder fehlendem Budget bleibt es bei „model review only“, und die Lücke wird gemeldet. Ohne solche Funde gibt es keinen Aufruf. Geschätzt kostet das etwa 4 Aufrufe und USD 0,30 bis 0,50 pro Lauf auf Juice Shop; gemessen ist das nicht.
14. Ein Messlauf auf einer zweiten Anwendung, die nicht absichtlich verwundbar ist, zusammen mit Schritt 13 und 80ca6d1d.
15. Die offenen Punkte aus Punkt 10, sobald einer davon stört.
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

## Auftrag für die nächste Sitzung (zum Einfügen)

Weiterarbeit an Survey und Verify (REQ-040) im appsec-analyzer. AGENTS.md beachten. Keine Modellaufrufe und keine Live-Läufe ohne Freigabe. Nur erforderliche Tests. Vor der ersten Änderung an einer versionierten Datei fragen, ob Feature-Branch oder main. Committen nur auf Nachfrage.

Zuerst lesen: `docs/internal/analysis/verification-run-5-handoff-2026-10-25.md` und `docs/internal/analysis/verification-cost-open-points-2026-10-23.md` (Punkte 11 und 12, Reihenfolge). Dann Schritt 13 der Reihenfolge umsetzen: reine Verify-Funde ohne bestätigenden Post-Check durch die Evidenzprüfung schicken, wie im Acceptance contract unter REQ-040 beschrieben. Das Proposal `specs/changes/verification-findings-evidence-review/proposal.md` nennt die nötigen Tests. Die Umsetzung gehört auf einen eigenen Feature-Branch in einem Worktree.
