# Vierter Messlauf (REQ-040): Übergabe

Stand 2026-10-25, gegen 11:10. Alles hier liegt außerhalb von /tmp und übersteht einen Neustart.

## Stand

Lauf 4 ist fertig. Ausgabe: `/home/mrohr/appsec-reports/juice-verify-cost-4`, Status `complete`, Run-Issues `clean`. Ausgewertet ist er noch nicht, siehe den Auftrag unten.

Abschluss (`.assessment-work/summary.txt`):

- Findings 55: Critical 3, High 21, Medium 31. Lauf 3 hatte 39.
- Mitigations 159: 5 P1, 44 P2, 110 P3.
- Verification: 40 findings, 3 controls, 35 undecidable (34 without a location to examine), 20 no finding, 190 not applicable.
- Abuse cases: 6 confirmed, 4 unresolved, 4 not checked (limit).
- Cost: etwa USD 15,91 für 149 Aufrufe. Davon wurden 125 Aufrufe übernommen (USD 14,72), aus Lauf 3, aus Verify (Versuch 2) und von finding_combiner (Versuch 3). Neu im letzten Versuch: 24 Aufrufe für etwa USD 1,19, also Abuse Cases und Bericht.

## Wie der Lauf lief

- Der Coverage-Block am Ende der Konsole bleibt, wie er ist; der Nutzer hat das so entschieden. Die beiden Zeilen, die `run4.sh` danach ausgab, sind gestrichen.
- Skript `run4.sh`, Profil `run4.yaml` (standard, Budget 25, keine Aspekte genannt, also der ausgelieferte Default AuthN, AuthZ, InputVal, DataProt, AI).
- Gemessen ist main 34ab1527, als Export in `code-34ab1527`. Das ist b41a37be plus die neue Konsole (1f79bc4e) und der Fix für Verify-Funde in Dateien ohne Komponente (34ab1527). Keine der beiden Änderungen ändert eine Modellanfrage. Verify lief in Versuch 2 noch auf `code-b41a37be`, und seine Jobs wurden übernommen.
- Juice Shop hatte den Fingerabdruck `9c3d5cda…`. Prüfen mit `tools/scope_sha.py`, siehe unten.

## Bisherige Versuche

1. 07:31: Abbruch nach 4 Minuten ohne neuen Modellaufruf. Der Lauf begann 25 Sekunden nach einem Neustart, und systemd leerte danach `/tmp` samt Host-Verzeichnis. Seitdem setzt `run4.sh` TMPDIR auf `verify-runs/tmp`.
2. 09:20 bis 09:44: Abbruch nach Verify mit „Selected source state changed“. Ein anderer Agent schrieb währenddessen in Juice Shop (`SECURITY.md`, `.agents/skills/create-threat-model/`, `skills-lock.json`, `threat-model.md`). Diese Dateien liegen jetzt in `verify-runs/juice-shop-aside`. `SECURITY.md` ist zurückgesetzt, Fassung und Diff liegen dort. Ob sie zurück nach Juice Shop sollen, entscheidet der Nutzer. Die Token-Daten dieses Versuchs sind verloren, weil ein späterer Start `host-events` ersetzt. Die Kosten pro Job stehen weiter in `jobs/*.receipt.json`.
3. 09:50 bis 09:56: Abbruch nach dem Merge mit „Merged finding anchor is outside its component ownership“. TCF-045 (XXE, TC-INPUT-06) liegt in `lib/xml.ts:35`, einer Datei ohne Komponente. Verify erlaubt das, das Modell lehnte es ab. Behoben in 34ab1527, an beiden Prüfstellen. Host-Events, Diagnose und Run-Issues dieses Versuchs liegen in `verify-runs/run4-attempt-0950`.
4. 10:22 bis etwa 10:40: vollständig. Bis einschließlich Consolidation wurde alles übernommen.

## Zahlen aus der Konsole (Versuch 3 und Offline-Nachbau, gleiche Jobs wie im fertigen Lauf)

- Verify pro Aspekt: AuthN 14 Funde, etwa USD 0,99; AuthZ 34, etwa USD 2,54; InputVal 27, etwa USD 1,37; DataProt 14, etwa USD 1,10; AI 2, etwa USD 0,19. Die Offline-Schätzung für AuthN lag bei USD 0,6 bis 0,9.
- Merge: 110 Survey-Funde, 101 Scanner-Treffer und 91 Verify-Funde ergeben 154. Die Consolidation meldete „121 of 154 findings in the report · 10 refuted · 23 below the severity floor“, der Abschluss aber „Findings 55“. Zu klären ist, ob das zwei Zählweisen sind (etwa Threats und gruppierte Funde, Lauf 3: 39) oder ein Fehler.
- Beide Verfahren gemeinsam / nur Verify / nur Survey: AuthN 10/4/3, AuthZ 5/28/4, InputVal 14/6/4, DataProt 8/6/3, AI 1/1/9.

## Auftrag für die nächste Sitzung (zum Einfügen)

Weiterarbeit an Survey und Verify (REQ-040) im appsec-analyzer. AGENTS.md beachten. Keine Modellaufrufe und keine Live-Läufe ohne Freigabe. Nur erforderliche Tests. Vor der ersten Änderung an einer versionierten Datei fragen, ob Feature-Branch oder main. Committen nur auf Nachfrage.

Zuerst lesen: `docs/internal/analysis/verification-run-4-handoff-2026-10-25.md` (diese Übergabe; die Arbeitskopie liegt unter `/home/mrohr/appsec-reports/verify-runs/HANDOFF.md`) und `docs/internal/analysis/verification-cost-open-points-2026-10-23.md` (Punkt 10 mit „Business abuse cases and verification“ und die Reihenfolge).

Der vierte Messlauf ist fertig (`/home/mrohr/appsec-reports/juice-verify-cost-4`, Code 34ab1527). Auswerten:

1. Kosten pro Rolle und Aspekt:
   `/home/mrohr/.local/pipx/venvs/appsec-analyzer/bin/python /home/mrohr/appsec-reports/verify-runs/tools/aspect_cost.py /home/mrohr/appsec-reports/juice-verify-cost-4`
   (Belege `jobs/*.receipt.json`, Selektoren aus `diagnostics/*/events.jsonl`). `tools/run_usage.py OUTPUT --summary` sieht nur die Aufrufe des letzten Versuchs (Abuse Cases, Bericht). Die finding_combiner-Aufrufe stehen in `run4-attempt-0950/host-events`. AuthN gegen die Offline-Schätzung: 4 Jobs, etwa USD 0,6 bis 0,9. Neu sind die Kosten der Rolle finding_combiner.
2. Neue AuthN-Items auf Juice Shop (Angular-Frontend):
   - TC-AUTHN-06 (SSO/OAuth): selbstgebauter Implicit-Flow ohne state/PKCE an `login.component.ts:148`, `app.routing.ts:286`, `user.service.ts:68`. Wird er mit dem Survey-Fund zum OAuth-Implicit-Flow (CWE-352, `login.component.ts:148`) ein Fund?
   - TC-AUTHN-07 (unsichere Verfahren): aus der E-Mail gebildetes Passwort (`oauth.component.ts:30`, `:46`), Token in der URL (`user.service.ts:68`).
3. `server.ts:501` trägt getrennte Funde für Products PUT, Hints PUT und SecurityAnswers POST (fa4e2924; die Register-Zusammenführung hält verschiedene Routen auf einer Zeile ebenfalls getrennt).
4. Business-Fälle bei standard: AC-B-001/002/003 sollten `not_performed` mit dem Grund „verification of AuthZ/AuthN asks the same question“ sein; stattdessen laufen AC-B-004 bis 007, soweit ihre Vorauswahl passt (`abuse_case_analysis` in `security-assessment.yaml`).
5. Abuse-Ketten nutzen jetzt Verify-Funde: Ist AC-T-003 (JWT-Algorithmus-Verwechslung) nicht mehr unentschieden, weil AuthN den nicht festgelegten Algorithmus findet (Lauf 3: TCF-077, `lib/insecurity.ts:55`)?
6. Gemeinsames Register: Wie viele Funde fasst die Zusammenführung zusammen, und stimmen die neu geschriebenen Texte (Stichproben)? TCF-045 in `lib/xml.ts` muss als Fund des Express-Servers im Bericht stehen. Dazu den Unterschied zwischen „121 of 154 findings in the report“ und „Findings 55“ klären.
7. Nutzen gegen Kosten von AuthN bei standard (neue Funde ohne anderen Fund auf derselben Zeile), wie in Punkt 10.
8. Ergebnis als Punkt 11 ins Statusdokument, Reihenfolge aktualisieren. Die drei Abbrüche und ihre Behebung gehören dazu.

## Offene Punkte außerhalb des Messlaufs

1. **Zwei Konsolenänderungen, erledigt in 3aa40989 auf main.** Beide hat der Nutzer anhand eines Entwurfs freigegeben. Lauf 4 lief noch ohne sie (34ab1527).
   - Jede Phase, in der Threat analysis jedes Verfahren, sagt „taken over from the earlier run“ einmal, sobald der erste Job übernommen wird. Bei Verify reicht die Startzeile, wenn sie es schon sagt. Eine längere Fassung („results of the earlier run are taken over where nothing changed“) fand der Nutzer zu lang. Umgesetzt mit `taken_over` in der Konsole und `on_reused` in `scripts/runtime/assessment_jobs.py`.
   - Gesamtzeit und Gesamtkosten fortgesetzter Läufe: Ein neuer Start, der einen unfertigen Lauf übernimmt, führt dessen `worked_seconds` weiter (`scripts/runtime/assessment_state.py`). Die Kopfzeile `Earlier run` nennt dessen Arbeitszeit und Ausgaben. ELAPSED zeigt die Gesamtzeit in Klammern, wie schon bei `--resume`, ebenso die Abschlusszeile („written in 15m (1h28m in total)“). Phasenzeilen mit neuen Kosten sagen „≈ USD 0.80 (USD 15.52 in total)“, mit `total_usd` aus `usage_mark`.
   - Tests: `tests/test_assessment_state.py`, `tests/test_assessment_jobs.py`, `tests/test_assessment_console.py` und die betroffenen Konsolentests in `tests/test_multi_repo_assessment.py`, alle grün. Ein Offline-Nachbau von Lauf 4 zeigt beides. Der Leitfaden (`docs/security-assessment.md`) ist angepasst.
2. **Quelländerung während eines Laufs (Anforderung, wartet auf Freigabe des Wortlauts).** Heute bricht ein Lauf an der nächsten Phasengrenze ab, wenn sich der Checkout ändert. Danach passt kein Beleg mehr, weil jeder an den Fingerabdruck der ganzen Quelle gebunden ist. Die Analyse liest aber nur das beim Start eingefrorene Abbild (`scope.read`, Scanner-Snapshots). Der Nutzer hat entschieden: weiterlaufen mit Warnung. Vorgeschlagen war:
   - requirements.md REQ-003 bleibt unverändert („Its conclusions apply to that examined source, not to later changes.“).
   - Neuer Satz im Acceptance contract unter REQ-003: „A change to a selected checkout during the run does not stop the assessment; it finishes on the captured snapshot, and the completion summary and the report name the changed files.“
   - Prüfbare Punkte:
     - Eine Änderung, Ergänzung oder Löschung im Checkout stoppt den Lauf nicht.
     - Abschluss und Bericht nennen die geänderten Dateien und den Startstand (Commit und Fingerabdruck).
     - Alle Funde und Belege stammen aus dem Startstand.
     - Ein neuer Lauf untersucht den neuen Stand.
   - Risiken:
     - Ein Bericht beschreibt einen Stand, den der Checkout nicht mehr hat.
     - `assess` endet erfolgreich statt mit Fehler.
     - Voraussetzung ist, dass kein Schritt doch von der Platte liest. Dafür zu prüfen sind `orchestration_controller.py:3466` (Git-Metadaten), `assessment_declarations.py:432` und `:500` (Deklarationsdateien), `assessment_review.py:125` (Abuse-Case-Dateien) und Analyzer mit eigenem `root` (`handler_resolver.py`, `actor_attribution.py`). Wo eine Stelle von der Platte liest, sie auf das Abbild umlegen oder für genau diese Dateien den Abbruch behalten.
   - Nächste Schritte: Freigabe des Wortlauts, dann Acceptance contract, Proposal unter `specs/changes/`, Bindings und Leitfaden (`docs/security-assessment.md`, Satz „A source change may require a fresh assessment“). Danach nach dem Branch fragen und umsetzen.
3. **Kostenschätzung bei `Verify start`**: `has_accepted` zählt laut Docstring absichtlich auch Belege mit geänderter Anfrage. Nach einer Katalogänderung ist die Schätzung deshalb viel zu niedrig (Lauf 4: etwa USD 0,58 statt etwa USD 6).
4. **Leitfaden**: `docs/security-assessment.md` sagt, der Lauf nenne vor der Survey die Komponenten, die er prüfen wird. Die Konsole zeigt diese Zeile aber nicht, sie gewichtet nur.
5. **Vorbestehend rote Tests (auch auf HEAD vor diesen Änderungen)**:
   - `tests/test_multi_repo_assessment.py`: die beiden Budget-Stop-Tests (Wrapper ohne `subscription`), `test_tight_budget_skips_optional_jobs…`, `test_a_clean_run_offers_questions…`, `test_a_run_opens_its_progress_file…`.
   - `tests/test_compose_threat_model.py::test_classification_line_links…` („Test cases:“ statt „Verification items:“).
   - 5 Tests in `tests/test_portable_model_readers.py` (fehlendes `scripts/baseline/baseline_state.py`).
   - `tests/test_figure1_dfd.py::test_readme_example…` (fehlendes `.claude-plugin/plugin.json`).
   - `tests/test_analyzer_distribution.py::test_reused_build_drops_retired_resources_and_keeps_guide_links` scheitert in der Sandbox, weil sie das Kopieren von `.claude/settings.json` und ähnlichen Dateien sperrt. Außerhalb der Sandbox ist er nicht geprüft.

## Werkzeuge in `tools/`

- `aspect_cost.py OUTPUT`: Kosten pro Rolle und pro verifiziertem Aspekt aus Belegen und Host-Events.
- `run_usage.py OUTPUT [--summary]`: Ein- und Ausgabe-Tokens, Cache und USD pro Aufruf oder Rolle, nur für den letzten Versuch.
- `scope_sha.py CODE REPO OUTPUT`: ob der Checkout noch den Fingerabdruck hat, den der Lauf festhält (`python -I`).
- `replay_run.py`, `rebuild_context.py`, `rebuild_survey.py`, `size_parts.py`, `server.py`, `show.py`, `transport_check.py`: Offline-Nachbau ohne Modellaufruf, siehe `tools/README.md`. Eine Kopie von `replay_run.py`, in der `--quiet` gestrichen ist, zeigt die ganze Konsole eines Laufs.
