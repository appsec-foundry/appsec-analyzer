# Verifikation nach dem Merge reviewen und fortsetzen

Stand 2026-10-31. Das Paket zur effizienteren Verifikation ist lokal in `main` zusammengeführt. Der begrenzte Ausbau ist implementiert und offline geprüft. Weitere Einsparungen im alten Juice-Shop-Lauf sind noch nicht nachgewiesen; das breite Gate hat bekannte Bestandsfehler. Diese Übergabe enthält den Einstieg für eine neue Session und den Review der bisherigen Änderungen.

## Arbeitsstand und Startprompt

Der Arbeitsort ist `/home/mrohr/appsec-analyzer` auf `main`. Merge-Commit des Codes ist `a439c372423d1b9044ccdd92f362bbb13310b7d0`. Die zweite Elternrevision ist `d6823b99c84bf16db525b5da614f341076c68d65`; der Dateiinhalt des Merge-Commits wurde gegen diesen Feature-Stand geprüft und ist identisch. Die Übergabe folgt als separater Dokumentationscommit. Es wurde nichts gepusht.

Der Feature-Branch `feat/verification-efficiency` und sein Worktree `/tmp/appsec-analyzer-verification-efficiency` bleiben als Referenz erhalten. Weitere Worktrees gehören zu anderen Arbeiten. Für neue Codeänderungen gelten die Branch- und Anforderungsregeln der [AGENTS.md](../../../AGENTS.md); dieser abgeschlossene Commit-/Merge-Auftrag gibt keine neuen Modellkosten frei.

Für eine frische Session kann der folgende Auftrag kopiert werden:

```text
Arbeite in /home/mrohr/appsec-analyzer.
Lies AGENTS.md und docs/internal/analysis/verification-efficiency-main-handoff-2026-10-31.md.
Prüfe zuerst Branch, Status und die angegebenen Commits gegen den tatsächlichen Git-Stand.
Reviewe das bisherige Verifikationspaket von 79e8ec10 bis a439c372, einschließlich Code, Tests und dokumentierter Grenzen.
Prüfe besonders, dass weniger Kandidaten oder Jobs keine ausführbaren Quellen, Scannerfunde, getrennten Schwachstellen oder notwendigen Prüfungen verbergen.
Trenne konkrete neue Fehler, bekannte Bestandsfehler und noch unbestätigte Vermutungen. Nenne für Befunde Datei und Zeile, Auswirkung und den kleinsten sinnvollen Nachweis oder nächsten Schritt.
Nimm zunächst keine Änderungen vor und wiederhole bereits bestandene Prüfungen nur bei geändertem Prüfgegenstand oder ausdrücklichem Auftrag.
Keine kostenpflichtigen Modellaufrufe, keine Live-Assessments, kein Push.
Nenne nach dem Review den nächsten aussagekräftigen Offline-Praxistest und die dafür benötigten lokalen Quellen oder Artefakte.
```

## Commits und Reviewbereiche

| Revision | Inhalt | Reviewumfang |
| --- | --- | --- |
| `79e8ec10` | Stand vor dem Verifikationspaket | Basis für den vollständigen Review |
| `a670b9b0` | Kleinere Modellantworten durch Wiederherstellung von Job- und Quellenmetadaten | War vor dem Feature-Merge bereits auf `main` |
| `663f1280` | Kandidatenpackung, Quellfenster, Generator-Guards, Fundzusammenführung und erste Texterkennung | Erster Feature-Commit einschließlich älterer Übergabe |
| `d6823b99` | Reguläre Texterkennung über benannte Imports, private Caches und flache Verzeichnisleser mit Gegenbeispielen und Limits | Letzter Implementierungscommit |
| `a439c372` | Merge von `feat/verification-efficiency` in `main` | Identischer Codebaum zu `d6823b99`, keine Konflikte |

Die Reviewbereiche sind mit festen Revisionen reproduzierbar:

```bash
cd /home/mrohr/appsec-analyzer
git status --short --branch
git log -5 --oneline --decorate
git diff --stat 79e8ec10 a439c372
git show a670b9b0 -- scripts/contexts/case_analysis.py scripts/orchestrator/assessment_test_cases.py data/test-case-investigation-policy.md tests/test_case_analysis.py tests/test_controller_fixture.py
git diff a670b9b0 a439c372 -- scripts tests data ARCHITECTURE.md docs/security-assessment.md docs/internal/contracts/orchestration-actions.md
git diff 663f1280 d6823b99 -- scripts/analyzers/source_usage.py tests/test_source_usage_delegated.py
```

`a670b9b0..a439c372` umfasst die beiden zusammengeführten Feature-Commits. `79e8ec10..a439c372` enthält zusätzlich den vorherigen Normalisierer-Ausbau. `BASE=HEAD` deckt diese bereits committierten Änderungen nicht ab.

## Implementierte Abläufe und Reviewfragen

### Modellantworten und Kandidatenpackung

[case_analysis.py](../../../scripts/contexts/case_analysis.py) ergänzt ausgelassene Identitätsfelder und Quellhashes aus dem Job und den zugelassenen Quellen, bevor die bisherigen Prüfungen laufen. Das gespeicherte Format bleibt erhalten. Im Review ist zu prüfen, dass falsche oder fremde Angaben weiterhin abgelehnt werden und der Normalisierer weder ungelesene Quellen noch zusätzliche Evidenz autorisiert. Die entsprechenden kompakten Antwortfälle stehen in [test_case_analysis.py](../../../tests/test_case_analysis.py).

[case_candidates.py](../../../scripts/model/case_candidates.py) gruppiert Kandidaten nach Priorität, Datei und gemeinsamem Modell oder Handler. Wenn diese Packung mehr Jobs erzeugen würde, gewinnt die bisherige Packung. Scannerhinweise bleiben vorn; jeder Kandidat und die gemeinsam geprüften Quellstellen bleiben enthalten. Der erste Job behält Prüfpunkte ohne Startkandidaten. Im Review müssen die vollständigen Kandidatenmengen und Jobgrenzen verglichen werden, nicht nur die Anzahl der Jobs.

### Quellenkontext und Generatorrouten

[assessment_test_cases.py](../../../scripts/orchestrator/assessment_test_cases.py) vereinigt überlappende oder angrenzende Quellfenster derselben Datei und desselben Repositorys. Ungelesene Lücken, Quellberechtigungen und Hostlimits bleiben Grenzen. Guards von Routen, die einen Handler erreichen, bekommen Vorrang. Generatorrouten ergänzen Datenmodelle und vorher registrierte, methodenspezifische Middleware. Später registrierte Guards dürfen frühere Generatorrouten nicht schützen. Die Gegenbeispiele stehen in [test_case_candidates.py](../../../tests/test_case_candidates.py).

### Identische Verifikationsfunde

[merge_threats.py](../../../scripts/model/merge_threats.py) vereinigt identische Verifikationsfunde vor der unabhängigen Evidenzprüfung. Komponente, primäre Quellstelle, CWE-Familie, vollständige Routenmenge, Mechanismus und automatische Bestätigung müssen übereinstimmen. Alle Item- und Fundverknüpfungen bleiben erhalten. Unbekannte Routenmengen dürfen verschiedene benannte Routen nicht verbinden; automatisch bestätigte und unbestätigte Funde bleiben getrennt. [test_multi_repo_builder.py](../../../tests/test_multi_repo_builder.py) prüft Zusammenführung und Trennfälle.

### Programmcode und als Text gelieferte Quellen

[route_inventory.py](../../../scripts/analyzers/route_inventory.py) unterscheidet JavaScript-Registrierungen von zitierten Beispielen und behält Kandidaten bei unklarer Stringausführung. [source_usage.py](../../../scripts/analyzers/source_usage.py) klassifiziert beobachtete Verwendung als `runtime`, `text-data` oder `unknown`. Nur nachgewiesene Textlieferungen in einfache JSON-Antworten dürfen scheinbare Serverrouten entfernen. Imports und Programmeinstiege haben Vorrang. Die Datei bleibt für Scanner, Codesignale, Komponenten und Quellprüfung zugelassen; die Rolle darf keine Quellausschlussregel werden.

Unterstützt sind begrenzte modulrelative UTF-8-Lesezugriffe in Express und Flask, kurze private JavaScript-Helferketten mit literalen Argumenten sowie Funktionen ohne Argumente über direkte relative benannte Imports. Letztere können private mit `null` initialisierte Caches und flache Verzeichnisleser verwenden. Zusätzliche Verbraucher, Namespace-Imports, entkommene Helfer oder Caches, veränderte Standardbindungen und ungelöste Pfade behalten Kandidaten. Die reguläre Einbindung übergibt Belege innerhalb eines Aufrufs; sie ersetzt keine gemeinsamen Funktionen zur Laufzeit.

Die 101 neuen Fälle in [test_source_usage_delegated.py](../../../tests/test_source_usage_delegated.py) prüfen auch `$`-Bezeichner, Unicode-Escapes, indirekte Modulreferenzen, Template-Ausführung, zusammengesetzte Modul-Ladepfade, manipulierte Array-Methoden, Ressourcenlimits und parallele Aufrufe. Physische Leseaufrufe zählen vor dem Ausblenden nachgewiesener Körper gegen das Dateilimit. Bindungen, Helfer, Körper, Namen und Verzeichniskinder sind begrenzt; Literale werden ohne quellgroße Matchlisten durchlaufen. Auch ein Loader in einer anderen Datei muss die unsicheren Kandidaten erhalten.

Die globale Unsicherheitsregel bleibt erhalten: Ein unvollständiger Quellenkontext, unklarer Loader oder anderer nicht aufgelöster Gebrauch kann die Textklassifizierung im gesamten Umfang verhindern. Das ist eine begrenzte statische Analyse, kein allgemeiner JavaScript-Ausführungsbeweis. Die verbindlichen Details stehen im [Ausführungsvertrag](../contracts/orchestration-actions.md#verification-jobs), im [aktuellen Leitfaden](../../security-assessment.md#configure-verification) und in der [Architektur](../../../ARCHITECTURE.md). [REQ-040](../../../requirements.md) und die [Bindings](../../../data/requirement-bindings.yaml) bleiben die Ausgangspunkte; ihre Zuordnung ist keine vollständige Abnahme.

## Belegte Wirkung und Grenzen

Der eingefrorene Vergleich verwendet den alten Lauf `/tmp/1667` mit 1.145 Quellen und dem Digest `9c3d5cda4f71032d565d8782987b3389fd2f01380d0765911f6cd247f97abd83`. Modellentscheidungen und Scannerbeobachtungen bleiben fest. Der Vergleich führt keine neuen Modell- oder Scannerläufe aus.

| Messgröße im alten Datenbestand | Vor der Packungs-/Fensterkorrektur | Gemessener integrierter Stand |
| --- | ---: | ---: |
| Verifikationsjobs | 31 | 31 |
| Kandidaten über alle Prüfpunkte | 987 | 987 |
| Scannerfunde | 82 | 82 |
| Vorab geladene Quellfenster | 763 | 674 |
| Geladene Zeilen mit Wiederholungen | 26.579 | 25.513 |
| Doppelte Zeilen innerhalb eines Jobs | 1.677 | 0 |
| JSON-Bytes der Quellausschnitte | 1.461.953 | 1.388.862 |
| JSON-Bytes der initialen Pakete | 3.608.443 | 3.536.077 |

Das sind rund fünf Prozent weniger Ausschnittbytes und zwei Prozent weniger Paketbytes. Antwortverhalten, Korrekturrunden, Provider-Caches, Transport und tatsächliche Token-/USD-Kosten sind damit nicht gemessen. Die 38 Funde für unabhängige Evidenzprüfung und deren sechs Jobs bleiben ebenfalls erhalten.

Ein synthetischer unterstützter Textlieferungsfall sinkt von 73 Routen und Authentifizierungskandidaten auf eine Route und von zwei Jobs auf einen. Der letzte Fall behält alle 26 Quellen; ausdrückliche Programmimports erhalten im regulären Gegenbeispiel wieder alle 73 Routen und zwei Jobs. Ein früherer privater Helferfall hatte 27 Quellen. Diese Zahlen gehören zu verschiedenen Testanwendungen und dürfen nicht vermischt oder als vollständiger Assessment-Kostennachweis gelesen werden.

Im alten Juice-Shop-Datenbestand bringt die erweiterte Texterkennung bisher keine weitere Reduktion. Die Diagnose fand unter 775 Klassifizierungsdateien 335 Dateien mit mindestens einem Blockiergrund; die Gruppen überlappen. Darunter sind 233 Dateien mit nicht unterstützten Endungen, 102 vermeintliche Leseaufrufe in 43 Dateien und 17 unklare Startbefehle. Von den 102 Namensübereinstimmungen sind 79 UI-Aufrufe und zwei Methodendeklarationen namens `open`. Zugleich existiert echte dynamische Ausführung. Kein passiver Textlesezugriff wurde erkannt; allein das Entfernen eines globalen Blockers würde daher noch keine Jobs sparen.

Der letzte eingefrorene Replay wurde vor den abschließenden konservativen Korrekturen zu Namen, Templates und Arbeitslimits ausgeführt. Der alte Lauf hat `complete=false`, überspringt die delegierte Erkennung und behält bereits global die unsicheren Kandidaten. Dieser Replay wurde nach den Korrekturen nicht wiederholt. Die letzten Korrekturen sind durch die fokussierten Tests abgedeckt.

## Prüfstand und bekannte Fehler

| Prüfung | Ergebnis | Einordnung |
| --- | --- | --- |
| Quellenverwendung einschließlich neuem Modul | 227 bestanden | 126 bisherige und 101 neue Fälle |
| Direkte Verbraucher | 352 bestanden | Routeninventar, Kandidaten, Post-Checks, Handlerauflösung und AuthZ-Bestätigung |
| Gebundene REQ-040-Auswahl mit Verbrauchern | 663 bestanden, 9 Fehler | Frühere Auswahl; dokumentierte Bestandsfehler |
| `make check-analyzer BASE=663f1280` | 1.076 bestanden, 7 Fehler | Spezifikation und projektweites Ruff bestanden; vor den letzten fokussierten Korrekturen |
| Separater Folgeblock des Gates | 167 bestanden, 1 Fehler | Der erste Gate-Block verhindert sonst seine Ausführung |
| Letzte gezielte Prüfungen | Ruff-Lint, Format, Spezifikation und Diffprüfung bestanden | Geänderte Python-Dateien, Bindings und lokale Dokumentationslinks |

Die sieben Fehler des breiten Gates liegen in [test_public_assessment_operations.py](../../../tests/test_public_assessment_operations.py) und betreffen Ausgabegrenzen, private Ausgabe sowie Host-Einstieg und Aufräumen. Sie sind bereits auf dem Ausgangsstand dokumentiert. Im gebundenen Block scheitern acht Controller-Fixtures vor der Verifikation an Architekturantworten ohne legitime Client-Rollen; ein Berichtstest erwartet `Test cases` statt `Verification items`. [test_check_specs.py](../../../tests/test_check_specs.py) erwartet im verbleibenden Folgeblock 43 statt 46 Anforderungen. Diese Fehler verhindern eine grüne Gesamtqualifikation und müssen mit ihren tatsächlichen Ursachen separat korrigiert werden.

Die globale Testauswahl verweigert weiterhin den fokussierten Aufruf wegen acht vorbestehender unzugeordneter Testmodule. Deshalb wurden die ausdrücklichen Routen aus `SOURCE_TESTS` mit den gebundenen Selektoren verwendet. Frühere Golden- und Layoutvergleiche zeigen ebenfalls Bestandsfehler; sie sind in der [historischen Übergabe](verification-efficiency-handoff-2026-10-31.md#prüfungen-und-bekannte-fehler) mit Protokollen aufgeführt. Fixtures und Tests wurden nicht abgeschwächt oder überschrieben.

Der Merge hatte denselben Dateiinhalt wie der geprüfte Feature-Stand. Commit und Merge wurden deshalb ohne Wiederholung bestandener Anwendungstests geprüft. Die neue Übergabe ist eine Dokumentationsänderung. Die gesamte Testsuite, Live-End-to-End-Ziele und neue kostenpflichtige Modellaufrufe wurden nicht ausgeführt. Das breite Gate und der Replay wurden nach den letzten konservativen Korrekturen nicht erneut ausgeführt.

Bei einer Codeänderung oder ausdrücklich gewünschter Wiederholung sind diese fokussierten Befehle die überprüften Einstiegspunkte:

```bash
PYTHONPATH=.:scripts python3 -m pytest -q tests/test_source_usage.py tests/test_source_usage_delegated.py
PYTHONPATH=.:scripts python3 -m pytest -q tests/test_route_inventory.py tests/test_case_candidates.py tests/test_case_postchecks.py tests/test_handler_resolver.py tests/test_authz_confirm.py
```

Für einen vollständigen Review des Pakets ist `79e8ec10` die Vergleichsbasis; für die zwei Feature-Commits `a670b9b0`, für den letzten Ausbau `663f1280`. Ein erforderliches Gate über das ganze Paket nutzt `make check-analyzer BASE=79e8ec10`; für den engeren Umfang wird die jeweilige Vergleichsbasis eingesetzt. Ein reiner Lesereview oder eine redaktionelle Änderung erfordert keine erneute Ausführung.

## Lokale Artefakte

| Pfad | Zweck |
| --- | --- |
| `/tmp/analyzer-verification-offline-1667/integrated-result.json` | Zusammenfassung des letzten uncommittierten Prüfstands; Git-Statusfelder darin sind inzwischen historisch |
| `/tmp/analyzer-verification-offline-1667/integrated_delegated.json` und `helper_flow.json` | Letzter integrierter Replay und vorheriger Vergleich; bis auf Modus und Messdauer identisch |
| `/tmp/analyzer-verification-offline-1667/source-usage-blockers.json` und `source-usage-patterns.json` | Blockiergründe mit Datei/Quellstelle und Aufrufgruppen |
| `/tmp/analyzer-verification-offline-1667/replay.py` | Privater eingefrorener Replay mit Digest- und Netzwerksperrprüfungen |
| `/tmp/analyzer-delegated-final-consumers.log` | 352 direkte Verbrauchertests |
| `/tmp/analyzer-verification-offline-1667/integrated-verification.log` | Gebundene Auswahl mit den neun Bestandsfehlern |
| `/tmp/analyzer-delegated-gate.log` und `/tmp/analyzer-delegated-gate-tail.log` | Breites Gate und separat ausgeführter Folgeblock |

Die `/tmp`-Dateien sind vorübergehende lokale Belege und nicht Teil des Commits. Insbesondere die Prototypdateien, `candidate_job_cap` und ältere Vergleichsdateien beschreiben Zwischenstände und keinen öffentlichen Analyzer-Modus. Nach einer Bereinigung bleiben Code, Tests, Verträge und diese Zusammenfassung im Repository; der historische Modell-/Scanner-Replay lässt sich ohne seine ursprünglichen Eingangsartefakte nicht vollständig rekonstruieren. Die ursprünglichen Messdetails stehen in der [historischen Übergabe](verification-efficiency-handoff-2026-10-31.md).

## Nächster fachlicher Schritt

Zuerst den zusammengeführten Code anhand der genannten Invarianten reviewen. Danach ist ein Offline-Praxistest an einer ausdrücklich ausgewählten realen Anwendung mit unterstützten Textlieferungsmustern sinnvoll: Kandidaten und Jobs vergleichen und zugleich gleiche Quellen, Scannerhinweise und notwendige Prüfungen nachweisen. Die bisherigen synthetischen Fälle allein belegen noch keine Ersparnis im alten Lauf.

Für den ursprünglichen Datenbestand bleiben arbeitsverzeichnisabhängige Pfade, rekursive Leser, Caches mit dynamischen Schlüsseln und umformende Ausschnitt-Flüsse ungelöst. Eine Begrenzung globaler Unsicherheit auf einzelne Ziele braucht einen eigenen Nachweis samt Gegenbeispielen, besonders für unabhängige Loader und weitere Verbraucher. Den globalen Schutz oder die Quellabdeckung nicht als Abkürzung entfernen. Ein kostenpflichtiger Vergleich kommt erst nach belegtem Offline-Nutzen und einer ausdrücklichen Freigabe von Aufruf und Budget infrage.
