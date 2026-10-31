# Übergabe zur Effizienz der Verifikation

Aktueller Einstieg nach dem Merge: [Verifikation nach dem Merge reviewen und fortsetzen](verification-efficiency-main-handoff-2026-10-31.md). Die folgenden Abschnitte dokumentieren die früheren Arbeitsstände im Feature-Worktree; ihre Aussagen zu uncommittierten Änderungen und damaligen Aufträgen sind historisch.

Stand 2026-10-31. Ziel ist eine generische Verbesserung des Analyzers: unnötige Verifikationsarbeit und Modellkosten reduzieren, ohne Sicherheitsprüfungen oder Quellabdeckung zu verlieren. Juice Shop dient als Vergleichsdatenbestand; anwendungsspezifische Ausschlüsse sind nicht gewünscht. Die zwischenzeitliche Anfrage zur Berichtstabelle wurde vom Benutzer als falsche Session zurückgezogen und gehört nicht zu dieser Arbeit.

## Arbeitsstand und Einstieg

Die Änderungen liegen auf `feat/verification-efficiency` im separaten Worktree `/tmp/appsec-analyzer-verification-efficiency`. Dieser Stand wird zusammen mit der Übergabe committet. Ausgangspunkt ist `a670b9b01c57219ad64658212700d36b6f36e9f8`; `main` im Hauptcheckout `/home/mrohr/appsec-analyzer` steht bei Erstellung ebenfalls dort. Der aktuelle Auftrag umfasst Commit und Übergabe, keinen Merge oder Push.

Eine frische Session sollte in diesem Worktree starten, diese Übergabe und die dortige `AGENTS.md` lesen und zuerst `git status --short --branch` prüfen. Die Komprimierung einer Unterhaltung überträgt deren Kontext nicht automatisch in eine neue Session. Der Commit sichert Code und Übergabe; die Messdateien unter `/tmp` sind nur lokale, vorübergehende Arbeitsartefakte.

```bash
cd /tmp/appsec-analyzer-verification-efficiency
git status --short --branch
git log -1 --oneline
```

## Umgesetzte Änderungen

Die bereits auf `main` enthaltene Änderung `a670b9b0` verkleinert Modellantworten der Verifikation: Der Normalisierer ergänzt Identitätsfelder und Quellhashes aus dem Job und den zugelassenen Quellen, bevor die bestehenden Prüfungen laufen. Das gespeicherte Ergebnisformat bleibt erhalten.

Der neue Commit ergänzt diese Änderungen:

- [case_candidates.py](../../../scripts/model/case_candidates.py) gruppiert Kandidaten nach Priorität, Datei und gemeinsamem Modell oder Handler. Erzeugt diese Reihenfolge mehr Jobs, gewinnt die bisherige Packung. Jeder Kandidat und jede zusammengehörige Quellstelle bleibt enthalten; der erste Job behält auch Prüfpunkte ohne Startkandidaten.
- [assessment_test_cases.py](../../../scripts/orchestrator/assessment_test_cases.py) vereinigt überlappende Quellfenster innerhalb derselben Datei und desselben Repositorys. Ungelesene Lücken und Hostgrenzen bleiben gewahrt. Guards von Routen, die einen Handler erreichen, bekommen Vorrang im Kontext.
- REST-Generatoren ergänzen bestehende Inventarrouten um Datenmodell und vorher registrierte, methodenspezifische Middleware. Später registrierte Guards gelten dadurch nicht als Schutz früherer Generatorrouten.
- [merge_threats.py](../../../scripts/model/merge_threats.py) vereinigt identische Verifikationsfunde vor ihrer Evidenzprüfung. Komponente, primäre Quellstelle, CWE-Familie, vollständige Routenmenge, Mechanismus und automatische Bestätigung müssen übereinstimmen. Alle Verifikationsverknüpfungen bleiben erhalten; automatisch bestätigte und unbestätigte Funde bleiben getrennt.
- [route_inventory.py](../../../scripts/analyzers/route_inventory.py) unterscheidet tatsächliche JavaScript-Registrierungen von zitierten Beispielen. Bei unklarer Stringausführung bleiben Kandidaten bestehen.
- [source_usage.py](../../../scripts/analyzers/source_usage.py) erkennt begrenzte Fälle, in denen eine Datei als Text in eine JSON-Antwort fließt. Solche Dateien liefern keine Serverrouten, bleiben aber für Scanner, Quellprüfung, Codesignale und Komponentenzuordnung zugelassen. Imports und Programmeinstiegspunkte haben Vorrang. Unklare Verwendung behält Kandidaten.

Die Texterkennung unterstützt einfache modulrelative UTF-8-Lesezugriffe in Express und Flask. JavaScript und TypeScript können zusätzlich private, synchrone Helfer mit einem einzelnen Rückgabeausdruck über höchstens drei Aufrufe nutzen. Literale Argumente, einfache Stringverknüpfung, Templates, `path.join(__dirname, ...)` und `new URL(..., import.meta.url)` sind begrenzt unterstützt. Exportierte oder dateiübergreifende Helfer, Verzeichnisschleifen, Caches und vom Arbeitsverzeichnis abhängige Pfade bleiben ungelöst. Quellcode wird dabei nicht ausgeführt.

README und übliche JSON-, YAML- und TOML-Dateien zählen als Referenzbelege. Ihre bloße Anwesenheit blockiert die Erkennung nicht; Verweise auf Programme und unklare Startbefehle zählen weiterhin. Architektur, aktueller Leitfaden, Ausführungsvertrag, Changelog, Testauswahl und REQ-040-Bindings sind angepasst. Anforderungswortlaut und öffentliche CLI wurden nicht erweitert.

## Offline gemessener Nutzen

Der ursprüngliche Lauf liegt unter `/tmp/1667`. Sein Quellenumfang wurde für den Vergleich mit 1.145 Dateien und dem Digest `9c3d5cda4f71032d565d8782987b3389fd2f01380d0765911f6cd247f97abd83` reproduziert. Modellentscheidungen und Scannerbeobachtungen des alten Laufs bleiben im Vergleich fest; es gab keine neuen Modellaufrufe und keine neuen Modellkosten.

| Messgröße im alten Datenbestand | Ausgangsstand | Korrigierter Stand |
| --- | ---: | ---: |
| Verifikationsjobs | 31 | 31 |
| Prüfkandidaten über alle Prüfpunkte | 987 | 987 |
| Scannerfunde | 82 | 82 |
| Funde für unabhängige Evidenzprüfung | 38 | 38 |
| Jobs dieser Evidenzprüfung | 6 | 6 |
| Vorab geladene Quellfenster | 763 | 674 |
| Geladene Zeilen einschließlich Wiederholungen | 26.579 | 25.513 |
| Doppelte Zeilen innerhalb eines Jobs | 1.677 | 0 |
| JSON-Bytes der Quellausschnitte | 1.461.953 | 1.388.862 |
| JSON-Bytes der initialen Pakete | 3.608.443 | 3.536.077 |
| Prüfkandidaten mit vorgeladener Quellstelle | 856 | 904 |

Das entspricht rund 5 Prozent weniger Bytes der Quellausschnitte und 2 Prozent weniger Bytes der initialen Pakete. Diese Größen sind keine Token-, Laufzeit- oder USD-Messung. Vertrauenswürdige Anweisungen, Schema und Transport fehlen in den Paketgrößen; nicht erhaltene deklarierte Kontextdateien wurden als leer angesetzt. Antwortverhalten, Korrekturrunden und Caches werden nicht simuliert.

Ein erster Gruppierungsversuch erhöhte die Jobs auf 32; der Fallback auf die bisherige Packung behebt das. Für einen Metadatenfehler wurde ebenfalls ein Gegenbeispiel geprüft: Ein README darf zusätzliche Beispielrouten nicht wieder aktivieren; vor und nach Hinzufügen des README bleibt es bei einer Route.

Der letzte Ausbau der lokalen Helfer zeigt in einer generischen Testanwendung mit 27 weiterhin zugelassenen Dateien eine Reduktion von 73 scheinbaren Routen und Authentifizierungskandidaten auf eine tatsächliche Route, damit von zwei Jobs auf einen. Im alten Juice-Shop-Datenbestand bringt dieser Ausbau dagegen keine weitere Reduktion: weiterhin 31 Jobs, 987 Kandidaten und keine als reine Textdaten erkannten Dateien. Eine konkrete Kostenersparnis für diesen Lauf ist daher weiterhin nicht belegt.

## Prüfungen und bekannte Fehler

Die letzte fokussierte Prüfung nach dem Helferausbau bestand mit 478 Tests; Protokoll `/tmp/analyzer-helper-flow-focused.log`. Paket- und Kontextprüfungen bestanden zuvor mit 42 Tests; Protokoll `/tmp/analyzer-source-usage-package.log`. Ruff-Lint und Formatprüfung der geänderten Python-Dateien sowie die Spezifikationsprüfung wurden durchgeführt. Bereits bestandene Prüfungen wurden für den abschließenden Commit nicht erneut ausgeführt; seitdem kommt nur diese Übergabe hinzu.

Das Standalone-Gate `make check-analyzer BASE=a670b9b0` ist nicht grün. Das letzte Protokoll `/tmp/analyzer-helper-flow-gate.log` zeigt erfolgreiche Spezifikationsprüfung und Ruff sowie 1.076 bestandene und sieben fehlgeschlagene Tests in `tests/test_public_assessment_operations.py`. Dieselben Fehler wurden bereits auf dem Ausgangsstand reproduziert. Sie betreffen Ausgabeorte außerhalb von Quellcheckouts, private Ausgabe und Host-Einstieg beziehungsweise Aufräumen. Das Gate bricht vor seinem nachfolgenden Testblock ab. Dieser Block war zuvor separat geprüft: 167 bestanden, ein vorbestehender Fehler in `tests/test_check_specs.py::test_main_reports_requirement_and_coverage_counts`, der 43 statt 46 Anforderungen erwartet; Protokoll `/tmp/analyzer-efficiency-gate-tail.log`.

Die letzte Prüfung der gebundenen REQ-040-Selektoren ergab 183 bestandene und neun vorbestehende Fehler; Protokoll `/tmp/analyzer-helper-flow-bound.log`. Acht Fälle in `tests/test_controller_fixture.py` scheitern bereits vor der Verifikation am Rollenablauf des Testclients. `tests/test_compose_threat_model.py::test_classification_line_links_the_test_cases_and_rules_behind_a_finding` erwartet den alten Text „Test cases“ statt „Verification items“. Diese Fehler wurden auf dem Ausgangsstand reproduziert.

Golden-Replay mit `tests/fixtures/golden/juice-shop` zeigt auf Ausgangsstand und geändertem Stand dieselben Fehler bei der SVG-Eingabeintegrität und Abweichungen für YAML, Markdown und SARIF. Protokolle: `/tmp/analyzer-efficiency-golden.log` und `/tmp/analyzer-efficiency-golden-base.log`. Die Fixtures wurden nicht überschrieben. Die Tests für Testauswahl und Skriptlayout haben außerdem 36 auf dem Ausgangsstand reproduzierte Fehler durch fehlende oder überholte Extraktionsrouten und Module; Vergleichsprotokoll `/tmp/analyzer-source-usage-layout-baseline.log`.

Es wurden keine neuen kostenpflichtigen Scans und keine gesamte Testsuite ausgeführt. Die bekannten Fehler wurden weder durch Abschwächung von Prüfungen noch durch Überspringen von Tests verdeckt.

## Lokale Messartefakte

Unter `/tmp/analyzer-verification-offline-1667/` liegen `replay.py`, `baseline.json`, `corrected.json`, `helper_flow.json` und `comparison-after-fixes.json`. Der Replay rekonstruiert den Plan und den Preload aus akzeptierten Artefakten, prüft Quellen- und Artefaktdigests und blockiert Netzwerkzugriffe. Neue Scanner- oder Modellläufe gehören nicht zu diesem Vergleich. Der historische Modus `candidate_job_cap` ist ein Diagnoseexperiment vor Übernahme des Fallbacks, kein zusätzlicher Analyzer-Modus.

Unter `/tmp/analyzer-helper-flow-benchmark/` liegen die synthetische Anwendung, `measure.py`, `before.json`, `after.json` und `comparison.json`. Diese Dateien halten den zusätzlichen Helfervergleich fest. Der Quellstand der letzten Messung ist über den SHA-256 von `source_usage.py` in `comparison.json` festgehalten: `65f52c68e249ce23d7cc7608db913572adba7049f58e38f2a39d4eaba3bc6a4c`.

`/tmp/analyzer-efficiency-base-a670-kw4unutg` enthält eine extrahierte Kopie des Ausgangsstands. Es ist kein Git-Worktree. Ältere Dateien wie `candidate.json`, `comparison.json` im Replay-Verzeichnis und `metadata_counterexample.py` dokumentieren Zwischenstände mit inzwischen behobenen Fehlern; sie dürfen nicht als aktuelles Ergebnis gelesen werden. `/tmp` kann bereinigt werden; die automatisierten Tests im Commit bleiben die dauerhafte Grundlage.

## Nächster Schritt beim Commit 663f1280

Zuerst die globale Unsicherheitsregel in `source_usage.classify` offline untersuchen. Aktuell sammelt ein gemeinsames `ambiguous` alle Unklarheiten aus dem gesamten Quellenumfang; nur bei `not ambiguous` können Dateien als `text-data` gelten. Ein unbekannter Loader, ein nicht unterstützter Dateityp oder eine nicht verfolgte Leseoperation irgendwo im Umfang kann dadurch alle Texterkennungen blockieren. Das ist ein bestätigter Kontrollfluss im Code; welche Ursachen im alten Scan wie viel Arbeit erklären, ist noch nicht ausgewertet.

1. Für den alten Datenbestand Blockiergründe mit Datei und Quellstelle erfassen und zählen. Das kann zunächst als lokale Diagnose ohne Änderung des öffentlichen Ergebnisses erfolgen.
2. Anhand der größten Gruppen entscheiden, welche Lade- oder Verwendungsmuster sich generisch auflösen lassen. Eine sichere Begrenzung der Unsicherheit auf unabhängige Dateien oder Pfade ist erst zu entwerfen und zu belegen; den globalen Schutz nicht einfach entfernen.
3. Positive und negative Gegenbeispiele ergänzen: insbesondere ein Loader in einer anderen Datei, importierte oder exportierte Helfer, Dateischleifen, Caches und unklare Arbeitsverzeichnisse. Tatsächlich ausführbare Dateien müssen Kandidaten bleiben, und Quellen sowie Scannerfunde müssen zugelassen bleiben.
4. Den Offlinevergleich wiederholen. Erst bei einer belegten Reduktion unnötiger Kandidaten oder Jobs einen neuen Livevergleich vorschlagen und dafür Budget und Aufruf ausdrücklich autorisieren lassen.

Dieser Ausbau war beim Commit `663f1280` noch nicht implementiert. Der damalige Auftrag endete mit dem Commit und dieser Übergabe. Der folgende Abschnitt beschreibt die anschließend autorisierte Fortsetzung; für Modellaufrufe bleibt eine ausdrückliche Ausgabenfreigabe erforderlich.

## Fortsetzung: Diagnose und reguläre Einbindung

Die Fortsetzung liegt als uncommittete Änderung auf demselben Branch und im selben Worktree. Der Benutzer hat die Fortsetzung bis zur Offline-Prüfung autorisiert; Modellaufrufe sind ausgeschlossen. Es gibt keinen neuen Commit, Merge oder Push. Vergleichsbasis dieser Fortsetzung ist `663f1280`.

Die Offline-Diagnose unter `/tmp/analyzer-verification-offline-1667/source-usage-diagnosis.json` reproduziert den Quellen-Digest und die Klassifizierung des bisherigen Stands. Unter 775 Dateien der Verwendungserkennung liefern 335 mindestens einen Blockiergrund. Die Gruppen überlappen: 233 Dateien haben eine nicht unterstützte Endung, 102 Namensübereinstimmungen in 43 Dateien gelten als nicht verfolgte Leseoperationen, und 17 Startbefehle im Paketmanifest machen den Quellenkontext unvollständig. Von den 102 Übereinstimmungen sind 79 UI-Aufrufe und zwei Methodendeklarationen mit dem Namen `open`. Zugleich gibt es echte dynamische Ausführung. Es wird kein passiver Textlesezugriff erkannt; eine Lockerung des globalen Blockers allein hätte daher noch keine Kandidaten entfernt. Die Einzelereignisse mit Datei und Quellstelle stehen in `source-usage-blockers.json`, die Aufrufgruppen in `source-usage-patterns.json` im selben Verzeichnis.

Nach einem isolierten Prototyp ist die Erkennung nun regulär in [source_usage.py](../../../scripts/analyzers/source_usage.py) eingebunden. Sie übergibt Lese- und Verbraucherbelege ausdrücklich innerhalb eines Aufrufs und ersetzt keine gemeinsamen Funktionen zur Laufzeit. Unterstützt sind synchrone UTF-8-Lesezugriffe mit festem modulrelativem Pfad in Funktionen ohne Argumente, direkte relative benannte Imports einschließlich Aliasnamen, private mit `null` initialisierte Caches und begrenzte flache Verzeichnisleser mit direkter Abbildung auf Text. Jeder beobachtete Gebrauch des Helfers, seines Moduls und seines Caches muss erfasst sein; zusätzliche Verbraucher, unklare Imports und veränderte Standardbindungen behalten die Kandidaten. Die globale Unsicherheitsregel bleibt erhalten. Auch Verzeichnisnamen, Scannerfunde und Quellzulassung werden unverändert behandelt.

[test_source_usage_delegated.py](../../../tests/test_source_usage_delegated.py) enthält 101 neue positive, negative und Integrationsfälle. Sie prüfen unter anderem dynamische Loader in anderen Dateien, entkommene Helfer und Caches, Imports und Programmeinstiege, manipulierte Array-Methoden, überschriebene Callback-Bindungen, Ressourcenlimits, genaue Lese- und Verbraucherbelege sowie parallele Aufrufe. Zusätzliche Gegenbeispiele sichern Bezeichner mit `$`, Unicode-Escapes, indirekte Modulreferenzen und Ausführung in Template-Strings ab. Konstanten in Template-Strings zählen als Referenzbelege; unerkannte interpolierte Ausdrücke außerhalb nachgewiesener Lesezugriffe behalten die Unsicherheit. Das gilt auch für die bisherigen privaten Helfer. Alle Fälle bestehen. Die produktiven Regeln zählen physische Leseaufrufe vor dem Ausblenden bereits nachgewiesener Körper gegen das Dateilimit. Referenzliterale werden ohne quellgroße Zwischenlisten durchlaufen. Bindings, Testauswahl, Architektur, aktueller Leitfaden, Ausführungsvertrag und Changelog sind angepasst; Anforderungswortlaut und öffentliche CLI bleiben unverändert.

Im synthetischen Vergleich des Prototyps sinken Routen und Kandidaten eines Authentifizierungs-Prüfpunkts von 73 auf eins und seine Jobs von zwei auf einen. Alle 26 Quelldateien bleiben zugelassen. Der reguläre Integrationstest prüft zusätzlich, dass ausdrückliche Programmimports alle 73 Routen und zwei Jobs wieder erhalten und Scannerkandidaten sowie Codesignale trotz einer Textklassifizierung bestehen bleiben. Diese Zahlen messen einen unterstützten Einzelfall, keine vollständige Assessment-Laufzeit, Tokens oder USD.

Der eingefrorene Vergleich mit dem integrierten Code steht unter `/tmp/analyzer-verification-offline-1667/integrated_delegated.json`. Gegenüber `helper_flow.json` sind sämtliche Felder außer Modus und Messdauer identisch: 1.145 Quellen, 31 Jobs, 987 Kandidaten, 82 Scannerfunde, 674 Quellfenster und dieselben Paketgrößen. Artefakt- und Quellprüfungen sowie die Komponentenidentität bleiben Bestandteil des Replay. Es gibt keine zusätzliche Einsparung im alten Lauf und keine neuen Modell- oder Scanneraufrufe. Insbesondere bleiben arbeitsverzeichnisabhängige Pfade, rekursive Leser, Schlüssel-Caches und die umformenden Ausschnitt-Flüsse dieses Datenbestands ungelöst.

Die direkten Testverbraucher und die gebundenen REQ-040-Selektoren liefen mit 663 bestandenen und denselben neun dokumentierten Fehlern; Protokoll `/tmp/analyzer-verification-offline-1667/integrated-verification.log`. Acht Fehler betreffen unveränderte Architekturantworten der Controller-Fixtures vor der Verifikation, einer den alten Berichtstext. Die neuen Fälle waren bereits separat bestanden und wurden in dieser Auswahl nicht wiederholt. Die globale Testauswahl verweigert weiterhin den fokussierten Aufruf, weil acht vorbestehende Testmodule keinem Testpaket zugeordnet sind. Deshalb wurde die ausdrückliche Route aus `SOURCE_TESTS` mit den gebundenen Selektoren verwendet; die fehlenden Zuordnungen wurden nicht repariert.

Der nächste fachliche Ausbau muss nachweisen, wie die bisher ungelösten Leser ihre Zielpfade und Verbraucher begrenzen. Die globale Unsicherheit darf erst dann auf einzelne Ziele beschränkt werden, wenn unabhängige Gegenbeispiele diese Begrenzung tragen. Die aktuellen Änderungen allein rechtfertigen keinen kostenpflichtigen Vergleich. Die unten ergänzten Gate-Ergebnisse gehören zur Verifikation dieser Fortsetzung.

### Abschließende Prüfungen der Fortsetzung

Nach den letzten Gegenbeispielen bestehen die Quellenverwendungs-Tests mit 227 Fällen und ihre direkten Verbraucher mit 352 Fällen, zusammen 579. Die Verbraucherauswahl umfasst `test_route_inventory.py`, `test_case_candidates.py`, `test_case_postchecks.py`, `test_handler_resolver.py` und `test_authz_confirm.py`; Protokoll `/tmp/analyzer-delegated-final-consumers.log`. Ruff-Lint und Formatprüfung der geänderten Python-Dateien sowie `make check-specs BASE=663f1280` bestehen. Der tatsächliche Diff und die geänderten lokalen Markdown-Links wurden geprüft.

Das einmal ausgeführte `make check-analyzer BASE=663f1280` bleibt mit denselben sieben Fehlern in `tests/test_public_assessment_operations.py` und 1.076 bestandenen Tests rot; Protokoll `/tmp/analyzer-delegated-gate.log`. Spezifikationsprüfung und projektweites Ruff bestanden im Gate. Der wegen dieser Fehler nicht erreichte Folgeblock wurde separat ausgeführt: 167 bestanden, ein vorbestehender Fehler in `test_check_specs.py::test_main_reports_requirement_and_coverage_counts` mit der Erwartung 43 statt 46 Anforderungen; Protokoll `/tmp/analyzer-delegated-gate-tail.log`. Die letzten Korrekturen zu Bezeichnergrenzen, Template-Verbrauchern und Arbeitslimits folgten dem Gate und sind durch die abschließenden 579 fokussierten Fälle, Ruff und die Spezifikationsprüfung abgedeckt; das breite Gate wurde danach nicht wiederholt. Die bestehende Ausgabe-/Host-Testbasis und die veraltete Anforderungszählung müssen separat korrigiert werden, bevor das Gate eine grüne Gesamtqualifikation liefern kann.

Der eingefrorene Replay wurde vor diesen letzten konservativen Korrekturen ausgeführt. Im alten Datenbestand ist `complete=false`; er überspringt die delegierte Erkennung und hat bereits die globale Unsicherheit gesetzt. Die letzten Korrekturen beschränken zusätzliche Textklassifizierungen und ändern diesen Pfad nicht. Der Replay wurde deshalb nicht wiederholt. Für diesen Lauf bleibt eine zusätzliche Kostenersparnis unbelegt. Neue Modellaufrufe, die gesamte Testsuite und Live-End-to-End-Ziele wurden nicht ausgeführt; vorbestehende Fehler und Fixtures wurden nicht abgeschwächt oder überschrieben.
