# Übergabe: offene Punkte nach den Robustheits-Paketen

Dies ist ein Hinweis, kein Auftrag. Jede Aussage vor dem Handeln am Code prüfen.

## Erledigt (auf `main`, nicht gepusht)

- Paket 1 und 2: `33154ab3`, `e21a5712` (Merge `7bda22a6`).
- Befund 10, optionale Aufträge bei ungültiger Host-Antwort ersetzen: `e203696e`.
- Befunde 5 und 19, ausgefallene Prüfschritte und unlesbare Dateien im Report nennen: `4f1cde89` (Merge `a042acc8`).
- Zu pushen: `main` liegt 9 Commits vor `origin/main`. Nur auf Anweisung pushen.

## Offen

1. **Befund 14: Modell in die Job-Identität.**
   - Ist heute: Die Wiederverwendung eines Schritts (`scripts/runtime/assessment_jobs.py`, Prüfung um `request_sha256`) vergleicht Rolle, Anfrage und Quellstand. Das Modell steckt nicht erkennbar im Vergleich. Noch lesen, ob die Anfrage es indirekt enthält.
   - Das ist ein Feature (geänderte Modellnutzung). Erst Requirement freigeben lassen, dann Code. Vorschlag, ergänzend zu REQ-016:
     > Resuming reuses accepted steps that are still valid. A step is reused only if it was produced by the model now selected for that step; after a model change, the affected steps run again and count toward the budget.
   - Risiken: Mehrkosten nach Modellwechsel. Bestehende Ergebnisse ohne Modellangabe werden nicht mehr wiederverwendet.
   - Nach Freigabe: `requirements.md`, Acceptance-Abschnitt, Binding und `specs/changes/<change>/proposal.md` (reason, affected IDs, compatibility, verification).
   - Status: Der Nutzer hat den Wortlaut noch nicht bestätigt.
2. **Befund 20:** Die Beschreibung im alten Handover war zu vage. Nichts geändert. Nachfragen oder verwerfen.
3. **Aufräumen:** Worktree `.claude/worktrees/report-gaps` und Branch `fix/report-gaps` sind gemergt und können weg (`git worktree remove`, `git branch -d`; im geteilten Checkout mit `dangerouslyDisableSandbox`). Erst nach den Vergleichsläufen unten.
4. **Befund 15, zweiter Teil:** Modellprozesse laufen nach einem zweiten Ctrl+C evtl. weiter. Nach Code-Lesen stoppen die Worker ihre Prozesse selbst. Nicht reproduziert, nicht geändert.

## Bereits vor dieser Arbeit rot (nicht von uns)

Auf dem Stand vor den Paketen (`f81d00d4`, per `git archive` geprüft) schlagen schon fehl:
- `test_multi_repo_assessment.py`: `test_tight_budget_skips_optional_jobs_and_still_publishes_a_gated_report`, `test_single_repository_controller_carries_oauth_provider_into_figure_1`, `test_budget_stop_keeps_accepted_candidates_in_a_separate_incomplete_report[names0/names1]`, `test_a_clean_run_offers_questions_about_its_scope_and_nothing_to_triage`, `test_a_run_opens_its_progress_file_with_what_it_is_about_to_spend`, `test_console_header_states_the_resolved_limits_models_and_checks`.
- `test_pregenerate_fragments.py::TestSystemOverview::test_scope_names_targets_the_analysis_could_not_decide`.
- `test_run_tests.py::test_every_test_has_an_explicit_group_or_manual_role`.

Ungeklärt: `test_rate_limit_pause.py::test_subscription_rate_limits_report_no_cost_and_use_the_free_retry_schedule` war im ersten Lauf rot und im späteren grün. Zwei Vergleichsläufe (Branch gegen Stand vor den Paketen) waren beim Schreiben noch nicht fertig.

## Regeln, die hier gelten

- Vor der ersten Änderung je Vorhaben fragen: Branch (eigener Worktree) oder `main`.
- Nur Tests der geänderten Module plus höchstens ein Grenztest. Kein `make check-analyzer`, keine ganze Suite, keine Controller-Fixtures, keine modellgestützten Befehle.
- Fixes müssen für jedes Repository gelten, der Text nennt den Mechanismus, nie das Beispiel.
- Commit, Merge und Push nur auf Anweisung. Kein `git stash` im geteilten Checkout.
- Das installierte `appsec-analyzer` ist eine pipx-Kopie; Änderungen erreichen es erst nach `pipx install --force .`.
