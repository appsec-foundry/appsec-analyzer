---
reason: Organizations need an independently packaged configuration with an automatic installed default, without forking or modifying the engine.
affected_ids: [REQ-018, REQ-019]
compatibility: Existing upstream CLI defaults and explicit organization profile selection remain unchanged; the new opt-in launcher requires manifest schema 1 and exact engine/interface pins.
verification: Test bundled selection and overrides, malformed and escaping resources, missing/incompatible profiles, installed wheels outside both source checkouts, runtime profile resolution, archive inventory, CI exit preservation, public CLI regressions, specifications and Ruff.
---

# Packaged organization defaults

Add a public organization launcher API and a strict versioned package manifest. The launcher explicitly names its own installed resource package. It validates the default scan/model/org configuration before dispatch and adds it to full assessments only when the operator has not selected an alternative. The package default takes precedence over the legacy org-profile environment variable; explicit flags still win. Existing core controls are unchanged.

Ship an installable fictional Nordlicht distribution, exact runtime/build locks and an English guide covering organization repository ownership, package data, clean source builds, local installation, approved wheelhouse checksums, CI authentication, noninteractive budgets, exit statuses, private artifacts and controlled engine updates. No publication, live model call, hook or external tool integration is added.

Incompatible or incomplete installed configuration fails before a scan. An organization package is a default-selection mechanism, not a way to enforce its settings across arbitrary operator commands. The engine package includes the example and guide; organizations release their own wheel with an exact engine dependency. Record source commits and artifact digests because this preview can have several source revisions with the same engine version.
