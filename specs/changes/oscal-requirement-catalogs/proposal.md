---
reason: >-
  Teams keep security requirements in OSCAL catalogs, for example the NIST SP 800-53 controls, but every command that takes a requirements catalog read only the Analyzer's own YAML shape and rejected an OSCAL file as "missing required key: categories". Users had to convert the catalog themselves first.
affected_ids: [REQ-046]
compatibility: >-
  Catalogs in the Analyzer's own format are read as before. A catalog above the context limits of a command (more than 32 context rows per component in assess, more than 160 audited requirements, more than 300 delivered to analyze-threats, an AuthNZ catalog above 128 000 bytes) was cut or failed late; assess now refuses it before the first model call, and the audit and AuthNZ messages name the size and the limit. Saved audits, AuthNZ results and assessments gain optional fields that name the catalog format and the checksum of the supplied file; older results stay valid. An assess run reads a remote catalog only up to 16 MiB and checks redirect targets against the URL policy.
verification: >-
  Offline tests convert nested groups, enhancements, parameter values, selections and open assignments, leave out withdrawn controls, and compare the JSON and YAML forms. Negative cases cover profiles and other OSCAL documents, mixed or extra top-level documents, controls without or with a repeated ID, nesting, control, node and size limits, YAML alias expansion, cyclic parameters, control characters in the title, and files that are not catalogs. Each of the four commands reads an OSCAL catalog and refuses a profile before any model call. The sample files from the NIST oscal-content repository were converted by hand as a plausibility check; they are not part of the test suite.
---

# OSCAL requirements catalogs

The user asked for `--requirements` to work with several formats, starting with OSCAL. The wording was shown in the conversation and approved by the user before any change.

Decisions: the format is taken from the content, so no new option exists and `--demo`, local catalogs, organization profiles and the cache keep working. Only OSCAL catalogs in JSON or YAML are read. XML would need a hardened parser as a new dependency, and resolving a profile means fetching other catalogs and applying merge rules, so both are refused with a hint to resolve or convert first. OSCAL has no obligation level, so every control is assigned MUST and the result says so; a CI gate on MUST therefore blocks on every violated control. A catalog that does not fit the command is refused for every format, not only for OSCAL, because requirements cut from the context would still appear as assessed in the report.

Risks raised: an OSCAL catalog costs more model tokens than the Analyzer's own catalogs, as its texts are longer. The catalog text goes to the model as before and no new host is contacted. The conversion keeps the statement of a control as its text and leaves out guidance and assessment objectives, so the model sees less than the full control. The full NIST SP 800-53 catalog (1 014 active controls) fits no command except `audit-requirements --category`; a resolved baseline, such as the LOW baseline with 149 controls, fits `audit-requirements` and fits `assess` after the conversion keeps the title out of the text.
