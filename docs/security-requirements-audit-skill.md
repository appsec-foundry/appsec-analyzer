# Requirements audit migration status

The independent Requirements Audit from AppSec Advisor grades a catalog
against a repository and produces a separate verdict and optional gate. It is
distinct from `appsec-analyzer scan` and the requirements check inside a full
`appsec-analyzer assess --requirements` run.

Its former launcher depended on a Claude plugin skill with broad tool rights.
The standalone bounded invocation has not yet been implemented, so this
pre-release Analyzer does not advertise a standalone audit command. Existing
catalog resolution, schema, deterministic summary, and gate code remain in the
source tree for that migration. The [historical audit guide](history/advisor/security-requirements-audit-skill.md)
documents its earlier behavior; its plugin commands are not current Analyzer
instructions.
