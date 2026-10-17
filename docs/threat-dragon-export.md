# Threat Dragon export

The full assessment can request an OWASP Threat Dragon v2 JSON export with
`appsec-analyzer assess --repo <path> --host claude-cli --budget <usd>
--threatdragon`. The export is alpha and opt-in. It is generated from the
validated assessment model; a deterministic scan has no architecture model
and cannot produce this export.

Use `appsec-analyzer results --output <assessment-directory>` to verify the
published deliverable and its recorded digest. The
[historical Advisor guide](history/advisor/threat-dragon-export.md) records the
earlier plugin command and format discussion.
