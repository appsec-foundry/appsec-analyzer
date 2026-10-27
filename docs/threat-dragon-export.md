# Threat Dragon export

Add `--threatdragon` to a full assessment to request an OWASP Threat Dragon v2 JSON export. For example, use `appsec-analyzer assess --repo <path> --host claude-cli --budget <usd> --threatdragon`, replacing `<path>` with the repository and `<usd>` with your authorized budget. This optional alpha export uses the validated assessment model. A deterministic scan has no architecture model to export.

Use `appsec-analyzer results --output <assessment-directory>` to check the published file against its recorded hash. Replace the placeholder with your result directory.
