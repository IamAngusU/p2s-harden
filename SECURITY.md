# Security scope

This CLI audits selected host PHP-FPM disk configuration, Nginx mappings, user write permissions and local HTTP endpoints. It is not a complete vulnerability scanner or a proof that PHP-to-shell is impossible.

Review particularly: privileged configuration loading, complete include provenance, environment confidentiality, argument transport, write targets, transaction recovery and rollback conflicts. An external command failure must not create a passed result. Missing optional capabilities must not stop independent read-only checks. Required fix capabilities must be checked before mutation.

Reports may contain private domains, paths, usernames and service names. Review/redact them before sharing. Process environments are used only in memory for FPM reconstruction; they must not be printed or saved. HTTP response bodies are discarded.

For a suspected vulnerability, use the repository's private vulnerability reporting channel when the published repository provides one. Do not put credentials, private configuration dumps or exploit targets in public issues. Ordinary compatibility reports should include a redacted `--doctor --json` result, tool version and Linux/FPM layout.
