# Changelog

## 2.2.0-rc.1

- Add `--doctor` with capabilities, affected checks and optional package suggestions.
- Continue independent checks when FPM inspection or individual configuration reads fail.
- Fall back to `/proc` when `ps` is missing or fails.
- Aggregate missing curl/runuser messages and keep useful audit results.
- Inspect supported FPM disk configuration without requiring a systemd service mapping; require verified service management for INI fixes.
- Preflight fix capabilities before starting a transaction.
- List missing helpers even when Python cannot start; return actionable incomplete results.
- Add self-contained Windows PowerShell launcher, preserving argument quoting and exact engine bytes.
- Add JSON schema version, terminal phase hints and fault-injection tests.
- Include repository documentation, MIT license, build consistency checks and CI definition.

## 2.1.0

- Embed the engine in a single Bash file.
- Discover common Nginx includes, sites, roots, aliases and FPM pools.
- Preserve unambiguous mappings when another include cannot be inspected.

## 2.0.0

- Rebuild checks around explicit OK/OPEN/UNKNOWN findings.
- Add reversible, scoped transactions and guarded rollback.
- Remove firewall/Fail2ban mutation from the tool.
