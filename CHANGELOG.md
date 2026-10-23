# Changelog

## 2.2.0-rc.2

- Make the manual ImageMagick assessment informational; complete audits can return 0/1 while real unknowns still return 2.
- Match Zend's case-sensitive function names and comma/ASCII-space delimiters. Real FastCGI tests confirm additive global/pool restrictions, including php_value.
- Give fixes a fresh modification time; restore original timestamps only on rollback. Detect metadata conflicts and make interrupted recovery resumable.
- Restrict implicit rollback to the latest transaction; repeating it never reverts an older fix.
- Use standard-library HTTP with no curl prerequisite, two missing-path baselines, bounded streaming and an absolute response deadline.
- Bound permission/Git traversal and total HTTP requests. Add explicit runtime-storage declarations without hiding writable PHP files.
- Default to English; add --lang de with readable German help, findings and prerequisite messages.
- Support JSON previews, fixes and rollback, including plans, transaction state and retained findings on failure.
- Add real PHP-FPM runtime CI, local HTTP integration, language and transaction regression coverage.

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
