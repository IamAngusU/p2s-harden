# Changelog

## Unreleased

- Add a separate bounded `--scan-webshells` read-only triage mode, local line/hash evidence, startup-reference review, redaction, Linux traversal safeguards and inert-sample regressions. Version the preview as 2.3.0-dev; stable 2.2.1 assets remain unchanged.
- Render redacted terminal details as readable EN/DE summaries while preserving structured JSON evidence and privacy filtering.
- Show the existing-INI package-upgrade notice before interactive approval, in human previews and with `--fix --yes`.
- Put the provenance verification command directly in both READMEs. Published 2.2.1 assets remain unchanged while field feedback accumulates.

## 2.2.1

- Aggregate unchanged global/pool findings while preserving independently actionable overrides and stable global IDs.
- Retain per-rule typed technical facts in redacted reports, with strict type/value validation and privacy regressions.
- Verify localhost through bounded current host resolution; never pass solely from a hostname string.
- Add Debian 13 and Ubuntu 22.04 VMs; all four distro VMs verify refusal of --fix --json without --yes.
- Add GitHub-signed provenance for CI-generated release files, an Audit feedback issue form, current/historical documentation links and explicit package-upgrade conffile behavior.

## 2.2.0

- Stabilize the documented Debian 12 / Ubuntu 24.04 host workflow behind nine required public CI jobs.
- Add read-only TCP client-policy, configured/live Unix socket mode, script-extension and environment checks, plus shared-UID context and loaded FFI policy. Pool/network changes remain manual.
- Add allowlisted `--redact` reports with fresh per-report IDs while preserving results, suppressions and exit codes.
- Bound FPM include provenance without Python recursion.
- Expand real PHP 8.2â€“8.5 FastCGI tests to 26 cases each, including extension enforcement, parent environment inheritance and TCP pool dumps. Both distro VMs also verify new pool rules and report privacy.

## 2.2.0-rc.3

- Raise the default walk ceiling to 250000 entries while retaining time limits; cover a real 36000-PHP-file dependency tree without silent exclusions.
- Add schema 2 stable rule/instance IDs, severity, structured resources, remediation, visible OPEN suppressions and open/unknown flags.
- Add `--fail-on open` for OPEN-first exit precedence; UNKNOWN still cannot pass.
- Show actual INI values in zero-context unified diffs; require interactive confirmation or `--yes`, detect edits after preview and print a precise undo command.
- Discover additional sensitive HTTP filenames; keep redirects and ambiguous soft-404s unverified. Show ImageMagick context only when relevant.
- Make English canonical, add diagnostic/ID AST checks and split reviewable source into eight components assembled into standalone distributions.
- Add real Debian 12/PHP 8.2 and Ubuntu 24.04/PHP 8.3 systemd-VM integration and PHP 8.2â€“8.5 FastCGI jobs to the required CI proof.
- Expand bilingual onboarding, option help, download verification, source transparency, English details and per-rule remediation.
- Keep new-file drop-ins, automatic redaction, broader isolation/profile checks and production-worker probes outside this release's tested scope.

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
