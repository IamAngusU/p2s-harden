# Finding IDs and remediation

Use `rule_id` for a check category and `id` for one canonical resource. IDs do not depend on language, status or prose.
The same rule may appear for multiple FPM instances, pools, users, roots or URLs. Always review the structured resource.

An OPEN severity is an assessment of the reported condition, not a CVSS score. UNKNOWN is incomplete evidence.
Fixes only support the documented INI/directory subset; HTTP, process isolation and host policy need manual changes.

## Webshell triage (development preview)

- `P2S-WS001`: high-priority PHP code indicators. Preserve evidence, compare with
  trusted source and review the line; this is not a malware verdict.
- `P2S-WS002`: startup-file references that may be legitimate. Verify intended
  configuration and inspect targets separately; their values are not reported.
- `P2S-WS003`: scan summary (INFO) or incomplete coverage (UNKNOWN). A zero exit
  never certifies absence of compromise. [Rules, limits and response](WEBSHELLS.md).
- `P2S-WS004`: review-only INFO for indirect constant-prefixed includes and registry
  callbacks. Context still needs review; this is not proof of a safe data flow.
- `P2S-WS005`: protected reviewed baseline status. Exact path/hash/indicator
  acceptance never suppresses coverage gaps; invalid input leaves UNKNOWN.

None of these rules adds an automatic fix, deletion or quarantine action.

## Reviewing and accepting findings

Start with `--json` and `--dry-run --json`. Review each resource and remediation. If an OPEN finding is explicitly accepted,
use `--ignore INSTANCE_ID`; a bare rule ID accepts every resource under that rule. Suppressed OPEN findings stay visible.
UNKNOWN remains incomplete and never becomes a pass through suppression. Suppressions do not prune paths or change fix scope.

## P2S-ENV001

Default OPEN importance: `info`.

Run on a Linux target with readable /proc; use --ssh from other systems.

## P2S-ENV002

Default OPEN importance: `info`.

Provide Python 3.8 or later on the Linux target, then rerun.

## P2S-ENV003

Default OPEN importance: `info`.

Use sudo or an existing root SSH login for complete checks and changes.

## P2S-ENV004

Default OPEN importance: `info`.

HTTP checks use the Python standard library; no curl installation is needed.

## P2S-ENV005

Default OPEN importance: `info`.

Use --doctor for the helper's purpose and the suggested package command.

## P2S-ENV006

Default OPEN importance: `info`.

Process discovery uses /proc when ps is unavailable.

## P2S-ENV007

Default OPEN importance: `info`.

Automatic INI changes need a matching active systemd FPM service.

## P2S-DISC001

Default OPEN importance: `info`.

Review discovery issues; supply --nginx-config or explicit --root/--site mappings.

## P2S-DISC002

Default OPEN importance: `info`.

Check the running FPM master and its protected configuration; unsupported contexts require separate assessment.

## P2S-DISC003

Default OPEN importance: `info`.

Repair the reported FPM configuration/provenance and rerun; other instances remain independently checked.

## P2S-DISC004

Default OPEN importance: `info`.

Review skipped paths or increase the traversal budget; no skipped subtree is certified.

## P2S-PHP001

Default OPEN importance: `high`.

Review --dry-run, test application compatibility, then apply --fix --yes or set the required function restrictions manually.

## P2S-PHP002

Default OPEN importance: `high`.

Set allow_url_include=Off in the effective FPM INI/pool and reload the matching service.

## P2S-PHP003

Default OPEN importance: `medium`.

Review a narrow per-pool open_basedir with application testing; it is an additional restriction, not a sandbox.

## P2S-FS001

Default OPEN importance: `high`.

Remove PHP-user write access to application code and verify ACLs; keep required runtime data separate.

## P2S-FS002

Default OPEN importance: `high`.

Separate code from runtime storage; use --runtime-dir only for reviewed storage and --protect-dir only for an explicit code directory.

## P2S-FS003

Default OPEN importance: `info`.

Resolve the reported user/access/coverage issue or narrow the scope; an incomplete walk cannot pass.

## P2S-FS004

Default OPEN importance: `info`.

Verify that declared upload/cache paths cannot execute uploaded PHP and cannot replace application code.

## P2S-FS005

Default OPEN importance: `high`.

Run the FPM pool as a dedicated non-root account and restart the service after reviewing ownership.

## P2S-HTTP001

Default OPEN importance: `high`.

Deny HTTP access to the reported sensitive file/path, remove public backups/debug scripts, and recheck both HTTP and HTTPS.

## P2S-HTTP002

Default OPEN importance: `info`.

Provide an explicit --site mapping or sufficient HTTP budget; inspect every unknown result.

## P2S-HTTP003

Default OPEN importance: `info`.

Correct the URL/document-root mapping and retry the intended local virtual host.

## P2S-SYS001

Default OPEN importance: `medium`.

Review the host ptrace policy against operational needs; this tool does not change sysctl settings.

## P2S-IM001

Default OPEN importance: `info`.

Review ImageMagick policy rules and delegates for the installed version and application requirements.

## P2S-FIX001

Default OPEN importance: `info`.

Resolve the specific fix preflight blocker, inspect the full proposed diff, and rerun.

## P2S-TX001

Default OPEN importance: `info`.

Keep the backup ID; a repeated implicit rollback never selects an older transaction.

## P2S-EXEC001

Default OPEN importance: `info`.

Resolve the execution error and rerun; consult transaction state before retrying a change.

## Manual verification

For PHP settings, verify the effective FPM pool as well as its INIs. Keep code read-only to the PHP account; move required
uploads/cache into separate storage and deny PHP execution there. Validate ACLs, not just the owner name. A writable
directory can replace code even when individual PHP files are not writable. Shared PHP users weaken pool separation.

For HTTP exposures, remove public backups/debug scripts and configure the intended virtual host to deny sensitive files.
Validate your Nginx configuration before reloading it, then audit the actual HTTPS mapping. A redirect, server error or
matching soft-404 page cannot prove that a file is protected. The filename-based probe set is deliberately bounded.

For incomplete discovery, fix the particular mapping/access issue and rerun. Raise limits only for a reviewed scope.
For fix errors, inspect `transaction.status` and the backup ID before retrying. Do not overwrite a reported rollback conflict.

[CLI and transaction manual](DETAILS.md) Ã‚Â· [Readme](../README.md)

## P2S-FPM001

Default OPEN importance: `high`.

Prefer a Unix socket or loopback bind; for required TCP access set listen.allowed_clients to the intended proxy IPs and verify firewall/container publication.

## P2S-FPM002

Default OPEN importance: `high`.

Restrict the Unix socket to the web-server identity, normally mode 0660 or 0600; review named ACL grants and verify the live socket after restart.

## P2S-FPM003

Default OPEN importance: `medium`.

Set security.limit_extensions=.php after checking application requirements; fix upload execution rules in the web server as well.

## P2S-FPM004

Default OPEN importance: `medium`.

Use clear_env=yes and declare only required env[] variables; test application configuration before reloading.

## P2S-FPM005

Default OPEN importance: `info`.

Use distinct Unix accounts and code ownership for mutually untrusted applications; shared pools may be intentional for one trust domain.

## P2S-PHP004

Default OPEN importance: `high`.

Review whether FFI is needed; set ffi.enable=Off in the effective FPM configuration when compatible, then reload and test the application.

These FPM rules assess disk configuration and, for Unix modes, the visible socket
inode. A TCP allowlist does not prove firewall correctness or Internet isolation.
Socket mode checks do not approve the intent of named ACL grants. `.php .phar`
is informational; empty or additional script suffixes need review. Shared UIDs
are informational because multiple pools may intentionally serve one trust domain.
FFI `preload` is informational and still needs review of preloaded native scopes.
Neither function restrictions nor these checks establish a sandbox.

Primary semantics: [PHP FPM configuration](https://www.php.net/manual/en/install.fpm.configuration.php)
and [PHP FFI configuration](https://www.php.net/manual/en/ffi.configuration.php).

## Aggregated scope and safe facts (2.2.1)

Unchanged function/include pool results share the global finding. The normal
report lists affected pool names and retains the original global resource ID.
Different effective sets and explicit unsafe include overrides remain distinct.
Redundant pool rows/IDs disappear; finding counts therefore count aggregated
causes rather than all inherited copies.

The additive schema-2 `evidence` object contains validated technical facts.
Redacted output retains approved function names, mode/source, setting states,
counts and HTTP status, while excluding private paths/names and arbitrary
diagnostics. Per-resource ignores still require the original local report.
