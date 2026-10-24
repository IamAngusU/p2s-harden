# p2s-harden CLI and recovery

`p2s` means PHP-to-shell. This tool supplies selected configuration evidence and
reversible changes for conventional Debian/Ubuntu host PHP-FPM. It does not
establish that every worker loaded the inspected configuration or that all
PHP-to-shell techniques are impossible. Function restrictions are defense in
depth; application compatibility and process isolation remain separate concerns.

## Scope and prerequisites

Use the [one-file quick start](../README.md). The Linux target needs Python 3.8+
and `/proc`; remote clients use existing OpenSSH access. Windows needs no local
Python/Bash. Full foreign-user permission checks and changes need root. Missing
capabilities affect the relevant checks and remain visible; the tool installs
nothing. `--doctor` explains prerequisites and `--discover` shows inventory.

Literal Nginx server names, roots, ports and simple aliases can be discovered.
Protected includes are parsed without running Nginx modules. Ambiguous/dynamic
paths, unresolved includes, symlinks and inaccessible areas are not certified.
Use `--nginx-config`, `--root`, repeated `--site URL=ROOT` and `--web-user USER`
to state the intended scope. An explicit site replaces automatic HTTP mappings.
Discovery never selects a permission-change target.

The default is 250000 entries/10 seconds per filesystem walk and 128 total HTTP
requests over up to 32 automatic mappings. Reached limits produce UNKNOWN.
Dependency directories remain in scope. The sensitive-path walk discovers
`.env*`, `.sql`, `.sql.gz`, `.bak`, `.log`, `phpinfo.php` and `eval-stdin.php`,
in addition to `.env` and nested `.git/config` paths. It is not a general file
classifier or exhaustive backup scanner. Endpoint count, response bytes (1 MiB)
and absolute response time (8 seconds) are bounded. Responses are streamed and
hashed, not saved or printed. Redirects/proxies are not followed. Local TLS
routing uses the original Host/SNI without certifying certificate authenticity.

## Findings and automation

[Rule IDs and remediation](FINDINGS.md) are independent of display language.
Schema 2 findings have a stable `rule_id`, a resource-specific `id`, structured
`resource`, `status`, `severity`, `remediation` and `suppressed` flag. Instance IDs
derive from the rule and canonical resource, not title/detail/status/language.
Changing a resource changes its ID. Severity describes the current OPEN finding;
UNKNOWN means unverified, not an established vulnerability. Treat technical
paths/users/URLs as data, not as localized prose.

`--ignore ID` marks accepted OPEN findings but does not remove them from the
report, change fix scope or prune traversal. A rule ID suppresses that rule for
all resources; an instance ID selects just one. UNKNOWN always remains a
non-success result. Suppressions are command arguments, not implicit project
configuration. Preserve reviewed arguments in your own CI configuration.

`--fail-on complete` (default): UNKNOWN/error -> 2, otherwise OPEN -> 1, else 0.
`--fail-on open`: OPEN -> 1 first, otherwise UNKNOWN/error -> 2, else 0.
JSON always reports both `has_open` and `has_unknown`, plus raw status counts
and the number of suppressed OPEN findings. A mixed result cannot silently
become successful. Schema 1 consumers must migrate to schema 2 fields/semantics;
bootstrap failures without Python provide a smaller schema 2 error envelope.

`--runtime-dir` declares an existing absolute, symlink-free strict subdirectory
of the selected roots. Writable directories there become INFO. Writable PHP,
unreadable paths and exhausted budgets remain findings. It is not a safe-path
detector: verify execution restrictions and code/runtime separation yourself.

## Preview and changes

Run `--dry-run` before changes. It shows proposed directive values and a unified
diff with zero context; unrelated neighboring INI settings are not printed.
JSON returns `plan.ini` entries with `path`, `values`, `diff` and the preview's
`before_sha256`, plus explicit directories and blockers. The tool refuses a
configuration changed between the displayed preview and transaction preparation.

Interactive `--fix` asks through `/dev/tty`, defaulting to No. The engine's stdin
is its code during SSH execution, so stdin is never consumed as an answer.
Reviewed automation must use `--fix --yes`; JSON fixes require that flag. Missing
capabilities block the plan before a transaction begins. Application behavior
can depend on the functions being restricted; test the application afterwards.

Only defined function restrictions and `allow_url_include=Off` in supported
FPM-specific INIs are changed. Shared INIs outside the FPM context are not edited.
There are no automatic Nginx, ImageMagick, firewall, Fail2ban, SSH or sysctl edits.
Permission changes require explicit `--protect-dir` and verified PHP users.
They affect that directory only, without recursive ownership/mode changes.

## Transactions and rollback

Backups are protected under `/root/p2s-harden-backup-v2/UTC-RANDOM/` by default.
The manifest records original bytes, digests, owner/group/mode/xattrs/timestamps,
replacement checkpoints and affected service identities. Fixes receive a new
mtime. Atomic file replacement, configuration tests, master/service checks and
verified reloads guard the supported change path. A failure attempts recovery
of started changes and retains the durable recovery status. JSON keeps earlier
findings and available transaction information on failure.

Human fix output prints an exact undo command. JSON returns `transaction.id`,
`backup_path`, `status`, `noop`, and affected file/directory counts. To recover:

```bash
sudo bash p2s-harden.sh --rollback --backup-id YOUR_ID --json
```

Rollback preflights contents and metadata before writing anything. Conflicting
newer edits, timestamps, permissions, identities or xattrs prevent overwriting.
Original timestamps are restored only during recovery. Interrupted recovery is
resumable. Manual rollback will not automatically start a stopped FPM service;
restored bytes and `rolling_back` state remain available to the administrator.

Without an ID, only the latest transaction is selected. A repeated completed
rollback is a no-op; an older transaction requires an explicit ID. Ambiguous
legacy transactions require explicit selection. Old flat v1 backups are not
guessed, and malformed manifests produce a controlled incomplete result.
This is not a replacement for server snapshots or database backups.

## Source and evidence

Edit `src/*.py`; [the builder](../build-standalone.py) assembles nine source
components into the auditable generated engine and both standalone launchers.
The Linux target does not need source components, imports, pip or package setup.
English is the diagnostic source; the separate catalog supplies German.

Fixture tests, real FastCGI tests and destructive disposable-VM system tests
have different scopes. [Validation](VALIDATION.md), [CI design](CI.md) and the
[rc.3 review decisions](REVIEW-rc3.md) explain those boundaries. Ordinary fixture
tests never modify real host PHP/Nginx/firewall configuration. System-runtime
tests require an explicit root-owned disposable-VM marker and environment flag;
never use that developer test on a production server.

## FPM boundaries and private reports (2.2.0)

The audit now checks TCP listeners against literal-IP client allowlists, Unix
socket configured/observed modes, `security.limit_extensions`, `clear_env`,
shared numeric UIDs and `ffi.enable` when that directive is present in the
inspected PHP configuration. Network reachability, host firewall, container
publication, named ACL grant intent and production-worker values are not inferred.
See [production scope](PRODUCTION.md) and [per-rule actions](FINDINGS.md).

`--redact` supports check/doctor/discover and the development webshell scan, with human or JSON output. It uses
an allowlist projection, so paths, domains, users, arbitrary diagnostics,
inventory, preview and transaction data cannot enter the report through a
new metadata field. Redacted instance IDs are fresh per output; original IDs
remain the automation contract locally. Exit status, rule IDs, result counts
and suppression status are preserved. Only report stdout is covered; existing
SSH/system stderr is outside that projection. Masked change approval is refused.

FPM include provenance walks are iterative and stop at 64 levels, 1024 files,
2 MiB per file or 16 MiB total. Reaching a bound is incomplete coverage.

## Aggregation and safe technical evidence (2.2.1)

Unchanged effective pool function/include results share the global resource
finding, with normal JSON `affected_pools` and typed `evidence.affected_pool_count`.
Different missing-function sets remain separate even when both are OPEN. An
explicit unsafe include override remains separate because a global change
cannot remove it. Global resource IDs stay the same; redundant pool rows are
removed, so finding counts and previously redundant pool IDs can change.

`evidence` is an additive schema-2 field, not raw configuration. Per-rule checks
admit known function names, canonical socket modes/source, safe setting enums,
booleans, counts and HTTP status. Redaction validates these fields again and
omits all unapproved values. Technical evidence keys remain stable English API
names in both languages. Host identifiers and arbitrary diagnostic text remain
omitted. [Current review decisions](REVIEW-2.2.1.md).

Exact localhost names use current host resolution in an isolated child with a
two-second timeout, cached per FPM instance. All returned IPs must be loopback;
other answers are OPEN and failure is UNKNOWN. It does not prove an existing
listener binding or support arbitrary DNS/container service names.

## Package upgrades

The supported fix edits existing INIs and can modify a package-managed
`php.ini`. If both the local file and the maintainer's version change, a later
package upgrade can ask which configuration to retain. Review the proposed
merge/diff and re-audit after an upgrade; do not blindly replace the file or
silently disable package-manager prompts. See [Debian configuration-file
handling](https://www.debian.org/doc/debian-policy/ap-pkg-conffiles.html).

New-file drop-ins remain deferred until ordering, creation, interrupted recovery
and rollback deletion/conflict cases have their own tested lifecycle. Deleting
a drop-in is not automatically a safe rollback if another tool changed it later.

## Distribution provenance

Checksums alone detect corruption, not independent origin. See the optional
[GitHub attestation verification](PROVENANCE.md) for exact bytes, signer workflow,
source-ref/commit checks and the same-maintainer CI account's trust boundary.


## Transaction concurrency and retention (development preview)

Fix preparation, apply/reload/recovery and rollback selection/restore use a nonblocking exclusive kernel lock on the fixed root-owned mode-0700 `/run/p2s-harden` directory inode, plus the protected backup-directory inode for compatibility. The CLI holds it across prepare and apply; contention returns an actionable UNKNOWN without changing target files. No lock file or stale PID needs deletion; the kernel releases it on process exit. Read-only audits never acquire it. Changing `--backup-root` cannot bypass the system lock. All current tool instances coordinate; unrelated editors/package tools and older versions do not participate in the new system lock. Do not remove its directory while writers are active. Existing digest/metadata checks still apply.

Backups are not automatically pruned. They retain configuration bytes and metadata for rollback; keep the directory protected, monitor its disk usage and remove only recovery data you no longer need after independently verifying the current deployment. Removing a backup removes that rollback option.


## INI editor and byte transport safeguards (dev.4 preview)

Multiline or unmatched quotes anywhere in a target INI are refused before editing. Single-line quotes/comments remain supported; a leading UTF-8 BOM and CRLF endings are preserved, and missing target directives share one appended PHP section. The tool does not attempt to rewrite general PHP INI syntax.

Before any target replacement, the affected FPM binaries provide complete three-column effective INI tables. The engine hashes directive values in memory, excludes environment dumps, then compares all unrelated registered directives after writing and before service reload. Ambiguous/incomplete snapshots refuse the fix. A mismatch restores original files instead of reloading the altered configuration. Only directive names/digests are handled internally; configuration values and process environments are not persisted in reports. The PHP-FPM matrix also runs 14 real editor/parser cases per image, including a 379M memory-limit sentinel and multiline refusal.

Schema-2 JSON is ASCII-escaped UTF-8, including legacy filesystem byte names. `path_encoding` describes filesystem-surrogateescape strings; Python `os.fsencode()` roundtrips their original bytes. Human streams use backslash replacement under restricted encodings; the banner uses an ASCII hyphen. These fixes are in dev.4, not the unchanged 2.2.1 downloads.
