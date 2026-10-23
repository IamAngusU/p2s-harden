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

Edit `src/*.py`; [the builder](../build-standalone.py) assembles eight source
components into the auditable generated engine and both standalone launchers.
The Linux target does not need source components, imports, pip or package setup.
English is the diagnostic source; the separate catalog supplies German.

Fixture tests, real FastCGI tests and destructive disposable-VM system tests
have different scopes. [Validation](VALIDATION.md), [CI design](CI.md) and the
[rc.3 review decisions](REVIEW-rc3.md) explain those boundaries. Ordinary fixture
tests never modify real host PHP/Nginx/firewall configuration. System-runtime
tests require an explicit root-owned disposable-VM marker and environment flag;
never use that developer test on a production server.
