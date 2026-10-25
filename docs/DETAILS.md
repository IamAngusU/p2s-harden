# php-fpm-audit: usage and technical details

Stable downloads and the short quick start are in the [README](../README.md). This guide contains the detailed operating instructions. **2.2.2 is stable; additional 2.3 features remain a development preview.** Script and backup names remain compatible.

[Workflow and coverage](#workflow-and-check-coverage) · [JSON/SSH/rollback](#json-ssh-and-rollback) · [Share reports](#share-a-report-without-host-details) · [Common situations](#common-situations) · [Verify downloads](#verify-your-download) · [FAQ](#faq) · [Development preview](#development-preview-23)


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
all resources; an instance ID selects just one. Stable 2.2.2 treats UNKNOWN as
a non-success result. The 2.3 preview permits explicit configuration-bound
Nginx acknowledgements while retaining raw UNKNOWN; see the [preview review semantics](NGINX-UPLOADS.md#explicit-review-of-unsupported-routing). Suppressions are command arguments, not implicit project
configuration. Preserve reviewed arguments in your own CI configuration.

For stable 2.2.2 and unacknowledged preview results:

For stable 2.2.2 and unacknowledged preview results:

`--fail-on complete` (default): UNKNOWN/error -> 2, otherwise OPEN -> 1, else 0.
`--fail-on open`: OPEN -> 1 first, otherwise UNKNOWN/error -> 2, else 0.
JSON always reports both `has_open` and `has_unknown`, plus raw status counts
and the number of suppressed OPEN findings. Unacknowledged incomplete coverage cannot silently
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

Edit `src/*.py`; [the builder](../build-standalone.py) assembles the source
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


## Transaction concurrency and retention (2.2.2 and preview)

Fix preparation, apply/reload/recovery and rollback selection/restore use a nonblocking exclusive kernel lock on the fixed root-owned mode-0700 `/run/p2s-harden` directory inode, plus the protected backup-directory inode for compatibility. The CLI holds it across prepare and apply; contention returns an actionable UNKNOWN without changing target files. No lock file or stale PID needs deletion; the kernel releases it on process exit. Read-only audits never acquire it. Changing `--backup-root` cannot bypass the system lock. All current tool instances coordinate; unrelated editors/package tools and older versions do not participate in the new system lock. Do not remove its directory while writers are active. Existing digest/metadata checks still apply.

Backups are not automatically pruned. They retain configuration bytes and metadata for rollback; keep the directory protected, monitor its disk usage and remove only recovery data you no longer need after independently verifying the current deployment. Removing a backup removes that rollback option.


## INI editor safeguards (2.2.2 and preview)

Multiline or unmatched quotes anywhere in a target INI are refused before editing. Single-line quotes/comments remain supported; a leading UTF-8 BOM and CRLF endings are preserved, and missing target directives share one appended PHP section. The tool does not attempt to rewrite general PHP INI syntax.

Before any target replacement, the affected FPM binaries provide complete three-column effective INI tables. The engine hashes directive values in memory, excludes environment dumps, then compares all unrelated registered directives after writing and before service reload. Ambiguous/incomplete snapshots refuse the fix. A mismatch restores original files instead of reloading the altered configuration. Only directive names/digests are handled internally; configuration values and process environments are not persisted in reports. The PHP-FPM matrix also runs 14 real editor/parser cases per image, including a 379M memory-limit sentinel and multiline refusal.

## Byte transport (2.3 preview only)

Schema-2 JSON uses Unicode-safe display paths and exact `path_bytes_hex`/`path_encoding` on affected path objects; root objects use equivalent root fields. No lone surrogate escapes remain. Baseline decoding verifies display/byte agreement and uses the original canonical bytes. IDs stay bound to original paths; redaction drops hex fields. [Protocol and draft workflow](WEBSHELLS.md#reviewed-baselines).

## Workflow and check coverage

1. Discover common Nginx roots, domains, ports and simple aliases, plus FPM instances and pools.
2. Audit the selected settings, filesystem permissions and HTTP targets.
3. Show findings with stable IDs and a concrete next step. Changes require `--fix` or `--rollback`.

Illustrative output (the instance ID is stable for the same rule and resource):

```text
OPEN    disable_functions /etc/php/8.3/fpm/php-fpm.conf: Missing: popen
        P2S-PHP001-<resource-hash>
        Review --dry-run, test application compatibility, then apply --fix --yes ...
UNKNOWN HTTP https://example.test/.env: 200; matches soft-404 fallback ...
        P2S-HTTP001-<resource-hash>

OK: 12   OPEN: 1   UNKNOWN: 1   INFO: 0
```

| Check | What the result covers | Automatic change |
| --- | --- | --- |
| FPM settings | Seven defined shell functions, additive pool restrictions, URL includes, `open_basedir` | Supported INI function/include changes |
| FPM boundaries | TCP bind/client policy, configured and observed Unix socket mode, script extensions, environment clearing, shared UIDs and loaded FFI policy | Review and fix manually; no pool/network rewrites |
| Code and directories | Actual PHP users/groups and ACL effects; writable PHP stays visible inside runtime storage | Only an explicit `--protect-dir`, non-recursive |
| Sensitive HTTP paths | `.env`, `.git/config`, discovered `.env*`, SQL/BAK/log files and named debug scripts | None; remediate web-server/app configuration |
| Missing-path baselines | Two random paths distinguish file responses from static/dynamic soft-404s | None |
| Host/manual context | `ptrace_scope`; ImageMagick notice only when policy/module is found | None |
| Prerequisites/coverage | Missing programs, unsupported contexts, skipped paths and exhausted budgets | Nothing installed automatically |

`OK` passed that selected check. `OPEN` needs review or remediation. `UNKNOWN` means the check could not establish a result. `INFO` is context, not a passed security check. [Remediation by rule ID](FINDINGS.md).

```bash
sudo bash p2s-harden.sh --doctor
sudo bash p2s-harden.sh --discover
```

Without `ps`, discovery falls back to `/proc`. HTTP uses Python, so curl is unnecessary. Missing `runuser` affects foreign-user permission checks; missing service management blocks automatic INI changes. No Python means the bootstrap explains that prerequisite; it cannot perform the Python audit.

## JSON, SSH and rollback

SSH has no remote controlling TTY: review `--dry-run`, then explicitly use `--fix --yes`. Interactive local fixes default to No. For reviewed automation:

```bash
sudo bash p2s-harden.sh --dry-run --json
sudo bash p2s-harden.sh --fix --yes --json
sudo bash p2s-harden.sh --rollback --backup-id BACKUP_ID --json
```

## Share a report without host details

```bash
sudo bash p2s-harden.sh --check --redact --json > p2s-report.json
```

`--redact` keeps rule IDs, results, remediation and **typed technical evidence**:
for example `missing_functions: ["popen"]`, `socket_mode: "0666"`, setting states,
counts and HTTP status. Each rule validates its allowed fields and values.
Paths, domains, users, raw diagnostics, inventory, plans and transactions are
omitted. Shared finding IDs are fresh per report; use the original local IDs
for per-resource `--ignore`. Supported modes: check, doctor, discover and the development webshell scan.
Results and exit codes stay the same. Review change previews locally without
redaction. Report stdout is covered; SSH/system stderr may identify the host.
[Send reviewed audit feedback](https://github.com/IamAngusU/php-fpm-audit/issues/new?template=audit-feedback.yml).

## Common situations

- **Repeated global settings:** unchanged pool results share the global finding. Normal JSON lists `affected_pools`; `evidence.affected_pool_count` is safe to share. Different effective policies and explicit unsafe include overrides remain separate causes.
- **TCP localhost:** its current host resolution is checked with a two-second deadline. Outside-loopback answers are OPEN; failed resolution and other hostnames remain UNKNOWN. This does not attest an existing listener or container service.

- **Expected uploads/cache:** repeat `--runtime-dir /srv/site/uploads`. Writable directories there become INFO; writable PHP files and incomplete coverage remain findings. Verify execution restrictions separately.
- **A larger application:** the configuration audit budget is **250000 entries and 10 seconds per walk**. Use `--max-paths`, `--walk-seconds` or a narrower `--root` when needed. Dependencies are not silently excluded. HTTP defaults to 128 total requests and 32 automatic mappings (`--max-http-probes`, `--max-sites`). The separate webshell mode defaults to 120 seconds per root and 2 seconds per file. Limits remain UNKNOWN.
- **HTTP redirects to HTTPS:** select `--site https://example.org=/srv/site`. Redirects remain UNKNOWN until the target is checked; a redirect alone is not evidence of protection. Automatic mappings prefer HTTPS.
- **Different layout:** supply `--nginx-config /path/nginx.conf`, or `--root /srv/site --web-user www-data --site https://example.org=/srv/site`. Users and sites are repeatable.
- **Automation:** schema 2 JSON includes `id`, `rule_id`, `resource`, `severity`, `remediation`, `suppressed`, `has_open`, `has_unknown`, `plan` and `transaction`. Text/paths are not an API identifier. `--verbose` shows every row.
- **Known accepted OPEN finding:** repeat `--ignore FINDING_ID` for one resource, or `--ignore P2S-FS002` for the entire rule. It stays visible and marked suppressed; UNKNOWN cannot be suppressed into a pass. This affects exit evaluation only, not fix scope or file traversal.

In the 2.3 preview, explicit configuration-bound Nginx acknowledgements retain raw UNKNOWN; JSON distinguishes `has_unaccepted_unknown` and `accepted_unknown`. [Review semantics](NGINX-UPLOADS.md#explicit-review-of-unsupported-routing). Exit 0 can therefore include acknowledged UNKNOWNs; it is never a clean-server verdict.

Default exit precedence (`--fail-on complete`) is **2 for UNKNOWN/error**, otherwise **1 for OPEN**, otherwise **0**. For CI that must distinguish an OPEN even alongside incomplete checks, use `--fail-on open`: OPEN returns 1 first, otherwise UNKNOWN still returns 2. The preview adds `--fail-on review`: an unaccepted WS004 code-review item or OPEN returns 1 first; otherwise UNKNOWN returns 2. Ordinary INFO does not fail. `--ignore`/exact baselines may accept review rows; JSON adds `has_review` and `suppressed_review`. JSON always exposes the flags and every finding. Ignored OPEN rows do not change the exit code; they remain in the report.

## Verify your download

Checksums detect corruption or mismatched downloads. A checksum from the same release cannot independently authenticate its origin. Releases also include **GitHub-signed build provenance** for the four distribution files, built after all test jobs pass. Verify the exact bytes, expected workflow and source commit with optional `gh attestation verify`: [verification commands and trust boundary](PROVENANCE.md).

With an authenticated GitHub CLI (optional; Bash and PowerShell):

```text
gh attestation verify p2s-harden.sh --repo angusu-de/p2s-harden --signer-workflow angusu-de/p2s-harden/.github/workflows/ci.yml --source-ref refs/heads/release/2.2 --deny-self-hosted-runners
```

Use `p2s-harden.ps1` for the Windows download. Add `--source-digest EXPECTED_COMMIT` to pin the release commit; [bundle/offline verification](PROVENANCE.md) explains the required trust material. The CI fork belongs to the same maintainer.

Download the SHA-256 sums alongside the chosen launcher. On Windows:

```powershell
$expected = (Select-String -Path .\p2s-harden-SHA256SUMS.txt -Pattern '  p2s-harden.ps1$').Line.Split(' ')[0]
$actual = (Get-FileHash .\p2s-harden.ps1 -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw 'Checksum mismatch' }
```

With a policy such as RemoteSigned that permits reviewed local scripts, [Unblock-File](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file) is an alternative to a process-wide bypass after verifying/reviewing the download:

```powershell
Unblock-File -LiteralPath .\p2s-harden.ps1
.\p2s-harden.ps1 --ssh root@SERVER
```

Unblocking removes the downloaded-file marker; it does not override Restricted or organizational policies. The earlier `-ExecutionPolicy Bypass` example applies only to that invocation and also respects enforced organizational policy. Checksums detect changed downloads; the readable [source components](../src), generated [Python engine](../p2s_harden.py), [build script](../build-standalone.py) and exact-commit CI evidence let you inspect what is embedded in the larger launchers.

## FAQ

### Does this fix PHP2Shell?

No. PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 were released on 21 October 2026 to fix CVE-2026-109618 and CVE-2026-109619. Distributions may backport fixes, so the upstream version alone is insufficient. Also review the additional session upload progress notice dated 23 October. Follow the [current PHP guidance](https://www.php.net/archive/2026.php) and your distribution's package advisory. This audit does not check the patch level.

### Does the default command change my server?

It does not change target configuration, permissions or services. The audit reads files and makes bounded HTTP requests, which can update ordinary logs and access times. Explicitly requested review drafts write their own files. Configuration changes require `--fix` with interactive confirmation or `--yes`.

### Why are the files still named p2s-harden?

`php-fpm-audit` is the new project and repository name. Existing script names, `P2S-` IDs and backup paths remain compatible. Public CI and the signing workflow still use `angusu-de/p2s-harden`; retain that expected signer identity when [verifying provenance](PROVENANCE.md).

## Development preview 2.3

Stable **2.2.2** contains the corrected INI editor and transaction lock. Additional webshell, residual-policy, systemd-posture and new upload-route checks belong to the **2.3.0-dev.7 preview** on main. Stable files do not include these additions.

[Bash preview](../p2s-harden.sh?raw=1) · [PowerShell preview](../p2s-harden.ps1?raw=1).

Check webshell indicators locally or over SSH:

```bash
sudo bash p2s-harden.sh --scan-webshells --root /srv/site
```

```powershell
.\p2s-harden.ps1 --ssh root@SERVER --scan-webshells --root /srv/site
```

This is bounded static triage: no sample is executed, uploaded or removed. Indicators need review; their absence does not establish a clean server. [Rules, budgets, redaction and reviewed baselines](WEBSHELLS.md).

Inspect upload routes read-only with the preview:

```bash
sudo bash p2s-harden.sh --check --root /srv/site \
  --nginx-config /etc/nginx/nginx.conf --runtime-dir /srv/site/uploads
```

A common `.*` upload denial can miss line-break filenames if such files can be placed in an executable upload path. The optional Docker lab reproduces this with harmless markers, no host mounts and no published ports. [Guard rules and limits](NGINX-UPLOADS.md) · [Reproduce the lab](UPLOAD-GUARD-LAB.md) · [Defense model](DEFENSES.md). The ordinary audit creates no upload marker and does not change Nginx configuration.

## Evidence and contributing

[Release boundaries](PRODUCTION.md) · [Validation](VALIDATION.md) · [Stable CI](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md) · [Development CI](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md) · [CI procedure](CI.md) · [Contributing](../CONTRIBUTING.md).

CI belongs to the same maintainer; it is not an independent audit. Disposable VMs validate their fixtures, not your server. Destructive system tests belong only in explicitly marked disposable VMs.
