<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/php-fpm-audit-wordmark-dark.svg">
    <img src="docs/assets/readme/php-fpm-audit-wordmark.svg" width="420" alt="php-fpm-audit — terminal-based PHP-FPM checks">
  </picture>
</p>

<p align="center">
  <a href="README.de.md"><img src="docs/assets/readme/readme-language-de.svg" height="40" alt="Diese README auf Deutsch lesen"></a>
</p>

<h1 align="center">Audit PHP-FPM. Preview the fix.</h1>
<p align="center">Read-only checks for PHP-FPM and Nginx. Review findings and preview selected fixes.</p>

<p align="center">
  <a href="#what-happens-next"><img src="docs/assets/readme/badge-default.svg" height="40" alt="Default: read-only first"></a>
  <a href="#review-fixes-before-applying"><img src="docs/assets/readme/badge-recovery.svg" height="40" alt="Recovery: reversible fixes with backups and conflict checks"></a>
  <a href="#scope-and-release-status"><img src="docs/assets/readme/badge-platforms.svg" height="40" alt="Platforms: Linux target, Windows, Linux and macOS SSH clients"></a>
  <a href="LICENSE"><img src="docs/assets/readme/badge-license.svg" height="40" alt="License: MIT"></a>
</p>
<p align="center">
  <a href="https://github.com/angusu-de/p2s-harden/actions/workflows/ci.yml"><img src="https://raw.githubusercontent.com/angusu-de/p2s-harden/ci-proof/proof/public-proof.svg" height="54" alt="Live public CI status: open the php-fpm-audit test workflow"></a>
</p>
<p align="center"><sub>Public CI on a separate account, same maintainer. <a href="https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md">Tested commit and individual steps</a>. Badge design: <a href="https://github.com/IamAngusU/Badges">IamAngusU/Badges</a>.</sub></p>
<p align="center"><a href="#start-here">Get started</a> · <a href="#review-fixes-before-applying">Preview fixes</a> · <a href="#scope-and-release-status">Scope</a> · <a href="#faq">FAQ</a> · <a href="docs/DETAILS.md">Documentation</a> · <a href="https://github.com/IamAngusU/php-fpm-audit/releases">Releases</a></p>

**php-fpm-audit** checks selected PHP-FPM settings, FPM listeners and sockets, filesystem permissions and sensitive HTTP paths. Findings have stable IDs and a concrete next step. The supported configuration workflow targets **Debian/Ubuntu servers running host PHP-FPM with Nginx and systemd**. English is the default; `--lang de` selects German.

- **Read-only first.** Audit, doctor, discovery and dry-run do not change target configuration, permissions or services. Reads and HTTP requests can update access times and ordinary logs.
- **Review changes before applying.** Selected INI fixes have a diff; directory changes have an explicit plan. The workflow includes confirmation, backups and rollback with conflict checks.
- **Incomplete checks stay visible.** `UNKNOWN` never becomes `OK`. A clean report is not a clean-server verdict.
- **Run one file.** Choose Bash or PowerShell. The Linux target needs Python 3.8+ and readable `/proc`; Windows needs existing OpenSSH access.

> [!IMPORTANT]
> **Update PHP separately.** This tool does not detect or patch PHP CVEs, check the security patch level or verify that FPM was restarted after an upgrade. For PHP2Shell and follow-up guidance, consult the [current PHP security advisories](https://www.php.net/archive/2026.php) and your distribution's package notices. Function restrictions are defense in depth, not a sandbox.

## Start here

### Stable release: 2.2.2

2.2.2 backports the corrected INI editor and transaction safeguards to the stable 2.2 configuration line. These fixes no longer require a development version.

> [!NOTE]
> **Use 2.2.2 or newer for automatic fixes.** Older 2.2.1 can damage multiline quoted INI values. 2.2.2 refuses ambiguous input, preserves BOM/CRLF and checks unrelated effective values before reload. Refused files require manual review. [Release and validation evidence](https://github.com/IamAngusU/php-fpm-audit/releases/tag/v2.2.2).

Download **one file** for the computer you run it from:

- [Windows PowerShell](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.ps1)
- [Linux / macOS Bash](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.sh)
- [Source package and SHA-256 sums](https://github.com/IamAngusU/php-fpm-audit/releases/tag/v2.2.2)

[Exact stable-release CI proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md). The top badge describes development main.

### Development preview: 2.3.0-dev.7

[Bash preview](p2s-harden.sh?raw=1) · [PowerShell preview](p2s-harden.ps1?raw=1).
The preview adds webshell indicators and new upload-route checks. **These additions are not part of stable 2.2.2.** The corrected INI editor is already included in 2.2.2; use the stable downloads above for that fix. [Webshell scope](#look-for-php-webshell-indicators) · [Upload checks](#check-upload-guards-preview).

**Existing filenames remain compatible:** this project was previously named `p2s-harden`. Launchers, release assets, backup paths and `P2S-` finding IDs retain their names so existing workflows and rollback commands keep working.

### Run the audit

On the Linux server:

```bash
sudo bash p2s-harden.sh
```

From Windows, with your existing OpenSSH access:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\p2s-harden.ps1 --ssh root@SERVER
```

From Linux/macOS:

```bash
bash p2s-harden.sh --ssh root@SERVER
```

Replace `SERVER` with a hostname, IP or existing SSH alias. The Linux target needs **Python 3.8+ and readable `/proc`**. Windows needs neither Bash nor Python locally. No pip, Composer, project configuration or Docker is needed for ordinary use. Missing capabilities are explained; independent checks continue. Full cross-user checks and fixes need root. If root SSH is disabled, copy the Bash file to the server and run it with `sudo`; an ordinary SSH account can run the checks it can read.

## Who is this for?

Useful for administrators of conventional Debian/Ubuntu **host PHP-FPM** installations, especially with Nginx. Automatic INI changes require protected `/etc/php/VERSION/fpm` configuration and a verified systemd service. Apache/mod_php, containerized applications, dynamic mappings and other layouts need separate assessment. This is defense in depth and configuration evidence; function bans and `open_basedir` do not establish process isolation or make every PHP-to-shell technique impossible.

## What happens next?

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

`OK` passed that selected check. `OPEN` needs review or remediation. `UNKNOWN` means the check could not establish a result. `INFO` is context, not a passed security check. [Remediation by rule ID](docs/FINDINGS.md).

```bash
sudo bash p2s-harden.sh --doctor
sudo bash p2s-harden.sh --discover
```

Without `ps`, discovery falls back to `/proc`. HTTP uses Python, so curl is unnecessary. Missing `runuser` affects foreign-user permission checks; missing service management blocks automatic INI changes. No Python means the bootstrap explains that prerequisite; it cannot perform the Python audit.

<details>
<summary>How the checks relate to attack paths</summary>

An attacker may already execute PHP through a vulnerable application or an uploaded file. **`disable_functions` is defense in depth, not a sandbox:** `--fix` restricts selected direct paths; it does not prevent the initial compromise, close every indirect execution path or make a host clean. Application updates, least privilege, OS isolation and incident recovery remain separate requirements; the new Nginx/systemd observations are read-only and bounded.

| Attack path | Countermeasure | Checked by this tool | Changed by this tool |
|---|---|---|---|
| Vulnerable plugin/application | Patch, remove vulnerable code, protect authentication | No application/CVE audit | Nothing |
| Selected direct PHP-to-command calls | Seven function restrictions and URL-include policy | Global/pool policy; separate CI worker tests | Supported INIs after reviewed confirmation |
| Indirect helpers, FFI, environment and file APIs | Application-specific policy plus OS confinement | FFI policy and residual policy observations; no bypass verdict | Nothing extra |
| PHP stored in upload paths | Nonexecutable storage and correct Nginx routing | Selected static root/URI mappings; ambiguous routes stay UNKNOWN | No Nginx changes |
| Privilege gain and OS writes/temp sharing | Review NoNewPrivileges, ProtectSystem, PrivateTmp and exceptions | Matched active unit's manager properties; no worker/kernel attestation | No unit changes |
| PHP user can replace code | Separate code ownership from writable runtime data | User/permission checks in selected roots | Only explicit supported directory targets |
| Existing webshell/persistence | Preserve evidence, isolate, rebuild, rotate exposed secrets | Bounded PHP indicators; no OS/memory persistence audit | No malware removal or recovery |

[What each observation means, supported Nginx subset and verification](docs/DEFENSES.md).

</details>

## Review fixes before applying

> [!NOTE]
> **Use stable 2.2.2 or newer for these commands.** Replace older 2.2.1 because of its INI editing defect. Review the diff and test application compatibility before applying changes. [Stable downloads](#stable-release-222).

```bash
sudo bash p2s-harden.sh --dry-run
sudo bash p2s-harden.sh --fix
```

The preview includes **the proposed values and a unified diff**, with zero context so unrelated neighboring INI settings are not printed. Interactive `--fix` asks through `/dev/tty` and defaults to No. Configuration changes after the displayed preview are rejected. The SSH transport has no remote controlling TTY: review `--dry-run`, then use `--yes`. For reviewed automation:

```bash
sudo bash p2s-harden.sh --dry-run --json
sudo bash p2s-harden.sh --fix --yes --json
sudo bash p2s-harden.sh --rollback --backup-id BACKUP_ID --json
```

`--fix` only adds the defined shell-function restrictions and disables URL includes in supported INIs. Test application compatibility. Directory changes need an explicit `--protect-dir /absolute/code/path` and known PHP user; discovery never chooses permission changes. Human output prints the exact undo command; JSON returns the backup ID and state. Repeating implicit `--rollback` never selects an older fix. Rollback checks contents and metadata before writing, restores original timestamps and supports interrupted recovery. Fixes receive fresh modification times. Stable 2.2.2 and the development preview include a nonblocking kernel lock against simultaneous fix/rollback writers using a fixed protected system directory, including different `--backup-root` values. Backups are retained until the operator removes them; monitor storage and retain needed recovery data. [Transaction details](docs/DETAILS.md).

The existing-file fix can modify a package-managed `php.ini`. If both local and package-maintainer versions change, a later package upgrade may ask which configuration to keep. Review that diff and re-audit after upgrading; new-file drop-ins remain deferred. [Upgrade behavior](docs/DETAILS.md#package-upgrades).

Audit, doctor, inventory and dry-run do not change target configuration, permissions or services. Reads and HTTP requests can update access times and ordinary logs.

## Check upload guards (preview)

**Can your upload guard miss a newline?**

The common `^/uploads/.*\.php$` denial can miss a line break encoded as `%0a`,
while a later PHP handler still executes the file. This requires a way to place
such a filename in the executable upload path; it is not a verdict about every
upload form. Real Nginx/FPM fixture tests reproduce the gap and its correction.

With the **dev.7 preview launcher from the quick start**, inspect your actual paths read-only:

```bash
sudo bash p2s-harden.sh --check --root /srv/site \
  --nginx-config /etc/nginx/nginx.conf --runtime-dir /srv/site/uploads
```

No upload marker is created by the audit. To reproduce all three outcomes in
an isolated local lab, run `python3 tools/reproduce-nginx-upload-guard.py` from
the source checkout. Only this optional lab needs Python and Docker; it publishes
no ports and mounts no host paths. [One-command reproduction and expected output](docs/UPLOAD-GUARD-LAB.md)
· [Image-preserving guard examples](docs/NGINX-UPLOADS.md)
· [Shareable EN/DE announcement](docs/LAUNCH.md).

**Upload route checks:** dev.7 recognizes bounded regex and nested PHP denials that preserve images, detects the `.*` line-break bypass, and supports explicit configuration-bound UNKNOWN review. [Examples and exact limits](docs/NGINX-UPLOADS.md).

## Look for PHP webshell indicators

Available in the **2.3.0 development preview**, separate from the configuration audit:

```bash
sudo bash p2s-harden.sh --scan-webshells
sudo bash p2s-harden.sh --scan-webshells --root /srv/site
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --redact --json > indicators.json
```

From Windows, forward the same options:

```powershell
.\p2s-harden.ps1 --ssh root@SERVER --scan-webshells --root /srv/site --lang de
```

Without `--root`, existing Nginx discovery selects the reported roots. An explicit
root works without Nginx, FPM, a web-user account or HTTP access. Files are read
locally; no sample is executed, unpacked, uploaded, deleted or quarantined.

- Flags request input near execution/include sinks, request-selected calls,
  encoded code near execution, network/shell combinations and nonempty startup directives in `.user.ini`,
  `.htaccess` and `php.ini`.
- Includes hidden files, upload/cache/dependency directories and PHP content
  under unusual extensions. Comments and literal examples inside PHP strings
  are filtered. Legitimate code and test samples can still produce indicators.
- Local findings contain a path, first relevant line, SHA-256 and next steps.
  Reports contain no source excerpts or directive target values. `--redact`
  removes paths, file hashes and original IDs while retaining validated reasons,
  line numbers and coverage counts.
- Default limits per root: 250000 entries, **120 seconds**, 2 MiB PHP parsing per file and
  **256 MiB** read in total, with at most 200 unaccepted finding rows. Each file
  has an independent **2-second** budget; a timed-out file does not stop later
  files. `--walk-seconds 0` disables only the root clock; `--scan-file-seconds`
  adjusts the file budget. Symlinks, mount boundaries,
  special/unreadable/changed files, excessive depth and exhausted budgets produce
  `UNKNOWN`; other accessible files continue where possible. Increase
  `--max-paths`, `--walk-seconds`, `--scan-file-bytes` or `--scan-total-bytes`,
  or split the scope. Nothing is silently accepted as clean.
- Local text/JSON identifies incomplete paths and reasons; redaction keeps only
  validated counters/reasons. Fully examined and incomplete files are counted
  separately. Unknown-helper-derived constant-prefixed includes and registry callbacks are
  visible **INFO review items**; a prefix/registry is not a safety guarantee.
  An optional **reviewed `--baseline`** accepts identical path/hash/indicator
  matches and keeps accepted rows in JSON. Explicit `reviewed_files` entries can acknowledge selected fully hashed parse/window limits after trusted source comparison; unreadable, unstable, timed-out or unvisited content stays UNKNOWN. Accepted incomplete files remain counted separately.
  Create a private, unreviewed proposal with `--write-baseline-draft /root/p2s-draft.json`. Every entry starts with `reviewed: false`; complete-file trusted-source review is required before approval. Existing files are never overwritten.
  [Safe baseline workflow and limits](docs/WEBSHELLS.md#reviewed-baselines).

The preview lowers scan CPU priority to nice 10 (or keeps an already lower priority) and requests idle I/O with optional `ionice`. `--no-nice` opts out. Missing/denied helpers are reported and scanning continues. These priorities do not cap CPU, memory or I/O usage. Large files are streamed for PHP openers before the parser size limit applies. Binary-like files require `<?php` or `<?=`; generic short tags in binary-like content are outside detection scope. Copies, casts and `basename()` retain OPEN include findings. Constant-prefixed request includes have their own MEDIUM rule; unrestricted request includes remain HIGH.

**An indicator requires review; absence of indicators does not establish a clean
server.** This is a small static triage aid, without a malware signature database,
full PHP data-flow analysis or coverage of OS persistence, memory, cron/SSH
backdoors, encrypted payloads or files outside the selected roots. A startup
reference's target is not followed automatically. If compromise is confirmed,
preserve evidence, isolate the host, close the entry point, rebuild from trusted
sources and rotate exposed credentials. [Detection rules, limits and response](docs/WEBSHELLS.md).

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

For explicit configuration-bound Nginx acknowledgements, raw UNKNOWN remains visible; JSON distinguishes `has_unaccepted_unknown` and `accepted_unknown`. [Review semantics](docs/NGINX-UPLOADS.md#explicit-review-of-unsupported-routing). Exit 0 can therefore include acknowledged UNKNOWNs; it is never a clean-server verdict.

Default exit precedence (`--fail-on complete`) is **2 for UNKNOWN/error**, otherwise **1 for OPEN**, otherwise **0**. For CI that must distinguish an OPEN even alongside incomplete checks, use `--fail-on open`: OPEN returns 1 first, otherwise UNKNOWN still returns 2. The preview adds `--fail-on review`: an unaccepted WS004 code-review item or OPEN returns 1 first; otherwise UNKNOWN returns 2. Ordinary INFO does not fail. `--ignore`/exact baselines may accept review rows; JSON adds `has_review` and `suppressed_review`. JSON always exposes the flags and every finding. Ignored OPEN rows do not change the exit code; they remain in the report.

## Verify your download

Checksums detect corruption or mismatched downloads. A checksum from the same release cannot independently authenticate its origin. Releases also include **GitHub-signed build provenance** for the four distribution files, built after all test jobs pass. Verify the exact bytes, expected workflow and source commit with optional `gh attestation verify`: [verification commands and trust boundary](docs/PROVENANCE.md).

With an authenticated GitHub CLI (optional; Bash and PowerShell):

```text
gh attestation verify p2s-harden.sh --repo angusu-de/p2s-harden --signer-workflow angusu-de/p2s-harden/.github/workflows/ci.yml --source-ref refs/heads/release/2.2 --deny-self-hosted-runners
```

Use `p2s-harden.ps1` for the Windows download. Add `--source-digest EXPECTED_COMMIT` to pin the release commit; [bundle/offline verification](docs/PROVENANCE.md) explains the required trust material. The CI fork belongs to the same maintainer.

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

Unblocking removes the downloaded-file marker; it does not override Restricted or organizational policies. The earlier `-ExecutionPolicy Bypass` example applies only to that invocation and also respects enforced organizational policy. Checksums detect changed downloads; the readable [source components](src), generated [Python engine](p2s_harden.py), [build script](build-standalone.py) and exact-commit CI evidence let you inspect what is embedded in the larger launchers.

## FAQ

### Does this fix PHP2Shell?

No. PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 were released on 21 October 2026 to fix CVE-2026-109618 and CVE-2026-109619. Distributions may backport fixes, so the upstream version alone is insufficient. Also review the additional session upload progress notice dated 23 October. Follow the [current PHP guidance](https://www.php.net/archive/2026.php) and your distribution's package advisory. This audit does not check the patch level.

### Does the default command change my server?

It does not change target configuration, permissions or services. The audit reads files and makes bounded HTTP requests, which can update ordinary logs and access times. Explicitly requested review drafts write their own files. Configuration changes require `--fix` with interactive confirmation or `--yes`.

### Why are the files still named p2s-harden?

`php-fpm-audit` is the new project and repository name. Existing script names, `P2S-` IDs and backup paths remain compatible. Public CI and the signing workflow still use `angusu-de/p2s-harden`; retain that expected signer identity when [verifying provenance](docs/PROVENANCE.md).

## Scope and release status

**Validated configuration workflow; preview additions remain under evaluation.** Disk inspection does not prove that every existing worker loaded that configuration, every vHost/container is covered, or every attack path is blocked. The disposable distro VM tests separately exercise real `/proc` discovery, Nginx mapping, PHP-user permissions, systemd fix/reload, HTTP worker values and rollback on Debian 12/PHP 8.2, Debian 13/PHP 8.4, Ubuntu 22.04/distro PHP 8.1 and Ubuntu 24.04/PHP 8.3. The FastCGI matrix covers PHP 8.2–8.5. [Current review response](docs/DEFENSES.md) · [2.2.1 review](docs/REVIEW-2.2.1.md) · [Validation](docs/VALIDATION.md) · [Release scope and acceptance gates](docs/PRODUCTION.md).

GitHub-hosted runner access is currently unavailable in the source account. The public CI fork uses a separate account owned by the same maintainer; it is not an independent audit. The proof checks that the tested commit, source main and fork main match before publishing. [Exact jobs and steps](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md) · [How synchronization works](docs/CI.md).

## For contributors

From the full source package:

```bash
python3 build-standalone.py --check
sudo bash tools/test-linux.sh
python3 tools/test_fpm_runtime.py --engine p2s_harden.py
```

Edit `src/*.py` and launcher templates, then rebuild. The builder assembles the reviewable components into the generated engine and two one-file launchers; users do not need the components alongside a launcher. Root fixtures are temporary; Docker is only needed for real FastCGI contributor tests. The **system-runtime test is destructive and restricted to explicitly marked disposable VMs**; ordinary tests and the CLI never invoke it. Windows transport: `powershell -NoProfile -File test-windows-launcher.ps1`.

[English details](docs/DETAILS.md) · [Deutsch](README.de.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [MIT license](LICENSE).
