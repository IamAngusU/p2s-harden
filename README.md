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
  <a href="https://github.com/angusu-de/p2s-harden/actions/workflows/ci.yml"><img src="https://raw.githubusercontent.com/angusu-de/p2s-harden/ci-proof-2.2/proof/public-proof.svg" height="54" alt="Live public CI status: open the maintenance release workflow"></a>
</p>
<p align="center"><sub>Public CI on a separate account, same maintainer. <a href="https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md">Tested commit and individual steps</a>. Badge design: <a href="https://github.com/IamAngusU/Badges">IamAngusU/Badges</a>.</sub></p>
<p align="center"><a href="#start-here">Get started</a> · <a href="#review-fixes-before-applying">Preview fixes</a> · <a href="#scope-and-release-status">Scope</a> · <a href="docs/DETAILS.md">Documentation</a> · <a href="https://github.com/IamAngusU/php-fpm-audit/releases">Releases</a></p>

**php-fpm-audit** checks selected PHP-FPM settings, FPM listeners and sockets, filesystem permissions and sensitive HTTP paths. Findings have stable IDs and a concrete next step. The supported configuration workflow targets **Debian/Ubuntu servers running host PHP-FPM with Nginx and systemd**. English is the default; `--lang de` selects German.

- **Read-only first.** Audit, doctor, discovery and dry-run do not change target configuration, permissions or services. Reads and HTTP requests can update access times and ordinary logs.
- **Review changes before applying.** Selected INI fixes have a diff; directory changes have an explicit plan. The workflow includes confirmation, backups and rollback with conflict checks.
- **Incomplete checks stay visible.** `UNKNOWN` never becomes `OK`. A clean report is not a clean-server verdict.
- **Run one file.** Choose Bash or PowerShell. The Linux target needs Python 3.8+ and readable `/proc`; Windows needs existing OpenSSH access.

> [!IMPORTANT]
> **Update PHP separately.** This tool does not detect or patch PHP CVEs, check the security patch level or verify that FPM was restarted after an upgrade. For PHP2Shell and follow-up guidance, consult the [current PHP security advisories](https://www.php.net/archive/2026.php) and your distribution's package notices. Function restrictions are defense in depth, not a sandbox.

**Stable maintenance release 2.2.2:** corrected INI editing on the 2.2.1 configuration workflow. Webshell and new upload-route checks remain in the [separate development preview](https://github.com/IamAngusU/php-fpm-audit/tree/main).

## Start here

> [!NOTE]
> **Use 2.2.2 or newer for automatic fixes.** Older 2.2.1 can damage multiline quoted INI values. 2.2.2 refuses these inputs and verifies unrelated effective settings before reload. Refused files require manual review.

Download **one file** for the computer you run it from:

- [Windows PowerShell](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.ps1)
- [Linux / macOS Bash](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.sh)
- [Source package and SHA-256 sums](https://github.com/IamAngusU/php-fpm-audit/releases/tag/v2.2.2)

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


**Existing filenames are retained:** the project is now named `php-fpm-audit`; scripts, backup paths and `P2S-` finding IDs remain compatible.

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

## Review fixes before applying

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

`--fix` only adds the defined shell-function restrictions and disables URL includes in supported INIs. Test application compatibility. Directory changes need an explicit `--protect-dir /absolute/code/path` and known PHP user; discovery never chooses permission changes. Human output prints the exact undo command; JSON returns the backup ID and state. Repeating implicit `--rollback` never selects an older fix. Rollback checks contents and metadata before writing, restores original timestamps and supports interrupted recovery. Fixes receive fresh modification times. [Transaction details](docs/DETAILS.md).

The existing-file fix can modify a package-managed `php.ini`. If both local and package-maintainer versions change, a later package upgrade may ask which configuration to keep. Review that diff and re-audit after upgrading; new-file drop-ins remain deferred. [Upgrade behavior](docs/DETAILS.md#package-upgrades).

Audit, doctor, inventory and dry-run do not change target configuration, permissions or services. Reads and HTTP requests can update access times and ordinary logs.

## Share a report without host details

```bash
sudo bash p2s-harden.sh --check --redact --json > p2s-report.json
```

`--redact` keeps rule IDs, results, remediation and **typed technical evidence**:
for example `missing_functions: ["popen"]`, `socket_mode: "0666"`, setting states,
counts and HTTP status. Each rule validates its allowed fields and values.
Paths, domains, users, raw diagnostics, inventory, plans and transactions are
omitted. Shared finding IDs are fresh per report; use the original local IDs
for per-resource `--ignore`. Supported modes: check, doctor and discover.
Results and exit codes stay the same. Review change previews locally without
redaction. Report stdout is covered; SSH/system stderr may identify the host.
[Send reviewed audit feedback](https://github.com/IamAngusU/php-fpm-audit/issues/new?template=audit-feedback.yml).

## Common situations

- **Repeated global settings:** unchanged pool results share the global finding. Normal JSON lists `affected_pools`; `evidence.affected_pool_count` is safe to share. Different effective policies and explicit unsafe include overrides remain separate causes.
- **TCP localhost:** its current host resolution is checked with a two-second deadline. Outside-loopback answers are OPEN; failed resolution and other hostnames remain UNKNOWN. This does not attest an existing listener or container service.

- **Expected uploads/cache:** repeat `--runtime-dir /srv/site/uploads`. Writable directories there become INFO; writable PHP files and incomplete coverage remain findings. Verify execution restrictions separately.
- **A larger application:** the default budget is **250000 entries and 10 seconds per walk**. Use `--max-paths`, `--walk-seconds` or a narrower `--root` when needed. Dependencies are not silently excluded. HTTP defaults to 128 total requests and 32 automatic mappings (`--max-http-probes`, `--max-sites`). Limits remain UNKNOWN.
- **HTTP redirects to HTTPS:** select `--site https://example.org=/srv/site`. Redirects remain UNKNOWN until the target is checked; a redirect alone is not evidence of protection. Automatic mappings prefer HTTPS.
- **Different layout:** supply `--nginx-config /path/nginx.conf`, or `--root /srv/site --web-user www-data --site https://example.org=/srv/site`. Users and sites are repeatable.
- **Automation:** schema 2 JSON includes `id`, `rule_id`, `resource`, `severity`, `remediation`, `suppressed`, `has_open`, `has_unknown`, `plan` and `transaction`. Text/paths are not an API identifier. `--verbose` shows every row.
- **Known accepted OPEN finding:** repeat `--ignore FINDING_ID` for one resource, or `--ignore P2S-FS002` for the entire rule. It stays visible and marked suppressed; UNKNOWN cannot be suppressed into a pass. This affects exit evaluation only, not fix scope or file traversal.

Default exit precedence (`--fail-on complete`) is **2 for UNKNOWN/error**, otherwise **1 for OPEN**, otherwise **0**. For CI that must distinguish an OPEN even alongside incomplete checks, use `--fail-on open`: OPEN returns 1 first, otherwise UNKNOWN still returns 2. JSON always exposes both flags and every finding. Ignored OPEN rows do not change the exit code; they remain in the report.

## Verify your download

Checksums detect corruption or mismatched downloads. A checksum from the same release cannot independently authenticate its origin. Releases also include **GitHub-signed build provenance** for the four distribution files, built after all test jobs pass. Verify the exact bytes, expected workflow and source commit with optional `gh attestation verify`: [verification commands and trust boundary](docs/PROVENANCE.md).

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

## Scope and release status

**Stable within the documented scope.** Disk inspection does not prove that every existing worker loaded that configuration, every vHost/container is covered, or every attack path is blocked. The disposable distro VM tests separately exercise real `/proc` discovery, Nginx mapping, PHP-user permissions, systemd fix/reload, HTTP worker values and rollback on Debian 12/PHP 8.2, Debian 13/PHP 8.4, Ubuntu 22.04/distro PHP 8.1 and Ubuntu 24.04/PHP 8.3. The FastCGI matrix covers PHP 8.2–8.5. [Latest review response](docs/REVIEW-2.2.1.md) · [Validation](docs/VALIDATION.md) · [Release scope and acceptance gates](docs/PRODUCTION.md).

GitHub-hosted runner access is currently unavailable in the source account. The public CI fork uses a separate account owned by the same maintainer; it is not an independent audit. The proof checks that the tested commit, source `release/2.2` and fork `release/2.2` match before publishing. [Exact jobs and steps](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md) · [How synchronization works](docs/CI.md).

## For contributors

From the full source package:

```bash
python3 build-standalone.py --check
sudo bash tools/test-linux.sh
python3 tools/test_fpm_runtime.py --engine p2s_harden.py
```

Edit `src/*.py` and launcher templates, then rebuild. The builder assembles the reviewable components into the generated engine and two one-file launchers; users do not need the components alongside a launcher. Root fixtures are temporary; Docker is only needed for real FastCGI contributor tests. The **system-runtime test is destructive and restricted to explicitly marked disposable VMs**; ordinary tests and the CLI never invoke it. Windows transport: `powershell -NoProfile -File test-windows-launcher.ps1`.

[English details](docs/DETAILS.md) · [Deutsch](README.de.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [MIT license](LICENSE).
