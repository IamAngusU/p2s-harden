<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/p2s-harden-wordmark-dark.svg">
    <img src="docs/assets/readme/p2s-harden-wordmark.svg" width="340" alt="p2s-harden — terminal-based PHP-FPM checks">
  </picture>
</p>

<p align="center">
  <a href="README.de.md"><img src="docs/assets/readme/readme-language-de.svg" height="40" alt="Diese README auf Deutsch lesen"></a>
</p>

<h1 align="center">Check PHP-FPM. Preview the fix.</h1>
<p align="center">Discover setups. See missing prerequisites. Stay in your terminal.</p>

<p align="center">
  <a href="#what-happens-next"><img src="docs/assets/readme/badge-default.svg" height="40" alt="Default: read-only first"></a>
  <a href="#review-fixes-before-applying"><img src="docs/assets/readme/badge-recovery.svg" height="40" alt="Recovery: reversible fixes with backups and conflict checks"></a>
  <a href="#scope-and-release-status"><img src="docs/assets/readme/badge-platforms.svg" height="40" alt="Platforms: Linux target, Windows, Linux and macOS SSH clients"></a>
  <a href="LICENSE"><img src="docs/assets/readme/badge-license.svg" height="40" alt="License: MIT"></a>
</p>
<p align="center">
  <a href="https://github.com/angusu-de/p2s-harden/actions/workflows/ci.yml"><img src="https://raw.githubusercontent.com/angusu-de/p2s-harden/ci-proof/proof/public-proof.svg" height="54" alt="Live public CI status: open the p2s-harden workflow"></a>
</p>
<p align="center"><sub>Public CI on a separate account, same maintainer. <a href="https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md">Tested commit and individual steps</a>. Badge design: <a href="https://github.com/IamAngusU/Badges">IamAngusU/Badges</a>.</sub></p>
<p align="center"><a href="#start-here">Get started</a> · <a href="#review-fixes-before-applying">Preview fixes</a> · <a href="#scope-and-release-status">Scope</a> · <a href="docs/DETAILS.de.md">Documentation</a> · <a href="https://github.com/IamAngusU/p2s-harden/releases">Releases</a></p>

For Linux servers running PHP-FPM, especially conventional Debian/Ubuntu installations with Nginx. **2.2.0-rc.1 is a release candidate.** The default command audits the server. Changes require an explicit `--fix` or `--rollback`. Findings are currently explained in German. [Deutsch](README.de.md).

## Start here

Download **one file** for the computer you will run it from:

- [Windows PowerShell](https://github.com/IamAngusU/p2s-harden/releases/download/v2.2.0-rc.1/p2s-harden.ps1)
- [Linux / macOS Bash](https://github.com/IamAngusU/p2s-harden/releases/download/v2.2.0-rc.1/p2s-harden.sh)
- [Full source package and checksums](https://github.com/IamAngusU/p2s-harden/releases/tag/v2.2.0-rc.1)

Both launchers contain the complete Python engine. No pip, Composer or project configuration.

### On the Linux server

```bash
sudo bash p2s-harden.sh
```

### From Windows

Open PowerShell in the folder containing the downloaded file:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\p2s-harden.ps1 --ssh root@SERVER
```

Replace `SERVER` with your server's hostname, IP address or existing SSH alias. The execution-policy option applies to this invocation. Your organization's enforced policy still applies.

### From Linux / macOS

```bash
bash p2s-harden.sh --ssh root@SERVER
```

The **Linux target** needs Python 3.8+ and readable `/proc`. Remote clients need an existing OpenSSH connection. Windows needs neither Bash nor Python on the client.

Full checks and fixes require root on the Linux target. **Root SSH disabled?** Log in normally, copy the Bash file to the server and run `sudo bash p2s-harden.sh` there. You can also use `--ssh USER@SERVER` for the checks that account can read; unavailable checks are explained.

## What happens next?

1. The CLI finds common Nginx roots, literal domains, ports and simple aliases, plus supported host FPM instances and pools.
2. It checks PHP settings, write permissions and selected HTTP endpoints.
3. It shows open findings, incomplete checks and missing capabilities. No paths or domains need configuring for a common supported setup.

`OK` means that individual check passed. `OPEN` needs review or a change. `UNKNOWN` means the check could not establish a result. A completed audit can have `UNKNOWN` findings; they stay visible.

Need help with the environment? Run the same launcher with `--doctor`:

```bash
sudo bash p2s-harden.sh --doctor
sudo bash p2s-harden.sh --discover
```

Missing `ps` uses a `/proc` fallback. Missing `curl` skips HTTP checks once with a package suggestion. Missing `runuser` skips permission checks for affected foreign users once per user. Missing systemd/service mapping blocks automatic INI fixes while supported audit checks continue. A failed FPM inspection does not discard independent checks. Nothing is installed automatically.

Without Python, the bootstrap still lists missing helpers and explains the next step. Provide Python, then rerun the same command. An unreachable SSH target also receives a clear error.

## Review fixes before applying

First inspect the proposed changes:

```bash
sudo bash p2s-harden.sh --dry-run
```

After reviewing the preview, explicitly apply the supported changes:

```bash
sudo bash p2s-harden.sh --fix
```

If you need to undo an applied transaction, use the separate recovery command:

```bash
sudo bash p2s-harden.sh --rollback
```

`--fix` adds seven defined shell-related functions to existing FPM `disable_functions` and switches enabled `allow_url_include` off in supported FPM-specific INIs. These restrictions can affect applications. Verify the affected applications afterwards.

Directory changes require an explicit `--protect-dir /absolute/path` and an identifiable web user. They affect that directory only. Discovery never selects permission changes for you. Required fix capabilities are checked before the transaction. Backups preserve file bytes and metadata; rollback refuses conflicting newer edits. [Detailed behavior and recovery](docs/DETAILS.de.md).

Audit, doctor, inventory and dry-run leave target configuration, permissions and services unchanged. Reads and HTTP requests can update access times and ordinary server logs.

## Common situations

- **A helper is missing:** `--doctor` explains what needs it. Independent checks continue; install only the helper you need, then rerun.
- **A different Nginx layout:** use `--nginx-config /path/nginx.conf`.
- **Scope one site:** use `--root /srv/site --web-user www-data --site https://example.org=/srv/site`. `--site` and `--web-user` can be repeated.
- **An HTTP limit is reported:** narrow the scope or increase `--max-sites` (default 32, maximum 512).
- **Need every finding:** add `--verbose`. For automation use `--json`; progress goes to stderr. `--no-progress` suppresses phase hints.
- **Exit 2 after an audit or fix:** inspect the `UNKNOWN` findings. Exit 0 means selected checks passed, 1 means open findings, 2 means incomplete coverage/error. It does not imply that all independent checks stopped. A completed fix can leave unrelated findings.

## Scope and release status

Automatic INI fixes support conventional Debian/Ubuntu **host FPM** layouts (`/etc/php/VERSION/fpm`) with protected configuration files and a matching systemd service. Apache/mod_php, other FPM layouts, containers, dynamic Nginx mappings and ImageMagick rules require separate/manual assessment.

This inspects disk configuration and selected permissions/endpoints. It does not prove that every running worker uses that configuration or that every PHP-to-shell technique is blocked. Writable runtime directories and HTTP 2xx catch-all responses need interpretation. The seven function restrictions and `open_basedir` do not replace process isolation.

[Actual validation and limitations](docs/VALIDATION.md) · [Changelog](CHANGELOG.md) · [MIT license](LICENSE).

## For contributors

**These commands need the full source package**, started from its main directory. They are unnecessary for normal one-file use:

```bash
python3 build-standalone.py --check
sudo bash tools/test-linux.sh
```

The Linux runner creates and removes protected disposable fixtures itself. Ownership/ACL/recovery tests require root, Python 3.8+, Bash, curl, runuser, ps and the `www-data` account. They never modify real PHP/Nginx/firewall configuration. Windows transport tests use a temporary fake SSH executable:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-windows-launcher.ps1
```

[Contributing](CONTRIBUTING.md) · [Security scope](SECURITY.md) · [CI workflow](.github/workflows/ci.yml).
