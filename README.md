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

**php-fpm-audit** checks selected PHP-FPM settings, sockets, filesystem permissions and sensitive HTTP paths on **Debian/Ubuntu with host PHP-FPM, Nginx and systemd**. The default command audits only; changes need your confirmation.

## Start here

Download stable **2.2.2**:

- [Windows: PowerShell file](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.ps1)
- [Linux/macOS: Bash file](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.sh)

On the Linux server:

```bash
sudo bash p2s-harden.sh
```

From Windows over SSH:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\p2s-harden.ps1 --ssh root@SERVER
```

From Linux/macOS over SSH:

```bash
bash p2s-harden.sh --ssh root@SERVER
```

Replace `SERVER`. The Linux target needs **Python 3.8+ and readable `/proc`**; remote use needs existing OpenSSH access. If root SSH is disabled, copy the Bash file to the server and run it with `sudo`. Existing filenames remain compatible.

## Preview changes

**Use 2.2.2 or newer for fixes.** Older 2.2.1 can corrupt INI settings.

```bash
sudo bash p2s-harden.sh --dry-run
sudo bash p2s-harden.sh --fix
```

Review the diff and test application compatibility. `--fix` asks for confirmation, creates backups and prints the rollback command. Automatic changes cover selected INI values; directory permission changes need explicit targets.

## Read the results

`OPEN` needs review; `UNKNOWN` means incomplete coverage. A clean report is not a clean-server verdict. The read-only audit does not change configuration, permissions or services; reads and HTTP requests can update logs and access times.

**Update PHP separately:** this tool does not detect or patch PHP CVEs. Function restrictions are defense in depth, not a sandbox.

## More information

[Usage and technical details](docs/DETAILS.md) · [Verify downloads](docs/PROVENANCE.md) · [Release and checksums](https://github.com/IamAngusU/php-fpm-audit/releases/tag/v2.2.2)

The 2.3 development preview with webshell and new upload checks is [documented separately](docs/DETAILS.md#development-preview-23) and is not part of stable 2.2.2.

[Stable CI evidence](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md) (same maintainer) · [Contributing](CONTRIBUTING.md) · [MIT license](LICENSE)
