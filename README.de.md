<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/php-fpm-audit-wordmark-dark.svg">
    <img src="docs/assets/readme/php-fpm-audit-wordmark.svg" width="420" alt="php-fpm-audit — PHP-FPM im Terminal prüfen">
  </picture>
</p>

<p align="center">
  <a href="README.md"><img src="docs/assets/readme/readme-language-en.svg" height="40" alt="Read this README in English"></a>
</p>

<h1 align="center">PHP-FPM prüfen. Fixes vorab ansehen.</h1>

**php-fpm-audit** prüft ausgewählte PHP-FPM-Einstellungen, Sockets, Dateirechte und sensible HTTP-Pfade auf **Debian/Ubuntu mit Host-PHP-FPM, Nginx und systemd**. Der Standardbefehl prüft nur; Änderungen brauchen deine Bestätigung.

## Direkt starten

Mit Homebrew auf Linux/macOS:

```sh
brew install iamangusu/tap/php-fpm-audit
php-fpm-audit --ssh root@SERVER --lang de
```

Oder Stable **2.2.2** als einzelne Datei herunterladen:

- [Windows: PowerShell-Datei](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.ps1)
- [Linux/macOS: Bash-Datei](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.sh)

Auf dem Linux-Server:

```bash
sudo bash p2s-harden.sh --lang de
```

Von Windows per SSH:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\p2s-harden.ps1 --ssh root@SERVER --lang de
```

Von Linux/macOS per SSH:

```bash
bash p2s-harden.sh --ssh root@SERVER --lang de
```

`SERVER` ersetzen. Das Linux-Ziel braucht **Python 3.8+ und lesbares `/proc`**; remote wird bestehender OpenSSH-Zugang genutzt. Ohne Root-SSH die Bash-Datei auf den Server kopieren und dort mit `sudo` starten. Die bisherigen Dateinamen bleiben kompatibel.

## Fixes erst ansehen

**Für Fixes 2.2.2 oder neuer verwenden.** Die alte 2.2.1 kann INI-Einstellungen beschädigen.

```bash
sudo bash p2s-harden.sh --dry-run --lang de
sudo bash p2s-harden.sh --fix --lang de
```

Diff und Anwendungskompatibilität prüfen. `--fix` fragt nach, erstellt Backups und nennt den Rollback-Befehl. Automatisch geändert werden ausgewählte INI-Werte; Rechteänderungen brauchen ausdrücklich gewählte Verzeichnisse.

## Ergebnisse einordnen

`OPEN` braucht Prüfung, `UNKNOWN` bedeutet fehlende Abdeckung. Ein unauffälliger Bericht belegt keinen sauberen Server. Das lesende Audit ändert keine Konfiguration, Rechte oder Dienste; Lesen und HTTP-Anfragen können Logs und Zugriffszeiten aktualisieren.

**PHP separat aktualisieren:** Das Tool erkennt oder behebt keine PHP-CVEs. Funktionssperren sind zusätzliche Härtung, keine Sandbox.

## Weitere Informationen

[Bedienung und technische Details](docs/DETAILS.de.md) · [Download prüfen](docs/PROVENANCE.md) · [Release und Prüfsummen](https://github.com/IamAngusU/php-fpm-audit/releases/tag/v2.2.2)

Die 2.3-Entwicklungsvorschau mit Webshell- und neuen Upload-Prüfungen ist [separat dokumentiert](docs/DETAILS.de.md#entwicklungsvorschau-23) und gehört nicht zu Stable 2.2.2.

[Stable-CI-Nachweis](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md) (gleicher Maintainer) · [Mitwirken](CONTRIBUTING.md) · [MIT-Lizenz](LICENSE)
