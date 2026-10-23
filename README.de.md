<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme/p2s-harden-wordmark-dark.svg">
    <img src="docs/assets/readme/p2s-harden-wordmark.svg" width="340" alt="p2s-harden — PHP-FPM im Terminal prüfen">
  </picture>
</p>

<p align="center">
  <a href="README.md"><img src="docs/assets/readme/readme-language-en.svg" height="40" alt="Read this README in English"></a>
</p>

<h1 align="center">PHP-FPM prüfen. Fixes vorab ansehen.</h1>
<p align="center">Setups erkennen. Fehlende Voraussetzungen verstehen. Im Terminal bleiben.</p>

<p align="center">
  <a href="#was-passiert-danach"><img src="docs/assets/readme/badge-default.svg" height="40" alt="Standard: zuerst nur prüfen"></a>
  <a href="#fixes-erst-ansehen-dann-anwenden"><img src="docs/assets/readme/badge-recovery.svg" height="40" alt="Wiederherstellung: rücknehmbare Fixes mit Backups und Konfliktprüfung"></a>
  <a href="#umfang-und-reifegrad"><img src="docs/assets/readme/badge-platforms.svg" height="40" alt="Plattformen: Linux-Ziel, SSH-Clients auf Windows, Linux und macOS"></a>
  <a href="LICENSE"><img src="docs/assets/readme/badge-license.svg" height="40" alt="Lizenz: MIT"></a>
</p>
<p align="center">
  <a href="https://github.com/angusu-de/p2s-harden/actions/workflows/ci.yml"><img src="https://raw.githubusercontent.com/angusu-de/p2s-harden/ci-proof/proof/public-proof.svg" height="54" alt="Live-Status der öffentlichen CI: p2s-harden-Workflow öffnen"></a>
</p>
<p align="center"><sub>Öffentliche CI auf einem separaten Konto, gleicher Maintainer. <a href="https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md">Getesteter Commit und einzelne Prüfschritte</a>. Badge-Design: <a href="https://github.com/IamAngusU/Badges">IamAngusU/Badges</a>.</sub></p>
<p align="center"><a href="#direkt-starten">Starten</a> · <a href="#fixes-erst-ansehen-dann-anwenden">Fixes vorab ansehen</a> · <a href="#umfang-und-reifegrad">Prüfumfang</a> · <a href="docs/DETAILS.de.md">Dokumentation</a> · <a href="https://github.com/IamAngusU/p2s-harden/releases">Releases</a></p>

**p2s bedeutet PHP-to-shell.** Das Tool prüft ausgewählte PHP-FPM-Einstellungen, Rechte und lokale HTTP-Pfade und zeigt einen begrenzten, rücknehmbaren Fix. **2.2.0-rc.3 ist ein Release Candidate.** Englisch ist Quell- und Standardsprache; `--lang de` wählt Deutsch.

## Direkt starten

Lade **eine Datei** für deinen Startrechner:

- [Windows PowerShell](https://github.com/IamAngusU/p2s-harden/releases/download/v2.2.0-rc.3/p2s-harden.ps1)
- [Linux/macOS Bash](https://github.com/IamAngusU/p2s-harden/releases/download/v2.2.0-rc.3/p2s-harden.sh)
- [Quellpaket und SHA-256-Prüfsummen](https://github.com/IamAngusU/p2s-harden/releases/tag/v2.2.0-rc.3)

Auf dem Linux-Server:

```bash
sudo bash p2s-harden.sh --lang de
```

Von Windows mit bestehendem OpenSSH-Zugang:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\p2s-harden.ps1 --ssh root@SERVER --lang de
```

Von Linux/macOS:

```bash
bash p2s-harden.sh --ssh root@SERVER --lang de
```

`SERVER` durch Hostname, IP oder bestehenden SSH-Alias ersetzen. Das Linux-Ziel braucht **Python 3.8+ und lesbares `/proc`**. Windows braucht lokal weder Bash noch Python. Kein pip, Composer, Konfigurationsprojekt oder Docker für normale Nutzung. Fehlende Fähigkeiten werden erklärt; unabhängige Prüfungen laufen weiter. Vollständige Benutzerprüfungen und Fixes brauchen root. Ohne Root-SSH die Bash-Datei auf den Server kopieren und dort mit `sudo` starten; normale SSH-Benutzer können lesbare Teilprüfungen ausführen.

## Für wen?

Für Administratoren konventioneller Debian/Ubuntu-**Host-FPM**-Installationen, besonders mit Nginx. Automatische INI-Änderungen benötigen geschützte `/etc/php/VERSION/fpm`-Konfiguration und einen geprüften systemd-Dienst. Apache/mod_php, Container, dynamische Zuordnungen und andere Layouts brauchen separate Bewertung. Funktionssperren und `open_basedir` sind zusätzliche Schutzschichten; sie belegen weder Prozessisolation noch die Unmöglichkeit jeder PHP-to-Shell-Technik.

## Was passiert danach?

1. Nginx-Webroots, feste Domains, Ports und einfache Aliases sowie FPM-Instanzen und Pools erkennen.
2. Einstellungen, Dateisystemrechte und HTTP-Ziele prüfen.
3. Befunde mit stabilen IDs und einem konkreten nächsten Schritt anzeigen. Änderungen brauchen `--fix` oder `--rollback`.

Beispielausgabe, mit illustrativen Pfaden:

```text
OPEN    disable_functions /etc/php/8.3/fpm/php-fpm.conf: Fehlt: popen
        P2S-PHP001-<Ressourcen-Hash>
        --dry-run und Anwendungskompatibilität prüfen ...
UNKNOWN HTTP https://example.test/.env: 200; entspricht Soft-404-Fallback ...

OK: 12   OPEN: 1   UNKNOWN: 1   INFO: 0
```

| Prüfung | Ausgewiesener Umfang | Automatische Änderung |
| --- | --- | --- |
| FPM-Einstellungen | Sieben Funktionen, additive Pool-Sperren, URL-Includes, open_basedir | Unterstützte Funktions-/Include-INI-Werte |
| Code und Verzeichnisse | Echte PHP-Benutzer/Gruppen und ACL-Wirkung; PHP-Dateien auch im Laufzeitspeicher | Nur ausdrückliches --protect-dir, nicht rekursiv |
| Sensible HTTP-Pfade | .env, .git/config, gefundene .env*, SQL-/BAK-/Log-Dateien und benannte Debugskripte | Keine; Webserver/Anwendung manuell korrigieren |
| Fehlpfad-Baseline | Zwei zufällige Pfade erkennen statische/dynamische Soft-404s | Keine |
| Host/manuelle Einordnung | ptrace_scope; ImageMagick nur bei gefundener Policy/Erweiterung | Keine |
| Voraussetzungen/Abdeckung | Fehlende Helfer, unbekannte Kontexte, ausgelassene Pfade und Limits | Keine automatische Installation |

`OK`: Einzelprüfung bestanden. `OPEN`: prüfen/beheben. `UNKNOWN`: Ergebnis nicht belegt. `INFO`: Kontext, keine bestandene Sicherheitsprüfung. [Behebung nach Regel-ID](docs/FINDINGS.md).

```bash
sudo bash p2s-harden.sh --doctor --lang de
sudo bash p2s-harden.sh --discover --lang de
```

Ohne ps nutzt die Erkennung `/proc`. HTTP nutzt Python und braucht kein curl. Fehlendes runuser betrifft fremde Benutzer; fehlende Dienstverwaltung sperrt automatische INI-Fixes. Ohne Python erklärt der Bootstrap die Voraussetzung; den Python-Audit kann er dann nicht ausführen.

## Fixes erst ansehen, dann anwenden

```bash
sudo bash p2s-harden.sh --dry-run --lang de
sudo bash p2s-harden.sh --fix --lang de
```

Die Vorschau zeigt **Werte und einen Unified Diff** ohne Nachbarzeilen, damit keine unbeteiligten INI-Einstellungen ausgegeben werden. Interaktives `--fix` fragt über `/dev/tty` und nimmt standardmäßig Nein an. Seit der Vorschau geänderte Inhalte werden abgelehnt. Die SSH-Übertragung hat keinen entfernten TTY: erst `--dry-run`, danach `--yes` nutzen. Für geprüfte Automatisierung:

```bash
sudo bash p2s-harden.sh --dry-run --json
sudo bash p2s-harden.sh --fix --yes --json
sudo bash p2s-harden.sh --rollback --backup-id BACKUP_ID --json
```

Der Fix ergänzt nur die definierten Funktionssperren und deaktiviert URL-Includes in unterstützten INIs. Anwendungskompatibilität prüfen. Verzeichnisänderungen brauchen `--protect-dir /absoluter/codepfad` und bekannten PHP-Benutzer; Erkennung wählt keine Rechteziele. Die Textausgabe nennt den exakten Undo-Befehl, JSON Backup-ID und Status. Wiederholtes implizites Rollback wählt keinen älteren Fix. Es prüft Inhalt und Metadaten, stellt ursprüngliche Zeitstempel wieder her und lässt sich nach Unterbrechung fortsetzen. Fixes erhalten aktuelle Änderungszeitpunkte.

Audit, Diagnose, Inventar und Trockenlauf ändern keine Zielkonfiguration, Rechte oder Dienste. Lesen und HTTP können Zugriffszeiten und gewöhnliche Logs aktualisieren.

## Häufige Situationen

- **Uploads/Cache:** `--runtime-dir /srv/site/uploads` wiederholen. Schreibbare Verzeichnisse dort werden INFO; schreibbare PHP-Dateien und fehlende Abdeckung bleiben sichtbar. Ausführungssperren separat prüfen.
- **Größere Anwendung:** Standard **250000 Einträge und 10 Sekunden je Suchlauf**. `--max-paths`, `--walk-seconds` oder `--root` anpassen. Abhängigkeiten werden nicht still ausgelassen. HTTP: 128 Anfragen insgesamt, 32 automatische Zuordnungen (`--max-http-probes`, `--max-sites`). Erreichte Limits bleiben UNKNOWN.
- **HTTP leitet zu HTTPS weiter:** `--site https://example.org=/srv/site` wählen. Ein Redirect bleibt unbekannt, bis das Ziel geprüft ist; er belegt keinen Zugriffsschutz. Automatische Zuordnungen bevorzugen HTTPS.
- **Abweichendes Layout:** `--nginx-config /pfad/nginx.conf` oder `--root /srv/site --web-user www-data --site https://example.org=/srv/site`. Benutzer und Sites sind wiederholbar.
- **Automatisierung:** Schema 2 enthält `id`, `rule_id`, `resource`, `severity`, `remediation`, `suppressed`, `has_open`, `has_unknown`, `plan` und `transaction`. Übersetzte Texte sind keine API-Kennung. `--verbose` zeigt alle Zeilen.
- **Akzeptierter offener Befund:** `--ignore BEFUND_ID` für eine Ressource oder `--ignore P2S-FS002` für die ganze Regel. Der Befund bleibt sichtbar und markiert. UNKNOWN lässt sich nicht zu einem Erfolg unterdrücken. Die Option betrifft nur die Exitwertung, nicht Fixumfang oder Suchpfade.

Standard (`--fail-on complete`): **2 bei UNKNOWN/Fehler**, sonst **1 bei OPEN**, sonst **0**. Für CI mit Vorrang offener Befunde: `--fail-on open` gibt bei OPEN zuerst 1 aus; andernfalls bleibt UNKNOWN bei 2. JSON zeigt beide Flags und alle Befunde. Ignorierte OPEN-Befunde bleiben im Bericht, beeinflussen den Exitcode aber nicht.

## Download prüfen

Prüfsummendatei neben den gewählten Launcher herunterladen. Unter Windows:

```powershell
$expected = (Select-String -Path .\p2s-harden-SHA256SUMS.txt -Pattern '  p2s-harden.ps1$').Line.Split(' ')[0]
$actual = (Get-FileHash .\p2s-harden.ps1 -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw 'Prüfsumme stimmt nicht' }
```

Wenn deine Richtlinie geprüfte lokale Skripte erlaubt, etwa RemoteSigned, ist nach Prüfung des Downloads `Unblock-File` eine Alternative zum Prozess-Bypass:

```powershell
Unblock-File -LiteralPath .\p2s-harden.ps1
.\p2s-harden.ps1 --ssh root@SERVER --lang de
```

Das entfernt die Downloadmarkierung, übersteuert aber weder Restricted noch Organisationsrichtlinien. Das frühere Bypass-Beispiel gilt für diesen Aufruf; erzwungene Organisationsrichtlinien gelten weiter. Prüfsummen erkennen veränderte Downloads. [Lesbare Quellen](src), [generierte Engine](p2s_harden.py), [Builder](build-standalone.py) und CI-Belege zeigen, was die größeren Ein-Datei-Launcher enthalten.

## Umfang und Reifegrad

**RC.3 bleibt ein Release Candidate.** Datenträgerprüfung belegt nicht die Konfiguration jedes bestehenden Workers oder alle vHosts/Container/Angriffspfade. Separate Wegwerf-VM-Tests prüfen echten `/proc`-Discover, Nginx-Zuordnung, PHP-Benutzerrechte, systemd-Fix/Reload, HTTP-Workerwerte und Rollback auf Debian 12/PHP 8.2 und Ubuntu 24.04/PHP 8.3. Die FastCGI-Matrix umfasst PHP 8.2–8.5. [Prüfnachweise](docs/VALIDATION.md) · [Review-Entscheidungen](docs/REVIEW-rc3.md).

Der Quellaccount kann derzeit keine GitHub-gehosteten Runner starten. Deshalb läuft öffentliche CI auf einem zweiten Account desselben Maintainers. Das ist kein unabhängiges Audit. Der Proof verlangt übereinstimmende getestete Quell-/Fork-Commits. [Jobs und Schritte](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md) · [Synchronisierung](docs/CI.md).

## Für Mitwirkende

Aus dem vollständigen Quellpaket:

```bash
python3 build-standalone.py --check
sudo bash tools/test-linux.sh
python3 tools/test_fpm_runtime.py --engine p2s_harden.py
```

`src/*.py` und Launcher-Vorlagen bearbeiten, danach neu bauen. Der Builder erstellt Engine und beide eigenständigen Launcher; Nutzer benötigen keine Quelldateien daneben. Root-Fixtures sind temporär. Docker ist nur für echte FastCGI-Entwicklertests nötig. **Der system-runtime-Test ist destruktiv und auf ausdrücklich markierte Wegwerf-VMs beschränkt**; normale Tests und die CLI rufen ihn nie auf. Windows: `powershell -NoProfile -File test-windows-launcher.ps1`.

[Deutsche Details](docs/DETAILS.de.md) · [English details](docs/DETAILS.md) · [Mitwirken](CONTRIBUTING.md) · [Sicherheit](SECURITY.md) · [Änderungen](CHANGELOG.md) · [MIT-Lizenz](LICENSE).
