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

Für Linux-Server mit PHP-FPM, insbesondere konventionelle Debian/Ubuntu-Installationen mit Nginx. **2.2.0-rc.2 ist ein Release Candidate.** Der Standardbefehl prüft. Ausgabe und Hilfe sind standardmäßig Englisch; `--lang de` wählt Deutsch. Änderungen erfolgen ausdrücklich mit `--fix` oder `--rollback`. [English](README.md).

## Direkt starten

Lade **eine Datei** für den Rechner herunter, von dem du starten möchtest:

- [Windows PowerShell](https://github.com/IamAngusU/p2s-harden/releases/download/v2.2.0-rc.2/p2s-harden.ps1)
- [Linux / macOS Bash](https://github.com/IamAngusU/p2s-harden/releases/download/v2.2.0-rc.2/p2s-harden.sh)
- [Vollständiger Quellcode und Prüfsummen](https://github.com/IamAngusU/p2s-harden/releases/tag/v2.2.0-rc.2)

Beide Startdateien enthalten die vollständige Python-Engine. Kein pip, Composer oder Konfigurationsprojekt nötig.

### Auf dem Linux-Server

```bash
sudo bash p2s-harden.sh
```

### Von Windows aus

Öffne PowerShell im Ordner mit der heruntergeladenen Datei:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\p2s-harden.ps1 --ssh root@SERVER
```

Ersetze `SERVER` durch Hostname, IP-Adresse oder bestehenden SSH-Alias deines Servers. Die ExecutionPolicy-Option gilt für diesen Aufruf; erzwungene Organisationsrichtlinien gelten weiterhin.

### Von Linux / macOS aus

```bash
bash p2s-harden.sh --ssh root@SERVER
```

Das **Linux-Ziel** braucht Python 3.8+ und lesbares `/proc`. Remote brauchst du einen vorhandenen OpenSSH-Zugang. Auf dem Windows-Rechner sind weder Bash noch Python nötig.

Vollständige Prüfungen und Fixes benötigen root auf dem Linux-Ziel. **Root-SSH ist gesperrt?** Melde dich normal an, kopiere die Bash-Datei auf den Server und starte dort `sudo bash p2s-harden.sh`. Mit `--ssh BENUTZER@SERVER` laufen alternativ die lesbaren Teilprüfungen; fehlende Rechte werden erklärt.

## Was passiert danach?

1. Das Tool erkennt gängige Nginx-Webroots, feste Domains, Ports und einfache Aliases sowie unterstützte Host-FPM-Instanzen und Pools.
2. Es prüft PHP-Einstellungen, Schreibrechte und ausgewählte HTTP-Endpunkte.
3. Es zeigt offene Befunde, unvollständige Prüfungen und fehlende Fähigkeiten. Für ein übliches unterstütztes Setup musst du keine Pfade oder Domains konfigurieren.

`OK` heißt: Diese Einzelprüfung hat bestanden. `OPEN` braucht eine Bewertung oder Änderung. `UNKNOWN` heißt: Die Prüfung konnte kein Ergebnis belegen. Auch eine abgeschlossene Prüfung kann solche unbekannten Punkte enthalten; sie bleiben sichtbar und bestimmen dann Exit 2. `INFO` beschreibt Hinweise außerhalb der ausgewählten automatischen Prüfungen, etwa die manuelle ImageMagick-Bewertung, und verändert den Exitcode nicht.

Bei fehlenden Voraussetzungen hilft derselbe Launcher mit `--doctor`:

```bash
sudo bash p2s-harden.sh --doctor
sudo bash p2s-harden.sh --discover
```

Ohne `ps` nutzt das Tool `/proc`. HTTP-Prüfungen nutzen Pythons Standardbibliothek und benötigen kein `curl`. Ohne `runuser` werden fremde Benutzer einmal pro Benutzer ausgelassen. Fehlende systemd-Dienstzuordnung sperrt automatische INI-Fixes, während unterstützte Prüfungen weiterlaufen. Ein Fehler in einer FPM-Instanz verwirft andere Teilprüfungen nicht. Es werden keine Pakete automatisch installiert.

Auch ohne Python listet der Bootstrap fehlende Helfer auf und erklärt den nächsten Schritt. Stelle Python bereit und starte denselben Befehl erneut. Bei fehlendem SSH-Zugang erscheint ebenfalls eine verständliche Meldung.

## Fixes erst ansehen, dann anwenden

Zeige zuerst die geplanten Änderungen an:

```bash
sudo bash p2s-harden.sh --dry-run
```

Nach Prüfung des Trockenlaufs die unterstützten Änderungen ausdrücklich anwenden:

```bash
sudo bash p2s-harden.sh --fix
```

Falls du eine angewendete Transaktion zurücknehmen möchtest, nutze separat:

```bash
sudo bash p2s-harden.sh --rollback
```

`--fix` ergänzt sieben definierte Shell-Funktionen in vorhandenen FPM-`disable_functions` und setzt ein aktiviertes `allow_url_include` in unterstützten FPM-spezifischen INIs auf `Off`. Das kann Anwendungen betreffen. Prüfe die betroffenen Anwendungen anschließend.

Verzeichnisrechte ändern sich ausschließlich mit einem ausdrücklichen `--protect-dir /absoluter/pfad` und bekanntem Web-Benutzer. Die Änderung gilt nur für dieses Verzeichnis. Erkennung wählt keine Rechteänderungen aus. Erforderliche Fix-Fähigkeiten werden vor der Transaktion geprüft. Fixes erhalten einen neuen Änderungszeitpunkt. Backups bewahren ursprüngliche Inhalte und Metadaten; Rollback stellt diese wieder her und lehnt Konflikte bei Inhalt oder Metadaten ab. `--rollback` wählt ausschließlich die letzte Transaktion; Wiederholen ändert nichts weiter. Ältere Transaktionen brauchen ausdrücklich `--backup-id ID`. [Details und Wiederherstellung](docs/DETAILS.de.md).

Prüfung, Diagnose, Inventar und Trockenlauf verändern keine Zielkonfiguration, Rechte oder laufenden Dienste. Lesen und HTTP-Anfragen können Zugriffszeiten und gewöhnliche Serverlogs aktualisieren.

## Häufige Situationen

- **Ein Helfer fehlt:** `--doctor` erklärt, welche Prüfung ihn braucht. Andere Prüfungen laufen weiter. Benötigten Helfer bereitstellen und erneut starten.
- **Abweichende Nginx-Konfiguration:** `--nginx-config /pfad/nginx.conf` angeben.
- **Eine Site eingrenzen:** `--root /srv/site --web-user www-data --site https://example.org=/srv/site` verwenden. `--site` und `--web-user` sind wiederholbar.
- **Erwartete Uploads oder Cache:** `--runtime-dir /srv/site/uploads` angeben, bei Bedarf mehrfach. Schreibbare Verzeichnisse dort werden zu `INFO`; schreibbare PHP-Dateien bleiben `OPEN`. Ausführungssperren für diese Pfade separat prüfen.
- **Ein Such- oder HTTP-Limit wird gemeldet:** Bereich eingrenzen oder `--max-paths` (20000 Einträge je Lauf), `--walk-seconds` (10 Sekunden je Lauf), `--max-http-probes` (128 Anfragen insgesamt) bzw. `--max-sites` (32 automatische Zuordnungen) anpassen. Erreichte Limits bleiben `UNKNOWN`.
- **Alle Befunde sehen:** `--verbose` ergänzen. Für Automatisierung ist `--json` in jedem Modus verfügbar: Vorschauen enthalten `plan`, Fix/Recovery enthalten `transaction`, Fehler bewahren frühere Befunde. Phasenhinweise gehen auf stderr. `--no-progress` blendet sie aus.
- **Exit 2 nach Prüfung oder Fix:** Die `UNKNOWN`-Befunde lesen. Exit 0 bedeutet bestandene Einzelprüfungen, 1 offene Punkte, 2 unvollständige Prüfung/Fehler. Unabhängige Teilprüfungen können trotzdem abgeschlossen sein. Nach einem abgeschlossenen Fix können andere Befunde verbleiben.

## Umfang und Reifegrad

Automatische INI-Fixes unterstützen konventionelle Debian/Ubuntu-**Host-FPM**-Layouts (`/etc/php/VERSION/fpm`) mit geschützter Konfiguration und passendem systemd-Dienst. Apache/mod_php, andere FPM-Layouts, Container, dynamische Nginx-Zuordnungen und ImageMagick-Regeln benötigen separate/manuelle Bewertung.

Geprüft werden Datenträgerkonfiguration und ausgewählte Rechte/Endpunkte. Damit ist weder belegt, dass jeder laufende Worker diese Konfiguration verwendet, noch dass jede PHP-to-Shell-Technik blockiert ist. HTTP-2xx-Antworten werden mit zwei zufälligen fehlenden Pfaden verglichen. Gleiche oder dynamische Soft-404-Seiten bleiben `UNKNOWN`; sie werden weder als belegter Dateizugriff noch als bestandene Prüfung ausgegeben. Die Funktionssperren und `open_basedir` ersetzen keine Prozessisolation.

[Review-Nacharbeit und echte PHP-FPM-Nachweise](docs/REVIEW-FOLLOWUP.md) · [Tatsächliche Tests und Grenzen](docs/VALIDATION.md) · [Änderungen](CHANGELOG.md) · [MIT-Lizenz](LICENSE).

## Für Mitwirkende

**Diese Befehle benötigen das vollständige Quellpaket**, gestartet aus dessen Hauptverzeichnis. Für die normale Ein-Datei-Nutzung sind sie nicht nötig:

```bash
python3 build-standalone.py --check
sudo bash tools/test-linux.sh
```

Der Linux-Teststarter erstellt und entfernt geschützte temporäre Testdateien selbst. Owner-/ACL-/Rollback-Tests benötigen root, Python 3.8+, Bash, runuser, ps und den Benutzer `www-data`. Echte PHP-/Nginx-/Firewall-Konfigurationen werden dabei nicht geändert. Der Windows-Test nutzt ein temporäres Ersatzprogramm für SSH:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-windows-launcher.ps1
```

Für den zusätzlichen echten PHP-FPM-Test auf einem Linux-Testrechner mit Docker:

```bash
python3 tools/test_fpm_runtime.py --engine p2s_harden.py
```

Er startet temporäre Container, sendet echte FastCGI-Anfragen und gleicht Funktionsaufrufe, Pool-Vererbung und URL-Includes mit dem Audit ab. Docker wird nur für diesen Entwicklertest benötigt. [Fälle und Grenzen](docs/REVIEW-FOLLOWUP.md).

[Mitwirken](CONTRIBUTING.md) · [Sicherheitsumfang](SECURITY.md) · [CI-Workflow](.github/workflows/ci.yml).
