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
<p align="center">PHP-FPM und Nginx lesend prüfen. Befunde verstehen und ausgewählte Fixes vorab ansehen.</p>

<p align="center">
  <a href="#was-passiert-danach"><img src="docs/assets/readme/badge-default.svg" height="40" alt="Standard: zuerst nur prüfen"></a>
  <a href="#fixes-erst-ansehen-dann-anwenden"><img src="docs/assets/readme/badge-recovery.svg" height="40" alt="Wiederherstellung: rücknehmbare Fixes mit Backups und Konfliktprüfung"></a>
  <a href="#umfang-und-reifegrad"><img src="docs/assets/readme/badge-platforms.svg" height="40" alt="Plattformen: Linux-Ziel, SSH-Clients auf Windows, Linux und macOS"></a>
  <a href="LICENSE"><img src="docs/assets/readme/badge-license.svg" height="40" alt="Lizenz: MIT"></a>
</p>
<p align="center">
  <a href="https://github.com/angusu-de/p2s-harden/actions/workflows/ci.yml"><img src="https://raw.githubusercontent.com/angusu-de/p2s-harden/ci-proof-2.2/proof/public-proof.svg" height="54" alt="Live-Status der öffentlichen CI: Wartungsrelease-Workflow öffnen"></a>
</p>
<p align="center"><sub>Öffentliche CI auf einem separaten Konto, gleicher Maintainer. <a href="https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md">Getesteter Commit und einzelne Prüfschritte</a>. Badge-Design: <a href="https://github.com/IamAngusU/Badges">IamAngusU/Badges</a>.</sub></p>
<p align="center"><a href="#direkt-starten">Starten</a> · <a href="#fixes-erst-ansehen-dann-anwenden">Fixes vorab ansehen</a> · <a href="#umfang-und-reifegrad">Prüfumfang</a> · <a href="docs/DETAILS.de.md">Dokumentation</a> · <a href="https://github.com/IamAngusU/php-fpm-audit/releases">Releases</a></p>

**php-fpm-audit** prüft ausgewählte PHP-FPM-Einstellungen, FPM-Listener und Sockets, Dateirechte und sensible HTTP-Pfade. Befunde haben stabile IDs und einen konkreten nächsten Schritt. Der unterstützte Konfigurationsablauf richtet sich an **Debian/Ubuntu mit Host-PHP-FPM, Nginx und systemd**. Englisch ist Standardsprache; `--lang de` wählt Deutsch.

- **Zuerst nur prüfen.** Audit, Diagnose, Erkennung und Trockenlauf ändern keine Zielkonfiguration, Rechte oder Dienste. HTTP-Anfragen und Lesen können Logs und Zugriffszeiten aktualisieren.
- **Änderungen vorab prüfen.** Ausgewählte INI-Fixes haben einen Diff; Rechteänderungen einen ausdrücklichen Plan. Bestätigung, Backups und Rollback mit Konfliktprüfung gehören zum Ablauf.
- **Fehlende Abdeckung bleibt sichtbar.** `UNKNOWN` wird nie zu `OK`. Ein unauffälliger Bericht belegt keinen sauberen Server.
- **Eine Datei starten.** Bash oder PowerShell wählen. Das Linux-Ziel braucht Python 3.8+ und lesbares `/proc`; Windows braucht bestehenden OpenSSH-Zugang.

> [!IMPORTANT]
> **PHP separat aktualisieren.** Dieses Tool erkennt oder behebt keine PHP-CVEs und prüft weder den Sicherheits-Patchstand noch einen FPM-Neustart nach Updates. Für PHP2Shell und weitere Hinweise die [aktuellen PHP-Sicherheitshinweise](https://www.php.net/archive/2026.php) und Paketmeldungen der Distribution beachten. Funktionssperren sind zusätzliche Härtung, keine Sandbox.

**Stabile Wartungsversion 2.2.2:** korrigierter INI-Editor auf Basis von 2.2.1. Webshell- und neue Upload-Routenprüfungen bleiben in der [separaten Entwicklungsvorschau](https://github.com/IamAngusU/php-fpm-audit/tree/main).

## Direkt starten

> [!NOTE]
> **Für automatische Fixes 2.2.2 oder neuer verwenden.** Die alte Version 2.2.1 kann mehrzeilig zitierte INI-Werte beschädigen. 2.2.2 verweigert solche Eingaben und prüft unbeteiligte effektive INI-Werte vor einem Reload. Bei verweigerten Dateien ist eine manuelle Prüfung erforderlich.

Lade **eine Datei** für deinen Startrechner:

- [Windows PowerShell](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.ps1)
- [Linux/macOS Bash](https://github.com/IamAngusU/php-fpm-audit/releases/download/v2.2.2/p2s-harden.sh)
- [Quellpaket und SHA-256-Prüfsummen](https://github.com/IamAngusU/php-fpm-audit/releases/tag/v2.2.2)

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


**Bisherige Dateinamen bleiben erhalten:** Das Projekt heißt jetzt `php-fpm-audit`; Skripte, Backup-Pfade und `P2S-`-Befund-IDs bleiben kompatibel.

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
| FPM-Grenzen | TCP-Bindung und Client-Freigaben, konfigurierte und tatsächliche Socket-Rechte, Skript-Endungen, Umgebungsbereinigung, gemeinsame UIDs und geladene FFI-Einstellung | Einzeln prüfen und manuell ändern |
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

## Bericht ohne private Hostdetails teilen

```bash
sudo bash p2s-harden.sh --check --redact --json > p2s-report.json
```

`--redact` erhält Regel-IDs, Ergebnisse, Handlungshinweise und **geprüfte
technische Fakten**: etwa `missing_functions: ["popen"]`, `socket_mode: "0666"`,
Schalterzustände, Zähler und HTTP-Status. Jede Regel begrenzt Felder, Typen und
Werte. Pfade, Domains, Nutzer, Rohdiagnosen, Inventar, Pläne und Transaktionen
entfallen. Geteilte Befund-IDs werden neu erzeugt; für einzelne `--ignore`-Ausnahmen
lokale Original-IDs verwenden. Unterstützt: check, doctor und discover. Ergebnisse
und Exit-Code bleiben gleich. Änderungsvorschauen lokal ohne Maskierung prüfen.
Die Maskierung gilt für Bericht-stdout; SSH-/System-stderr kann den Host nennen.
[Geprüftes Audit-Feedback senden](https://github.com/IamAngusU/php-fpm-audit/issues/new?template=audit-feedback.yml).

Die Änderung bestehender INIs kann eine paketverwaltete `php.ini` betreffen. Ändern sich lokale und Paketversion, kann ein späteres Upgrade nach der gewünschten Konfiguration fragen. Diff prüfen und danach erneut auditieren; neue Drop-ins bleiben zurückgestellt. [Upgrade-Verhalten](docs/DETAILS.md#package-upgrades).

## Häufige Situationen

- **Wiederholte globale Einstellungen:** Unveränderte Pool-Ergebnisse teilen den globalen Befund. Normales JSON nennt `affected_pools`; `evidence.affected_pool_count` ist teilbar. Abweichende wirksame Einstellungen und explizite unsichere Include-Overrides bleiben eigene Ursachen.
- **TCP localhost:** Die aktuelle Host-Auflösung hat ein Zwei-Sekunden-Limit. Adressen außerhalb Loopback sind OPEN; fehlgeschlagene Auflösung und andere Hostnamen bleiben UNKNOWN. Das attestiert keinen bestehenden Listener oder Containerdienst.

- **Uploads/Cache:** `--runtime-dir /srv/site/uploads` wiederholen. Schreibbare Verzeichnisse dort werden INFO; schreibbare PHP-Dateien und fehlende Abdeckung bleiben sichtbar. Ausführungssperren separat prüfen.
- **Größere Anwendung:** Standard **250000 Einträge und 10 Sekunden je Suchlauf**. `--max-paths`, `--walk-seconds` oder `--root` anpassen. Abhängigkeiten werden nicht still ausgelassen. HTTP: 128 Anfragen insgesamt, 32 automatische Zuordnungen (`--max-http-probes`, `--max-sites`). Erreichte Limits bleiben UNKNOWN.
- **HTTP leitet zu HTTPS weiter:** `--site https://example.org=/srv/site` wählen. Ein Redirect bleibt unbekannt, bis das Ziel geprüft ist; er belegt keinen Zugriffsschutz. Automatische Zuordnungen bevorzugen HTTPS.
- **Abweichendes Layout:** `--nginx-config /pfad/nginx.conf` oder `--root /srv/site --web-user www-data --site https://example.org=/srv/site`. Benutzer und Sites sind wiederholbar.
- **Automatisierung:** Schema 2 enthält `id`, `rule_id`, `resource`, `severity`, `remediation`, `suppressed`, `has_open`, `has_unknown`, `plan` und `transaction`. Übersetzte Texte sind keine API-Kennung. `--verbose` zeigt alle Zeilen.
- **Akzeptierter offener Befund:** `--ignore BEFUND_ID` für eine Ressource oder `--ignore P2S-FS002` für die ganze Regel. Der Befund bleibt sichtbar und markiert. UNKNOWN lässt sich nicht zu einem Erfolg unterdrücken. Die Option betrifft nur die Exitwertung, nicht Fixumfang oder Suchpfade.

Standard (`--fail-on complete`): **2 bei UNKNOWN/Fehler**, sonst **1 bei OPEN**, sonst **0**. Für CI mit Vorrang offener Befunde: `--fail-on open` gibt bei OPEN zuerst 1 aus; andernfalls bleibt UNKNOWN bei 2. JSON zeigt beide Flags und alle Befunde. Ignorierte OPEN-Befunde bleiben im Bericht, beeinflussen den Exitcode aber nicht.

## Download prüfen

Prüfsummen erkennen Korruption oder unpassende Downloads. Prüfsumme und Datei aus demselben Release belegen allein keine Herkunft. Zusätzlich enthalten Releases **GitHub-signierte Build-Nachweise** für die vier Distributionsdateien, gebaut nach bestandenen Testjobs. Mit optionalem `gh attestation verify` Bytes, Workflow und Quell-Commit prüfen: [Befehle und Vertrauensgrenze](docs/PROVENANCE.md).

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

**Stabil innerhalb des dokumentierten Umfangs.** Datenträgerprüfung belegt nicht die Konfiguration jedes bestehenden Workers oder alle vHosts/Container/Angriffspfade. Separate Wegwerf-VM-Tests prüfen echten `/proc`-Discover, Nginx-Zuordnung, PHP-Benutzerrechte, systemd-Fix/Reload, HTTP-Workerwerte und Rollback auf Debian 12/PHP 8.2, Debian 13/PHP 8.4, Ubuntu 22.04/Distributions-PHP 8.1 und Ubuntu 24.04/PHP 8.3. Die FastCGI-Matrix umfasst PHP 8.2–8.5. [Aktuelle Review-Antwort](docs/REVIEW-2.2.1.md) · [Prüfnachweise](docs/VALIDATION.md) · [Release-Umfang und Abnahmekriterien](docs/PRODUCTION.md).

Der Quellaccount kann derzeit keine GitHub-gehosteten Runner starten. Deshalb läuft öffentliche CI auf einem zweiten Account desselben Maintainers. Das ist kein unabhängiges Audit. Der Proof verlangt übereinstimmende getestete Quell-/Fork-Commits auf `release/2.2`. [Jobs und Schritte](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md) · [Synchronisierung](docs/CI.md).

## Für Mitwirkende

Aus dem vollständigen Quellpaket:

```bash
python3 build-standalone.py --check
sudo bash tools/test-linux.sh
python3 tools/test_fpm_runtime.py --engine p2s_harden.py
```

`src/*.py` und Launcher-Vorlagen bearbeiten, danach neu bauen. Der Builder erstellt Engine und beide eigenständigen Launcher; Nutzer benötigen keine Quelldateien daneben. Root-Fixtures sind temporär. Docker ist nur für echte FastCGI-Entwicklertests nötig. **Der system-runtime-Test ist destruktiv und auf ausdrücklich markierte Wegwerf-VMs beschränkt**; normale Tests und die CLI rufen ihn nie auf. Windows: `powershell -NoProfile -File test-windows-launcher.ps1`.

[Deutsche Details](docs/DETAILS.de.md) · [English details](docs/DETAILS.md) · [Mitwirken](CONTRIBUTING.md) · [Sicherheit](SECURITY.md) · [Änderungen](CHANGELOG.md) · [MIT-Lizenz](LICENSE).
