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

**p2s bedeutet PHP-to-shell.** Das Tool prüft ausgewählte PHP-FPM-Einstellungen, Rechte und lokale HTTP-Pfade und zeigt einen begrenzten, rücknehmbaren Fix. **Unterstützter Konfigurationsablauf: Debian/Ubuntu mit Host-PHP-FPM, Nginx und systemd.** Konfigurationsfixes für RHEL, Apache/mod_php und Plesk/cPanel sind nicht abgedeckt. Die statische Dateisuche mit explizitem `--root` hat einen breiteren Linux-Umfang. **2.2.1 ist die ältere veröffentlichte Konfigurationsversion; den INI-Hinweis unten beachten.** Englisch ist Quell- und Standardsprache; `--lang de` wählt Deutsch.

## Direkt starten

Ein Angreifer kann durch eine verwundbare Anwendung oder eine hochgeladene Datei bereits PHP ausführen. **`disable_functions` ist zusätzliche Härtung, keine Sandbox:** `--fix` begrenzt ausgewählte direkte Wege; es verhindert weder den ersten Einbruch noch jeden indirekten Ausführungsweg und erklärt keinen Host für sauber. Anwendungsupdates, minimale Rechte, OS-Isolation und Vorfallbehandlung bleiben eigenständige Aufgaben; die neuen Nginx-/systemd-Beobachtungen sind lesend und begrenzt.

| Angriffsweg | Gegenmaßnahme | Prüft p2s | Ändert p2s |
|---|---|---|---|
| Verwundbares Plugin/Anwendung | Updates, verwundbaren Code entfernen, Anmeldung schützen | Kein Anwendungs-/CVE-Audit | Nichts |
| Ausgewählte direkte PHP-Befehlsaufrufe | Sieben Funktionssperren und URL-Include-Policy | Globale/Pool-Policy; separate CI-Worker-Tests | Unterstützte INIs nach geprüfter Bestätigung |
| Indirekte Helfer, FFI, Umgebungs- und Datei-APIs | Anwendungsspezifische Policy plus OS-Isolation | FFI-Policy und verbleibende Policy-Möglichkeiten; kein Bypass-Nachweis | Keine zusätzlichen Sperren |
| PHP in Upload-Pfaden | Nicht ausführbarer Speicher und korrekte Nginx-Routen | Statische Root-/URI-Zuordnungen; Mehrdeutigkeit bleibt UNKNOWN | Keine Nginx-Änderung |
| Privileggewinn, OS-Schreiben und temporäre Dateien | NoNewPrivileges, ProtectSystem, PrivateTmp samt Ausnahmen prüfen | Manager-Properties der zugeordneten aktiven Unit; keine Worker-/Kernel-Attestierung | Keine Unit-Änderung |
| PHP-Benutzer kann Code ersetzen | Codebesitz und beschreibbare Laufzeitdaten trennen | Benutzer-/Rechteprüfung der ausgewählten Wurzeln | Nur ausdrücklich gewählte unterstützte Verzeichnisse |
| Bestehende Webshell/Persistenz | Beweise sichern, isolieren, neu aufsetzen, betroffene Secrets tauschen | Begrenzte PHP-Indikatoren; keine OS-/Speicher-Persistenzprüfung | Keine Malware-Entfernung/Wiederherstellung |

[Bedeutung, Nginx-Umfang und Prüfnachweise](docs/DEFENSES.md).

**Entwicklungsvorschau:** Dieser Branch ergänzt `--scan-webshells` in **2.3.0-dev.7**.
Die unten verlinkten **2.2.1-Downloads enthalten diesen Modus noch nicht**.
Zum Testen den generierten Launcher dieses Branches verwenden:
[Bash-Vorschau](p2s-harden.sh?raw=1) · [PowerShell-Vorschau](p2s-harden.ps1?raw=1).
Die Vorschau hat Commit-genaue CI-Nachweise und ist von den Stable-Release-Dateien getrennt.

**Upload-Routen:** dev.7 erkennt begrenzte Regex- und verschachtelte PHP-Sperren, die Bilder ausliefern, meldet den Zeilenumbruch-Bypass bei `.*` und erlaubt ausdrücklich reviewte UNKNOWN-Einträge mit Bindung an die komplette Konfiguration. [Beispiele und genaue Grenzen](docs/NGINX-UPLOADS.md).

**Hinweis zu INI-Fixes:** 2.2.1 kann mehrzeilig zitierte INI-Werte beschädigen. Vor `--fix` die korrigierte dev.7-Vorschau oben verwenden oder die Konfiguration manuell prüfen/bearbeiten. Lesende Audits sind nicht betroffen. Die Vorschau verweigert mehrdeutige Quotes und vergleicht andere effektive INI-Werte vor dem Reload.
[Umfang und Befehle](#nach-php-webshell-indikatoren-suchen).

Lade **eine Datei** für deinen Startrechner:

- [Windows PowerShell](https://github.com/IamAngusU/p2s-harden/releases/download/v2.2.1/p2s-harden.ps1)
- [Linux/macOS Bash](https://github.com/IamAngusU/p2s-harden/releases/download/v2.2.1/p2s-harden.sh)
- [Quellpaket und SHA-256-Prüfsummen](https://github.com/IamAngusU/p2s-harden/releases/tag/v2.2.1)

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

Der Fix ergänzt nur die definierten Funktionssperren und deaktiviert URL-Includes in unterstützten INIs. Anwendungskompatibilität prüfen. Verzeichnisänderungen brauchen `--protect-dir /absoluter/codepfad` und bekannten PHP-Benutzer; Erkennung wählt keine Rechteziele. Die Textausgabe nennt den exakten Undo-Befehl, JSON Backup-ID und Status. Wiederholtes implizites Rollback wählt keinen älteren Fix. Es prüft Inhalt und Metadaten, stellt ursprüngliche Zeitstempel wieder her und lässt sich nach Unterbrechung fortsetzen. Fixes erhalten aktuelle Änderungszeitpunkte. Die Entwicklungsvorschau ergänzt eine nicht wartende Kernel-Sperre gegen parallele Fix-/Rollback-Schreibzugriffe über ein festes geschütztes Systemverzeichnis, auch bei unterschiedlichen `--backup-root`-Werten. Backups werden nicht automatisch gelöscht; Speicherplatz und benötigte Wiederherstellungen selbst verwalten.

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
lokale Original-IDs verwenden. Unterstützt: check, doctor, discover und die Webshell-Entwicklungsvorschau. Ergebnisse
und Exit-Code bleiben gleich. Änderungsvorschauen lokal ohne Maskierung prüfen.
Die Maskierung gilt für Bericht-stdout; SSH-/System-stderr kann den Host nennen.
[Geprüftes Audit-Feedback senden](https://github.com/IamAngusU/p2s-harden/issues/new?template=audit-feedback.yml).

Die Änderung bestehender INIs kann eine paketverwaltete `php.ini` betreffen. Ändern sich lokale und Paketversion, kann ein späteres Upgrade nach der gewünschten Konfiguration fragen. Diff prüfen und danach erneut auditieren; neue Drop-ins bleiben zurückgestellt. [Upgrade-Verhalten](docs/DETAILS.md#package-upgrades).

## Häufige Situationen

- **Wiederholte globale Einstellungen:** Unveränderte Pool-Ergebnisse teilen den globalen Befund. Normales JSON nennt `affected_pools`; `evidence.affected_pool_count` ist teilbar. Abweichende wirksame Einstellungen und explizite unsichere Include-Overrides bleiben eigene Ursachen.
- **TCP localhost:** Die aktuelle Host-Auflösung hat ein Zwei-Sekunden-Limit. Adressen außerhalb Loopback sind OPEN; fehlgeschlagene Auflösung und andere Hostnamen bleiben UNKNOWN. Das attestiert keinen bestehenden Listener oder Containerdienst.

- **Uploads/Cache:** `--runtime-dir /srv/site/uploads` wiederholen. Schreibbare Verzeichnisse dort werden INFO; schreibbare PHP-Dateien und fehlende Abdeckung bleiben sichtbar. Ausführungssperren separat prüfen.
- **Größere Anwendung:** Das Konfigurationsaudit hat **250000 Einträge und 10 Sekunden je Suchlauf** als Standard. `--max-paths`, `--walk-seconds` oder `--root` anpassen. Abhängigkeiten werden nicht still ausgelassen. HTTP: 128 Anfragen insgesamt, 32 automatische Zuordnungen (`--max-http-probes`, `--max-sites`). Der separate Webshell-Modus nutzt 120 Sekunden je Wurzel und 2 Sekunden je Datei. Erreichte Limits bleiben UNKNOWN.
- **HTTP leitet zu HTTPS weiter:** `--site https://example.org=/srv/site` wählen. Ein Redirect bleibt unbekannt, bis das Ziel geprüft ist; er belegt keinen Zugriffsschutz. Automatische Zuordnungen bevorzugen HTTPS.
- **Abweichendes Layout:** `--nginx-config /pfad/nginx.conf` oder `--root /srv/site --web-user www-data --site https://example.org=/srv/site`. Benutzer und Sites sind wiederholbar.
- **Automatisierung:** Schema 2 enthält `id`, `rule_id`, `resource`, `severity`, `remediation`, `suppressed`, `has_open`, `has_unknown`, `plan` und `transaction`. Übersetzte Texte sind keine API-Kennung. `--verbose` zeigt alle Zeilen.
- **Akzeptierter offener Befund:** `--ignore BEFUND_ID` für eine Ressource oder `--ignore P2S-FS002` für die ganze Regel. Der Befund bleibt sichtbar und markiert. UNKNOWN lässt sich nicht zu einem Erfolg unterdrücken. Die Option betrifft nur die Exitwertung, nicht Fixumfang oder Suchpfade.

Bei ausdrücklich reviewten Nginx-Einträgen bleibt UNKNOWN sichtbar; JSON unterscheidet `has_unaccepted_unknown` und `accepted_unknown`. [Review-Semantik](docs/NGINX-UPLOADS.md#explicit-review-of-unsupported-routing). Exit 0 kann deshalb akzeptierte UNKNOWNs enthalten und ist kein Urteil über einen sauberen Server.

Standard (`--fail-on complete`): **2 bei UNKNOWN/Fehler**, sonst **1 bei OPEN**, sonst **0**. Für CI mit Vorrang offener Befunde: `--fail-on open` gibt bei OPEN zuerst 1 aus; andernfalls bleibt UNKNOWN bei 2. Die Vorschau ergänzt `--fail-on review`: Ein nicht akzeptierter WS004-Code-Review oder OPEN ergibt zuerst 1; sonst ergibt UNKNOWN weiterhin 2. Gewöhnliches INFO führt nicht zum Fehlschlag. `--ignore` und exakte Baselines können Review-Befunde akzeptieren; JSON ergänzt `has_review` und `suppressed_review`. JSON zeigt alle Flags und Befunde. Ignorierte OPEN-Befunde bleiben im Bericht, beeinflussen den Exitcode aber nicht.

## Download prüfen

Prüfsummen erkennen Korruption oder unpassende Downloads. Prüfsumme und Datei aus demselben Release belegen allein keine Herkunft. Zusätzlich enthalten Releases **GitHub-signierte Build-Nachweise** für die vier Distributionsdateien, gebaut nach bestandenen Testjobs. Mit optionalem `gh attestation verify` Bytes, Workflow und Quell-Commit prüfen: [Befehle und Vertrauensgrenze](docs/PROVENANCE.md).

Mit angemeldeter GitHub CLI (optional; Bash und PowerShell):

```text
gh attestation verify p2s-harden.sh --repo angusu-de/p2s-harden --signer-workflow angusu-de/p2s-harden/.github/workflows/ci.yml --source-ref refs/heads/main --deny-self-hosted-runners
```

Für den Windows-Download `p2s-harden.ps1` einsetzen. `--source-digest ERWARTETER_COMMIT` bindet die Prüfung an den Release-Commit; [Bundle-/Offline-Prüfung](docs/PROVENANCE.md) erklärt das benötigte Vertrauensmaterial. Die CI-Fork gehört demselben Maintainer.

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

## Nach PHP-Webshell-Indikatoren suchen

In der **Entwicklungsvorschau 2.3.0**, als eigener lesender Prüfmodus:

```bash
sudo bash p2s-harden.sh --scan-webshells --lang de
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --lang de
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --redact --json > indikatoren.json
```

Von Windows mit denselben Optionen:

```powershell
.\p2s-harden.ps1 --ssh root@SERVER --scan-webshells --root /srv/site --lang de
```

Ohne `--root` wählt die vorhandene Nginx-Erkennung die ausgewiesenen Webroots.
Ein expliziter Pfad benötigt weder Nginx noch laufendes FPM, PHP-Benutzer oder
HTTP-Zugriff. Die Suche liest lokal; sie führt keinen Fund aus und entpackt,
überträgt, löscht oder isoliert keine Datei.

- Erkennt Request-Daten nahe Ausführungs-/Include-Funktionen, durch Requests
  gewählte Aufrufe, Decoder nahe Code-Ausführung, Netzwerk-/Shell-Kombinationen und gesetzte Startdatei-Verweise
  in `.user.ini`, `.htaccess` und `php.ini`.
- Untersucht auch versteckte Dateien, Uploads, Cache und Abhängigkeiten sowie
  PHP-Inhalt unter anderen Endungen. Kommentare und wörtliche Beispiele in
  PHP-Strings werden gefiltert. Legitimer Code und Testbeispiele können dennoch
  Indikatoren erzeugen.
- Lokale Befunde enthalten Pfad, erste passende Zeile, SHA-256 und nächste
  Schritte. Quelltext und Zielwerte von Startdirektiven stehen nicht im Report.
  `--redact` entfernt zusätzlich Pfade, Datei-Hashes und ursprüngliche IDs;
  geprüfte Gründe, Zeilennummern und Zähler bleiben erhalten.
- Pro Wurzel gelten zunächst 250000 Einträge, **120 Sekunden**, 2 MiB PHP-Parserlimit je Datei,
  **256 MiB** insgesamt und höchstens 200 nicht durch Baseline akzeptierte Befundzeilen.
  Jede Datei hat ein eigenes **2-Sekunden-Limit**; danach geht die Suche weiter.
  `--walk-seconds 0` hebt nur den Wurzeltimer auf; `--scan-file-seconds` passt
  das Dateilimit an. Symlinks, Dateisystemgrenzen,
  Spezialdateien, Lesefehler, während des Lesens geänderte Dateien und erreichte
  Limits bleiben `UNKNOWN`. Andere zugängliche Dateien werden nach Möglichkeit
  weiter geprüft. Bei Bedarf mit `--max-paths`, `--walk-seconds`,
  `--scan-file-bytes` und `--scan-total-bytes` erweitern oder kleinere Wurzeln wählen.
- Lokale Berichte nennen unvollständig geprüfte Pfade mit Grund; redigiert bleiben
  nur geprüfte Zähler und Grund-Codes. Vollständig untersuchte und unvollständige
  Dateien werden getrennt gezählt. Indirekte Includes mit konstantem Präfix und
  Registry-Callbacks bleiben als **INFO-Prüfpunkte** sichtbar; das belegt keine
  Sicherheit. Eine ausdrücklich geprüfte **`--baseline`** akzeptiert nur denselben
  Pfad, Hash und Indikator. Ausdrückliche `reviewed_files`-Einträge können nach vertrauenswürdigem Quellvergleich bestimmte Parser-/Fensterlimits bei vollständig gehashten Dateien anerkennen. Unlesbare, instabile, zeitlich abgebrochene oder unbesuchte Inhalte bleiben UNKNOWN; akzeptierte unvollständige Dateien werden getrennt gezählt.
  Mit `--write-baseline-draft /root/p2s-draft.json` entsteht ein privater Entwurf
  (0600), der nichts überschreibt und ausschließlich `reviewed: false` enthält.
  Erst nach Vergleich jeder vollständigen Datei mit vertrauenswürdigem Quellstand
  gezielt auf `true` setzen. Mit SSH liegt die Datei auf dem Zielserver;
  `--redact` ist damit nicht kombinierbar.
  [Sichere Baseline-Nutzung und Grenzen](docs/WEBSHELLS.md#reviewed-baselines).

**Ein Indikator braucht Prüfung; keine Treffer belegen keinen sauberen Server.**
Die Suche hat keine Malware-Signaturdatenbank und keine vollständige PHP-Datenflussanalyse.
OS-, Cron-/SSH- und Speicher-Backdoors, verschlüsselte Payloads und Dateien außerhalb
der ausgewählten Wurzeln bleiben außerhalb ihres Umfangs. Ziele von Startdirektiven
werden nicht automatisch verfolgt. Bei bestätigtem Einbruch Beweise sichern, Host
isolieren, Einstiegslücke schließen, aus vertrauenswürdigen Quellen neu aufsetzen
und betroffene Zugangsdaten erneuern. Die Vorschau senkt die Scan-CPU-Priorität auf nice 10 (bereits niedrigere bleibt erhalten) und fordert Idle-I/O mit optionalem `ionice` an. `--no-nice` deaktiviert dies; fehlende oder gesperrte Helfer werden gemeldet und die Suche läuft weiter. Das sind keine festen Ressourcenlimits. Große Dateien werden vor dem Parserlimit nach PHP-Tags durchsucht. Binärartig erkannte Inhalte benötigen `<?php` oder `<?=`; einfache Short-Tags darin liegen außerhalb der Erkennung. Kopien, Casts und `basename()` behalten offene Include-Befunde. Request-Includes mit konstantem Präfix haben eine eigene MEDIUM-Regel; unbeschränkte Request-Includes bleiben HIGH. [Regeln, Grenzen und Reaktion](docs/WEBSHELLS.md).

## Umfang und Reifegrad

**Geprüfter Konfigurationsablauf; Vorschau-Erweiterungen werden weiter erprobt.** Datenträgerprüfung belegt nicht die Konfiguration jedes bestehenden Workers oder alle vHosts/Container/Angriffspfade. Separate Wegwerf-VM-Tests prüfen echten `/proc`-Discover, Nginx-Zuordnung, PHP-Benutzerrechte, systemd-Fix/Reload, HTTP-Workerwerte und Rollback auf Debian 12/PHP 8.2, Debian 13/PHP 8.4, Ubuntu 22.04/Distributions-PHP 8.1 und Ubuntu 24.04/PHP 8.3. Die FastCGI-Matrix umfasst PHP 8.2–8.5. [Aktuelle Schutzgrenzen](docs/DEFENSES.md) · [2.2.1-Review](docs/REVIEW-2.2.1.md) · [Prüfnachweise](docs/VALIDATION.md) · [Release-Umfang und Abnahmekriterien](docs/PRODUCTION.md).

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
