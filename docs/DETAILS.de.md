# p2s-harden 2.2.0-rc.2

Begrenzte PHP/FPM-Prüfung für Linux mit ausdrücklich ausgewiesenem Prüfumfang.
`OK` ist ein belegter Einzelbefund; `OPEN` ist eine Abweichung oder ein zu
klärender Schreibpfad; `UNKNOWN` bedeutet, dass die Prüfung unvollständig ist.
Es gibt kein pauschales Urteil „Server sicher“.

Zur kurzen Einstiegshilfe: [README auf Deutsch](../README.de.md).

## Start mit einer Datei

Nur `p2s-harden.sh` herunterladen. Die Python-Engine ist darin enthalten.
Keine eigene Konfigurationsdatei und keine Installation des Tools erforderlich.

Unter Windows reicht alternativ die einzelne Datei `p2s-harden.ps1` mit einem
vorhandenen OpenSSH-Client. Auf dem Windows-Rechner sind weder Bash noch Python
nötig. Die Ausführung folgt der lokalen PowerShell-Richtlinie:

```powershell
.\p2s-harden.ps1 --ssh root@SERVER
.\p2s-harden.ps1 --ssh root@SERVER --doctor
```

Beide Launcher enthalten exakt dieselbe Python-Engine.

```bash
# Auf dem Linux-Server:
sudo bash p2s-harden.sh

# Oder von deinem Rechner mit vorhandenem SSH-Zugang:
bash p2s-harden.sh --ssh root@SERVER

# Fehlende Voraussetzungen und konkrete nächste Schritte:
sudo bash p2s-harden.sh --doctor

# Erst das erkannte Inventar ansehen:
sudo bash p2s-harden.sh --discover

# Änderungsvorschläge und begrenzte Fixes:
sudo bash p2s-harden.sh --dry-run
sudo bash p2s-harden.sh --fix
```

Standardmäßig wird ausschließlich geprüft. Ohne Pfadangaben erkennt das Tool
gängige Nginx-Konfigurationen, Includes, literal benannte Domains, HTTP-/HTTPS-
Ports, einfache Location-Roots und Verzeichnis-Aliases. Root-Symlinks, dynamische
Hostnamen/Pfade, widersprüchliche Zuordnungen und nicht vertrauenswürdige Includes
bleiben ausdrücklich unbekannt. Andere eindeutig erkannte Sites werden trotzdem
berücksichtigt. FPM-Instanzen, Pools, Benutzer und Listener werden ebenfalls
aufgelistet. Die Erkennung läuft durch Lesen, ohne Nginx-Module zu laden.

Überlappende Dateisystembereiche werden zusammengefasst. Standardmäßig werden
höchstens 32 automatische HTTP-Zuordnungen geprüft; weitere Zuordnungen werden
als ausgelassen ausgewiesen. `--max-sites` kann das Limit bis 512 erhöhen.
Domains werden vor verschachtelten Alias-Pfaden priorisiert. IPv4 und IPv6 für
dieselbe URL werden nicht doppelt geprüft. Die Ausgabe konzentriert sich auf
offene/unbekannte Punkte; `--verbose` und `--json` liefern sämtliche Einzelbefunde.

Dies ist eine Konfigurations- und Rechteprüfung. Sie führt keine vollständige
PHP-to-Shell-Angriffssuite aus. Erfolgreiche Tooltests belegen keine allgemeine
Unmöglichkeit von PHP-to-Shell.

## Dateien und Voraussetzungen

Nur `p2s-harden.sh` wird für die Ausführung benötigt. `p2s_harden.py` und die
Build-Vorlage im Entwicklerpaket sind die lesbaren Quellen der eingebetteten
Engine. Der Bash-Launcher benötigt auf dem Client Bash und bei Remote-Nutzung OpenSSH;
`SSH_BIN` kann einen anderen SSH-Pfad angeben. Unter Windows wird vorhandenes
Windows-OpenSSH bevorzugt. Interaktive SSH-Aufrufe erlauben die bestehende
Passwortanmeldung; nichtinteraktive Aufrufe bleiben im Batch-Modus.
Der Linux-Kern benötigt Python 3.8+ und lesbares `/proc`. Weitere Helfer
werden pro Teilprüfung erkannt. Ohne `ps` wird direkt `/proc` verwendet. Ohne
`curl` laufen HTTP-Prüfungen über die Python-Standardbibliothek;
ohne `runuser` werden fremde Benutzer einmal pro Benutzer ausgelassen. Als
nicht-root laufen die lesbaren Prüfungen weiter. Fehlende systemd-Zuordnung
verhindert automatische INI-Fixes, aber nicht die unterstützte FPM-Datenträger-
prüfung. Auch ein Fehler in einer FPM-Instanz stoppt andere Instanzen und Module
nicht. Die vollständige Host-Prüfung benötigt root.

`--doctor` zeigt die Fähigkeiten und Hinweise unabhängig von Webkonfigurationen.
Auch ohne Python listet der Shell-Bootstrap fehlende Helfer auf und erklärt den
nächsten Schritt; PHP-Konfigurationsprüfungen können erst mit Python laufen.
Es werden keine Pakete automatisch installiert. Bei fehlendem SSH-Zugang wird
eine verständliche Fehlermeldung ausgegeben. Nach Behebung denselben Befehl
erneut ausführen.
Automatische FPM-Änderungen unterstützen konventionelle Debian/Ubuntu-FPM-INIs
und eindeutig zugeordnete systemd-Dienste. Andere Kontexte bleiben `UNKNOWN`.

Der Python-Code wird über stdin in **einer** SSH-Verbindung ausgeführt.
Es werden weder ControlMaster noch externe IP-Dienste benötigt.

## Optionale Eingrenzung und abweichende Setups

`--root` schränkt den Dateisystembereich ein. Explizite `--site`-Angaben ersetzen
die automatische HTTP-Zuordnung; ohne `--root` werden ihre Dokumentwurzeln als
Prüfbereiche verwendet. `--nginx-config` wählt eine abweichende Hauptkonfiguration.
`--no-auto` deaktiviert die automatische Zuordnung. Ohne erkannten/manuellen
Webroot bleibt `/var/www` ein ausdrücklich unvollständiger Fallback.

```bash
bash p2s-harden.sh --ssh root@SERVER --check \
  --root /var/www/html/MEINE-SITE --web-user www-data \
  --site https://example.org=/var/www/html/MEINE-SITE

bash p2s-harden.sh --ssh root@SERVER --dry-run \
  --root /var/www/html/MEINE-SITE --web-user www-data \
  --site https://example.org=/var/www/html/MEINE-SITE

# Erst nach Prüfung der angezeigten, konkreten Änderungen:
bash p2s-harden.sh --ssh root@SERVER --fix \
  --root /var/www/html/MEINE-SITE --web-user www-data \
  --site https://example.org=/var/www/html/MEINE-SITE

# Ein ausdrücklich gewähltes Code-Verzeichnis schützen, ohne Rekursion:
bash p2s-harden.sh --ssh root@SERVER --fix \
  --web-user www-data --protect-dir /var/www/html/MEINE-SITE

bash p2s-harden.sh --ssh root@SERVER --rollback
bash p2s-harden.sh --ssh root@SERVER --rollback --backup-id TRANSAKTIONS-ID
```

`--local` führt dieselbe Engine direkt auf einem Linux-Server aus. `--site` und
`--web-user` sind wiederholbar. Dokumentwurzeln und Schreibziele müssen absolut
sein. Für HTTP und HTTPS können getrennte `--site`-Angaben verwendet werden.
URLs dürfen keine Zugangsdaten, Query oder Fragmente enthalten. IPv6-SSH-Ziele
wie `root@[::1]` und vorhandene SSH-Hostaliases werden unterstützt.

Exitcodes: `0` alle ausgewiesenen Einzelprüfungen bestanden, `1` offene Punkte,
`2` unbekannte Punkte, unvollständige Prüfung oder technischer Fehler. Ein Fix
kann erfolgreich angewendet sein und trotzdem Exit 1/2 liefern, wenn andere
Befunde verbleiben. `--json` ist in jedem Modus verfügbar und enthält
`schema_version: 1`, Fähigkeiten, Befunde, Inventar und den passenden Exitcode.
Phasenhinweise gehen im interaktiven Terminal auf stderr; `--no-progress`
unterdrückt sie. Fehlende Fähigkeiten führen zu unvollständigen Ergebnissen
(Exit 2), während unabhängige Teilprüfungen zu Ende laufen.
`--discover` führt ausschließlich die Inventarisierung aus.
Die alten Optionen `--yes`, `-y` und `--no-self-guard` werden mit Hinweis als
wirkungslose Kompatibilitätsoptionen angenommen.

## Was geprüft wird

- Laufende Host-FPM-Master, Binärdatei, Hauptkonfiguration, Include-Dateien,
  Haupt-INI, geordnete zusätzliche INIs und getrennte Poolabschnitte. Als root
  werden nur vertrauenswürdige Konfigurationen mit geschützten Vorfahren geladen.
  Container und nicht eindeutig rekonstruierbare Startkontexte bleiben unbekannt.
- `disable_functions`: globale und Pool-Sperren werden additiv ausgewertet.
  Definierter Mindestumfang: `exec`, `system`, `shell_exec`, `passthru`, `popen`,
  `proc_open`, `pcntl_exec`. Weitere vorhandene Sperren bleiben erhalten.
- `allow_url_include` und `open_basedir`; leere Werte und `/` gelten nicht als
  Einschränkung. `open_basedir` und Pools ersetzen keine Prozessisolation.
- Schreibrechte an PHP-Dateien **und Verzeichnissen**, unter der tatsächlichen
  UID und den Gruppen jedes bekannten FPM-Benutzers, einschließlich ACL-Wirkung.
  Die Prüfung unterscheidet nicht automatisch sichere Laufzeitverzeichnisse von
  über HTTP ausführbaren Schreibpfaden; entsprechende Treffer bleiben sichtbar.
- HTTP auf `/.env`, `/.git/config` und verschachtelte gefundene Git-Pfade jeder
  expliziten Dokumentwurzel, mit lokalem Ziel sowie korrektem Host und TLS-SNI.
  `2xx` wird mit zwei zufälligen fehlenden Pfaden verglichen. Gleiche oder
  dynamische Catch-all-Antworten bleiben unbekannt. Inhalte werden nur
  gehasht, nicht im Bericht gespeichert. `401/403/404/410` sind für den jeweiligen Endpunkt geschützt.
  Redirects, Serverfehler, Timeouts und fehlgeschlagene Abfragen sind unbekannt.
- `ptrace_scope`. ImageMagick-Policies erscheinen als `INFO` zur separaten regel-
  und versionsbezogenen Prüfung; bloße XML-Schlüsselwörter beweisen nichts.

## Änderungen, Sicherungen und Rücknahme

`--check`, `--discover` und `--dry-run` schreiben keine Zielkonfiguration, verändern keine
Rechte, erzeugen keine Backups und laden keine Dienste neu. Die Abfragen und
HTTP-Anfragen können gewöhnliche Zugriffs-/Dienstlogs und Dateizugriffszeiten
aktualisieren. Es gibt keinerlei Firewall-, Fail2ban- oder SSH-Änderungen.

`--fix` ergänzt ausschließlich fehlende Funktionen aus dem genannten
Mindestumfang und setzt ein aktiviertes `allow_url_include` auf `Off`.
`putenv`, `parse_ini_file`, `chmod` usw. werden nicht zusätzlich gesperrt.
Gemeinsam genutzte INI-Dateien außerhalb der jeweiligen FPM-INI-Wurzel werden
nicht automatisch geändert, damit andere SAPIs wie CLI unberührt bleiben.
Auch die sieben Mindestfunktionen können Anwendungen betreffen; deshalb den
Trockenlauf und die betroffenen Anwendungen prüfen. Bestehende weitergehende
Sperren werden vom Tool nicht stillschweigend entfernt.

Dateirechte werden nur für ausdrücklich benannte `--protect-dir`-Verzeichnisse
geändert: Eigentümer root, kein Gruppen-/Other-Schreibrecht, keine Rekursion.
Ein schreibbarer oder ungeschützter Vorfahr verhindert die Änderung. Unterordner,
Uploads und andere Laufzeitdaten behalten ihre Rechte. Das schützt nur den
benannten Knoten; weitere schreibbare Code-Verzeichnisse müssen separat geplant
werden. Es gibt keinen automatischen `.git`-chmod-, ImageMagick- oder Sysctl-Fix.

Pro Änderungslauf entsteht eine eindeutige Transaktion unter
`/root/p2s-harden-backup-v2/<UTC-Zeit>-<Zufall>/`, mit Modus 0700. Jede betroffene
Datei wird einmal gesichert. Das Manifest enthält absolute Ziele, Original- und
Nachher-Prüfsummen sowie Owner, Gruppe, Modus, Zeiten und erweiterte Attribute.
Dateien werden atomar ersetzt. FPM-Syntax und erwartete neue INI-Werte werden
vor dem Reload geprüft; nur die eindeutig zugeordneten Dienste werden geladen.
Benötigte Root-, Benutzerwechsel- und Dienstfähigkeiten werden vor Beginn der
geplanten Transaktion geprüft. Bei fehlenden Voraussetzungen wird der Fix
gesperrt und der bis dahin erstellte Prüfbericht trotzdem ausgegeben.
Fehler lösen eine Rücknahme der begonnenen Änderungen aus und werden gemeldet.

Rollback prüft zuerst auf zwischenzeitliche Änderungen. Bei Konflikten wird
nichts überschrieben. Auch begonnene, unterbrochene Transaktionen können zurück-
genommen werden. Ältere flache v1-Backups werden nicht geraten; sie bleiben
erhalten und erfordern eine manuelle Zuordnung. Einen vollständigen Server-
Snapshot oder Datenbank-Backups ersetzt dieser Mechanismus nicht.

## Grenzen und Tests

Die Konfigurationsprüfung rekonstruiert einen Zustand vom Datenträger. Sie liest
keine PHP-Werte aus einem bestehenden Webrequest und beweist nicht, dass jeder
laufende Worker genau diese Konfiguration verwendet. `-c`/`-d`-Startparameter,
FastCGI-Overrides, Container, weitere vHosts, Aliases, andere PHP-Endungen und
nicht verfolgte Symlinks können zusätzliche Prüfung erfordern. HTTP-Ergebnisse
gelten für die angegebenen lokalen Endpunkte, nicht für vorgeschaltete CDNs.

`test_p2s_harden.py` ist eine isolierte Linux-Regressionssuite. Sie prüft unter
anderem falsche Erfolgsmeldungen, Kommentare, Pool-Vererbung, HTTP-Fehler,
Trockenlauf, mehrere Änderungen derselben Datei, Paralleländerungen, atomare
Sicherung/Rücknahme und nichtrekursive Verzeichnisrechte. Aus dem Hauptverzeichnis des vollständigen Quellpakets starten. Der Teststarter
erstellt und entfernt den geschützten temporären Fixture-Ordner selbst:

```bash
python3 build-standalone.py --check
sudo bash tools/test-linux.sh
```

Prüfungen mit echten Schreiboperationen verwenden ausschließlich Fixture-Dateien.
Ein erfolgreicher Testlauf bedeutet keine vollständige Härtung des Zielservers.

Der zusätzliche Erkennungstest deckt unter anderem Quotes, Kommentare,
Includes, Include-Zyklen, Symlinks, Vererbung, Alias-/Root-Unterschiede, mehrere
Domains, Ports, IPv6, mehrdeutige und unvollständige Konfigurationen sowie die
exakte eingebettete Engine und den SSH-Argumenttransport ab. Rechteziele werden
aus der Erkennung nicht automatisch abgeleitet.

Der Teststarter arbeitet in einem geschützten temporären Fixture-Verzeichnis.
Die ergänzende Fehler-Injektionssuite prüft fehlende Programme, fehlendes Python,
SSH-Fehler, unvollständige Benutzerrechte, isolierte FPM-Fehler und gesperrte Fixes.
Der Windows-Test wird mit `powershell -NoProfile -File test-windows-launcher.ps1`
gestartet. [Prüfumgebungen und verbleibende Grenzen](VALIDATION.md).

## Präzisierungen in rc.2

`--lang en` ist Standard; `--lang de` übersetzt Befunde, Hilfe und Bootstrap.
`INFO` verändert den Exitcode nicht. ImageMagick bleibt ausdrücklich außerhalb
der automatischen Bewertung. Echte fehlende Abdeckung bleibt `UNKNOWN` und hat
vor `OPEN` Vorrang (Exit 2). Vollständig ausgewertete Prüfungen können Exit 0
oder 1 erreichen.

`--runtime-dir /absoluter/pfad` deklariert einen existierenden, symlinkfreien
Unterordner eines Prüfbereichs als benötigten Laufzeitspeicher. Das ist eine
ausdrückliche Einordnung, keine automatisch erkannte Ausnahme. Schreibbare
PHP-Dateien darin bleiben offen; Zugriffsfehler und Grenzen bleiben unbekannt.
Der gesamte Prüfbereich kann nicht zum Runtime-Verzeichnis erklärt werden.

Dateisystemläufe sind standardmäßig auf 20000 Einträge und 10 Sekunden begrenzt
(`--max-paths`, `--walk-seconds`), einschließlich der Suche nach verschachtelten
Git-Verzeichnissen. HTTP hat insgesamt 128 Anfragen (`--max-http-probes`), pro
Antwort höchstens 1 MiB und 8 Sekunden. Zwei zufällige fehlende URLs bilden
bei 2xx eine Soft-404-Baseline. Dynamische oder gleiche Fallback-Antworten sind
unbekannt. Weiterleitungen werden nicht verfolgt. Bodies werden nur im Speicher
gestreamt/gehasht und nicht gespeichert oder ausgegeben. Die lokale TLS-Prüfung
verifiziert Routing/Antwort, nicht die Authentizität eines Zertifikats.

`--json` funktioniert für jeden Modus. Neben Befunden und Inventar enthält es
`language`, `plan` und `transaction` (je nach Modus auch `null`). Fix-Fehler
bewahren vorherige Befunde und den verfügbaren Recovery-Status. Pfade und
technische Werte werden nicht übersetzt.

Fixes behalten keine alten Änderungszeitpunkte. Nur Rollback stellt die
ursprünglichen Zeitstempel wieder her. Ohne ID wird ausschließlich die neueste
Transaktion gewählt. Ist sie zurückgenommen, ist ein weiterer Aufruf ohne
Wirkung; ein älterer Fix wird nicht stillschweigend zurückgenommen. Konflikte
bei Inhalt, Owner, Mode, xattrs, Identität oder mtime verhindern das Überschreiben.
Eine unterbrochene Wiederherstellung ist fortsetzbar.

[Praktische FPM-Nachweise und Korrektur der Review-Vermutung](REVIEW-FOLLOWUP.md).
