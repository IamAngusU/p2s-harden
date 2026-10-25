# php-fpm-audit: Bedienung und technische Details

Stabile Downloads und die wenigen Startbefehle stehen in der [README](../README.de.md). Dieses Dokument enthält die ausführliche Bedienung. **2.2.2 ist Stable; die zusätzlichen 2.3-Funktionen sind Entwicklungsvorschau.** Skript- und Backup-Namen bleiben kompatibel.

[Ablauf und Prüfumfang](#ablauf-und-prüfumfang) · [JSON/SSH/Rollback](#json-ssh-und-rollback) · [Berichte teilen](#bericht-ohne-private-hostdetails-teilen) · [Häufige Situationen](#häufige-situationen) · [Download prüfen](#download-prüfen) · [FAQ](#faq) · [Entwicklungsvorschau](#entwicklungsvorschau-23)


Begrenzte PHP/FPM-Prüfung für Linux mit ausdrücklich ausgewiesenem Prüfumfang.
`OK` ist ein belegter Einzelbefund; `OPEN` ist eine Abweichung oder ein zu
klärender Schreibpfad; `UNKNOWN` bedeutet, dass die Prüfung unvollständig ist.
Es gibt kein pauschales Urteil â€žServer sicherâ€œ.

Zur kurzen Einstiegshilfe: [README auf Deutsch](../README.de.md).

## Homebrew-Installation

Der [Tap des Maintainers](https://github.com/IamAngusU/homebrew-tap) stellt Stable 2.2.2 für Linux und macOS bereit:

```sh
brew install iamangusu/tap/php-fpm-audit
php-fpm-audit --ssh root@SERVER --lang de
```

macOS dient als SSH-Client; das Audit-Ziel bleibt Linux. Für ein vollständiges lokales Linux-Audit den absoluten installierten Pfad verwenden, damit sudo Homebrew nicht im Suchpfad braucht:

```sh
sudo "$(brew --prefix)/bin/php-fpm-audit" --lang de
```

Vor `--fix` zunächst `--dry-run` prüfen. Für Rollback die ausgegebenen Rollback-Optionen an diesen installierten Befehl übergeben, bei sudo wie oben mit absolutem Pfad. Der bisherige Befehl `p2s-harden.sh` wird ebenfalls installiert.

Updates: `brew update && brew upgrade php-fpm-audit`. Entfernen: `brew uninstall php-fpm-audit`. Die Formel prüft das versionierte Release-Archiv mit SHA-256 und erhält die eingebetteten Launcher-Bytes unverändert. Homebrew stellt Bash und auf Linux Python bereit; entfernte Linux-Ziele brauchen weiterhin selbst Python 3.8+ und lesbares `/proc`. [Paketierungs-CI](https://github.com/angusu-de/homebrew-tap/actions/workflows/ci.yml) läuft auf dem separaten CI-Konto desselben Maintainers.

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
`schema_version: 2`, Fähigkeiten, Befunde, Inventar und den passenden Exitcode.
Phasenhinweise gehen im interaktiven Terminal auf stderr; `--no-progress`
unterdrückt sie. Fehlende Fähigkeiten führen zu unvollständigen Ergebnissen
(Exit 2), während unabhängige Teilprüfungen zu Ende laufen.
`--discover` führt ausschließlich die Inventarisierung aus.
`--yes`/`-y` geben den Fix-Plan ausdrücklich frei. Ohne diese Option fragt ein lokaler
interaktiver Fix über /dev/tty; JSON-Fixes benötigen --yes. Nur --no-self-guard bleibt
eine wirkungslose alte Kompatibilitätsoption.

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

Dateisystemläufe sind standardmäßig auf 250000 Einträge und 10 Sekunden begrenzt
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

## Neu in rc.3

Die Vorschau enthält Werte und einen Diff ohne Nachbarzeilen. Seit der Vorschau
veränderte Inhalte werden abgelehnt. `--fix --yes --json` ist die explizite
Automatisierungsform. Die SSH-Übertragung verwendet keinen entfernten TTY:
erst `--dry-run`, dann den geprüften Fix mit `--yes` ausführen.

Schema 2 enthält stabile Regel-/Ressourcen-IDs, severity, remediation und
suppressed sowie has_open/has_unknown. `--ignore` lässt akzeptierte OPEN-Befunde
sichtbar und beeinflusst nur deren Exitwirkung; In Stable 2.2.2 führt UNKNOWN weiterhin zu einem Fehlercode. Die 2.3-Vorschau erlaubt ausdrücklich geprüfte Nginx-Ausnahmen bei weiterhin sichtbarem UNKNOWN; siehe [Review-Semantik](NGINX-UPLOADS.md#explicit-review-of-unsupported-routing).
`--fail-on open` wertet OPEN vor UNKNOWN aus. Der Standard bleibt UNKNOWN zuerst.
Die englische [vollständige Anleitung](DETAILS.md) und [Regelübersicht](FINDINGS.md)
erläutern diese Verträge. Die englische Quellsprache und Komponenten in src/
werden vom Builder weiterhin zu eigenständigen Ein-Datei-Launchern zusammengesetzt.

## Stabile Version 2.2.0

Zusätzlich werden TCP-Listener/Client-Freigaben, konfigurierte und tatsächliche
Unix-Socket-Rechte, Skript-Endungen, clear_env, gemeinsame numerische UIDs und
geladene FFI-Einstellungen geprüft. Netzwerk-Erreichbarkeit und bestehende
Produktions-Worker werden dabei nicht attestiert. Pool- und Netzwerkänderungen
bleiben manuell. [Umfang und Abnahme](PRODUCTION.md).

Mit `--check --redact --json` entsteht ein teilbarer Bericht aus einer festen
Auswahl: Regel-ID, Status, Schweregrad, Handlungshinweis und Zähler. Private
Hostdaten, Rohdiagnosen, Inventar und Transaktionsdaten entfallen. Befund-IDs
werden für geteilte Berichte neu erzeugt. Exit-Code und Ergebnisse bleiben
erhalten. Auch doctor/discover und Textausgabe werden unterstützt. Fix-Vorschauen
müssen lokal ohne Maskierung geprüft werden. Die Maskierung gilt für stdout,
nicht für SSH-/Systemdiagnosen auf stderr.

FPM-Includes sind auf 64 Ebenen, 1024 Dateien, 2 MiB je Datei und 16 MiB insgesamt
begrenzt. Ein erreichtes Limit bleibt UNKNOWN; unabhängige Prüfungen laufen weiter.

## Änderungen in 2.2.1

Gleiche wirksame Pool-Ergebnisse teilen den globalen Befund. Normales JSON nennt
`affected_pools` und den teilbaren Zähler `evidence.affected_pool_count`.
Abweichungen und explizite unsichere Include-Overrides bleiben eigene Ursachen.
Globale IDs bleiben stabil; redundante Pool-Zeilen und ihre IDs entfallen.

Maskierte Berichte behalten geprüfte technische Fakten: fehlende bekannte
Funktionen, Socket-Modus und Quelle, Schalterzustände, Zähler und HTTP-Status.
Die Felder werden pro Regel nach Typ und erlaubten Werten geprüft; Hostdaten
und beliebige Diagnosetexte bleiben ausgeblendet. Technische API-Schlüssel sind
in beiden Sprachen gleich. localhost braucht eine Loopback-Auflösung mit
Zwei-Sekunden-Limit; Name oder DNS-Konvention allein reichen nicht für OK.

Die Änderung einer paketverwalteten php.ini kann beim späteren Upgrade eine
Konfigurationsrückfrage auslösen, wenn lokale und Paketversion geändert wurden.
Diff prüfen und danach erneut auditieren. Neue Drop-ins bleiben zurückgestellt.
Die Matrix enthält Debian 12/13 und Ubuntu 22.04/24.04 samt echter
JSON-Fix-Verweigerung ohne --yes. [Build-Herkunft prüfen](PROVENANCE.md) und
[aktuelle Review-Antwort](REVIEW-2.2.1.md).


## Parallele Transaktionen und Aufbewahrung (2.2.2 und Vorschau)

Vorbereitung, Anwenden/Reload/Fehlerwiederherstellung und Auswahl/Rücknahme einer Transaktion verwenden eine nicht wartende exklusive Kernel-Sperre auf dem festen root-eigenen Modus-0700-Verzeichnis `/run/p2s-harden`, zusätzlich zur kompatiblen Sperre auf dem Backup-Verzeichnis. Die CLI hält sie über Vorbereitung und Anwendung hinweg. Bei Belegung folgt UNKNOWN mit einem konkreten Hinweis, ohne Zieldateien zu verändern. Keine Sperrdatei oder veraltete PID muss gelöscht werden; Prozessende gibt die Sperre frei. Lesende Audits sperren nicht. Ein anderer `--backup-root` umgeht die Systemsperre nicht. Aktuelle Tool-Instanzen koordinieren sich darüber; externe Editoren/Paketprogramme und ältere Versionen nehmen nicht an der neuen Systemsperre teil. Das Sperrverzeichnis nicht bei aktiven Schreibern entfernen. Hash-/Metadatenprüfungen bleiben wirksam.

Backups werden nicht automatisch bereinigt. Sie enthalten Konfiguration und Metadaten für Rollback. Verzeichnis geschützt halten, Speicherplatz überwachen und nur nicht mehr benötigte Sicherungen nach unabhängiger Prüfung des aktuellen Deployments entfernen. Eine entfernte Sicherung steht für Rollback nicht mehr zur Verfügung.


## INI-Editor-Schutz (2.2.2 und Vorschau)

Mehrzeilige oder ungeschlossene Quotes in einer Ziel-INI werden vor der Bearbeitung verweigert. Einzeilige Quotes/Kommentare bleiben unterstützt; UTF-8-BOM und CRLF werden erhalten, fehlende Zieldirektiven teilen einen neuen PHP-Abschnitt. Vor dem Schreiben werden effektive registrierte INI-Werte des betroffenen FPM erfasst und gehasht; danach werden alle anderen Direktiven vor dem Reload verglichen. Mehrdeutige oder unvollständige Tabellen blockieren den Fix. Abweichungen führen zur Wiederherstellung. Werte und Prozessumgebungen werden nicht im Bericht gespeichert. Je PHP-Version laufen 14 echte Editor-/Parserfälle, einschließlich eines 379M-memory_limit-Testwerts.

## Byte-Ausgabe (nur 2.3-Vorschau)

Schema-2-JSON zeigt gültige Unicode-Pfade; betroffene Pfadobjekte erhalten zusätzlich `path_bytes_hex` und `path_encoding`. Einzelne Surrogat-Escapes entfallen. Baselines prüfen die Übereinstimmung und verwenden die Originalbytes. IDs bleiben am Originalpfad; Redaction entfernt Hexfelder. [Protokoll und Entwürfe](WEBSHELLS.md#reviewed-baselines).

## Ablauf und Prüfumfang

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

`OK`: Einzelprüfung bestanden. `OPEN`: prüfen/beheben. `UNKNOWN`: Ergebnis nicht belegt. `INFO`: Kontext, keine bestandene Sicherheitsprüfung. [Behebung nach Regel-ID](FINDINGS.md).

```bash
sudo bash p2s-harden.sh --doctor --lang de
sudo bash p2s-harden.sh --discover --lang de
```

Ohne ps nutzt die Erkennung `/proc`. HTTP nutzt Python und braucht kein curl. Fehlendes runuser betrifft fremde Benutzer; fehlende Dienstverwaltung sperrt automatische INI-Fixes. Ohne Python erklärt der Bootstrap die Voraussetzung; den Python-Audit kann er dann nicht ausführen.

## JSON, SSH und Rollback

Bei SSH gibt es keinen entfernten Steuer-TTY: zuerst `--dry-run`, danach ausdrücklich `--fix --yes` nutzen. Interaktive lokale Fixes fragen standardmäßig Nein ab. Für geprüfte Automatisierung:

```bash
sudo bash p2s-harden.sh --dry-run --json
sudo bash p2s-harden.sh --fix --yes --json
sudo bash p2s-harden.sh --rollback --backup-id BACKUP_ID --json
```

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
[Geprüftes Audit-Feedback senden](https://github.com/IamAngusU/php-fpm-audit/issues/new?template=audit-feedback.yml).

Die Änderung bestehender INIs kann eine paketverwaltete `php.ini` betreffen. Ändern sich lokale und Paketversion, kann ein späteres Upgrade nach der gewünschten Konfiguration fragen. Diff prüfen und danach erneut auditieren; neue Drop-ins bleiben zurückgestellt. [Upgrade-Verhalten](DETAILS.md#package-upgrades).

## Häufige Situationen

- **Wiederholte globale Einstellungen:** Unveränderte Pool-Ergebnisse teilen den globalen Befund. Normales JSON nennt `affected_pools`; `evidence.affected_pool_count` ist teilbar. Abweichende wirksame Einstellungen und explizite unsichere Include-Overrides bleiben eigene Ursachen.
- **TCP localhost:** Die aktuelle Host-Auflösung hat ein Zwei-Sekunden-Limit. Adressen außerhalb Loopback sind OPEN; fehlgeschlagene Auflösung und andere Hostnamen bleiben UNKNOWN. Das attestiert keinen bestehenden Listener oder Containerdienst.

- **Uploads/Cache:** `--runtime-dir /srv/site/uploads` wiederholen. Schreibbare Verzeichnisse dort werden INFO; schreibbare PHP-Dateien und fehlende Abdeckung bleiben sichtbar. Ausführungssperren separat prüfen.
- **Größere Anwendung:** Das Konfigurationsaudit hat **250000 Einträge und 10 Sekunden je Suchlauf** als Standard. `--max-paths`, `--walk-seconds` oder `--root` anpassen. Abhängigkeiten werden nicht still ausgelassen. HTTP: 128 Anfragen insgesamt, 32 automatische Zuordnungen (`--max-http-probes`, `--max-sites`). Der separate Webshell-Modus nutzt 120 Sekunden je Wurzel und 2 Sekunden je Datei. Erreichte Limits bleiben UNKNOWN.
- **HTTP leitet zu HTTPS weiter:** `--site https://example.org=/srv/site` wählen. Ein Redirect bleibt unbekannt, bis das Ziel geprüft ist; er belegt keinen Zugriffsschutz. Automatische Zuordnungen bevorzugen HTTPS.
- **Abweichendes Layout:** `--nginx-config /pfad/nginx.conf` oder `--root /srv/site --web-user www-data --site https://example.org=/srv/site`. Benutzer und Sites sind wiederholbar.
- **Automatisierung:** Schema 2 enthält `id`, `rule_id`, `resource`, `severity`, `remediation`, `suppressed`, `has_open`, `has_unknown`, `plan` und `transaction`. Übersetzte Texte sind keine API-Kennung. `--verbose` zeigt alle Zeilen.
- **Akzeptierter offener Befund:** `--ignore BEFUND_ID` für eine Ressource oder `--ignore P2S-FS002` für die ganze Regel. Der Befund bleibt sichtbar und markiert. UNKNOWN lässt sich nicht zu einem Erfolg unterdrücken. Die Option betrifft nur die Exitwertung, nicht Fixumfang oder Suchpfade.

In der 2.3-Vorschau bleibt bei ausdrücklich reviewten Nginx-Einträgen UNKNOWN sichtbar; JSON unterscheidet `has_unaccepted_unknown` und `accepted_unknown`. [Review-Semantik](NGINX-UPLOADS.md#explicit-review-of-unsupported-routing). Exit 0 kann deshalb akzeptierte UNKNOWNs enthalten und ist kein Urteil über einen sauberen Server.

Standard (`--fail-on complete`): **2 bei UNKNOWN/Fehler**, sonst **1 bei OPEN**, sonst **0**. Für CI mit Vorrang offener Befunde: `--fail-on open` gibt bei OPEN zuerst 1 aus; andernfalls bleibt UNKNOWN bei 2. Die Vorschau ergänzt `--fail-on review`: Ein nicht akzeptierter WS004-Code-Review oder OPEN ergibt zuerst 1; sonst ergibt UNKNOWN weiterhin 2. Gewöhnliches INFO führt nicht zum Fehlschlag. `--ignore` und exakte Baselines können Review-Befunde akzeptieren; JSON ergänzt `has_review` und `suppressed_review`. JSON zeigt alle Flags und Befunde. Ignorierte OPEN-Befunde bleiben im Bericht, beeinflussen den Exitcode aber nicht.

## Download prüfen

Prüfsummen erkennen Korruption oder unpassende Downloads. Prüfsumme und Datei aus demselben Release belegen allein keine Herkunft. Zusätzlich enthalten Releases **GitHub-signierte Build-Nachweise** für die vier Distributionsdateien, gebaut nach bestandenen Testjobs. Mit optionalem `gh attestation verify` Bytes, Workflow und Quell-Commit prüfen: [Befehle und Vertrauensgrenze](PROVENANCE.md).

Mit angemeldeter GitHub CLI (optional; Bash und PowerShell):

```text
gh attestation verify p2s-harden.sh --repo angusu-de/p2s-harden --signer-workflow angusu-de/p2s-harden/.github/workflows/ci.yml --source-ref refs/heads/release/2.2 --deny-self-hosted-runners
```

Für den Windows-Download `p2s-harden.ps1` einsetzen. `--source-digest ERWARTETER_COMMIT` bindet die Prüfung an den Release-Commit; [Bundle-/Offline-Prüfung](PROVENANCE.md) erklärt das benötigte Vertrauensmaterial. Die CI-Fork gehört demselben Maintainer.

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

Das entfernt die Downloadmarkierung, übersteuert aber weder Restricted noch Organisationsrichtlinien. Das frühere Bypass-Beispiel gilt für diesen Aufruf; erzwungene Organisationsrichtlinien gelten weiter. Prüfsummen erkennen veränderte Downloads. [Lesbare Quellen](../src), [generierte Engine](../p2s_harden.py), [Builder](../build-standalone.py) und CI-Belege zeigen, was die größeren Ein-Datei-Launcher enthalten.

## FAQ

### Behebt das PHP2Shell?

Nein. PHP 8.5.12, 8.4.27, 8.3.36 und 8.2.35 wurden am 21. Oktober 2026 als Fixes für CVE-2026-109618 und CVE-2026-109619 veröffentlicht. Distributionen können Patches zurückportieren; die upstream Versionsnummer allein reicht deshalb nicht. Auch den zusätzlichen Session-Upload-Progress-Hinweis vom 23. Oktober beachten. Maßgeblich sind die [aktuellen PHP-Hinweise](https://www.php.net/archive/2026.php) und die Paketmeldung deiner Distribution. Dieses Audit prüft den Patchstand nicht.

### Verändert der Standardbefehl meinen Server?

Er ändert keine Zielkonfiguration, Rechte oder Dienste. Das Audit liest Dateien und führt begrenzte HTTP-Anfragen aus; normale Logs und Zugriffszeiten können sich ändern. Ausdrücklich angeforderte Review-Drafts schreiben eigene Dateien. Konfigurationsänderungen brauchen `--fix` mit interaktiver Bestätigung oder `--yes`.

### Warum heißen die Dateien weiterhin p2s-harden?

`php-fpm-audit` ist der neue Projekt- und Repository-Name. Die bisherigen Skriptnamen, `P2S-`-IDs und Backup-Pfade bleiben für Kompatibilität erhalten. Die öffentliche CI und der Signier-Workflow liegen weiter unter `angusu-de/p2s-harden`; bei der [Herkunftsprüfung](PROVENANCE.md) die erwartete Signiereridentität beibehalten.

## Entwicklungsvorschau 2.3

Stable **2.2.2** enthält den korrigierten INI-Editor und die Transaktionssperre. Die zusätzlichen Webshell-, verbleibenden Policy-, systemd- und neuen Upload-Routenprüfungen gehören zur **2.3.0-dev.7-Vorschau** auf main. Die Stable-Dateien enthalten diese Erweiterungen nicht.

[Bash-Vorschau](../p2s-harden.sh?raw=1) · [PowerShell-Vorschau](../p2s-harden.ps1?raw=1).

Webshell-Indikatoren lokal oder per SSH prüfen:

```bash
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --lang de
```

```powershell
.\p2s-harden.ps1 --ssh root@SERVER --scan-webshells --root /srv/site --lang de
```

Eine begrenzte statische Suche, kein Malware-Freibrief: keine Proben werden ausgeführt, hochgeladen oder entfernt. Treffer brauchen Prüfung; keine Treffer belegen keinen sauberen Server. [Regeln, Budgets, Maskierung und Baselines](WEBSHELLS.md).

Upload-Routen mit der Vorschau lesend prüfen:

```bash
sudo bash p2s-harden.sh --check --root /srv/site \
  --nginx-config /etc/nginx/nginx.conf --runtime-dir /srv/site/uploads
```

Eine verbreitete `.*`-Upload-Sperre kann Dateinamen mit Zeilenumbruch übersehen, sofern solche Dateien im ausführbaren Upload-Pfad entstehen können. Das optionale Docker-Labor reproduziert den Fall mit harmlosen Markern, ohne Host-Pfade einzubinden oder Ports zu veröffentlichen. [Regeln und Grenzen](NGINX-UPLOADS.md) · [Labor nachstellen](UPLOAD-GUARD-LAB.md) · [Schutzmodell](DEFENSES.md). Das normale Audit erstellt keine Upload-Marker und ändert keine Nginx-Konfiguration.

## Prüfnachweise und Mitwirkung

[Release-Grenzen](PRODUCTION.md) · [Validierung](VALIDATION.md) · [Stable-CI](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md) · [Entwicklungs-CI](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md) · [CI-Verfahren](CI.md) · [Mitwirken](../CONTRIBUTING.md).

Die CI gehört demselben Maintainer; sie ist kein unabhängiges Audit. Wegwerf-VMs prüfen ihre Testsysteme, nicht deinen Server. Destruktive Systemtests gehören ausschließlich in ausdrücklich markierte Wegwerf-VMs.
