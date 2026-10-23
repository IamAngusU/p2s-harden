# p2s-harden 2.2.1

Begrenzte PHP/FPM-PrÃ¼fung fÃ¼r Linux mit ausdrÃ¼cklich ausgewiesenem PrÃ¼fumfang.
`OK` ist ein belegter Einzelbefund; `OPEN` ist eine Abweichung oder ein zu
klÃ¤render Schreibpfad; `UNKNOWN` bedeutet, dass die PrÃ¼fung unvollstÃ¤ndig ist.
Es gibt kein pauschales Urteil â€žServer sicherâ€œ.

Zur kurzen Einstiegshilfe: [README auf Deutsch](../README.de.md).

## Start mit einer Datei

Nur `p2s-harden.sh` herunterladen. Die Python-Engine ist darin enthalten.
Keine eigene Konfigurationsdatei und keine Installation des Tools erforderlich.

Unter Windows reicht alternativ die einzelne Datei `p2s-harden.ps1` mit einem
vorhandenen OpenSSH-Client. Auf dem Windows-Rechner sind weder Bash noch Python
nÃ¶tig. Die AusfÃ¼hrung folgt der lokalen PowerShell-Richtlinie:

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

# Fehlende Voraussetzungen und konkrete nÃ¤chste Schritte:
sudo bash p2s-harden.sh --doctor

# Erst das erkannte Inventar ansehen:
sudo bash p2s-harden.sh --discover

# Ã„nderungsvorschlÃ¤ge und begrenzte Fixes:
sudo bash p2s-harden.sh --dry-run
sudo bash p2s-harden.sh --fix
```

StandardmÃ¤ÃŸig wird ausschlieÃŸlich geprÃ¼ft. Ohne Pfadangaben erkennt das Tool
gÃ¤ngige Nginx-Konfigurationen, Includes, literal benannte Domains, HTTP-/HTTPS-
Ports, einfache Location-Roots und Verzeichnis-Aliases. Root-Symlinks, dynamische
Hostnamen/Pfade, widersprÃ¼chliche Zuordnungen und nicht vertrauenswÃ¼rdige Includes
bleiben ausdrÃ¼cklich unbekannt. Andere eindeutig erkannte Sites werden trotzdem
berÃ¼cksichtigt. FPM-Instanzen, Pools, Benutzer und Listener werden ebenfalls
aufgelistet. Die Erkennung lÃ¤uft durch Lesen, ohne Nginx-Module zu laden.

Ãœberlappende Dateisystembereiche werden zusammengefasst. StandardmÃ¤ÃŸig werden
hÃ¶chstens 32 automatische HTTP-Zuordnungen geprÃ¼ft; weitere Zuordnungen werden
als ausgelassen ausgewiesen. `--max-sites` kann das Limit bis 512 erhÃ¶hen.
Domains werden vor verschachtelten Alias-Pfaden priorisiert. IPv4 und IPv6 fÃ¼r
dieselbe URL werden nicht doppelt geprÃ¼ft. Die Ausgabe konzentriert sich auf
offene/unbekannte Punkte; `--verbose` und `--json` liefern sÃ¤mtliche Einzelbefunde.

Dies ist eine Konfigurations- und RechteprÃ¼fung. Sie fÃ¼hrt keine vollstÃ¤ndige
PHP-to-Shell-Angriffssuite aus. Erfolgreiche Tooltests belegen keine allgemeine
UnmÃ¶glichkeit von PHP-to-Shell.

## Dateien und Voraussetzungen

Nur `p2s-harden.sh` wird fÃ¼r die AusfÃ¼hrung benÃ¶tigt. `p2s_harden.py` und die
Build-Vorlage im Entwicklerpaket sind die lesbaren Quellen der eingebetteten
Engine. Der Bash-Launcher benÃ¶tigt auf dem Client Bash und bei Remote-Nutzung OpenSSH;
`SSH_BIN` kann einen anderen SSH-Pfad angeben. Unter Windows wird vorhandenes
Windows-OpenSSH bevorzugt. Interaktive SSH-Aufrufe erlauben die bestehende
Passwortanmeldung; nichtinteraktive Aufrufe bleiben im Batch-Modus.
Der Linux-Kern benÃ¶tigt Python 3.8+ und lesbares `/proc`. Weitere Helfer
werden pro TeilprÃ¼fung erkannt. Ohne `ps` wird direkt `/proc` verwendet. Ohne
`curl` laufen HTTP-PrÃ¼fungen Ã¼ber die Python-Standardbibliothek;
ohne `runuser` werden fremde Benutzer einmal pro Benutzer ausgelassen. Als
nicht-root laufen die lesbaren PrÃ¼fungen weiter. Fehlende systemd-Zuordnung
verhindert automatische INI-Fixes, aber nicht die unterstÃ¼tzte FPM-DatentrÃ¤ger-
prÃ¼fung. Auch ein Fehler in einer FPM-Instanz stoppt andere Instanzen und Module
nicht. Die vollstÃ¤ndige Host-PrÃ¼fung benÃ¶tigt root.

`--doctor` zeigt die FÃ¤higkeiten und Hinweise unabhÃ¤ngig von Webkonfigurationen.
Auch ohne Python listet der Shell-Bootstrap fehlende Helfer auf und erklÃ¤rt den
nÃ¤chsten Schritt; PHP-KonfigurationsprÃ¼fungen kÃ¶nnen erst mit Python laufen.
Es werden keine Pakete automatisch installiert. Bei fehlendem SSH-Zugang wird
eine verstÃ¤ndliche Fehlermeldung ausgegeben. Nach Behebung denselben Befehl
erneut ausfÃ¼hren.
Automatische FPM-Ã„nderungen unterstÃ¼tzen konventionelle Debian/Ubuntu-FPM-INIs
und eindeutig zugeordnete systemd-Dienste. Andere Kontexte bleiben `UNKNOWN`.

Der Python-Code wird Ã¼ber stdin in **einer** SSH-Verbindung ausgefÃ¼hrt.
Es werden weder ControlMaster noch externe IP-Dienste benÃ¶tigt.

## Optionale Eingrenzung und abweichende Setups

`--root` schrÃ¤nkt den Dateisystembereich ein. Explizite `--site`-Angaben ersetzen
die automatische HTTP-Zuordnung; ohne `--root` werden ihre Dokumentwurzeln als
PrÃ¼fbereiche verwendet. `--nginx-config` wÃ¤hlt eine abweichende Hauptkonfiguration.
`--no-auto` deaktiviert die automatische Zuordnung. Ohne erkannten/manuellen
Webroot bleibt `/var/www` ein ausdrÃ¼cklich unvollstÃ¤ndiger Fallback.

```bash
bash p2s-harden.sh --ssh root@SERVER --check \
  --root /var/www/html/MEINE-SITE --web-user www-data \
  --site https://example.org=/var/www/html/MEINE-SITE

bash p2s-harden.sh --ssh root@SERVER --dry-run \
  --root /var/www/html/MEINE-SITE --web-user www-data \
  --site https://example.org=/var/www/html/MEINE-SITE

# Erst nach PrÃ¼fung der angezeigten, konkreten Ã„nderungen:
bash p2s-harden.sh --ssh root@SERVER --fix \
  --root /var/www/html/MEINE-SITE --web-user www-data \
  --site https://example.org=/var/www/html/MEINE-SITE

# Ein ausdrÃ¼cklich gewÃ¤hltes Code-Verzeichnis schÃ¼tzen, ohne Rekursion:
bash p2s-harden.sh --ssh root@SERVER --fix \
  --web-user www-data --protect-dir /var/www/html/MEINE-SITE

bash p2s-harden.sh --ssh root@SERVER --rollback
bash p2s-harden.sh --ssh root@SERVER --rollback --backup-id TRANSAKTIONS-ID
```

`--local` fÃ¼hrt dieselbe Engine direkt auf einem Linux-Server aus. `--site` und
`--web-user` sind wiederholbar. Dokumentwurzeln und Schreibziele mÃ¼ssen absolut
sein. FÃ¼r HTTP und HTTPS kÃ¶nnen getrennte `--site`-Angaben verwendet werden.
URLs dÃ¼rfen keine Zugangsdaten, Query oder Fragmente enthalten. IPv6-SSH-Ziele
wie `root@[::1]` und vorhandene SSH-Hostaliases werden unterstÃ¼tzt.

Exitcodes: `0` alle ausgewiesenen EinzelprÃ¼fungen bestanden, `1` offene Punkte,
`2` unbekannte Punkte, unvollstÃ¤ndige PrÃ¼fung oder technischer Fehler. Ein Fix
kann erfolgreich angewendet sein und trotzdem Exit 1/2 liefern, wenn andere
Befunde verbleiben. `--json` ist in jedem Modus verfÃ¼gbar und enthÃ¤lt
`schema_version: 2`, FÃ¤higkeiten, Befunde, Inventar und den passenden Exitcode.
Phasenhinweise gehen im interaktiven Terminal auf stderr; `--no-progress`
unterdrÃ¼ckt sie. Fehlende FÃ¤higkeiten fÃ¼hren zu unvollstÃ¤ndigen Ergebnissen
(Exit 2), wÃ¤hrend unabhÃ¤ngige TeilprÃ¼fungen zu Ende laufen.
`--discover` fÃ¼hrt ausschlieÃŸlich die Inventarisierung aus.
`--yes`/`-y` geben den Fix-Plan ausdrÃ¼cklich frei. Ohne diese Option fragt ein lokaler
interaktiver Fix Ã¼ber /dev/tty; JSON-Fixes benÃ¶tigen --yes. Nur --no-self-guard bleibt
eine wirkungslose alte KompatibilitÃ¤tsoption.

## Was geprÃ¼ft wird

- Laufende Host-FPM-Master, BinÃ¤rdatei, Hauptkonfiguration, Include-Dateien,
  Haupt-INI, geordnete zusÃ¤tzliche INIs und getrennte Poolabschnitte. Als root
  werden nur vertrauenswÃ¼rdige Konfigurationen mit geschÃ¼tzten Vorfahren geladen.
  Container und nicht eindeutig rekonstruierbare Startkontexte bleiben unbekannt.
- `disable_functions`: globale und Pool-Sperren werden additiv ausgewertet.
  Definierter Mindestumfang: `exec`, `system`, `shell_exec`, `passthru`, `popen`,
  `proc_open`, `pcntl_exec`. Weitere vorhandene Sperren bleiben erhalten.
- `allow_url_include` und `open_basedir`; leere Werte und `/` gelten nicht als
  EinschrÃ¤nkung. `open_basedir` und Pools ersetzen keine Prozessisolation.
- Schreibrechte an PHP-Dateien **und Verzeichnissen**, unter der tatsÃ¤chlichen
  UID und den Gruppen jedes bekannten FPM-Benutzers, einschlieÃŸlich ACL-Wirkung.
  Die PrÃ¼fung unterscheidet nicht automatisch sichere Laufzeitverzeichnisse von
  Ã¼ber HTTP ausfÃ¼hrbaren Schreibpfaden; entsprechende Treffer bleiben sichtbar.
- HTTP auf `/.env`, `/.git/config` und verschachtelte gefundene Git-Pfade jeder
  expliziten Dokumentwurzel, mit lokalem Ziel sowie korrektem Host und TLS-SNI.
  `2xx` wird mit zwei zufÃ¤lligen fehlenden Pfaden verglichen. Gleiche oder
  dynamische Catch-all-Antworten bleiben unbekannt. Inhalte werden nur
  gehasht, nicht im Bericht gespeichert. `401/403/404/410` sind fÃ¼r den jeweiligen Endpunkt geschÃ¼tzt.
  Redirects, Serverfehler, Timeouts und fehlgeschlagene Abfragen sind unbekannt.
- `ptrace_scope`. ImageMagick-Policies erscheinen als `INFO` zur separaten regel-
  und versionsbezogenen PrÃ¼fung; bloÃŸe XML-SchlÃ¼sselwÃ¶rter beweisen nichts.

## Ã„nderungen, Sicherungen und RÃ¼cknahme

`--check`, `--discover` und `--dry-run` schreiben keine Zielkonfiguration, verÃ¤ndern keine
Rechte, erzeugen keine Backups und laden keine Dienste neu. Die Abfragen und
HTTP-Anfragen kÃ¶nnen gewÃ¶hnliche Zugriffs-/Dienstlogs und Dateizugriffszeiten
aktualisieren. Es gibt keinerlei Firewall-, Fail2ban- oder SSH-Ã„nderungen.

`--fix` ergÃ¤nzt ausschlieÃŸlich fehlende Funktionen aus dem genannten
Mindestumfang und setzt ein aktiviertes `allow_url_include` auf `Off`.
`putenv`, `parse_ini_file`, `chmod` usw. werden nicht zusÃ¤tzlich gesperrt.
Gemeinsam genutzte INI-Dateien auÃŸerhalb der jeweiligen FPM-INI-Wurzel werden
nicht automatisch geÃ¤ndert, damit andere SAPIs wie CLI unberÃ¼hrt bleiben.
Auch die sieben Mindestfunktionen kÃ¶nnen Anwendungen betreffen; deshalb den
Trockenlauf und die betroffenen Anwendungen prÃ¼fen. Bestehende weitergehende
Sperren werden vom Tool nicht stillschweigend entfernt.

Dateirechte werden nur fÃ¼r ausdrÃ¼cklich benannte `--protect-dir`-Verzeichnisse
geÃ¤ndert: EigentÃ¼mer root, kein Gruppen-/Other-Schreibrecht, keine Rekursion.
Ein schreibbarer oder ungeschÃ¼tzter Vorfahr verhindert die Ã„nderung. Unterordner,
Uploads und andere Laufzeitdaten behalten ihre Rechte. Das schÃ¼tzt nur den
benannten Knoten; weitere schreibbare Code-Verzeichnisse mÃ¼ssen separat geplant
werden. Es gibt keinen automatischen `.git`-chmod-, ImageMagick- oder Sysctl-Fix.

Pro Ã„nderungslauf entsteht eine eindeutige Transaktion unter
`/root/p2s-harden-backup-v2/<UTC-Zeit>-<Zufall>/`, mit Modus 0700. Jede betroffene
Datei wird einmal gesichert. Das Manifest enthÃ¤lt absolute Ziele, Original- und
Nachher-PrÃ¼fsummen sowie Owner, Gruppe, Modus, Zeiten und erweiterte Attribute.
Dateien werden atomar ersetzt. FPM-Syntax und erwartete neue INI-Werte werden
vor dem Reload geprÃ¼ft; nur die eindeutig zugeordneten Dienste werden geladen.
BenÃ¶tigte Root-, Benutzerwechsel- und DienstfÃ¤higkeiten werden vor Beginn der
geplanten Transaktion geprÃ¼ft. Bei fehlenden Voraussetzungen wird der Fix
gesperrt und der bis dahin erstellte PrÃ¼fbericht trotzdem ausgegeben.
Fehler lÃ¶sen eine RÃ¼cknahme der begonnenen Ã„nderungen aus und werden gemeldet.

Rollback prÃ¼ft zuerst auf zwischenzeitliche Ã„nderungen. Bei Konflikten wird
nichts Ã¼berschrieben. Auch begonnene, unterbrochene Transaktionen kÃ¶nnen zurÃ¼ck-
genommen werden. Ã„ltere flache v1-Backups werden nicht geraten; sie bleiben
erhalten und erfordern eine manuelle Zuordnung. Einen vollstÃ¤ndigen Server-
Snapshot oder Datenbank-Backups ersetzt dieser Mechanismus nicht.

## Grenzen und Tests

Die KonfigurationsprÃ¼fung rekonstruiert einen Zustand vom DatentrÃ¤ger. Sie liest
keine PHP-Werte aus einem bestehenden Webrequest und beweist nicht, dass jeder
laufende Worker genau diese Konfiguration verwendet. `-c`/`-d`-Startparameter,
FastCGI-Overrides, Container, weitere vHosts, Aliases, andere PHP-Endungen und
nicht verfolgte Symlinks kÃ¶nnen zusÃ¤tzliche PrÃ¼fung erfordern. HTTP-Ergebnisse
gelten fÃ¼r die angegebenen lokalen Endpunkte, nicht fÃ¼r vorgeschaltete CDNs.

`test_p2s_harden.py` ist eine isolierte Linux-Regressionssuite. Sie prÃ¼ft unter
anderem falsche Erfolgsmeldungen, Kommentare, Pool-Vererbung, HTTP-Fehler,
Trockenlauf, mehrere Ã„nderungen derselben Datei, ParallelÃ¤nderungen, atomare
Sicherung/RÃ¼cknahme und nichtrekursive Verzeichnisrechte. Aus dem Hauptverzeichnis des vollstÃ¤ndigen Quellpakets starten. Der Teststarter
erstellt und entfernt den geschÃ¼tzten temporÃ¤ren Fixture-Ordner selbst:

```bash
python3 build-standalone.py --check
sudo bash tools/test-linux.sh
```

PrÃ¼fungen mit echten Schreiboperationen verwenden ausschlieÃŸlich Fixture-Dateien.
Ein erfolgreicher Testlauf bedeutet keine vollstÃ¤ndige HÃ¤rtung des Zielservers.

Der zusÃ¤tzliche Erkennungstest deckt unter anderem Quotes, Kommentare,
Includes, Include-Zyklen, Symlinks, Vererbung, Alias-/Root-Unterschiede, mehrere
Domains, Ports, IPv6, mehrdeutige und unvollstÃ¤ndige Konfigurationen sowie die
exakte eingebettete Engine und den SSH-Argumenttransport ab. Rechteziele werden
aus der Erkennung nicht automatisch abgeleitet.

Der Teststarter arbeitet in einem geschÃ¼tzten temporÃ¤ren Fixture-Verzeichnis.
Die ergÃ¤nzende Fehler-Injektionssuite prÃ¼ft fehlende Programme, fehlendes Python,
SSH-Fehler, unvollstÃ¤ndige Benutzerrechte, isolierte FPM-Fehler und gesperrte Fixes.
Der Windows-Test wird mit `powershell -NoProfile -File test-windows-launcher.ps1`
gestartet. [PrÃ¼fumgebungen und verbleibende Grenzen](VALIDATION.md).

## PrÃ¤zisierungen in rc.2

`--lang en` ist Standard; `--lang de` Ã¼bersetzt Befunde, Hilfe und Bootstrap.
`INFO` verÃ¤ndert den Exitcode nicht. ImageMagick bleibt ausdrÃ¼cklich auÃŸerhalb
der automatischen Bewertung. Echte fehlende Abdeckung bleibt `UNKNOWN` und hat
vor `OPEN` Vorrang (Exit 2). VollstÃ¤ndig ausgewertete PrÃ¼fungen kÃ¶nnen Exit 0
oder 1 erreichen.

`--runtime-dir /absoluter/pfad` deklariert einen existierenden, symlinkfreien
Unterordner eines PrÃ¼fbereichs als benÃ¶tigten Laufzeitspeicher. Das ist eine
ausdrÃ¼ckliche Einordnung, keine automatisch erkannte Ausnahme. Schreibbare
PHP-Dateien darin bleiben offen; Zugriffsfehler und Grenzen bleiben unbekannt.
Der gesamte PrÃ¼fbereich kann nicht zum Runtime-Verzeichnis erklÃ¤rt werden.

DateisystemlÃ¤ufe sind standardmÃ¤ÃŸig auf 250000 EintrÃ¤ge und 10 Sekunden begrenzt
(`--max-paths`, `--walk-seconds`), einschlieÃŸlich der Suche nach verschachtelten
Git-Verzeichnissen. HTTP hat insgesamt 128 Anfragen (`--max-http-probes`), pro
Antwort hÃ¶chstens 1 MiB und 8 Sekunden. Zwei zufÃ¤llige fehlende URLs bilden
bei 2xx eine Soft-404-Baseline. Dynamische oder gleiche Fallback-Antworten sind
unbekannt. Weiterleitungen werden nicht verfolgt. Bodies werden nur im Speicher
gestreamt/gehasht und nicht gespeichert oder ausgegeben. Die lokale TLS-PrÃ¼fung
verifiziert Routing/Antwort, nicht die AuthentizitÃ¤t eines Zertifikats.

`--json` funktioniert fÃ¼r jeden Modus. Neben Befunden und Inventar enthÃ¤lt es
`language`, `plan` und `transaction` (je nach Modus auch `null`). Fix-Fehler
bewahren vorherige Befunde und den verfÃ¼gbaren Recovery-Status. Pfade und
technische Werte werden nicht Ã¼bersetzt.

Fixes behalten keine alten Ã„nderungszeitpunkte. Nur Rollback stellt die
ursprÃ¼nglichen Zeitstempel wieder her. Ohne ID wird ausschlieÃŸlich die neueste
Transaktion gewÃ¤hlt. Ist sie zurÃ¼ckgenommen, ist ein weiterer Aufruf ohne
Wirkung; ein Ã¤lterer Fix wird nicht stillschweigend zurÃ¼ckgenommen. Konflikte
bei Inhalt, Owner, Mode, xattrs, IdentitÃ¤t oder mtime verhindern das Ãœberschreiben.
Eine unterbrochene Wiederherstellung ist fortsetzbar.

[Praktische FPM-Nachweise und Korrektur der Review-Vermutung](REVIEW-FOLLOWUP.md).

## Neu in rc.3

Die Vorschau enthÃ¤lt Werte und einen Diff ohne Nachbarzeilen. Seit der Vorschau
verÃ¤nderte Inhalte werden abgelehnt. `--fix --yes --json` ist die explizite
Automatisierungsform. Die SSH-Ãœbertragung verwendet keinen entfernten TTY:
erst `--dry-run`, dann den geprÃ¼ften Fix mit `--yes` ausfÃ¼hren.

Schema 2 enthÃ¤lt stabile Regel-/Ressourcen-IDs, severity, remediation und
suppressed sowie has_open/has_unknown. `--ignore` lÃ¤sst akzeptierte OPEN-Befunde
sichtbar und beeinflusst nur deren Exitwirkung; UNKNOWN besteht weiterhin nie.
`--fail-on open` wertet OPEN vor UNKNOWN aus. Der Standard bleibt UNKNOWN zuerst.
Die englische [vollstÃ¤ndige Anleitung](DETAILS.md) und [RegelÃ¼bersicht](FINDINGS.md)
erlÃ¤utern diese VertrÃ¤ge. Die englische Quellsprache und acht Komponenten in src/
werden vom Builder weiterhin zu eigenstÃ¤ndigen Ein-Datei-Launchern zusammengesetzt.

## Stabile Version 2.2.0

ZusÃ¤tzlich werden TCP-Listener/Client-Freigaben, konfigurierte und tatsÃ¤chliche
Unix-Socket-Rechte, Skript-Endungen, clear_env, gemeinsame numerische UIDs und
geladene FFI-Einstellungen geprÃ¼ft. Netzwerk-Erreichbarkeit und bestehende
Produktions-Worker werden dabei nicht attestiert. Pool- und NetzwerkÃ¤nderungen
bleiben manuell. [Umfang und Abnahme](PRODUCTION.md).

Mit `--check --redact --json` entsteht ein teilbarer Bericht aus einer festen
Auswahl: Regel-ID, Status, Schweregrad, Handlungshinweis und ZÃ¤hler. Private
Hostdaten, Rohdiagnosen, Inventar und Transaktionsdaten entfallen. Befund-IDs
werden fÃ¼r geteilte Berichte neu erzeugt. Exit-Code und Ergebnisse bleiben
erhalten. Auch doctor/discover und Textausgabe werden unterstÃ¼tzt. Fix-Vorschauen
mÃ¼ssen lokal ohne Maskierung geprÃ¼ft werden. Die Maskierung gilt fÃ¼r stdout,
nicht fÃ¼r SSH-/Systemdiagnosen auf stderr.

FPM-Includes sind auf 64 Ebenen, 1024 Dateien, 2 MiB je Datei und 16 MiB insgesamt
begrenzt. Ein erreichtes Limit bleibt UNKNOWN; unabhÃ¤ngige PrÃ¼fungen laufen weiter.

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
