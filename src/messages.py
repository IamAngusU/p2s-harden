# The audit keeps canonical findings so tests, fix decisions and stored state do
# not depend on the display language. Translate complete messages only: captured
# paths, URLs, users and function names are opaque and must stay byte-for-byte.
# A {message} capture is the one exception, for a nested diagnostic we own.
_MESSAGES = {'Invalid backup manifest: {name}': ('Invalid backup manifest: {name}', 'Ungültiges Backup-Manifest: {name}'),
 'available': ('available', 'verfügbar'),
 'unknown': ('unknown', 'unbekannt'),
 'Permissions': ('Permissions', 'Berechtigungen'),
 'Automatic INI fixes': ('Automatic INI fixes', 'Automatische INI-Fixes'),
 'FPM process discovery': ('FPM process discovery', 'FPM-Prozesserkennung'),
 'Automatic discovery': ('Automatic discovery', 'Automatische Erkennung'),
 'FPM coverage': ('FPM coverage', 'FPM-Abdeckung'),
 'File permissions': ('File permissions', 'Dateirechte'),
 'FPM user': ('FPM user', 'FPM-Benutzer'),
 'HTTP coverage': ('HTTP coverage', 'HTTP-Abdeckung'),
 'HTTP configuration': ('HTTP configuration', 'HTTP-Konfiguration'),
 'Git path coverage': ('Git path coverage', 'Git-Pfadabdeckung'),
 'ImageMagick policy': ('ImageMagick policy', 'ImageMagick-Regeln'),
 'Automatic INI fix skipped': ('Automatic INI fix skipped', 'Automatischer INI-Fix ausgespart'),
 'Fix blocked': ('Fix blocked', 'Fix gesperrt'),
 'Execution': ('Execution', 'Ausführung'),
 'Prerequisites': ('Prerequisites', 'Voraussetzungen'),
 'Bounded PHP/FPM checks; UNKNOWN means an incomplete check.': ('Bounded PHP/FPM checks; UNKNOWN means an '
                                                                'incomplete check.',
                                                                'Begrenzte PHP/FPM-Prüfung; UNKNOWN bedeutet eine '
                                                                'unvollständige Prüfung.'),
 'Audit scope (default: discovered document roots)': ('Audit scope (default: discovered document roots)',
                                                      'Prüfbereich (Standard: erkannte Webroots)'),
 'Custom Nginx main configuration': ('Custom Nginx main configuration', 'Abweichende Nginx-Hauptkonfiguration'),
 'Disable automatic document-root/domain discovery': ('Disable automatic document-root/domain discovery',
                                                      'Automatische Webroot-/Domain-Erkennung deaktivieren'),
 'Maximum automatic HTTP mappings (default 32)': ('Maximum automatic HTTP mappings (default 32)',
                                                  'Maximale automatische HTTP-Zuordnungen (Standard 32)'),
 'Maximum entries per filesystem walk (default 250000)': ('Maximum entries per filesystem walk (default 250000)',
                                                          'Maximale Einträge pro Dateisystem-Suchlauf (Standard '
                                                          '250000)'),
 'Seconds per filesystem walk (default 10)': ('Seconds per filesystem walk (default 10)',
                                              'Sekunden pro Dateisystem-Suchlauf (Standard 10)'),
 'Total HTTP request budget (default 128)': ('Total HTTP request budget (default 128)',
                                             'Gesamtlimit für HTTP-Anfragen (Standard 128)'),
 'Declare writable runtime storage inside selected roots; repeatable': ('Declare writable runtime storage inside '
                                                                        'selected roots; repeatable',
                                                                        'Schreibbaren Laufzeitspeicher innerhalb '
                                                                        'der ausgewählten Wurzeln deklarieren; '
                                                                        'wiederholbar'),
 'Transfer explicit directory ownership to root; non-recursive': ('Transfer explicit directory ownership to root; '
                                                                  'non-recursive',
                                                                  'Explizites Verzeichnis an root übertragen; '
                                                                  'nicht rekursiv'),
 'Show all findings, including OK': ('Show all findings, including OK',
                                     'Alle Einzelbefunde einschließlich OK ausgeben'),
 'Hide interactive progress messages': ('Hide interactive progress messages',
                                        'Phasenhinweise im interaktiven Terminal ausblenden'),
 'Write progress to stderr even without a TTY': ('Write progress to stderr even without a TTY',
                                                 'Phasenhinweise auch ohne TTY auf stderr ausgeben'),
 '--max-paths must be between 1 and 1000000': ('--max-paths must be between 1 and 1000000',
                                               '--max-paths muss zwischen 1 und 1000000 liegen'),
 '--walk-seconds must be between 0.05 and 120': ('--walk-seconds must be between 0.05 and 120',
                                                 '--walk-seconds muss zwischen 0.05 und 120 liegen'),
 '--max-http-probes must be between 1 and 4096': ('--max-http-probes must be between 1 and 4096',
                                                  '--max-http-probes muss zwischen 1 und 4096 liegen'),
 'Latest transaction already restored; no changes made': ('Latest transaction already restored; no changes made',
                                                          'Neueste Transaktion bereits wiederhergestellt; keine '
                                                          'Änderungen vorgenommen'),
 'Selected transaction restored': ('Selected transaction restored', 'Ausgewählte Transaktion wiederhergestellt'),
 'Incomplete HTTP response': ('Incomplete HTTP response', 'Unvollständige HTTP-Antwort'),
 'HTTP backend': ('HTTP backend', 'HTTP-Verbindung'),
 'Python standard library; curl is optional, response bodies are not saved': ('Python standard library; curl is '
                                                                              'optional, response bodies are not '
                                                                              'saved',
                                                                              'Python-Standardbibliothek; curl '
                                                                              'ist optional, Antwortinhalte '
                                                                              'werden nicht gespeichert'),
 'Invalid HTTP status': ('Invalid HTTP status', 'Ungültiger HTTP-Status'),
 'HTTP response time budget exceeded': ('HTTP response time budget exceeded',
                                        'Zeitlimit für HTTP-Antwort überschritten'),
 'HTTP response byte budget exceeded': ('HTTP response byte budget exceeded',
                                        'Größenlimit für HTTP-Antwort überschritten'),
 'HTTP probe budget reached; use --max-http-probes or narrow --site': ('HTTP probe budget reached; use '
                                                                       '--max-http-probes or narrow --site',
                                                                       'HTTP-Anfragelimit erreicht; '
                                                                       '--max-http-probes anpassen oder --site '
                                                                       'eingrenzen'),
 'Git discovery budget reached; use --max-paths/--walk-seconds or narrow --root': ('Git discovery budget reached; '
                                                                                   'use '
                                                                                   '--max-paths/--walk-seconds or '
                                                                                   'narrow --root',
                                                                                   'Limit der Git-Pfadsuche '
                                                                                   'erreicht; '
                                                                                   '--max-paths/--walk-seconds '
                                                                                   'anpassen oder --root '
                                                                                   'eingrenzen'),
 'Git endpoint budget reached; narrow --root': ('Git endpoint budget reached; narrow --root',
                                                'Limit der Git-Endpunkte erreicht; --root eingrenzen'),
 'Filesystem time budget reached; use --walk-seconds or narrow --root': ('Filesystem time budget reached; use '
                                                                         '--walk-seconds or narrow --root',
                                                                         'Zeitlimit der Dateisystemsuche '
                                                                         'erreicht; --walk-seconds anpassen oder '
                                                                         '--root eingrenzen'),
 'Filesystem discovery budget reached; use --max-paths/--walk-seconds or narrow --root': ('Filesystem discovery '
                                                                                          'budget reached; use '
                                                                                          '--max-paths/--walk-seconds '
                                                                                          'or narrow --root',
                                                                                          'Limit der '
                                                                                          'Dateisystemsuche '
                                                                                          'erreicht; '
                                                                                          '--max-paths/--walk-seconds '
                                                                                          'anpassen oder --root '
                                                                                          'eingrenzen'),
 'Not assessed automatically; review rules and delegates separately': ('Not assessed automatically; review rules '
                                                                       'and delegates separately',
                                                                       'Nicht automatisch bewertet; Regeln und '
                                                                       'Delegates gesondert prüfen'),
 'No v2 backup found; legacy flat backups are never guessed': ('No v2 backup found; legacy flat backups are never '
                                                               'guessed',
                                                               'Kein v2-Backup gefunden; alte flache Backups '
                                                               'werden nicht geraten'),
 'Rollback conflict in directory permissions or timestamps': ('Rollback conflict in directory permissions or '
                                                              'timestamps',
                                                              'Rollback-Konflikt bei Verzeichnisrechten oder '
                                                              'Zeitstempel'),
 'Multiple backups in the same second; select one explicitly with --backup-id': ('Multiple backups in the same '
                                                                                 'second; select one explicitly '
                                                                                 'with --backup-id',
                                                                                 'Mehrere Backups in derselben '
                                                                                 'Sekunde; eindeutige Auswahl mit '
                                                                                 '--backup-id erforderlich'),
 'Discovered inventory': ('Discovered inventory', 'Erkanntes Inventar'),
 'Configuration audit': ('Configuration audit', 'Konfigurationsprüfung'),
 'A Linux target with readable /proc is required; use --ssh from Windows/macOS': ('A Linux target with readable '
                                                                                  '/proc is required; use --ssh '
                                                                                  'from Windows/macOS',
                                                                                  'Linux-Ziel mit lesbarem /proc '
                                                                                  'erforderlich; von '
                                                                                  'Windows/macOS --ssh verwenden'),
 'root: full host audit available': ('root: full host audit available', 'root: vollständige Host-Prüfung möglich'),
 'Readable checks continue; use sudo/root to check other FPM users and apply fixes': ('Readable checks continue; '
                                                                                      'use sudo/root to check '
                                                                                      'other FPM users and apply '
                                                                                      'fixes',
                                                                                      'Lesbare Teilprüfungen '
                                                                                      'laufen; für fremde '
                                                                                      'FPM-Benutzer und Fixes '
                                                                                      'sudo/root verwenden'),
 'ps available': ('ps available', 'ps verfügbar'),
 'ps missing; using the /proc fallback (no installation needed)': ('ps missing; using the /proc fallback (no '
                                                                   'installation needed)',
                                                                   'ps fehlt; /proc-Fallback wird verwendet '
                                                                   '(keine Installation nötig)'),
 'The systemd service mapping can be verified': ('The systemd service mapping can be verified',
                                                 'systemd-Dienstzuordnung kann geprüft werden'),
 'systemd/systemctl is missing or inactive; the audit continues, automatic INI fixes are blocked': ('systemd/systemctl '
                                                                                                    'is missing '
                                                                                                    'or inactive; '
                                                                                                    'the audit '
                                                                                                    'continues, '
                                                                                                    'automatic '
                                                                                                    'INI fixes '
                                                                                                    'are blocked',
                                                                                                    'systemd/systemctl '
                                                                                                    'fehlt oder '
                                                                                                    'ist nicht '
                                                                                                    'aktiv; Audit '
                                                                                                    'läuft, '
                                                                                                    'automatische '
                                                                                                    'INI-Fixes '
                                                                                                    'gesperrt'),
 'FPM discovery: /proc is unreadable; other checks continue': ('FPM discovery: /proc is unreadable; other checks '
                                                               'continue',
                                                               'FPM-Erkennung: /proc nicht lesbar; andere Module '
                                                               'laufen weiter'),
 'Some FPM processes cannot be read; use sudo/root': ('Some FPM processes cannot be read; use sudo/root',
                                                      'FPM-Prozesserkennung teilweise ohne Leserecht; sudo/root '
                                                      'verwenden'),
 'Cannot parse the FPM pool dump': ('Cannot parse the FPM pool dump', 'FPM-Pool-Dump nicht auswertbar'),
 'Conditional PATH/HOST INI sections: automatic changes refused': ('Conditional PATH/HOST INI sections: automatic '
                                                                   'changes refused',
                                                                   'Bedingte PATH/HOST-INI: automatische Änderung '
                                                                   'abgelehnt'),
 'Custom INI context: a separate runtime check is required': ('Custom INI context: a separate runtime check is '
                                                              'required',
                                                              'Abweichender INI-Kontext: separate Laufzeitprüfung '
                                                              'erforderlich'),
 'INI context differs from the expected FPM context': ('INI context differs from the expected FPM context',
                                                       'INI-Kontext weicht vom erwarteten FPM-Kontext ab'),
 'INI scan directory differs from the expected FPM context': ('INI scan directory differs from the expected FPM '
                                                              'context',
                                                              'INI-Scan-Verzeichnis weicht vom erwarteten '
                                                              'FPM-Kontext ab'),
 'No running FPM master found': ('No running FPM master found', 'Kein laufender FPM-Master gefunden'),
 'A relative FPM include requires a manual context check': ('A relative FPM include requires a manual context '
                                                            'check',
                                                            'Relativer FPM-Include erfordert manuelle '
                                                            'Kontextprüfung'),
 'An HTTP(S) URL without credentials is required': ('An HTTP(S) URL without credentials is required',
                                                    'HTTP(S)-URL ohne Zugangsdaten erforderlich'),
 'No valid HTTP status received': ('No valid HTTP status received', 'Kein gültiger HTTP-Status'),
 'Nginx: incomplete escape sequence': ('Nginx: incomplete escape sequence', 'Nginx: unvollständiges Escape'),
 'Nginx: incomplete variable': ('Nginx: incomplete variable', 'Nginx: unvollständige Variable'),
 'Nginx: token limit reached': ('Nginx: token limit reached', 'Nginx: Tokenlimit erreicht'),
 'Nginx: unterminated string': ('Nginx: unterminated string', 'Nginx: nicht abgeschlossene Zeichenkette'),
 'Nginx: nesting limit reached': ('Nginx: nesting limit reached', 'Nginx: Verschachtelungslimit erreicht'),
 'Nginx: unexpected block end': ('Nginx: unexpected block end', 'Nginx: unerwartetes Blockende'),
 'Nginx: missing block end': ('Nginx: missing block end', 'Nginx: fehlendes Blockende'),
 'Nginx: configuration file too large or not a regular file': ('Nginx: configuration file too large or not a '
                                                               'regular file',
                                                               'Nginx: Konfigurationsdatei zu groß oder kein '
                                                               'regulärer Dateityp'),
 'Nginx: read limit reached': ('Nginx: read limit reached', 'Nginx: Leselimit erreicht'),
 'Nginx: dynamic or invalid include': ('Nginx: dynamic or invalid include',
                                       'Nginx: dynamischer oder ungültiger Include'),
 'Nginx: expansion limit reached': ('Nginx: expansion limit reached', 'Nginx: Expansionslimit erreicht'),
 'No unique Nginx main configuration; specify --nginx-config or --site/--root': ('No unique Nginx main '
                                                                                 'configuration; specify '
                                                                                 '--nginx-config or --site/--root',
                                                                                 'Keine eindeutige '
                                                                                 'Nginx-Hauptkonfiguration; '
                                                                                 '--nginx-config oder '
                                                                                 '--site/--root angeben'),
 'No unique document root; /var/www is only an explicitly reported filesystem fallback': ('No unique document '
                                                                                          'root; /var/www is only '
                                                                                          'an explicitly reported '
                                                                                          'filesystem fallback',
                                                                                          'Kein eindeutiger '
                                                                                          'Webroot; /var/www '
                                                                                          'dient nur als '
                                                                                          'ausgewiesener '
                                                                                          'Dateisystem-Fallback'),
 'No permission-change targets inferred from discovery': ('No permission-change targets inferred from discovery',
                                                          'Keine Rechteziele aus Erkennung abgeleitet'),
 'Value missing': ('Value missing', 'Wert fehlt'),
 'The 7 selected shell functions are disabled': ('The 7 selected shell functions are disabled',
                                                 '7 definierte Shell-Funktionen gesperrt'),
 'Global and pool restrictions evaluated together': ('Global and pool restrictions evaluated together',
                                                     'Globale und Pool-Sperren zusammen ausgewertet'),
 'Unrestricted': ('Unrestricted', 'Nicht einschränkend'),
 'Conflicting INI values across FPM instances': ('Conflicting INI values across FPM instances',
                                                 'Widersprüchliche INI-Werte mehrerer Instanzen'),
 'No verified FPM user; specify --web-user': ('No verified FPM user; specify --web-user',
                                              'Kein geprüfter FPM-Benutzer; --web-user erforderlich'),
 'Cannot check another UID; use sudo/root. Other checks continue.': ('Cannot check another UID; use sudo/root. '
                                                                     'Other checks continue.',
                                                                     'Fremde UID nicht prüfbar; sudo/root '
                                                                     'verwenden. Andere Module laufen weiter.'),
 'User does not exist on this host; correct --web-user or audit the container separately': ('User does not exist '
                                                                                            'on this host; '
                                                                                            'correct --web-user '
                                                                                            'or audit the '
                                                                                            'container separately',
                                                                                            'Benutzer existiert '
                                                                                            'nicht auf diesem '
                                                                                            'Host; --web-user '
                                                                                            'korrigieren oder '
                                                                                            'Container separat '
                                                                                            'prüfen'),
 'No --site URL=DOCUMENT_ROOT specified': ('No --site URL=DOCUMENT_ROOT specified',
                                           'Keine --site URL=DOKUMENTWURZEL angegeben'),
 '--site requires an HTTP(S) base URL without query, fragment or credentials': ('--site requires an HTTP(S) base '
                                                                                'URL without query, fragment or '
                                                                                'credentials',
                                                                                '--site benötigt '
                                                                                'HTTP(S)-Basis-URL ohne Query, '
                                                                                'Fragment oder Zugangsdaten'),
 'Document root is missing or relative': ('Document root is missing or relative',
                                          'Dokumentwurzel fehlt oder ist relativ'),
 'Unreadable': ('Unreadable', 'Nicht lesbar'),
 'No known policy found; module/container coverage remains unverified': ('No known policy found; module/container '
                                                                         'coverage remains unverified',
                                                                         'Keine bekannte Policy; '
                                                                         'Modul-/Container-Abdeckung offen'),
 'FPM master changed; reload cancelled': ('FPM master changed; reload cancelled',
                                          'FPM-Master hat gewechselt; Reload abgebrochen'),
 'Service and FPM master do not match': ('Service and FPM master do not match',
                                         'Dienst und FPM-Master stimmen nicht überein'),
 'FPM master and service no longer match': ('FPM master and service no longer match',
                                            'FPM-Master und Dienst stimmen nicht mehr überein'),
 'Changes require root; use sudo or --ssh root@SERVER': ('Changes require root; use sudo or --ssh root@SERVER',
                                                         'Änderungen erfordern root; sudo oder --ssh root@SERVER '
                                                         'verwenden'),
 'Not all INI changes have a complete FPM mapping': ('Not all INI changes have a complete FPM mapping',
                                                     'Keine vollständige FPM-Zuordnung für alle INI-Änderungen'),
 'A verified systemd reload is unavailable for some affected FPM instances; INI fixes are blocked, the audit continues': ('A '
                                                                                                                          'verified '
                                                                                                                          'systemd '
                                                                                                                          'reload '
                                                                                                                          'is '
                                                                                                                          'unavailable '
                                                                                                                          'for '
                                                                                                                          'some '
                                                                                                                          'affected '
                                                                                                                          'FPM '
                                                                                                                          'instances; '
                                                                                                                          'INI '
                                                                                                                          'fixes '
                                                                                                                          'are '
                                                                                                                          'blocked, '
                                                                                                                          'the '
                                                                                                                          'audit '
                                                                                                                          'continues',
                                                                                                                          'Kein '
                                                                                                                          'geprüfter '
                                                                                                                          'systemd-Reload '
                                                                                                                          'für '
                                                                                                                          'alle '
                                                                                                                          'betroffenen '
                                                                                                                          'FPM-Instanzen; '
                                                                                                                          'INI-Fixes '
                                                                                                                          'gesperrt, '
                                                                                                                          'Audit '
                                                                                                                          'weiterhin '
                                                                                                                          'möglich'),
 '--protect-dir requires a discovered or explicit --web-user for verification': ('--protect-dir requires a '
                                                                                 'discovered or explicit '
                                                                                 '--web-user for verification',
                                                                                 '--protect-dir erfordert einen '
                                                                                 'erkannten oder expliziten '
                                                                                 '--web-user zur Verifikation'),
 'Changes and rollback require root': ('Changes and rollback require root',
                                       'Änderungen und Rollback erfordern root'),
 'Backup directory must be absolute': ('Backup directory must be absolute',
                                       'Backup-Verzeichnis muss absolut sein'),
 'Backup directory must have mode 0700': ('Backup directory must have mode 0700',
                                          'Backup-Verzeichnis muss Modus 0700 haben'),
 'No verified FPM service for INI changes': ('No verified FPM service for INI changes',
                                             'Kein geprüfter FPM-Dienst für INI-Änderungen'),
 '--protect-dir requires an existing absolute directory': ('--protect-dir requires an existing absolute directory',
                                                           '--protect-dir braucht ein bestehendes absolutes '
                                                           'Verzeichnis'),
 'Symlink in --protect-dir refused': ('Symlink in --protect-dir refused', 'Symlink in --protect-dir abgelehnt'),
 'Configuration changed since preflight': ('Configuration changed since preflight',
                                           'Konfiguration wurde zwischenzeitlich geändert'),
 'Directory changed since preflight': ('Directory changed since preflight',
                                       'Verzeichnis wurde zwischenzeitlich geändert'),
 'Directory identity changed': ('Directory identity changed', 'Verzeichnisidentität hat gewechselt'),
 'Expected PHP settings did not take effect': ('Expected PHP settings did not take effect',
                                               'Erwartete PHP-Einstellungen greifen nicht'),
 'Rollback directory was replaced': ('Rollback directory was replaced', 'Rollback-Verzeichnis wurde ersetzt'),
 'Rollback conflict in directory permissions': ('Rollback conflict in directory permissions',
                                                'Rollback-Konflikt bei Verzeichnisrechten'),
 'Rollback conflict in partially changed directory permissions': ('Rollback conflict in partially changed '
                                                                  'directory permissions',
                                                                  'Rollback-Konflikt bei begonnenen '
                                                                  'Verzeichnisrechten'),
 'Rollback conflict in directory ACL': ('Rollback conflict in directory ACL',
                                        'Rollback-Konflikt bei Verzeichnis-ACL'),
 'Files restored; FPM service is stopped (manual rollback never starts a service automatically)': ('Files '
                                                                                                   'restored; FPM '
                                                                                                   'service is '
                                                                                                   'stopped '
                                                                                                   '(manual '
                                                                                                   'rollback '
                                                                                                   'never starts '
                                                                                                   'a service '
                                                                                                   'automatically)',
                                                                                                   'Dateien '
                                                                                                   'wiederhergestellt; '
                                                                                                   'FPM-Dienst '
                                                                                                   'ist gestoppt '
                                                                                                   '(kein '
                                                                                                   'automatischer '
                                                                                                   'Start beim '
                                                                                                   'manuellen '
                                                                                                   'Rollback)'),
 'Invalid backup ID': ('Invalid backup ID', 'Ungültige Backup-ID'),
 'No applied v2 backup found; legacy flat backups are never guessed': ('No applied v2 backup found; legacy flat '
                                                                       'backups are never guessed',
                                                                       'Kein angewendetes v2-Backup gefunden; '
                                                                       'alte flache Backups werden nicht geraten'),
 'A Linux target with /proc is required; use --ssh root@SERVER from Windows/macOS': ('A Linux target with /proc '
                                                                                     'is required; use --ssh '
                                                                                     'root@SERVER from '
                                                                                     'Windows/macOS',
                                                                                     'Linux-Ziel mit /proc '
                                                                                     'erforderlich; unter '
                                                                                     'Windows/macOS --ssh '
                                                                                     'root@SERVER verwenden'),
 '--root must be absolute': ('--root must be absolute', '--root muss absolut sein'),
 '--max-sites must be between 1 and 512': ('--max-sites must be between 1 and 512',
                                           '--max-sites muss zwischen 1 und 512 liegen'),
 'Changes require root: sudo bash p2s-harden.sh --fix or --ssh root@SERVER': ('Changes require root: sudo bash '
                                                                              'p2s-harden.sh --fix or --ssh '
                                                                              'root@SERVER',
                                                                              'Änderungen erfordern root: sudo '
                                                                              'bash p2s-harden.sh --fix oder '
                                                                              '--ssh root@SERVER'),
 '--json supports --check, --doctor and --discover; omit --json for this mode': ('--json supports --check, '
                                                                                 '--doctor and --discover; omit '
                                                                                 '--json for this mode',
                                                                                 '--json unterstützt --check, '
                                                                                 '--doctor und --discover; für '
                                                                                 'diesen Modus --json weglassen'),
 'HTTP, ImageMagick, runtime and writable-storage findings require individual review; they are not changed automatically.': ('HTTP, '
                                                                                                                             'ImageMagick, '
                                                                                                                             'runtime '
                                                                                                                             'and '
                                                                                                                             'writable-storage '
                                                                                                                             'findings '
                                                                                                                             'require '
                                                                                                                             'individual '
                                                                                                                             'review; '
                                                                                                                             'they '
                                                                                                                             'are '
                                                                                                                             'not '
                                                                                                                             'changed '
                                                                                                                             'automatically.',
                                                                                                                             'Offene '
                                                                                                                             'HTTP-/ImageMagick-/Laufzeit-/Speicherpfad-Befunde '
                                                                                                                             'werden '
                                                                                                                             'nicht '
                                                                                                                             'pauschal '
                                                                                                                             'verändert.'),
 'Discovering Nginx mappings and audit paths': ('Discovering Nginx mappings and audit paths',
                                                'Nginx-Zuordnungen und Prüfpfade erkennen'),
 'Discovering FPM instances and pools': ('Discovering FPM instances and pools',
                                         'FPM-Instanzen und Pools erkennen'),
 'Checking file permissions as the discovered FPM users': ('Checking file permissions as the discovered FPM users',
                                                           'Dateirechte unter den erkannten FPM-Benutzern prüfen'),
 'Checking HTTP endpoints and other host settings': ('Checking HTTP endpoints and other host settings',
                                                     'HTTP-Endpunkte und weitere Host-Einstellungen prüfen'),
 'runuser missing; ': ('runuser missing; ', 'runuser fehlt; '),
 'Apply this displayed plan? [y/N] ': ('Apply this displayed plan? [y/N] ',
                                       'Diesen angezeigten Plan anwenden? [j/N] '),
 'Review --dry-run --json first; --fix --json requires --yes': ('Review --dry-run --json first; --fix --json '
                                                                'requires --yes',
                                                                'Zuerst --dry-run --json prüfen; --fix --json '
                                                                'erfordert --yes'),
 'No controlling terminal; review --dry-run first, then use --fix --yes': ('No controlling terminal; review '
                                                                           '--dry-run first, then use --fix --yes',
                                                                           'Kein steuerndes Terminal; zuerst '
                                                                           '--dry-run prüfen, danach --fix --yes '
                                                                           'verwenden'),
 'Configuration changed after the displayed preview; rerun --dry-run': ('Configuration changed after the '
                                                                        'displayed preview; rerun --dry-run',
                                                                        'Konfiguration seit der angezeigten '
                                                                        'Vorschau geändert; --dry-run erneut '
                                                                        'ausführen'),
 'INI preview exceeds 2 MiB; review this file manually': ('INI preview exceeds 2 MiB; review this file manually',
                                                          'INI-Vorschau überschreitet 2 MiB; diese Datei manuell '
                                                          'prüfen'),
 'Fix cancelled': ('Fix cancelled', 'Fix abgebrochen'),
 'No changes made; rerun --dry-run to review the plan': ('No changes made; rerun --dry-run to review the plan',
                                                         'Nichts geändert; den Plan erneut mit --dry-run prüfen'),
 'Sensitive-file endpoint budget reached; narrow --root': ('Sensitive-file endpoint budget reached; narrow --root',
                                                           'Endpunktlimit für sensible Dateien erreicht; --root '
                                                           'eingrenzen'),
 '--ignore requires a finding id or rule_id from --json': ('--ignore requires a finding id or rule_id from --json',
                                                           '--ignore erfordert eine Befund-id oder rule_id aus '
                                                           '--json')}

_MESSAGE_TEMPLATES = (('Additional skipped paths: {count}', 'Additional skipped paths: {count}', 'Weitere ausgelassene Pfade: {count}'),
 ('HTTP request failed: {kind}', 'HTTP request failed: {kind}', 'HTTP-Anfrage fehlgeschlagen: {kind}'),
 ('{code}; unexpected HTTP status', '{code}; unexpected HTTP status', '{code}; unerwarteter HTTP-Status'),
 ('{code}; missing-path baseline unavailable',
  '{code}; missing-path baseline unavailable',
  '{code}; Vergleich mit einem fehlenden Pfad nicht verfügbar'),
 ('{code}; possible file access; missing paths were rejected',
  '{code}; possible file access; missing paths were rejected',
  '{code}; möglicher Dateizugriff; fehlende Pfade wurden abgewiesen'),
 ('{code}; ambiguous missing-path baseline',
  '{code}; ambiguous missing-path baseline',
  '{code}; Vergleich mit fehlenden Pfaden ist uneindeutig'),
 ('{code}; dynamic soft-404 fallback; file exposure not established',
  '{code}; dynamic soft-404 fallback; file exposure not established',
  '{code}; dynamischer Soft-404-Fallback; Dateizugriff nicht nachgewiesen'),
 ('{code}; matches soft-404 fallback; file exposure not established',
  '{code}; matches soft-404 fallback; file exposure not established',
  '{code}; entspricht Soft-404-Fallback; Dateizugriff nicht nachgewiesen'),
 ('{code}; response differs from missing-path fallback; possible file access',
  '{code}; response differs from missing-path fallback; possible file access',
  '{code}; Antwort weicht vom Fallback für fehlende Pfade ab; möglicher Dateizugriff'),
 ('Different filesystem skipped: {path}',
  'Different filesystem skipped: {path}',
  'Anderes Dateisystem ausgelassen: {path}'),
 ('Symlink skipped: {path}', 'Symlink skipped: {path}', 'Symlink ausgelassen: {path}'),
 ('Unreadable path: {path}', 'Unreadable path: {path}', 'Nicht lesbarer Pfad: {path}'),
 ('Runtime directory must be an existing absolute path without symlinks: {path}',
  'Runtime directory must be an existing absolute path without symlinks: {path}',
  'Laufzeitverzeichnis muss ein bestehender absoluter Pfad ohne Symlinks sein: {path}'),
 ('Runtime directory must be a strict subdirectory of the selected roots: {path}',
  'Runtime directory must be a strict subdirectory of the selected roots: {path}',
  'Laufzeitverzeichnis muss ein echtes Unterverzeichnis der ausgewählten Wurzeln sein: {path}'),
 ('Declared runtime storage ({user})',
  'Declared runtime storage ({user})',
  'Deklarierter Laufzeitspeicher ({user})'),
 ('{count} writable directories; PHP files remain checked; execution restrictions require separate verification; '
  '{paths}',
  '{count} writable directories; PHP files remain checked; execution restrictions require separate verification; '
  '{paths}',
  '{count} schreibbare Verzeichnisse; PHP-Dateien werden weiter geprüft; Ausführungsbeschränkungen erfordern eine '
  'gesonderte Prüfung; {paths}'),
 ('Not assessed automatically; review rules and delegates separately; {paths}',
  'Not assessed automatically; review rules and delegates separately; {paths}',
  'Nicht automatisch bewertet; Regeln und Delegates gesondert prüfen; {paths}'),
 ('Rollback conflict in content, file metadata or timestamps: {path}',
  'Rollback conflict in content, file metadata or timestamps: {path}',
  'Rollback-Konflikt bei Inhalt, Dateimetadaten oder Zeitstempel: {path}'),
 ('Latest transaction is unknown; select one explicitly with --backup-id: {path}',
  'Latest transaction is unknown; select one explicitly with --backup-id: {path}',
  'Neueste Transaktion ist unbekannt; gezielte Auswahl mit --backup-id erforderlich: {path}'),
 ('No further changes: {path} ({status}); select an older backup explicitly with --backup-id',
  'No further changes: {path} ({status}); select an older backup explicitly with --backup-id',
  'Keine weiteren Änderungen: {path} ({status}); älteres Backup nur mit --backup-id auswählen'),
 ('Install if needed: {command}', 'Install if needed: {command}', 'Bei Bedarf installieren: {command}'),
 ("Install package '{package}' with your package manager if needed",
  "Install package '{package}' with your package manager if needed",
  "Bei Bedarf Paket '{package}' mit dem Paketmanager bereitstellen"),
 ('{version}; version 3.8 or later required',
  '{version}; version 3.8 or later required',
  '{version}; mindestens 3.8 erforderlich'),
 ('HTTP status checks: available', 'HTTP status checks: available', 'HTTP-Statusprüfungen: verfügbar'),
 ('File permission checks as another FPM user: available',
  'File permission checks as another FPM user: available',
  'Dateirechte als fremder FPM-Benutzer: verfügbar'),
 ('HTTP status checks: missing; {message}',
  'HTTP status checks: missing; {message}',
  'HTTP-Statusprüfungen: fehlt; {message}'),
 ('File permission checks as another FPM user: missing; {message}',
  'File permission checks as another FPM user: missing; {message}',
  'Dateirechte als fremder FPM-Benutzer: fehlt; {message}'),
 ('Cannot execute {program}: {kind}', 'Cannot execute {program}: {kind}', '{program} nicht ausführbar: {kind}'),
 ('{program} failed (exit {code})', '{program} failed (exit {code})', '{program} fehlgeschlagen (Exit {code})'),
 ('Absolute path required: {path}', 'Absolute path required: {path}', 'Absoluter Pfad erforderlich: {path}'),
 ('Untrusted path or ancestor: {path}',
  'Untrusted path or ancestor: {path}',
  'Nicht vertrauenswürdiger Root-Pfad: {path}'),
 ('Cannot read ACL: {path}', 'Cannot read ACL: {path}', 'ACL nicht lesbar: {path}'),
 ('FPM PID {pid}: container or different filesystem namespace',
  'FPM PID {pid}: container or different filesystem namespace',
  'FPM PID {pid}: Container/anderer Dateisystem-Namensraum'),
 ('FPM PID {pid}: dangling INI reference {path}',
  'FPM PID {pid}: dangling INI reference {path}',
  'FPM PID {pid}: hängender INI-Verweis {path}'),
 ('FPM PID {pid}: {message}', 'FPM PID {pid}: {message}', 'FPM PID {pid}: {message}'),
 ('FPM include has no readable target: {path}',
  'FPM include has no readable target: {path}',
  'FPM-Include ohne lesbares Ziel: {path}'),
 ('Cannot switch UID for {user}', 'Cannot switch UID for {user}', 'Kann UID für {user} nicht wechseln'),
 ('Nginx: incomplete directive ({source})',
  'Nginx: incomplete directive ({source})',
  'Nginx: unvollständige Direktive ({source})'),
 ('Nginx: unexpected delimiter ({source})',
  'Nginx: unexpected delimiter ({source})',
  'Nginx: unerwartetes Trennzeichen ({source})'),
 ('Nginx configuration is not protected by root ownership: {path}',
  'Nginx configuration is not protected by root ownership: {path}',
  'Nginx-Konfiguration ist nicht rootgeschützt: {path}'),
 ('Nginx: include cycle at {path}', 'Nginx: include cycle at {path}', 'Nginx: Include-Zyklus bei {path}'),
 ('Nginx include missing: {path}', 'Nginx include missing: {path}', 'Nginx-Include fehlt: {path}'),
 ('{source}: dynamic or relative document path',
  '{source}: dynamic or relative document path',
  '{source}: dynamischer oder relativer Dokumentpfad'),
 ('{source}: document path missing: {path}',
  '{source}: document path missing: {path}',
  '{source}: Dokumentpfad fehlt: {path}'),
 ('{source}: system path excluded from automatic scanning: {path}',
  '{source}: system path excluded from automatic scanning: {path}',
  '{source}: Systempfad wird nicht automatisch durchsucht: {path}'),
 ('{source}: document path contains symlinks: {path}',
  '{source}: document path contains symlinks: {path}',
  '{source}: Dokumentpfad enthält Symlinks: {path}'),
 ('{source}: server with unresolved includes excluded from automatic HTTP mapping',
  '{source}: server with unresolved includes excluded from automatic HTTP mapping',
  '{source}: Server mit unvollständigen Includes wird nicht automatisch per HTTP zugeordnet'),
 ('{source}: wildcard, regex or default hostname requires an explicit --site',
  '{source}: wildcard, regex or default hostname requires an explicit --site',
  '{source}: Wildcard/Regex/Default-Hostname braucht eine explizite --site-Angabe'),
 ('{source}: Unix/UDP listener excluded from HTTP checks',
  '{source}: Unix/UDP listener excluded from HTTP checks',
  '{source}: Unix-/UDP-Listener wird nicht per HTTP geprüft'),
 ('{source}: a specific listener requires an explicit local mapping',
  '{source}: a specific listener requires an explicit local mapping',
  '{source}: spezifischer Listener erfordert manuelle lokale Zuordnung'),
 ('{source}: invalid listener port', '{source}: invalid listener port', '{source}: ungültiger Listener-Port'),
 ('{source}: conditional document path is ambiguous',
  '{source}: conditional document path is ambiguous',
  '{source}: bedingter Dokumentpfad ist nicht eindeutig'),
 ('{source}: regex or dynamic location path requires an explicit mapping',
  '{source}: regex or dynamic location path requires an explicit mapping',
  '{source}: Regex-/dynamischer Location-Pfad braucht manuelle Zuordnung'),
 ('{source}: redirect without a document root does not count as a file check',
  '{source}: redirect without a document root does not count as a file check',
  '{source}: Redirect ohne Dokumentwurzel wird nicht als Dateiprüfung gewertet'),
 ('{source}: proxy or missing document root requires a separate backend audit',
  '{source}: proxy or missing document root requires a separate backend audit',
  '{source}: Proxy/fehlende Dokumentwurzel benötigt eigene Backend-Prüfung'),
 ('Ambiguous document root for {url}; automatic HTTP check skipped',
  'Ambiguous document root for {url}; automatic HTTP check skipped',
  'Mehrdeutige Dokumentwurzel für {url}; automatische HTTP-Prüfung ausgespart'),
 ('Automatic Nginx discovery incomplete: {message}',
  'Automatic Nginx discovery incomplete: {message}',
  'Automatische Nginx-Erkennung unvollständig: {message}'),
 ('HTTP limit: {count} mappings omitted; increase --max-sites or narrow the scope with --site',
  'HTTP limit: {count} mappings omitted; increase --max-sites or narrow the scope with --site',
  'HTTP-Limit: {count} Zuordnungen ausgelassen; --max-sites erhöhen oder --site eingrenzen'),
 ('Missing: {functions}', 'Missing: {functions}', 'Fehlt: {functions}'),
 ('{value}; correct the pool override manually',
  '{value}; correct the pool override manually',
  '{value}; Pool-Override manuell korrigieren'),
 ('{value} (an additional restriction, not a sandbox)',
  '{value} (an additional restriction, not a sandbox)',
  '{value} (zusätzliche Schranke, keine Sandbox)'),
 ('{key}: shared file outside the FPM INI root: {path}',
  '{key}: shared file outside the FPM INI root: {path}',
  '{key}: geteilte Datei außerhalb der FPM-INI-Wurzel: {path}'),
 ('FPM configuration {path}', 'FPM configuration {path}', 'FPM-Konfiguration {path}'),
 ('{user} has UID 0', '{user} has UID 0', '{user} hat UID 0'),
 ('File permissions ({user})', 'File permissions ({user})', 'Dateirechte ({user})'),
 ('Writable PHP files ({user})', 'Writable PHP files ({user})', 'Schreibbare PHP-Dateien ({user})'),
 ('Writable directories ({user})', 'Writable directories ({user})', 'Schreibbare Verzeichnisse ({user})'),
 ('Filesystem coverage ({user})', 'Filesystem coverage ({user})', 'Dateisystem-Abdeckung ({user})'),
 ('runuser missing; {message}. Other checks continue.',
  'runuser missing; {message}. Other checks continue.',
  'runuser fehlt; {message}. Andere Module laufen weiter.'),
 ('{count} unreadable or skipped paths; {message}',
  '{count} unreadable or skipped paths; {message}',
  '{count} unlesbare/ausgelassene Pfade; {message}'),
 ('curl missing; HTTP checks skipped. {message}. Filesystem and FPM checks continue.',
  'curl missing; HTTP checks skipped. {message}. Filesystem and FPM checks continue.',
  'curl fehlt; HTTP-Prüfungen ausgelassen. {message}. Dateisystem-/FPM-Prüfungen laufen weiter.'),
 ('{code}; possible file exposure, content not evaluated',
  '{code}; possible file exposure, content not evaluated',
  '{code}; möglicher Dateizugriff, Inhalt nicht bewertet'),
 ('Manual review of rules and versions required; {paths}',
  'Manual review of rules and versions required; {paths}',
  'Regel- und versionsbezogene manuelle Prüfung erforderlich; {paths}'),
 ('Symlink refused as a change target: {path}',
  'Symlink refused as a change target: {path}',
  'Symlink als Änderungsziel abgelehnt: {path}'),
 ('Reload preflight {service}: {message}',
  'Reload preflight {service}: {message}',
  'Reload-Vorprüfung {service}: {message}'),
 ('Cannot restrict UID 0 with file permissions: {user}',
  'Cannot restrict UID 0 with file permissions: {user}',
  'Rechteschutz gegen UID 0 ist nicht möglich: {user}'),
 ('Permission verification for {user}: runuser missing; {message}',
  'Permission verification for {user}: runuser missing; {message}',
  'Rechteverifikation für {user}: runuser fehlt; {message}'),
 ('Permission verification: unknown user {user}',
  'Permission verification: unknown user {user}',
  'Rechteverifikation: unbekannter Benutzer {user}'),
 ('{path} remains writable by {user}', '{path} remains writable by {user}', '{path} bleibt für {user} schreibbar'),
 ('Rollback conflict or damaged backup: {path}',
  'Rollback conflict or damaged backup: {path}',
  'Rollback-Konflikt oder beschädigtes Backup: {path}'),
 ('Rollback conflict in file metadata: {path}',
  'Rollback conflict in file metadata: {path}',
  'Rollback-Konflikt bei Dateimetadaten: {path}'),
 ('Restored: {path}', 'Restored: {path}', 'Wiederhergestellt: {path}'),
 ('Python 3.8 or later required; {message}',
  'Python 3.8 or later required; {message}',
  'Python 3.8+ erforderlich; {message}'),
 ('PLANNED INI {path}: {keys}', 'PLANNED INI {path}: {keys}', 'GEPLANT INI {path}: {keys}'),
 ('PLANNED DIRECTORY {path}: owner root, no g+w/o+w, non-recursive',
  'PLANNED DIRECTORY {path}: owner root, no g+w/o+w, non-recursive',
  'GEPLANT VERZEICHNIS {path}: Eigentümer root, kein g+w/o+w, nicht rekursiv'),
 ('ERROR: {message}', 'ERROR: {message}', 'FEHLER: {message}'),
 ('Undo this transaction: sudo bash p2s-harden.sh --rollback --backup-id {id}',
  'Undo this transaction: sudo bash p2s-harden.sh --rollback --backup-id {id}',
  'Diese Transaktion zurücknehmen: sudo bash p2s-harden.sh --rollback --backup-id {id}'))


def _compile_message(template):
    import string
    parts, names = [], []
    for literal, name, _, _ in string.Formatter().parse(template):
        parts.append(re.escape(literal))
        if name is not None:
            names.append(name)
            parts.append("(.*?)")
    return re.compile("".join(parts), re.S), names


_NEW_GERMAN = {
    "Audit selected settings, permissions and HTTP paths (default)": "Ausgewählte Einstellungen, Rechte und HTTP-Pfade prüfen (Standard)",
    "Explain prerequisites and missing capabilities": "Voraussetzungen und fehlende Fähigkeiten erklären",
    "Show detected FPM pools and web mappings": "Erkannte FPM-Pools und Webzuordnungen anzeigen",
    "Show proposed values and a unified diff without changes": "Geplante Werte und einen Diff anzeigen, ohne Änderungen",
    "Apply the displayed supported plan after confirmation": "Angezeigten unterstützten Plan nach Bestätigung anwenden",
    "Restore only the latest transaction, or one explicit backup ID": "Nur die letzte Transaktion oder eine ausdrückliche Backup-ID wiederherstellen",
    "Additional PHP user for permission checks; repeatable": "Zusätzlicher PHP-Benutzer für Rechteprüfungen; wiederholbar",
    "Explicit virtual host and document root; repeatable": "Expliziter virtueller Host und Dokumentwurzel; wiederholbar",
    "Protected transaction directory (default /root/p2s-harden-backup-v2)": "Geschütztes Transaktionsverzeichnis (Standard /root/p2s-harden-backup-v2)",
    "Choose one transaction explicitly for rollback": "Eine bestimmte Transaktion für Rollback auswählen",
    "Approve the displayed fix plan without an interactive prompt": "Angezeigten Fix-Plan ohne interaktive Rückfrage freigeben",
    "Exit precedence: complete (UNKNOWN first) or open (OPEN first); unknowns never pass": "Exit-Vorrang: complete (UNKNOWN zuerst) oder open (OPEN zuerst); unbekannte Ergebnisse bestehen nie",
    "Suppress one finding/rule's OPEN exit impact; keep it visible; repeatable": "OPEN-Exitwirkung eines Befunds/einer Regel ausnehmen; Befund bleibt sichtbar; wiederholbar",
    "Structured findings, stable IDs, remediation, preview and transaction state": "Strukturierte Befunde, stabile IDs, Behebung, Vorschau und Transaktionsstatus",
    "Maximum entries per filesystem walk (default 250000)": "Höchstens 250000 Einträge je Dateisystem-Suchlauf (Standard)",
    "Run on a Linux target with readable /proc; use --ssh from other systems.": "Auf einem Linux-Ziel mit lesbarem /proc ausführen; von anderen Systemen --ssh nutzen.",
    "Provide Python 3.8 or later on the Linux target, then rerun.": "Python 3.8 oder neuer auf dem Linux-Ziel bereitstellen und erneut ausführen.",
    "Use sudo or an existing root SSH login for complete checks and changes.": "Für vollständige Prüfungen und Änderungen sudo oder einen vorhandenen Root-SSH-Zugang nutzen.",
    "HTTP checks use the Python standard library; no curl installation is needed.": "HTTP-Prüfungen nutzen Pythons Standardbibliothek; curl muss nicht installiert werden.",
    "Use --doctor for the helper's purpose and the suggested package command.": "--doctor zeigt den Zweck des Hilfsprogramms und einen Paketvorschlag.",
    "Process discovery uses /proc when ps is unavailable.": "Ohne ps nutzt die Prozesserkennung /proc.",
    "Automatic INI changes need a matching active systemd FPM service.": "Automatische INI-Änderungen benötigen einen passenden aktiven systemd-FPM-Dienst.",
    "Review discovery issues; supply --nginx-config or explicit --root/--site mappings.": "Erkennungsprobleme prüfen; --nginx-config oder explizite --root/--site-Zuordnungen angeben.",
    "Check the running FPM master and its protected configuration; unsupported contexts require separate assessment.": "Laufenden FPM-Master und geschützte Konfiguration prüfen; andere Kontexte separat bewerten.",
    "Repair the reported FPM configuration/provenance and rerun; other instances remain independently checked.": "Gemeldete FPM-Konfiguration/Herkunft korrigieren und erneut prüfen; andere Instanzen werden unabhängig geprüft.",
    "Review skipped paths or increase the traversal budget; no skipped subtree is certified.": "Ausgelassene Pfade prüfen oder Suchlimit erhöhen; ausgelassene Unterbäume gelten nicht als bestanden.",
    "Review --dry-run, test application compatibility, then apply --fix --yes or set the required function restrictions manually.": "--dry-run und Anwendungskompatibilität prüfen; danach --fix --yes oder die nötigen Funktionssperren manuell setzen.",
    "Set allow_url_include=Off in the effective FPM INI/pool and reload the matching service.": "allow_url_include=Off in der wirksamen FPM-INI/im Pool setzen und passenden Dienst neu laden.",
    "Review a narrow per-pool open_basedir with application testing; it is an additional restriction, not a sandbox.": "Enges open_basedir je Pool mit Anwendungstests prüfen; es ist eine zusätzliche Schranke, keine Sandbox.",
    "Remove PHP-user write access to application code and verify ACLs; keep required runtime data separate.": "PHP-Schreibrechte auf Anwendungscode entfernen und ACLs prüfen; benötigte Laufzeitdaten getrennt halten.",
    "Separate code from runtime storage; use --runtime-dir only for reviewed storage and --protect-dir only for an explicit code directory.": "Code und Laufzeitspeicher trennen; --runtime-dir nur für geprüften Speicher und --protect-dir nur für ein explizites Codeverzeichnis nutzen.",
    "Resolve the reported user/access/coverage issue or narrow the scope; an incomplete walk cannot pass.": "Gemeldetes Benutzer-/Zugriffs-/Abdeckungsproblem beheben oder Bereich eingrenzen; ein unvollständiger Suchlauf kann nicht bestehen.",
    "Verify that declared upload/cache paths cannot execute uploaded PHP and cannot replace application code.": "Prüfen, dass deklarierte Upload-/Cache-Pfade hochgeladenes PHP nicht ausführen und Anwendungscode nicht ersetzen können.",
    "Run the FPM pool as a dedicated non-root account and restart the service after reviewing ownership.": "FPM-Pool unter einem eigenen Benutzer ohne root betreiben und nach Rechteprüfung neu starten.",
    "Deny HTTP access to the reported sensitive file/path, remove public backups/debug scripts, and recheck both HTTP and HTTPS.": "HTTP-Zugriff auf gemeldeten sensiblen Pfad sperren, öffentliche Backups/Debugskripte entfernen und HTTP sowie HTTPS erneut prüfen.",
    "Provide an explicit --site mapping or sufficient HTTP budget; inspect every unknown result.": "Explizite --site-Zuordnung oder ausreichendes HTTP-Limit bereitstellen; jedes unbekannte Ergebnis prüfen.",
    "Correct the URL/document-root mapping and retry the intended local virtual host.": "URL-/Dokumentwurzel-Zuordnung korrigieren und den gemeinten lokalen virtuellen Host erneut prüfen.",
    "Review the host ptrace policy against operational needs; this tool does not change sysctl settings.": "ptrace-Regel des Hosts gegen Betriebsanforderungen prüfen; das Tool ändert keine sysctl-Einstellungen.",
    "Review ImageMagick policy rules and delegates for the installed version and application requirements.": "ImageMagick-Regeln und Delegates für installierte Version und Anwendung prüfen.",
    "Resolve the specific fix preflight blocker, inspect the full proposed diff, and rerun.": "Konkrete Fix-Vorbedingung erfüllen, vollständigen vorgeschlagenen Diff prüfen und erneut ausführen.",
    "Keep the backup ID; a repeated implicit rollback never selects an older transaction.": "Backup-ID aufbewahren; wiederholtes implizites Rollback wählt niemals eine ältere Transaktion.",
    "Resolve the execution error and rerun; consult transaction state before retrying a change.": "Ausführungsfehler beheben und erneut ausführen; vor erneuter Änderung den Transaktionsstatus prüfen.",
    "Review this diagnostic in its reported context.": "Diese Diagnose im angegebenen Kontext prüfen.",
}
_EVIDENCE_GERMAN = dict(pool="Pool", pools="Pools", none="keine", yes="ja", no="nein",
                        configured="konfiguriert", observed="beobachtet", acl="ACL", loopback="Loopback",
                        network="Netzwerk", unverified="ungeprüft", non_loopback="außerhalb Loopback",
                        unavailable="nicht verfügbar", unknown="unbekannt", on="an", off="aus")

_NEW_GERMAN.update({
    "Missing": "Fehlend",
    "Unrestricted": "Unbeschränkt",
    "TCP binding": "TCP-Bindung",
    "Client allowlist": "Client-Freigaben",
    "Name resolution": "Namensauflösung",
    "Socket mode": "Socket-Rechte",
    "Source": "Quelle",
    "Named ACL": "Benannte ACL",
    "Known script extensions": "Bekannte Skript-Endungen",
    "Other script extensions": "Andere Skript-Endungen",
    "Pools": "Pools",
    "Runtime directories": "Laufzeitverzeichnisse",
    "HTTP status": "HTTP-Status",
    "Changing an existing INI such as php.ini may cause a package-upgrade configuration prompt if local and package versions both change.": "Die Änderung einer bestehenden INI wie php.ini kann beim Paket-Upgrade eine Konfigurationsrückfrage auslösen, wenn lokale und Paketversion geändert wurden.",
    "Shell function restrictions": "Shell-Funktionssperren",
    "URL includes": "URL-Includes",
    "Filesystem restriction": "Dateisystembegrenzung",
    "PHP FFI": "PHP-FFI",
    "FPM TCP listener": "FPM-TCP-Listener",
    "FPM Unix socket": "FPM-Unix-Socket",
    "FPM script extensions": "FPM-Skriptendungen",
    "FPM environment clearing": "FPM-Umgebungsbereinigung",
    "Writable PHP files": "Schreibbare PHP-Dateien",
    "Writable directories": "Schreibbare Verzeichnisse",
    "Declared runtime storage": "Deklarierter Laufzeitspeicher",
    "Sensitive HTTP path": "Sensibler HTTP-Pfad",
    "localhost resolution is unavailable; use a literal loopback IP or verify the host name-service configuration": "localhost-Auflösung nicht verfügbar; konkrete Loopback-IP verwenden oder Namensdienst des Hosts prüfen",
    "Main-script extensions are unrestricted; set security.limit_extensions=.php after application review": "Hauptskript-Endungen sind unbeschränkt; nach Prüfung der Anwendung security.limit_extensions=.php setzen",
    "Shareable read-only report: omit host details, inventory and original finding IDs": "Teilbarer Prüfbericht: Hostdetails, Inventar und ursprüngliche Befund-IDs weglassen",
    "Host details omitted; rerun locally without --redact": "Hostdetails ausgelassen; zur lokalen Diagnose ohne --redact wiederholen",
    "--redact supports --check, --doctor and --discover; review change previews locally without redaction": "--redact unterstützt --check, --doctor und --discover; Änderungsvorschauen lokal ohne Maskierung prüfen",
    "Cannot parse the configured Unix socket mode": "Konfigurierte Unix-Socket-Rechte sind nicht auswertbar",
    "Unix socket path has a symlink; verify the effective endpoint separately": "Unix-Socket-Pfad enthält einen Symlink; tatsächlichen Endpunkt separat prüfen",
    "Configured Unix socket is missing or is not a socket": "Konfigurierter Unix-Socket fehlt oder ist kein Socket",
    "Named Unix socket ACL grants require individual review; owner/group settings may be ignored": "Benannte Unix-Socket-ACL-Rechte einzeln prüfen; Eigentümer-/Gruppeneinstellungen können wirkungslos sein",
    "Cannot classify the TCP listener or client allowlist; use literal IP addresses and verify the effective endpoint": "TCP-Listener oder Client-Freigaben nicht einordbar; konkrete IP-Adressen verwenden und tatsächlichen Endpunkt prüfen",
    "Shared FPM account": "Gemeinsames FPM-Konto",
    "FPM include coverage limit reached (64 levels / 1024 files)": "FPM-Include-Limit erreicht (64 Ebenen / 1024 Dateien)",
    "FPM include byte budget reached (2 MiB per file / 16 MiB total)": "FPM-Include-Datenlimit erreicht (2 MiB je Datei / 16 MiB insgesamt)",
    "Review whether FFI is needed; set ffi.enable=Off in the effective FPM configuration when compatible, then reload and test the application.": "FFI-Bedarf prüfen; bei Kompatibilität ffi.enable=Off in wirksamer FPM-Konfiguration setzen, neu laden und Anwendung testen.",
    "Prefer a Unix socket or loopback bind; for required TCP access set listen.allowed_clients to the intended proxy IPs and verify firewall/container publication.": "Unix-Socket oder Loopback bevorzugen; bei erforderlichem TCP-Zugriff listen.allowed_clients auf vorgesehene Proxy-IPs setzen und Firewall/Container-Portfreigaben prüfen.",
    "Restrict the Unix socket to the web-server identity, normally mode 0660 or 0600; review named ACL grants and verify the live socket after restart.": "Unix-Socket auf Webserver-Identität begrenzen, normalerweise Modus 0660 oder 0600; benannte ACL-Rechte und tatsächlichen Socket nach Neustart prüfen.",
    "Set security.limit_extensions=.php after checking application requirements; fix upload execution rules in the web server as well.": "Nach Prüfung der Anwendung security.limit_extensions=.php setzen; auch Ausführungsregeln für Uploads im Webserver korrigieren.",
    "Use clear_env=yes and declare only required env[] variables; test application configuration before reloading.": "clear_env=yes verwenden und nur benötigte env[]-Variablen setzen; Anwendung vor Neuladen testen.",
    "Use distinct Unix accounts and code ownership for mutually untrusted applications; shared pools may be intentional for one trust domain.": "Für gegenseitig nicht vertrauenswürdige Anwendungen getrennte Unix-Konten und Code-Eigentümer verwenden; gemeinsame Pools können bei gleichem Vertrauen beabsichtigt sein.",
})
_POOL_TEMPLATES = {
    "localhost resolves outside loopback; inspect the host name-service configuration; {listener}": "localhost wird außerhalb von Loopback aufgelöst; Namensdienst des Hosts prüfen; {listener}",
    "FPM listener [{pool}] {config}": "FPM-Listener [{pool}] {config}",
    "FPM script extensions [{pool}] {config}": "FPM-Skriptendungen [{pool}] {config}",
    "FPM environment clearing [{pool}] {config}": "FPM-Umgebungsbereinigung [{pool}] {config}",
    "PHP FFI [{pool}] {config}": "PHP-FFI [{pool}] {config}",
    "Configured Unix socket mode: {mode}": "Konfigurierte Unix-Socket-Rechte: {mode}",
    "Observed Unix socket mode: {mode}; {path}": "Beobachtete Unix-Socket-Rechte: {mode}; {path}",
    "Loopback TCP bind; local processes can still connect; {listener}": "TCP auf Loopback begrenzt; lokale Prozesse können weiterhin zugreifen; {listener}",
    "Network TCP bind with an explicit client allowlist; verify firewall and network reachability separately; {listener}": "TCP-Netzwerkbindung mit konkreten Client-Freigaben; Firewall und Erreichbarkeit separat prüfen; {listener}",
    "Network TCP bind accepts any client address; firewall and Internet reachability were not assessed; {listener}": "TCP-Netzwerkbindung akzeptiert jede Client-Adresse; Firewall und Internet-Erreichbarkeit wurden nicht geprüft; {listener}",
    "Allowed main-script extensions: {extensions}; .php is the narrow recommended setting": "Erlaubte Hauptskript-Endungen: {extensions}; .php ist die eng begrenzte Empfehlung",
    "clear_env={value}; explicit pool env[] values are not printed": "clear_env={value}; konkrete env[]-Werte des Pools werden nicht ausgegeben",
    "ffi.enable={value}; native/preloaded code requires separate review; function restrictions are defense in depth": "ffi.enable={value}; nativen/vorgeladenen Code separat prüfen; Funktionssperren sind zusätzliche Härtung",
    "{count} pools share UID {uid}; they do not form a Unix-user isolation boundary": "{count} Pools teilen UID {uid}; sie bilden keine Isolation durch Unix-Benutzer",
}
_MESSAGE_TEMPLATES += tuple((en, en, de) for en, de in _POOL_TEMPLATES.items())
_MESSAGES.update({en: (en, de) for en, de in _NEW_GERMAN.items()})
_COMPILED_MESSAGES = [(*_compile_message(source), en, de)
                      for source, en, de in _MESSAGE_TEMPLATES]
_COMPILED_MESSAGES.extend((*_compile_message(en), en, de)
                          for source, en, de in _MESSAGE_TEMPLATES if source != en)


def localize(message, lang="en"):
    """Translate a diagnostic, preserving every captured technical value."""
    if lang not in ("en", "de"):
        raise ValueError("Unsupported language; choose en or de")
    if lang == "en":
        return message
    if message in _MESSAGES:
        return _MESSAGES[message][lang == "de"]
    for pattern, names, en, de in _COMPILED_MESSAGES:
        match = pattern.fullmatch(message)
        if match:
            fields = dict(zip(names, match.groups()))
            if "message" in fields:
                fields["message"] = localize(fields["message"], lang)
            return (de if lang == "de" else en).format(**fields)
    # External OS/tool diagnostics and unknown future messages remain verbatim.
    return message


def localized_discovery(discovery, lang="en"):
    """Copy only known prose fields; arbitrary configuration data is opaque."""
    result = dict(discovery)
    if "issues" in result:
        result["issues"] = [localize(message, lang) for message in result["issues"]]
    if "automatic_changes" in result:
        result["automatic_changes"] = localize(result["automatic_changes"], lang)
    if "manual_checks" in result:
        result["manual_checks"] = [dict(check, name=localize(check["name"], lang))
                                   for check in result["manual_checks"]]
    # Pool names, users and listener strings remain opaque, including a real
    # account or socket literally named "unbekannt".
    return result
