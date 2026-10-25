# Shareable preview announcement

These are ready-to-copy drafts. Nothing is posted automatically. Keep the
preview status and the filename/handler conditions when shortening them.

## Deutsch

**Deine Nginx-Upload-Sperre kann an einem Zeilenumbruch scheitern.**

Die verbreitete Regel `^/uploads/.*\.php$` kann einen Dateinamen mit Zeilenumbruch
übersehen. Ein späterer PHP-Handler kann die Datei trotzdem ausführen. Das setzt
voraus, dass so eine Datei im ausführbaren Upload-Pfad entstehen kann; nicht jede
Upload-Funktion ist dadurch ausnutzbar.

p2s-harden erkennt diesen Konfigurationsfall, erklärt den Befund und zeigt eine
geprüfte Regel mit DOTALL, die PHP sperrt und Bilder weiter ausliefert. Ein
lokales Docker-Labor reproduziert alle drei Fälle mit echten Nginx/FPM-Prozessen
und harmlosen Markern: kein Guard, klassische Regel und korrigierte Regel.
Ohne veröffentlichte Ports oder Änderungen an deiner Serverkonfiguration.

[Reproduzieren](https://github.com/IamAngusU/p2s-harden/blob/main/docs/UPLOAD-GUARD-LAB.md)
· [Tool und lesender Audit](https://github.com/IamAngusU/p2s-harden)

**2.3.0-dev.7 ist eine Entwicklungsvorschau.** Der Konfigurationsworkflow richtet
sich an Debian/Ubuntu mit Host-FPM, Nginx und systemd. Funktionssperren sind keine
Sandbox; ein Audit ist kein Beweis für einen sauberen Server. Nginx wird nicht
automatisch geändert. Für das Labor braucht man Python und Docker, für normale
Audits kein Docker. Unabhängige Produktionsserver-Trials stehen noch aus.

## English

**A newline can slip past a common Nginx upload denial.**

The familiar `^/uploads/.*\.php$` rule can miss a filename containing a line break,
while a later PHP handler still executes it. Exploitation requires a way to put
that filename in the executable upload path; this does not make every upload
form vulnerable.

p2s-harden identifies this configuration pattern and documents a tested DOTALL
denial that blocks PHP while preserving image access. A local Docker lab
reproduces no guard, the ordinary rule and its correction with real Nginx/FPM
processes and harmless markers. No published ports or host configuration edits.

[Reproduce it](https://github.com/IamAngusU/p2s-harden/blob/main/docs/UPLOAD-GUARD-LAB.md)
· [Tool and read-only audit](https://github.com/IamAngusU/p2s-harden)

**2.3.0-dev.7 is a development preview.** The configuration workflow targets
Debian/Ubuntu host FPM, Nginx and systemd. Function restrictions are not a sandbox;
an audit cannot prove a clean server. Nginx is not edited automatically. Python
and Docker are needed for the lab; ordinary audits do not need Docker.
Independent production-server trials remain pending.
