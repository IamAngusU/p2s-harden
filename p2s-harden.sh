#!/usr/bin/env bash
# p2s-harden 2.3.0-dev.7 — self-contained; engine is embedded below.
set -uo pipefail

# Read language before handling --help or local/SSH prerequisite failures.
# A later --lang therefore also applies to an earlier --help.
lang=en
p2s_next_language=0
for p2s_argument in "$@"; do
  if [ "$p2s_next_language" = 1 ]; then lang=$p2s_argument; p2s_next_language=0; continue; fi
  case "$p2s_argument" in
    --lang) p2s_next_language=1 ;;
    --lang=*) lang=${p2s_argument#--lang=} ;;
  esac
done
if [ "$p2s_next_language" = 1 ] || { [ "$lang" != en ] && [ "$lang" != de ]; }; then
  printf '%s\n' '--lang requires en or de.' >&2
  exit 2
fi

message() {
  if [ "$lang" = de ]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi
}

usage() {
  if [ "$lang" = en ]; then
    cat <<'HELP'
p2s-harden 2.3.0-dev.7 — one file, automatic discovery

  sudo bash p2s-harden.sh                     Discover and audit locally
  bash p2s-harden.sh --ssh root@SERVER         Discover and audit over SSH
  bash p2s-harden.sh --doctor                  Explain prerequisites and next steps
  sudo bash p2s-harden.sh --discover           Show discovered mappings
  sudo bash p2s-harden.sh --scan-webshells     Read-only PHP file indicator scan
  sudo bash p2s-harden.sh --dry-run            Preview specific changes
  sudo bash p2s-harden.sh --fix                Apply bounded INI fixes
  sudo bash p2s-harden.sh --rollback           Restore the latest transaction

No separate Python file, installation or configuration file.
Requires a Linux target with Python 3.8+; --ssh uses your existing SSH access.
Missing optional helpers are explained; independent checks continue.

Options (override automatically discovered values):
  --lang en|de                 Output language (default: en)
  --root /path                 Limit the filesystem audit scope
  --site URL=DOCUMENT_ROOT     Explicit virtual host; repeatable
  --nginx-config /path         Custom Nginx main configuration
  --nginx-baseline FILE        Reviewed UNKNOWN exceptions; --check only
  --write-nginx-review-draft FILE  Private unreviewed draft; --check only
  --web-user USER              Additional FPM user
  --no-auto                   Use explicit mappings only
  --max-sites 32              Limit automatic HTTP mappings
  --max-paths COUNT           Limit filesystem traversal
  --walk-seconds SECONDS      Audit: 10s; webshell scan: 120s; scan-only 0 disables root timer
  --scan-file-seconds N       Independent webshell file timer (default 2s)
  --no-nice                  Skip lowering scan CPU/I/O priority
  --baseline FILE             Reviewed JSON: exact path/hash/indicator acceptance
  --write-baseline-draft FILE  Create a new private draft; no entries approved
  --max-http-probes COUNT     Limit HTTP requests
  --runtime-dir /path          Review a known upload/cache directory separately
  --protect-dir /path          Protect an explicit directory; non-recursive
  --backup-root /root/path     Custom backup directory
  --backup-id ID               Restore a specific transaction
  --json                      Machine-readable output
  --redact                    Shareable read-only report without host details
  --scan-file-bytes N          PHP parsing byte limit; larger files streamed (2097152)
  --scan-total-bytes N         Webshell scan: bytes per root (268435456)
  --yes, -y                   Approve the fix without an interactive prompt
  --fail-on complete|open|review     Exit precedence; unacknowledged UNKNOWN never passes
  --ignore ID                 Keep a finding visible but suppress its OPEN/review exit
  --verbose                   Include all findings, including OK
  --no-progress               Hide interactive progress messages

Discovery never infers permission-change targets.
--check/--discover/--dry-run do not modify configuration or reload services.
Exit 0: no active blockers (reviewed UNKNOWN may remain); 1: open findings (or review with --fail-on review); 2: unknown/error.
HELP
    return
  fi
  cat <<'HELP'
p2s-harden 2.3.0-dev.7 — eine Datei, automatische Erkennung

  sudo bash p2s-harden.sh                     Lokal erkennen und prüfen
  bash p2s-harden.sh --ssh root@SERVER         Remote erkennen und prüfen
  bash p2s-harden.sh --doctor                  Voraussetzungen und nächste Schritte
  sudo bash p2s-harden.sh --discover           Erkannte Zuordnungen anzeigen
  sudo bash p2s-harden.sh --scan-webshells     PHP-Datei-Indikatoren lesend prüfen
  sudo bash p2s-harden.sh --dry-run            Konkrete Änderungen anzeigen
  sudo bash p2s-harden.sh --fix                Begrenzte INI-Fixes anwenden
  sudo bash p2s-harden.sh --rollback           Letzte Transaktion zurücknehmen

Kein separates Python-Skript, keine Installation und keine Konfigurationsdatei.
Voraussetzungen: Linux-Ziel mit Python 3.8+ und bestehender SSH-Zugang bei --ssh.
Fehlende optionale Helfer werden erklärt; unabhängige Prüfungen laufen weiter.

Optional (automatisch erkannte Werte lassen sich überschreiben):
  --lang en|de                 Ausgabesprache (Standard: en)
  --root /pfad                 Dateisystem-Prüfbereich einschränken
  --site URL=DOKUMENTWURZEL     Expliziter vHost, wiederholbar
  --nginx-config /pfad          Abweichende Nginx-Hauptkonfiguration
  --nginx-baseline DATEI       Reviewte UNKNOWN-Ausnahmen; nur --check
  --write-nginx-review-draft DATEI  Privater ungeprüfter Entwurf; nur --check
  --web-user BENUTZER           Zusätzlicher FPM-Benutzer
  --no-auto                    Nur explizite Zuordnungen verwenden
  --max-sites 32               Limit automatischer HTTP-Zuordnungen
  --max-paths ANZAHL           Dateisystem-Suchlauf begrenzen
  --walk-seconds SEKUNDEN      Audit: 10s; Webshell-Suche: 120s; nur Suche: 0 ohne Wurzeltimer
  --scan-file-seconds N        Eigenes Webshell-Zeitlimit je Datei (Standard 2s)
  --no-nice                  Scan-Priorität nicht absenken
  --baseline DATEI            Geprüfte JSON: exakter Pfad/Hash/Indikator
  --write-baseline-draft DATEI  Privaten Entwurf erstellen; keine Freigaben
  --max-http-probes ANZAHL     HTTP-Anfragen begrenzen
  --runtime-dir /pfad           Bekanntes Upload-/Cache-Verzeichnis gesondert bewerten
  --protect-dir /pfad           Nur explizites Verzeichnis schützen; kein Rekurs
  --backup-root /root/pfad      Anderes Backup-Verzeichnis
  --backup-id ID                Bestimmte Transaktion zurücknehmen
  --json                       Maschinenlesbare Ausgabe
  --redact                     Teilbarer Prüfbericht ohne private Hostdetails
  --scan-file-bytes N           PHP-Parserlimit; größere Dateien gestreamt (2097152)
  --scan-total-bytes N          Webshell-Suche: Bytes je Wurzel (268435456)
  --yes, -y                    Fix ohne interaktive Rückfrage freigeben
  --fail-on complete|open|review      Exit-Vorrang; nicht akzeptiertes UNKNOWN besteht niemals
  --ignore ID                  Befund sichtbar lassen, seine OPEN-/Review-Exitwirkung ausnehmen
  --verbose                    Alle Einzelbefunde einschließlich OK anzeigen
  --no-progress                Phasenhinweise im interaktiven Terminal ausblenden

Erkennung leitet keine automatischen Rechteänderungen ab.
--check/--discover/--dry-run schreiben keine Zielkonfiguration und laden nichts neu.
Exit 0: keine aktiven Blocker (reviewtes UNKNOWN kann bleiben); 1: offen (oder Review mit --fail-on review); 2: unbekannt/Fehler.
HELP
}

target=local
target_set=0
json_mode=0
args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --local)
      [ "$target_set" = 0 ] || { message 'Target specified more than once' 'Ziel mehrfach angegeben' >&2; exit 2; }
      target=local; target_set=1; shift ;;
    --ssh)
      [ "$target_set" = 0 ] && [ "$#" -ge 2 ] && [ -n "$2" ] || { message '--ssh requires one target' '--ssh braucht ein Ziel' >&2; exit 2; }
      target=$2; target_set=1; shift 2
      name_pattern='^[A-Za-z0-9_][A-Za-z0-9_.@:-]*$'
      ipv6_pattern='^([A-Za-z0-9_.-]+@)?\[[0-9A-Fa-f:.%]+\]$'
      [[ "$target" =~ $name_pattern || "$target" =~ $ipv6_pattern ]] || { message 'Invalid SSH target' 'Ungültiges SSH-Ziel' >&2; exit 2; } ;;
    --help|-h) usage; exit 0 ;;
    --version) echo 'p2s-harden 2.3.0-dev.7'; exit 0 ;;
    --json) json_mode=1; args+=("$1"); shift ;;
    --yes|-y) args+=("$1"); shift ;;
    --no-self-guard)
      message "Note: $1 has no effect; no firewall/Fail2ban changes are made." "Hinweis: $1 ist wirkungslos; keine Firewall-/Fail2ban-Änderungen." >&2; shift ;;
    *) args+=("$1"); shift ;;
  esac
done
[ -t 2 ] && args+=(--progress)

payload() {
  local inside=0 line
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = '# __P2S_PYTHON__' ]; then
      inside=1
    elif [ "$line" = '__P2S_ENGINE_EOF__' ]; then
      break
    elif [ "$inside" = 1 ]; then
      printf '%s\n' "$line"
    fi
  done < "$0"
}

# POSIX shell syntax: this same definition is sent to the remote login shell.
# Even without Python, enumerate missing helpers and give one actionable result.
bootstrap() {
  p2s_problem=''
  p2s_kernel=''
  p2s_lang=${2:-en}
  if [ "$p2s_lang" = de ]; then
    p2s_platform='Linux-Ziel mit lesbarem /proc erforderlich; Windows/macOS können per --ssh prüfen.'
    p2s_python_missing='Python 3.8+ fehlt; Paket python3 bereitstellen. Ohne Python sind die Konfigurationsprüfungen nicht ausführbar.'
    p2s_python_old='Python 3.8+ erforderlich; vorhandenes python3 ist zu alt oder nicht ausführbar.'
    p2s_title='Voraussetzungen'
    p2s_header='p2s-harden: Voraussetzungen unvollständig'
    p2s_missing='FEHLT'
    p2s_helpers='ps ist optional (/proc-Fallback). HTTP nutzt Python, kein curl nötig. runuser: fremde FPM-Benutzer. systemctl: INI-Fixes.'
    p2s_next='Nach Bereitstellung von Python denselben Befehl erneut ausführen. Es wurde nichts installiert oder geändert.'
  else
    p2s_platform='A Linux target with readable /proc is required; use --ssh from Windows/macOS.'
    p2s_python_missing='Python 3.8+ is missing; install package python3. Configuration checks cannot run without Python.'
    p2s_python_old='Python 3.8+ is required; the existing python3 is too old or cannot run.'
    p2s_title='Prerequisites'
    p2s_header='p2s-harden: prerequisites incomplete'
    p2s_missing='MISSING'
    p2s_helpers='ps is optional (/proc fallback). HTTP uses Python; curl is not needed. runuser: other FPM users. systemctl: INI fixes.'
    p2s_next='Provide Python and run the same command again. Nothing was installed or changed.'
  fi
  if [ -r /proc/sys/kernel/ostype ]; then IFS= read -r p2s_kernel < /proc/sys/kernel/ostype; fi
  [ "$p2s_kernel" = Linux ] && [ -r /proc/self/stat ] || p2s_problem=$p2s_platform
  if ! command -v python3 >/dev/null 2>&1; then
    p2s_problem="${p2s_problem:+$p2s_problem }$p2s_python_missing"
  elif ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    p2s_problem="${p2s_problem:+$p2s_problem }$p2s_python_old"
  fi
  [ -n "$p2s_problem" ] || return 0
  if [ "$1" = 1 ]; then
    printf '{"schema_version":2,"version":"2.3.0-dev.7","language":"%s","exit_code":2,"has_open":false,"has_unknown":true,"findings":[{"id":"P2S-EXEC001-75568215812df402","rule_id":"P2S-EXEC001","resource":"bootstrap","severity":"unknown","suppressed":false,"status":"UNKNOWN","title":"%s","detail":"%s","remediation":"%s"}],"discovery":{"bootstrap":true,"capabilities":{"tools":{' "$p2s_lang" "$p2s_title" "$p2s_problem" "$p2s_problem"
    p2s_comma=''
    for p2s_tool in python3 ps runuser systemctl; do
      p2s_present=false
      command -v "$p2s_tool" >/dev/null 2>&1 && p2s_present=true
      printf '%s"%s":%s' "$p2s_comma" "$p2s_tool" "$p2s_present"
      p2s_comma=,
    done
    printf '}}}}\n'
  else
    printf '%s\n%s\n' "$p2s_header" "$p2s_problem" >&2
    for p2s_tool in python3 ps runuser systemctl; do
      command -v "$p2s_tool" >/dev/null 2>&1 || printf '%s   %s\n' "$p2s_missing" "$p2s_tool" >&2
    done
    printf '%s\n' "$p2s_helpers" "$p2s_next" >&2
  fi
  return 2
}
if [ "$target" = local ]; then
  bootstrap "$json_mode" "$lang" || exit 2
  payload | python3 -B - "${args[@]}"
  exit "$?"
fi
default_ssh=ssh
[ -x C:/Windows/System32/OpenSSH/ssh.exe ] && default_ssh=C:/Windows/System32/OpenSSH/ssh.exe
ssh_bin=${SSH_BIN:-$default_ssh}
if ! command -v "$ssh_bin" >/dev/null 2>&1; then
  if [ "$json_mode" = 1 ]; then
    detail=$(message 'OpenSSH client is missing; provide the client or set SSH_BIN.' 'OpenSSH-Client fehlt; Client bereitstellen oder SSH_BIN setzen.')
    printf '{"schema_version":2,"version":"2.3.0-dev.7","language":"%s","exit_code":2,"has_open":false,"has_unknown":true,"findings":[{"id":"P2S-EXEC001-9773e1e8b98e2493","rule_id":"P2S-EXEC001","resource":"ssh_transport","severity":"unknown","suppressed":false,"status":"UNKNOWN","title":"SSH","detail":"%s","remediation":"%s"}],"discovery":{}}\n' "$lang" "$detail" "$detail"
  else
    message 'Prerequisite missing: OpenSSH client (or set SSH_BIN).' 'Voraussetzung fehlt: OpenSSH-Client (oder SSH_BIN setzen).' >&2
  fi
  exit 2
fi
remote="$(declare -f bootstrap); bootstrap $json_mode $lang || exit 2; exec python3 -B -"
for argument in "${args[@]}"; do
  escaped=${argument//\'/\'\\\'\'}
  remote+=" '$escaped'"
done
batch=yes
[ -t 2 ] && batch=no
payload | MSYS_NO_PATHCONV=1 "$ssh_bin" -T -o "BatchMode=$batch" -o ConnectTimeout=15 \
  -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -- "$target" "$remote"
result=$?
if [ "$result" = 255 ]; then
  if [ "$json_mode" = 1 ]; then
    detail=$(message 'Target unreachable or login failed; check your existing SSH access and retry.' 'Ziel nicht erreichbar oder Anmeldung fehlgeschlagen; vorhandenen SSH-Zugang prüfen und erneut ausführen.')
    printf '{"schema_version":2,"version":"2.3.0-dev.7","language":"%s","exit_code":2,"has_open":false,"has_unknown":true,"findings":[{"id":"P2S-EXEC001-9773e1e8b98e2493","rule_id":"P2S-EXEC001","resource":"ssh_transport","severity":"unknown","suppressed":false,"status":"UNKNOWN","title":"SSH","detail":"%s","remediation":"%s"}],"discovery":{}}\n' "$lang" "$detail" "$detail"
  else
    message 'SSH connection unavailable. Check your existing SSH access, then run the same command again.' 'SSH-Verbindung nicht verfügbar. Vorhandenen SSH-Zugang prüfen; danach denselben Befehl erneut ausführen.' >&2
  fi
  exit 2
fi
exit "$result"

: <<'__P2S_ENGINE_EOF__'
# __P2S_PYTHON__
# Generated by build-standalone.py; edit the source components in src/.

# Source: src/runtime.py
"""p2s-harden 2: bounded Linux checks and reversible, explicit changes.

The shell launcher streams this standard-library-only module over one SSH
connection. Importing it has no side effects; check/dry-run create no files.
"""
import argparse
import base64
import contextlib
import datetime
import difflib
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:  # Keep --help and the unsupported-platform explanation usable.
    pwd = None
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

VERSION = "2.3.0-dev.7"
DEFAULT_MAX_PATHS = 250000
REQUIRED = frozenset("exec system shell_exec passthru popen proc_open pcntl_exec".split())


class CheckError(RuntimeError):
    pass


class HttpBudgetExceeded(CheckError):
    pass


def configure_output(as_json=False):
    """Use safe terminal encodings; JSON projection supplies Unicode path displays."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            options = dict(errors="backslashreplace")
            if as_json and stream is sys.stdout:
                options["encoding"] = "utf-8"
            reconfigure(**options)


def install_hint(package):
    """Suggestions only; never run a package manager or install anything."""
    try:
        release = Path("/etc/os-release").read_text()
    except OSError:
        release = ""
    identifiers = " ".join(re.findall(r'^ID(?:_LIKE)?=["\']?([^\n"\']+)', release, re.M)).split()
    if any(i in identifiers for i in ("debian", "ubuntu")):
        return f'Install if needed: sudo apt-get install {package}'
    if any(i in identifiers for i in ("fedora", "rhel", "centos", "rocky", "almalinux")):
        return f"Install if needed: sudo dnf install {('procps-ng' if package == 'procps' else package)}"
    if "alpine" in identifiers:
        return f'Install if needed: sudo apk add {package}'
    return f"Install package '{package}' with your package manager if needed"


def capabilities():
    return dict(platform=sys.platform, python=".".join(map(str, sys.version_info[:3])),
                root=os.geteuid() == 0 if hasattr(os, "geteuid") else False,
                proc=Path("/proc/self/stat").is_file(),
                systemd=Path("/run/systemd/system").is_dir(),
                tools={name: shutil.which(name) is not None for name in ("ps", "curl", "runuser", "systemctl")})


def doctor():
    report = Report()
    cap = capabilities()
    report.discovery = dict(doctor=True, capabilities=cap)
    report.add("OK" if sys.platform == "linux" and cap["proc"] else "UNKNOWN", "Linux /proc",
               'available' if sys.platform == "linux" and cap["proc"] else 'A Linux target with readable /proc is required; use --ssh from Windows/macOS', rule_id='P2S-ENV001', resource="platform")
    report.add("OK" if sys.version_info >= (3, 8) else "UNKNOWN", "Python", f"{cap['python']}; version 3.8 or later required", rule_id='P2S-ENV002', resource="python")
    report.add("OK" if cap["root"] else "UNKNOWN", 'Permissions',
               'root: full host audit available' if cap["root"] else 'Readable checks continue; use sudo/root to check other FPM users and apply fixes', rule_id='P2S-ENV003', resource="privileges")
    report.add("INFO", "HTTP backend", "Python standard library; curl is optional, response bodies are not saved", rule_id='P2S-ENV004', resource="http")
    for name, purpose, package in (("runuser", "File permission checks as another FPM user", "util-linux"),):
        report.add("OK" if cap["tools"][name] else "UNKNOWN", name,
                   purpose + ": available" if cap["tools"][name] else purpose + ": missing; " + install_hint(package), rule_id='P2S-ENV005', resource=name)
    report.add("OK", 'FPM process discovery', 'ps available' if cap["tools"]["ps"] else 'ps missing; using the /proc fallback (no installation needed)', rule_id='P2S-ENV006', resource="processes")
    managed = cap["tools"]["systemctl"] and cap["systemd"]
    report.add("OK" if managed else "UNKNOWN", 'Automatic INI fixes',
               'The systemd service mapping can be verified' if managed else 'systemd/systemctl is missing or inactive; the audit continues, automatic INI fixes are blocked', rule_id='P2S-ENV007', resource="service_management")
    return report


def stage(args, message):
    if not getattr(args, "no_progress", False) and (sys.stderr.isatty() or getattr(args, "progress", False)):
        print("[p2s] " + localize(message, getattr(args, "lang", "en")), file=sys.stderr, flush=True)


def process_listing():
    """Use procfs when minimal images lack ps, or ps cannot run."""
    if shutil.which("ps"):
        try:
            return command(["ps", "-eo", "pid=,args="])[0], []
        except CheckError:
            pass
    lines, denied = [], False
    try:
        entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise CheckError('FPM discovery: /proc is unreadable; other checks continue') from exc
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            title = (entry / "cmdline").read_bytes()[:131072].split(b"\0", 1)[0].decode(errors="replace")
            if title.startswith("php-fpm: master process ("):
                lines.append(entry.name + " " + title)
        except PermissionError:
            denied = True
        except OSError:
            pass  # Processes can exit during enumeration.
    issues = ['Some FPM processes cannot be read; use sudo/root'] if denied else []
    return "\n".join(lines), issues


def command(argv, *, env=None, timeout=30):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, env=env,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError(f'Cannot execute {argv[0]}: {type(exc).__name__}') from exc
    if result.returncode:
        # Do not print config dumps, application environment, or HTTP bodies.
        raise CheckError(f'{argv[0]} failed (exit {result.returncode})')
    return result.stdout, result.stderr


def digest(data):
    return hashlib.sha256(data).hexdigest()


def functions(value):
    # Zend splits on commas and ASCII spaces and removes case-sensitive keys.
    return {item for item in re.split(r"[, ]+", value) if item}


def info_values(text):
    values = {}
    for line in text.splitlines():
        if " => " in line:
            key, value = line.split(" => ", 1)
            values[key.strip()] = value.split(" => ", 1)[0].strip()
    return values


def pool_values(text):
    pools, current = {}, None
    for line in text.splitlines():
        match = re.search(r"NOTICE:\s+(.*)$", line)
        if not match:
            continue
        body = match.group(1).strip()
        if re.fullmatch(r"\[[^]]+\]", body):
            current = body[1:-1]
            if current != "global":
                pools[current] = {}
        elif current in pools and "=" in body:
            # strip() removes the trailing space of an empty pool value.
            key, value = body.split("=", 1)
            pools[current][key.strip()] = value.strip()
    if not pools:
        raise CheckError('Cannot parse the FPM pool dump')
    return pools


def active_ini_lines(text, key):
    # Exclude both PHP comment syntaxes, retain only real assignments.
    pattern = re.compile(r"^\s*" + re.escape(key) + r"\s*=")
    return [i for i, line in enumerate(text.splitlines()) if pattern.match(line[1:] if i == 0 and line.startswith("\ufeff") else line)]


def validate_ini_edit(text):
    """Refuse multiline/unclosed quotes anywhere before a line-based edit."""
    for line in text.splitlines():
        quote, escaped = None, False
        if line.lstrip("\ufeff \t").startswith((";", "#")):
            continue
        for char in line:
            if escaped:
                escaped = False
            elif quote and char == "\\":
                escaped = True
            elif quote and char == quote:
                quote = None
            elif quote is None and char in ("'", '"'):
                quote = char
            elif quote is None and char in (";", "#"):
                break
        if quote:
            raise CheckError("Multiline or unclosed INI quotes: automatic changes refused; review the file manually")


def ini_snapshot(text):
    """Hash only PHP's three-column INI tables, never its environment dump."""
    values, table = {}, False
    for line in text.splitlines():
        if line.strip() == "Directive => Local Value => Master Value":
            table = True
            continue
        if not line.strip():
            table = False
            continue
        if not table:
            continue
        parts = line.split(" => ")
        key = parts[0].strip()
        if len(parts) != 3 or key in values or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.-]*", key) is None:
            raise CheckError("PHP INI snapshot is ambiguous; automatic changes refused")
        values[key] = digest(json.dumps(parts[1:], ensure_ascii=True).encode("ascii"))
    if not {"disable_functions", "allow_url_include", "memory_limit"} <= values.keys():
        raise CheckError("Cannot verify the complete PHP INI snapshot; automatic changes refused")
    return values


def set_ini(text, updates):
    validate_ini_edit(text)
    if re.search(r"^\s*\[(?:PATH|HOST)\s*=", text, re.M | re.I):
        raise CheckError('Conditional PATH/HOST INI sections: automatic changes refused')
    lines = text.splitlines(keepends=True)
    newline = next(iter(re.findall(r"\r\n|\n|\r", text)), "\n")
    missing = []
    for key, value in updates.items():
        indices = active_ini_lines("".join(lines), key)
        if indices:
            old = lines[indices[-1]]
            ending = "\r\n" if old.endswith("\r\n") else "\n" if old.endswith("\n") else "\r" if old.endswith("\r") else newline
            bom = "\ufeff" if indices[-1] == 0 and old.startswith("\ufeff") else ""
            lines[indices[-1]] = bom + f"{key} = {value}" + ending
        else:
            missing.append(f"{key} = {value}" + newline)
    if missing:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += newline
        lines.extend([newline + "[PHP]" + newline, *missing])
    return "".join(lines)


def trusted(path):
    """Root-owned, non-writable configuration and ancestors, no symlinks."""
    p = Path(path)
    if not p.is_absolute():
        raise CheckError(f'Absolute path required: {p}')
    for item in [p, *p.parents]:
        st = item.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise CheckError(f'Untrusted path or ancestor: {item}')
        # Linux maps the extended ACL mask to group mode bits. Rejecting
        # group/other write above also rejects writable named-user ACL grants.
    return p


def selected_environment(pid):
    raw = Path(f"/proc/{pid}/environ").read_bytes()
    # Match the master's environment, including variables expanded by INI.
    # Never print or persist this dictionary (it may contain application secrets).
    env = {}
    for item in raw.split(b"\0"):
        key, _, value = item.partition(b"=")
        if key and b"=" not in key:
            env[os.fsdecode(key)] = os.fsdecode(value)
    env["LC_ALL"] = "C"
    return env


def start_identity(pid):
    # /proc comm can contain spaces/parentheses; fields after the last ')' start at 3.
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def discover():
    output, unknown = process_listing()
    instances = []
    for line in output.splitlines():
        m = re.match(r"\s*(\d+)\s+php-fpm: master process \((.+)\)\s*$", line)
        if not m:
            continue
        pid, config = int(m[1]), m[2]
        try:
            host_root, process_root = Path("/").stat(), Path(f"/proc/{pid}/root").stat()
            if (host_root.st_dev, host_root.st_ino) != (process_root.st_dev, process_root.st_ino):
                unknown.append(f'FPM PID {pid}: container or different filesystem namespace')
                continue
            binary = str(Path(f"/proc/{pid}/exe").resolve(strict=True))
            trusted(binary)
            trusted(config)
            env = selected_environment(pid)
            # Only inspect the conventional FPM ini context. Nonstandard
            # provenance cannot be reconstructed from the overwritten title.
            version = re.search(r"php-fpm(\d+\.\d+)$", binary)
            conventional = Path(f"/etc/php/{version[1]}/fpm") if version else None
            if conventional is None or env.get("PHPRC") or env.get("PHP_INI_SCAN_DIR"):
                raise CheckError('Custom INI context: a separate runtime check is required')
            trusted(conventional / "php.ini")
            trusted(conventional / "conf.d")
            extra_inis = []
            for ini in sorted((conventional / "conf.d").glob("*.ini")):
                try:
                    extra_inis.append(trusted(ini.resolve(strict=True)))
                except FileNotFoundError:
                    # PHP ignores dangling *.ini links. Keep the operational
                    # defect visible without inventing a loaded configuration.
                    unknown.append(f'FPM PID {pid}: dangling INI reference {ini}')
            # Includes are untrusted until their full include closure is checked.
            validate_fpm_files(Path(config))
            out, _ = command([binary, "-i"], env=env)
            info = info_values(out)
            loaded = info.get("Loaded Configuration File", "")
            if loaded != str(conventional / "php.ini"):
                raise CheckError('INI context differs from the expected FPM context')
            if info.get("Scan this dir for additional .ini files") != str(conventional / "conf.d"):
                raise CheckError('INI scan directory differs from the expected FPM context')
            inis = [trusted(Path(loaded).resolve(strict=True)), *extra_inis]
            _, dump = command([binary, "-tt", "-y", config], env=env)
            pools = pool_values(dump)
            cgroup = Path(f"/proc/{pid}/cgroup").read_text()
            service = re.search(r"/([A-Za-z0-9_.@-]+\.service)(?:/|$)", cgroup, re.M)
            instances.append(dict(pid=pid, start=start_identity(pid), binary=binary, service=service[1] if service else None,
                                  config=config, inis=[str(p) for p in inis],
                                  values=info, pools=pools, env=env))
        except (OSError, ValueError, CheckError) as exc:
            unknown.append(f"FPM PID {pid}: {exc}")
    if not instances and not unknown:
        unknown.append('No running FPM master found')
    return instances, unknown


def validate_fpm_files(path, seen=None):
    import glob
    seen = set() if seen is None else seen
    pending, total = [(Path(path), 0)], 0
    while pending:
        current, depth = pending.pop()
        current = trusted(current)
        if str(current) in seen:
            continue
        if depth > 64 or len(seen) >= 1024:
            raise CheckError("FPM include coverage limit reached (64 levels / 1024 files)")
        seen.add(str(current))
        with current.open("rb") as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        total += len(raw)
        if len(raw) > 2 * 1024 * 1024 or total > 16 * 1024 * 1024:
            raise CheckError("FPM include byte budget reached (2 MiB per file / 16 MiB total)")
        for line in raw.decode().splitlines():
            match = re.match(r"^\s*include\s*=\s*(.*?)\s*(?:;.*)?$", line)
            if not match:
                continue
            pattern = match[1].strip().strip("\"'")
            if not os.path.isabs(pattern):
                raise CheckError('A relative FPM include requires a manual context check')
            files = []
            for child in glob.iglob(pattern):
                files.append(child)
                if len(files) + len(pending) > 1024:
                    raise CheckError("FPM include coverage limit reached (64 levels / 1024 files)")
            if not files:
                raise CheckError(f'FPM include has no readable target: {pattern}')
            pending.extend((Path(child), depth + 1) for child in sorted(files, reverse=True))


# Source: src/filesystem_http.py
PERMISSION_SCAN = r'''
import json, os, sys, time
root = sys.argv[1]
options = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
runtime = options.get('runtime_dirs', [])
max_paths, max_seconds = options.get('max_paths', 250000), options.get('max_seconds', 10)
result = dict(files=0, directories=0, runtime_directories=0, file_sample=[], directory_sample=[], runtime_sample=[], errors=[], error_count=0)
deadline, visited = time.monotonic() + max_seconds, 0
def error(path):
    result['error_count'] += 1
    if len(result['errors']) < 16: result['errors'].append(path)
def is_runtime(path):
    return any(os.path.commonpath([path, item]) == item for item in runtime)
try:
    if not os.path.isdir(root): raise OSError('Not a directory')
    device, stack = os.stat(root).st_dev, [root]
    while stack:
        if time.monotonic() > deadline:
            error('Filesystem time budget reached; use --walk-seconds or narrow --root')
            break
        parent = stack.pop()
        try:
            if os.stat(parent).st_dev != device:
                error(parent + ' (different filesystem)')
                continue
            if os.access(parent, os.W_OK | os.X_OK):
                key = 'runtime_directories' if is_runtime(parent) else 'directories'
                sample = 'runtime_sample' if key == 'runtime_directories' else 'directory_sample'
                result[key] += 1
                if len(result[sample]) < 6: result[sample].append(parent)
            with os.scandir(parent) as entries:
                for entry in entries:
                    visited += 1
                    if visited > max_paths or time.monotonic() > deadline:
                        error('Filesystem discovery budget reached; use --max-paths/--walk-seconds or narrow --root')
                        stack[:] = []
                        break
                    if entry.is_symlink():
                        error(entry.path + ' (symlink skipped)')
                    elif entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.name.lower().endswith('.php') and os.access(entry.path, os.W_OK):
                        result['files'] += 1
                        if len(result['file_sample']) < 6: result['file_sample'].append(entry.path)
        except OSError:
            error(parent)
except OSError:
    error(root)
print(json.dumps(result))
'''


def as_user(user, argv):
    account = pwd.getpwnam(user)
    if os.geteuid() == account.pw_uid:
        return command(argv, timeout=120)[0]
    if os.geteuid() != 0:
        raise CheckError(f'Cannot switch UID for {user}')
    return command(["runuser", "-u", user, "--", *argv], timeout=120)[0]


def probe(url, connect_ip="127.0.0.1"):
    """Compatibility status-only interface; no external HTTP program needed."""
    return http_observation(url, connect_ip)["status"]


def http_observation(url, connect_ip="127.0.0.1", *, max_bytes=1024 * 1024, timeout=8):
    """Hash a bounded response stream; never store/log response bodies.

    Connect to the explicit local address, send the original Host and TLS SNI,
    ignore proxy environment variables, and never follow redirects. TLS peer
    authenticity is outside this local routing check's scope.
    """
    from urllib.parse import urlsplit
    import ipaddress
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise CheckError('An HTTP(S) URL without credentials is required')
    port = parts.port or (443 if parts.scheme == "https" else 80)
    address = ipaddress.ip_address(connect_ip)
    host = parts.hostname.encode("idna").decode("ascii")
    authority = "[" + host + "]" if ":" in host else host
    if parts.port is not None:
        authority += ":" + str(port)
    connection = http.client.HTTPConnection(host, port=port, timeout=min(3, timeout))
    deadline = time.monotonic() + timeout
    response, timer = None, None
    try:
        connection.sock = socket.create_connection((str(address), port), timeout=min(3, timeout))
        if parts.scheme == "https":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection.sock = context.wrap_socket(connection.sock, server_hostname=host)
        transport = connection.sock
        # A socket timeout alone resets after every received byte. A separate
        # absolute deadline also bounds peers that drip headers/chunks forever.
        def expire():
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(max(0.001, deadline - time.monotonic()), expire)
        timer.daemon = True
        timer.start()
        connection.sock.settimeout(max(0.01, deadline - time.monotonic()))
        connection.request("GET", parts.path or "/", headers={"Host": authority, "Accept-Encoding": "identity",
                           "Connection": "close", "User-Agent": "p2s-harden/" + VERSION})
        response = connection.getresponse()
        if not 100 <= response.status <= 599:
            raise CheckError("Invalid HTTP status")
        size, fingerprint = 0, hashlib.sha256()
        while not response.isclosed():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CheckError("HTTP response time budget exceeded")
            transport.settimeout(remaining)
            chunk = response.read(min(65536, max_bytes - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise CheckError("HTTP response byte budget exceeded")
            fingerprint.update(chunk)
        if time.monotonic() >= deadline:
            raise CheckError("HTTP response time budget exceeded")
        if response.length not in (None, 0):
            raise CheckError("Incomplete HTTP response")
        return dict(status=response.status, bytes=size, sha256=fingerprint.hexdigest())
    except (OSError, ValueError, UnicodeError, http.client.HTTPException) as exc:
        # No exception text: peers may reflect body/header content into errors.
        raise CheckError("HTTP request failed: " + type(exc).__name__) from exc
    finally:
        if timer is not None:
            timer.cancel()
        if response is not None:
            response.close()
        connection.close()


def classify_http(observation, baselines):
    code = observation["status"]
    if code in (401, 403, 404, 410):
        return "OK", str(code)
    if not 200 <= code < 300:
        return "UNKNOWN", str(code) + "; unexpected HTTP status"
    if not baselines or any("error" in row for row in baselines):
        return "UNKNOWN", str(code) + "; missing-path baseline unavailable"
    if all(row["status"] in (401, 403, 404, 410) for row in baselines):
        return "OPEN", str(code) + "; possible file access; missing paths were rejected"
    if not all(200 <= row["status"] < 300 for row in baselines):
        return "UNKNOWN", str(code) + "; ambiguous missing-path baseline"
    signatures = {(row["bytes"], row["sha256"]) for row in baselines}
    signature = observation["bytes"], observation["sha256"]
    if len(signatures) != 1:
        return "UNKNOWN", str(code) + "; dynamic soft-404 fallback; file exposure not established"
    if signature in signatures:
        return "UNKNOWN", str(code) + "; matches soft-404 fallback; file exposure not established"
    return "OPEN", str(code) + "; response differs from missing-path fallback; possible file access"


def git_endpoints(root, *, max_paths=250000, max_seconds=10, max_endpoints=128):
    """Discover sensitive HTTP targets; include every skipped-coverage issue."""
    root = Path(root)
    endpoints, issues, stack = {".git/config", ".env"}, [], [root]
    issue_count = 0
    def issue(message):
        nonlocal issue_count
        issue_count += 1
        if issue_count <= 16:
            issues.append(message)
        elif issue_count == 17:
            issues.append("Additional skipped paths: 1")
        else:
            issues[-1] = "Additional skipped paths: " + str(issue_count - 16)
    deadline, count = time.monotonic() + max_seconds, 0
    device = root.stat().st_dev
    while stack:
        if time.monotonic() > deadline:
            issue("Git discovery budget reached; use --max-paths/--walk-seconds or narrow --root")
            break
        current = stack.pop()
        try:
            if current.stat().st_dev != device:
                issue("Different filesystem skipped: " + str(current))
                continue
            with os.scandir(current) as entries:
                for entry in entries:
                    count += 1
                    if count > max_paths or time.monotonic() > deadline:
                        issue("Git discovery budget reached; use --max-paths/--walk-seconds or narrow --root")
                        return endpoints, issues
                    if entry.is_symlink():
                        issue("Symlink skipped: " + str(Path(entry.path)))
                    elif entry.is_dir(follow_symlinks=False):
                        if entry.name == ".git":
                            if len(endpoints) >= max_endpoints:
                                issue("Git endpoint budget reached; narrow --root")
                                return endpoints, issues
                            endpoints.add((Path(entry.path) / "config").relative_to(root).as_posix())
                        else:
                            stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False) and (
                            entry.name.startswith(".env") or entry.name.lower().endswith((".sql", ".sql.gz", ".bak", ".log"))
                            or entry.name.lower() in ("phpinfo.php", "eval-stdin.php")):
                        endpoint = Path(entry.path).relative_to(root).as_posix()
                        if endpoint not in endpoints and len(endpoints) >= max_endpoints:
                            issue("Sensitive-file endpoint budget reached; narrow --root")
                            return endpoints, issues
                        endpoints.add(endpoint)
        except OSError:
            issue("Unreadable path: " + str(current))
    return endpoints, issues


# Source: src/nginx.py
def nginx_tokens(text):
    """A bounded lexer: quoted braces, comments and ${variables} stay distinct."""
    tokens, word, active, quote, line, word_line = [], [], False, None, 1, 1
    i = 0
    def flush():
        nonlocal word, active
        if active:
            tokens.append(("word", "".join(word), word_line))
            word, active = [], False
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            if i + 1 >= len(text):
                raise CheckError('Nginx: incomplete escape sequence')
            if not active:
                active, word_line = True, line
            following = text[i + 1]
            word.append({"t": "\t", "r": "\r", "n": "\n"}.get(following, following if following in "\\\"' #;{}" else "\\" + following))
            line += int(following == "\n")
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
            else:
                word.append(ch)
                line += int(ch == "\n")
            i += 1
            continue
        if ch in "\"'":
            if not active:
                active, word_line = True, line
            quote = ch
        elif ch == "#":
            flush()
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        elif ch.isspace():
            flush()
            line += int(ch == "\n")
        elif ch == "$" and text[i:i + 2] == "${":
            end = text.find("}", i + 2)
            if end < 0:
                raise CheckError('Nginx: incomplete variable')
            if not active:
                active, word_line = True, line
            word.append(text[i:end + 1])
            i = end
        elif ch in ";{}":
            flush()
            tokens.append(("symbol", ch, line))
        else:
            if not active:
                active, word_line = True, line
            word.append(ch)
        i += 1
        if len(tokens) > 2500000:
            raise CheckError('Nginx: token limit reached')
    if quote:
        raise CheckError('Nginx: unterminated string')
    flush()
    return tokens


def parse_nginx(text, source="<config>"):
    tokens, index = nginx_tokens(text), 0
    def block(depth=0, nested=False):
        nonlocal index
        if depth > 64:
            raise CheckError('Nginx: nesting limit reached')
        nodes = []
        while index < len(tokens):
            if tokens[index][:2] == ("symbol", "}"):
                if not nested:
                    raise CheckError('Nginx: unexpected block end')
                index += 1
                return nodes
            words = []
            start_line = tokens[index][2]
            while index < len(tokens) and tokens[index][0] == "word":
                words.append(tokens[index][1])
                index += 1
            if not words or index == len(tokens):
                raise CheckError(f'Nginx: incomplete directive ({source}:{start_line})')
            kind, symbol, _ = tokens[index]
            index += 1
            if symbol not in (";", "{"):
                raise CheckError(f'Nginx: unexpected delimiter ({source}:{start_line})')
            children = block(depth + 1, True) if symbol == "{" else None
            nodes.append(dict(name=words[0], args=words[1:], children=children,
                              source=source, line=start_line))
        if nested:
            raise CheckError('Nginx: missing block end')
        return nodes
    return block()


class NginxTree(list):
    """Expanded nodes with an optional stable, complete configuration identity."""


def read_nginx(config, partial=False):
    """Read configs, never execute nginx or load modules during discovery."""
    import glob
    config = Path(config)
    prefix, cache, budget = config.parent, {}, [0, 0]
    fingerprints, aliases, expansions = {}, [], []
    def load(path, stack):
        path = Path(path)
        for component in [path, *path.parents]:
            st = component.lstat()
            if st.st_uid != 0 or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022):
                raise CheckError(f'Nginx configuration is not protected by root ownership: {component}')
        resolved = trusted(path.resolve(strict=True))
        aliases.append((str(path), str(resolved)))
        if str(resolved) in stack:
            raise CheckError(f'Nginx: include cycle at {resolved}')
        if str(resolved) not in cache:
            if not resolved.is_file() or resolved.stat().st_size > 1024 * 1024:
                raise CheckError('Nginx: configuration file too large or not a regular file')
            budget[0] += 1
            with resolved.open("rb") as stream:
                before = os.fstat(stream.fileno())
                raw = stream.read(1024 * 1024 + 1)
                after = os.fstat(stream.fileno())
            identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            if len(raw) > 1024 * 1024 or identity(before) != identity(after):
                raise CheckError("Nginx configuration changed while reading")
            text = raw.decode("utf-8")
            fingerprints[str(resolved)] = (identity(after), digest(raw))
            budget[1] += len(text)
            if budget[0] > 2048 or budget[1] > 8 * 1024 * 1024:
                raise CheckError('Nginx: read limit reached')
            cache[str(resolved)] = parse_nginx(text, str(path))
        return expand(cache[str(resolved)], [*stack, str(resolved)])
    def expand(nodes, stack):
        result = []
        def unresolved(node, message):
            result.append(dict(name="__p2s_unresolved_include__", args=[str(message)], children=None,
                               source=node["source"], line=node["line"]))
        for node in nodes:
            if node["name"] == "include" and node["children"] is None:
                if len(node["args"]) != 1 or "$" in node["args"][0]:
                    if not partial:
                        raise CheckError('Nginx: dynamic or invalid include')
                    unresolved(node, 'Nginx: dynamic or invalid include')
                    continue
                pattern = Path(node["args"][0])
                pattern = str(pattern if pattern.is_absolute() else prefix / pattern)
                paths = sorted(glob.glob(pattern))
                expansions.append((pattern, paths))
                if not paths and not glob.has_magic(pattern):
                    if not partial:
                        raise CheckError(f'Nginx include missing: {pattern}')
                    unresolved(node, f'Nginx include missing: {pattern}')
                for child in paths:
                    try:
                        result.extend(load(child, stack))
                    except (OSError, UnicodeError, CheckError) as exc:
                        if not partial:
                            raise
                        unresolved(node, exc)
            else:
                copied = dict(node)
                if node["children"] is not None:
                    copied["children"] = expand(node["children"], stack)
                result.append(copied)
            if len(result) > 100000:
                raise CheckError('Nginx: expansion limit reached')
        return result
    result = NginxTree(load(config, []))
    pending, complete = list(result), True
    while pending:
        node = pending.pop()
        complete &= node["name"] != "__p2s_unresolved_include__"
        pending.extend(node["children"] or [])
    try:
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        complete &= all(identity(Path(path).stat()) == metadata for path, (metadata, fingerprint) in fingerprints.items())
        complete &= all(str(Path(path).resolve(strict=True)) == resolved for path, resolved in aliases)
        complete &= all(sorted(glob.glob(pattern)) == paths for pattern, paths in expansions)
    except OSError:
        complete = False
    if complete:
        # Raw hashes include comments; expanded nodes and glob results bind order,
        # empty globs, source paths, lines and the complete include closure.
        content = dict(main=str(config.absolute()), files=sorted((path, value[1]) for path, value in fingerprints.items()),
                       expansions=expansions, nodes=result)
        result.snapshot_sha256 = digest(json.dumps(content, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"))
    result.snapshot_complete = bool(complete)
    return result


def nginx_inventory(tree):
    from urllib.parse import quote
    inventory = dict(server="nginx", sites=[], roots=[], issues=[], skipped_proxy_servers=0)
    mappings, roots, issues = {}, set(), set()
    def issue(message):
        issues.add(message)
    def values(nodes, name):
        return [n["args"] for n in nodes if n["name"] == name and n["children"] is None]
    def directory(value, source):
        if not value or "$" in value or not Path(value).is_absolute():
            issue(f'{source}: dynamic or relative document path')
            return None
        path = Path(value)
        if not path.is_dir():
            issue(f'{source}: document path missing: {path}')
            return None
        if str(path) == "/" or path.parts[1] in ("etc", "proc", "sys", "dev", "run", "root", "usr"):
            issue(f'{source}: system path excluded from automatic scanning: {path}')
            return None
        if path.is_symlink() or str(path.resolve()) != str(path):
            issue(f'{source}: document path contains symlinks: {path}')
            return None
        roots.add(str(path))
        return str(path)
    def add_mapping(url, path, ip, source):
        if path is not None:
            mappings.setdefault(url, []).append(dict(url=url, root=path, connect_ip=ip, source=source))
    def unresolved(nodes):
        return [n for n in nodes if n["name"] == "__p2s_unresolved_include__"] + [u for n in nodes if n["children"] is not None for u in unresolved(n["children"])]
    for node in unresolved(tree):
        issue(node["args"][0])
    for http in [n for n in tree if n["name"] == "http" and n["children"] is not None]:
        inherited = values(http["children"], "root")
        for server in [n for n in http["children"] if n["name"] == "server" and n["children"] is not None]:
            nodes, source = server["children"], f"{server['source']}:{server['line']}"
            server_roots = values(nodes, "root") or inherited
            root = directory(server_roots[-1][0], source) if server_roots and len(server_roots[-1]) == 1 else None
            if unresolved(nodes):
                issue(f'{source}: server with unresolved includes excluded from automatic HTTP mapping')
                continue
            names = []
            for name in [v for group in values(nodes, "server_name") for v in group]:
                if re.fullmatch(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", name) and ".." not in name:
                    names.append(name.lower())
                else:
                    issue(f'{source}: wildcard, regex or default hostname requires an explicit --site')
            listeners = []
            for args in values(nodes, "listen") or [["80"]]:
                if not args:
                    continue
                address = args[0]
                if address.startswith("unix:") or any(v in args for v in ("quic", "udp")):
                    issue(f'{source}: Unix/UDP listener excluded from HTTP checks')
                    continue
                if address.isdigit():
                    ip, port = "127.0.0.1", int(address)
                elif re.fullmatch(r"(?:\*|0\.0\.0\.0|127\.\d+\.\d+\.\d+):\d+", address):
                    ip, value = address.rsplit(":", 1)
                    ip, port = ("127.0.0.1" if ip in ("*", "0.0.0.0") else ip), int(value)
                elif re.fullmatch(r"\[(?:::|::1)\]:\d+", address):
                    ip, port = "::1", int(address.rsplit(":", 1)[1])
                else:
                    issue(f'{source}: a specific listener requires an explicit local mapping')
                    continue
                if not 1 <= port <= 65535:
                    issue(f'{source}: invalid listener port')
                    continue
                listeners.append(("https" if "ssl" in args else "http", port, ip))
            # Prefer one address per URL: IPv4 if both IPv4 and IPv6 are bound.
            listeners = sorted(set(listeners), key=lambda v: v[2] != "127.0.0.1")
            variants = []
            for name in sorted(set(names)):
                seen = set()
                for scheme, port, ip in listeners:
                    url = f"{scheme}://{name}" + (f":{port}" if port != (443 if scheme == "https" else 80) else "")
                    if url not in seen:
                        variants.append((url, ip))
                        seen.add(url)
            if root is not None:
                for url, ip in variants:
                    add_mapping(url, root, ip, source)
            def locations(children, inherited_root):
                for node in children:
                    if node["children"] is None:
                        continue
                    if node["name"] != "location":
                        if values(node["children"], "root") or values(node["children"], "alias"):
                            issue(f'{source}: conditional document path is ambiguous')
                        continue
                    args, body = node["args"], node["children"]
                    candidate = args[-1] if args else ""
                    own_root, alias = values(body, "root"), values(body, "alias")
                    literal = candidate.startswith("/") and not any(x in candidate for x in ("$", "?", "#")) and args[:1] not in (["~"], ["~*"])
                    chosen_root = own_root[-1][0] if own_root and len(own_root[-1]) == 1 else inherited_root
                    if alias or own_root:
                        if not literal:
                            issue(f'{source}: regex or dynamic location path requires an explicit mapping')
                        else:
                            path = alias[-1][0] if alias and len(alias[-1]) == 1 else str(Path(chosen_root) / candidate.lstrip("/")) if chosen_root else ""
                            # Static file aliases have no directory tree to enumerate.
                            if path and "$" not in path and Path(path).is_file():
                                pass
                            else:
                                path = directory(path, source)
                                for url, ip in variants:
                                    add_mapping(url + quote(candidate.rstrip("/"), safe="/"), path, ip, source)
                    locations(body, chosen_root)
            locations(nodes, root)
            if root is None and not any(n["name"] == "location" and any(c["name"] in ("root", "alias") for c in n["children"] or []) for n in nodes):
                if values(nodes, "return"):
                    issue(f'{source}: redirect without a document root does not count as a file check')
                else:
                    inventory["skipped_proxy_servers"] += 1
                    issue(f'{source}: proxy or missing document root requires a separate backend audit')
    for url, entries in sorted(mappings.items()):
        if len({e["root"] for e in entries}) > 1:
            issue(f'Ambiguous document root for {url}; automatic HTTP check skipped')
        else:
            inventory["sites"].append(entries[0])
    inventory["roots"], inventory["issues"] = sorted(roots), sorted(issues)
    return inventory


def minimal_roots(paths):
    result = []
    for path in sorted(set(paths), key=lambda p: (len(Path(p).parts), p)):
        if not any(os.path.commonpath([path, parent]) == parent for parent in result):
            result.append(path)
    return result


def prepare_scope(args):
    """Derive read-only scope; never infer chmod/chown targets from discovery."""
    explicit_root, explicit_sites = args.root, list(args.site)
    inventory = dict(server=None, sites=[], roots=[], issues=[])
    if not explicit_sites and not args.no_auto:
        candidates = [Path(args.nginx_config)] if args.nginx_config else [p for p in map(Path, ("/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/usr/local/etc/nginx/nginx.conf")) if p.is_file()]
        if len(candidates) == 1:
            try:
                args.nginx_tree = read_nginx(candidates[0], partial=True)
                inventory = nginx_inventory(args.nginx_tree)
                inventory["config"] = str(candidates[0])
            except (OSError, UnicodeError, CheckError) as exc:
                inventory["issues"].append(f'Automatic Nginx discovery incomplete: {exc}')
        else:
            inventory["issues"].append('No unique Nginx main configuration; specify --nginx-config or --site/--root')
    sites, roots, addresses = [], [], {}
    if explicit_sites:
        sites = explicit_sites
        for site in sites:
            if "=" in site and Path(site.split("=", 1)[1]).is_absolute():
                roots.append(site.split("=", 1)[1])
    else:
        entries = inventory["sites"]
        if explicit_root:
            entries = [e for e in entries if os.path.commonpath([e["root"], explicit_root]) == explicit_root]
        # Prefer HTTPS, then shorter/root mappings before nested aliases.
        from urllib.parse import urlsplit
        entries = sorted(entries, key=lambda e: (bool(urlsplit(e["url"]).path), not e["url"].startswith("https://"), e["url"]))
        if len(entries) > args.max_sites and getattr(args, "mode", None) != "scan-webshells":
            inventory["issues"].append(f'HTTP limit: {len(entries) - args.max_sites} mappings omitted; increase --max-sites or narrow the scope with --site')
        for entry in entries[:args.max_sites]:
            sites.append(entry["url"] + "=" + entry["root"])
            addresses[entry["url"]] = entry["connect_ip"]
        roots = inventory["roots"]
    if explicit_root:
        roots = [explicit_root]
    if not roots:
        roots = ["/var/www"]
        inventory["issues"].append('No unique document root; /var/www is only an explicitly reported filesystem fallback')
    args.roots, args.site, args.site_addresses = minimal_roots(roots), sites, addresses
    args.root = explicit_root or args.roots[0]
    inventory["scan_roots"], inventory["selected_sites"] = args.roots, sites
    inventory["automatic_changes"] = 'No permission-change targets inferred from discovery'
    args.discovery = inventory
    return args


def prepare_runtime_dirs(args):
    valid, issues = [], []
    for name in getattr(args, "runtime_dir", []):
        path = Path(os.path.normpath(name))
        try:
            if not path.is_absolute() or not path.is_dir() or path.resolve(strict=True) != path:
                raise CheckError("Runtime directory must be an existing absolute path without symlinks: " + name)
            if not any(os.path.commonpath([str(path), root]) == root and str(path) != root for root in getattr(args, "roots", [args.root])):
                raise CheckError("Runtime directory must be a strict subdirectory of the selected roots: " + name)
            valid.append(str(path))
        except (OSError, ValueError, CheckError) as exc:
            issues.append(str(exc))
    args.runtime_dirs = sorted(set(valid))
    if not hasattr(args, "discovery"):
        args.discovery = {}
    args.discovery["runtime_dirs"] = args.runtime_dirs
    args.discovery.setdefault("issues", []).extend(issues)


# Source: src/messages.py
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

_MESSAGES.update({
    'Baseline requires_review marker must be true': ('Baseline requires_review marker must be true', 'Baseline-Markierung requires_review muss true sein'),
    'Write a new private baseline draft; every entry is unreviewed and accepts nothing': ('Write a new private baseline draft; every entry is unreviewed and accepts nothing', 'Neue private Baseline-Vorlage schreiben; alle Einträge sind ungeprüft und geben nichts frei'),
    '--write-baseline-draft supports --scan-webshells only': ('--write-baseline-draft supports --scan-webshells only', '--write-baseline-draft unterstützt nur --scan-webshells'),
    '--write-baseline-draft contains local paths and hashes; use it locally without --redact': ('--write-baseline-draft contains local paths and hashes; use it locally without --redact', '--write-baseline-draft enthält lokale Pfade und Hashes; lokal ohne --redact verwenden'),
    'Unreviewed baseline draft written; compare complete files with trusted source before setting reviewed=true; existing files are never overwritten': ('Unreviewed baseline draft written; compare complete files with trusted source before setting reviewed=true; existing files are never overwritten', 'Ungeprüfter Baseline-Entwurf geschrieben; vollständige Dateien vor reviewed=true mit vertrauenswürdigem Quellstand vergleichen; vorhandene Dateien werden nie überschrieben'),
    'Baseline draft was not written; Draft destination exists, is unsafe or is not writable': ('Baseline draft was not written; Draft destination exists, is unsafe or is not writable', 'Baseline-Entwurf nicht geschrieben; Ziel existiert bereits, ist unsicher oder nicht beschreibbar'),
    'Unreviewed baseline draft: compare complete files with trusted source and set reviewed=true explicitly': ('Unreviewed baseline draft: compare complete files with trusted source and set reviewed=true explicitly', 'Ungeprüfter Baseline-Entwurf: vollständige Dateien mit vertrauenswürdigem Quellstand vergleichen und reviewed=true ausdrücklich setzen'),
    'Baseline path encoding requires matching path_bytes_hex': ('Baseline path encoding requires matching path_bytes_hex', 'Baseline-Pfadkodierung benötigt passende path_bytes_hex'),
    'Invalid baseline path byte encoding': ('Invalid baseline path byte encoding', 'Ungültige Byte-Kodierung des Baseline-Pfads'),
    'Baseline display path does not match its exact bytes': ('Baseline display path does not match its exact bytes', 'Angezeigter Baseline-Pfad passt nicht zu seinen exakten Bytes'),
    'Baseline draft entry limit exceeded; narrow the scan scope': ('Baseline draft entry limit exceeded; narrow the scan scope', 'Eintragslimit des Baseline-Entwurfs überschritten; Prüfbereich einschränken'),
    'Baseline draft exceeds 2 MiB; narrow the scan scope': ('Baseline draft exceeds 2 MiB; narrow the scan scope', 'Baseline-Entwurf überschreitet 2 MiB; Prüfbereich einschränken'),
    'Baseline draft requires a new file path': ('Baseline draft requires a new file path', 'Baseline-Entwurf benötigt einen neuen Dateipfad'),
})
_MESSAGES.update({
    'Residual PHP capabilities': ('Residual PHP capabilities', 'Verbleibende PHP-Möglichkeiten'),
    'Nginx upload execution': ('Nginx upload execution', 'Nginx-Ausführung in Upload-Pfaden'),
    'FPM systemd hardening': ('FPM systemd hardening', 'FPM-systemd-Härtung'),
    'Not disabled by policy': ('Not disabled by policy', 'Durch Policy nicht gesperrt'),
    'Mail helper command': ('Mail helper command', 'Mail-Helferbefehl'),
    'Policy only': ('Policy only', 'Nur Policy'),
    'Assessment': ('Assessment', 'Bewertung'),
    'Storage candidates': ('Storage candidates', 'Speicherkandidaten'),
    'Declared storage': ('Declared storage', 'Deklarierter Speicher'),
    'Worker attestation': ('Worker attestation', 'Worker-Attestierung'),
    'Configuration only': ('Configuration only', 'Nur Konfiguration'),
    'No verified active systemd context; service hardening is not assessed. Audit the actual service/container boundary separately.': ('No verified active systemd context; service hardening is not assessed. Audit the actual service/container boundary separately.', 'Kein verifizierter aktiver systemd-Kontext; Diensthärtung nicht bewertet. Tatsächliche Dienst-/Container-Grenze separat prüfen.'),
    'Active FPM service properties could not be verified; inspect systemctl show and the running worker boundary separately. No unit is changed.': ('Active FPM service properties could not be verified; inspect systemctl show and the running worker boundary separately. No unit is changed.', 'Properties des aktiven FPM-Dienstes nicht verifiziert; systemctl show und laufende Worker-Grenzen separat prüfen. Keine Unit wird geändert.'),
    'A static rejection guards the selected upload URI prefix in this parsed server block; alternate application includes and live-worker/network enforcement are not attested. No upload file or HTTP probe is created.': ('A static rejection guards the selected upload URI prefix in this parsed server block; alternate application includes and live-worker/network enforcement are not attested. No upload file or HTTP probe is created.', 'Eine statische Ablehnung schützt das ausgewählte Upload-URI-Präfix in diesem geparsten Serverblock; alternative Anwendungs-Includes und Durchsetzung in Workern/im Netz sind nicht attestiert. Keine Upload-Datei oder HTTP-Probe wird erstellt.'),
    'An upload PHP URI has a FastCGI script mapping in the parsed configuration. An existing uploaded PHP file may execute; live application reachability is not tested. No upload file or HTTP probe is created.': ('An upload PHP URI has a FastCGI script mapping in the parsed configuration. An existing uploaded PHP file may execute; live application reachability is not tested. No upload file or HTTP probe is created.', 'Eine Upload-PHP-URI hat eine FastCGI-Skriptzuordnung in der geparsten Konfiguration. Eine vorhandene hochgeladene PHP-Datei könnte ausgeführt werden; Erreichbarkeit der laufenden Anwendung ist nicht geprüft. Keine Upload-Datei oder HTTP-Probe wird erstellt.'),
    'Upload execution could not be established from the supported static Nginx subset; inspect aliases, regex order, nested locations and internal redirects manually. No upload file or HTTP probe is created.': ('Upload execution could not be established from the supported static Nginx subset; inspect aliases, regex order, nested locations and internal redirects manually. No upload file or HTTP probe is created.', 'Upload-Ausführung ließ sich mit der unterstützten statischen Nginx-Teilmenge nicht feststellen; Aliase, Regex-Reihenfolge, verschachtelte Locations und interne Umleitungen manuell prüfen. Keine Upload-Datei oder HTTP-Probe wird erstellt.'),
    'No parsed Nginx configuration for upload checks; provide --nginx-config and declare storage with --runtime-dir. No upload file or HTTP probe is created.': ('No parsed Nginx configuration for upload checks; provide --nginx-config and declare storage with --runtime-dir. No upload file or HTTP probe is created.', 'Keine geparste Nginx-Konfiguration für Upload-Prüfungen; --nginx-config angeben und Speicher mit --runtime-dir deklarieren. Keine Upload-Datei oder HTTP-Probe wird erstellt.'),
    "No upload storage identified; use --runtime-dir for actual writable storage. Directory names alone do not establish an application's upload paths.": ("No upload storage identified; use --runtime-dir for actual writable storage. Directory names alone do not establish an application's upload paths.", 'Kein Upload-Speicher identifiziert; tatsächlichen beschreibbaren Speicher mit --runtime-dir angeben. Verzeichnisnamen allein belegen keine Upload-Pfade einer Anwendung.'),
    'Declared storage has no unambiguous static Nginx root mapping; inspect aliases and the intended virtual host manually.': ('Declared storage has no unambiguous static Nginx root mapping; inspect aliases and the intended virtual host manually.', 'Deklarierter Speicher hat keine eindeutige statische Nginx-Root-Zuordnung; Aliase und beabsichtigten vHost manuell prüfen.'),
    'Upload mapping limit reached; narrow the selected scope.': ('Upload mapping limit reached; narrow the selected scope.', 'Limit der Upload-Zuordnungen erreicht; ausgewählten Bereich einschränken.'),
})
_MESSAGES.update({
    'Function restrictions are not a sandbox. Function availability and indirect execution are not tested; dl is unavailable in FPM. Mail, environment and file APIs may be required by the application. No extra functions or settings are changed.': ('Function restrictions are not a sandbox. Function availability and indirect execution are not tested; dl is unavailable in FPM. Mail, environment and file APIs may be required by the application. No extra functions or settings are changed.', 'Funktionssperren sind keine Sandbox. Verfügbarkeit und indirekte Ausführung sind nicht geprüft; dl ist in FPM nicht verfügbar. Mail-, Umgebungs- und Datei-APIs können für die Anwendung nötig sein. Keine zusätzlichen Funktionen oder Einstellungen werden geändert.'),
    'Manager-reported policy only; existing workers, exceptions and kernel enforcement are not attested. Review application writes, mail and shared temporary-file requirements before changing a service. No unit is changed.': ('Manager-reported policy only; existing workers, exceptions and kernel enforcement are not attested. Review application writes, mail and shared temporary-file requirements before changing a service. No unit is changed.', 'Nur vom Manager gemeldete Policy; bestehende Worker, Ausnahmen und Kernel-Durchsetzung sind nicht attestiert. Vor Dienständerungen Schreibbedarf, Mail und gemeinsam genutzte temporäre Dateien prüfen. Keine Unit wird geändert.'),
    'disable_functions is defense in depth, not isolation. Review mail/helper commands, environment and file access, FFI policy and OS confinement against application requirements. Policy does not prove function availability or exploitability. No extra functions are disabled automatically.': ('disable_functions is defense in depth, not isolation. Review mail/helper commands, environment and file access, FFI policy and OS confinement against application requirements. Policy does not prove function availability or exploitability. No extra functions are disabled automatically.', 'disable_functions ist zusätzliche Härtung, keine Isolation. Mail-Helfer, Umgebungs-/Dateizugriff, FFI-Policy und OS-Grenzen nach Anwendungsbedarf prüfen. Policy belegt weder Verfügbarkeit noch Ausnutzbarkeit. Keine zusätzlichen Funktionen werden automatisch gesperrt.'),
    'Keep untrusted uploads outside executable code paths. Review an explicit Nginx rejection for upload PHP and all aliases/locations, validate with nginx -t and test the real virtual hosts. This tool changes no Nginx configuration and creates no upload probes.': ('Keep untrusted uploads outside executable code paths. Review an explicit Nginx rejection for upload PHP and all aliases/locations, validate with nginx -t and test the real virtual hosts. This tool changes no Nginx configuration and creates no upload probes.', 'Nicht vertrauenswürdige Uploads von ausführbarem Code trennen. Explizite Nginx-Sperre samt Aliasen/Locations prüfen, mit nginx -t validieren und tatsächliche vHosts testen. Das Tool ändert Nginx nicht und erstellt keine Upload-Proben.'),
    'Review NoNewPrivileges, ProtectSystem and PrivateTmp for the actual FPM unit, including write exceptions, shared temporary files and mail compatibility. Inspect worker/kernel enforcement separately. These options do not prevent all execution; this tool changes no systemd unit.': ('Review NoNewPrivileges, ProtectSystem and PrivateTmp for the actual FPM unit, including write exceptions, shared temporary files and mail compatibility. Inspect worker/kernel enforcement separately. These options do not prevent all execution; this tool changes no systemd unit.', 'NoNewPrivileges, ProtectSystem und PrivateTmp für die tatsächliche FPM-Unit prüfen, einschließlich Schreibausnahmen, temporärer Dateien und Mail-Kompatibilität. Worker-/Kernel-Durchsetzung separat prüfen. Die Optionen verhindern nicht jede Ausführung; das Tool ändert keine Unit.'),
})
_MESSAGE_TEMPLATES = (('Residual PHP capabilities {config}', 'Residual PHP capabilities {config}', 'Verbleibende PHP-Möglichkeiten {config}'), ('FPM systemd hardening {config}', 'FPM systemd hardening {config}', 'FPM-systemd-Härtung {config}'), ('Nginx upload execution {path}', 'Nginx upload execution {path}', 'Nginx-Ausführung in Upload-Pfaden {path}')) + (('Additional skipped paths: {count}', 'Additional skipped paths: {count}', 'Weitere ausgelassene Pfade: {count}'),
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
    "Exit precedence: complete (UNKNOWN first) or open (OPEN first); unacknowledged unknowns never pass": "Exit-Vorrang: complete (UNKNOWN zuerst) oder open (OPEN zuerst); nicht akzeptierte unbekannte Ergebnisse bestehen nie",
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
_WS_GERMAN = {
    "Seconds per walk: audit 10, webshell scan 120; scan only: 0 disables root time limit": "Sekunden je Suchlauf: Audit 10, Webshell-Suche 120; nur Suche: 0 hebt Wurzel-Zeitlimit auf",
    "Webshell time budget per file (default 2 seconds; maximum 30)": "Webshell-Zeitlimit je Datei (Standard 2 Sekunden; höchstens 30)",
    "Reviewed webshell JSON baseline; exact path, SHA256 and indicator matches only": "Geprüfte Webshell-JSON-Baseline; nur identischer Pfad, SHA256 und Indikator",
    "Webshell scan byte limit per root (default 268435456)": "Webshell-Datenlimit je Wurzel (Standard 268435456)",
    "Webshell --walk-seconds must be 0 or between 0.05 and 86400": "Webshell --walk-seconds muss 0 sein oder zwischen 0.05 und 86400 liegen",
    "--scan-file-seconds must be between 0.05 and 30": "--scan-file-seconds muss zwischen 0.05 und 30 liegen",
    "--baseline supports --scan-webshells only": "--baseline unterstützt nur --scan-webshells",
    "PHP code review": "PHP-Code prüfen",
    "Webshell baseline": "Webshell-Baseline",
    "Indirect input in a constant-prefixed PHP include requires review": "Indirekte Eingabe in PHP-Include mit konstantem Präfix muss geprüft werden",
    "Request-selected registry callback requires review": "Durch Request gewählter Registry-Callback muss geprüft werden",
    "Attempted files": "Berücksichtigte Dateien", "Incomplete files": "Unvollständige Dateien",
    "Baseline accepted": "Durch Baseline akzeptiert", "Baseline entries": "Baseline-Einträge",
    "Omitted coverage paths": "Nicht aufgelistete Abdeckungspfade", "Coverage counts": "Abdeckungszähler", "Review required": "Prüfung erforderlich",
    "Incomplete path ({reason}): {path}": "Unvollständiger Pfad ({reason}): {path}",
    "More incomplete paths: use --verbose or --json": "Weitere unvollständige Pfade: --verbose oder --json verwenden",
    "Coverage path list truncated at 1000 entries per root; narrow --root to resolve remaining paths": "Abdeckungsliste auf 1000 Einträge je Wurzel begrenzt; --root zur Aufklärung restlicher Pfade eingrenzen",
    "Baseline accepted: {count} unchanged indicator rows; --verbose or --json retains them": "Baseline akzeptiert: {count} unveränderte Indikatorzeilen; --verbose oder --json zeigt sie weiter",
    "Reviewed baseline loaded; exact path, SHA256 and indicator matches only; coverage is never accepted": "Geprüfte Baseline geladen; nur identischer Pfad, SHA256 und Indikator; Prüflücken werden nie akzeptiert",
    "Baseline must be a local, nonredacted webshell report or schema 1 file list": "Baseline muss lokaler unmaskierter Webshell-Bericht oder Schema-1-Dateiliste sein",
    "Baseline finding limit exceeded or invalid finding list": "Baseline-Befundlimit überschritten oder ungültige Befundliste",
    "Invalid baseline finding": "Ungültiger Baseline-Befund", "Invalid baseline resource": "Ungültige Baseline-Ressource",
    "Invalid baseline entry": "Ungültiger Baseline-Eintrag", "Conflicting baseline entries": "Widersprüchliche Baseline-Einträge",
    "Baseline entry limit exceeded or invalid file list": "Baseline-Eintragslimit überschritten oder ungültige Dateiliste",
    "Baseline entries require an absolute canonical path, SHA256 and known indicator names": "Baseline-Einträge erfordern absoluten kanonischen Pfad, SHA256 und bekannte Indikatoren",
    "Baseline and ancestors must be owned by root/current user without group/other write access": "Baseline und Elternpfade müssen root/aktuellem Benutzer gehören und dürfen für Gruppe/andere nicht schreibbar sein",
    "Baseline must be a regular file": "Baseline muss reguläre Datei sein",
    "Baseline must be a regular JSON file no larger than 2 MiB": "Baseline muss reguläre JSON-Datei mit höchstens 2 MiB sein",
    "Baseline changed while reading": "Baseline wurde beim Lesen geändert",
    "Baseline path is unreadable or unsafe": "Baseline-Pfad ist unlesbar oder unsicher",
    "Baseline JSON or encoding is invalid": "Baseline-JSON oder Zeichenkodierung ist ungültig",
    "Review this include/callback in application context and compare with trusted source. A constant prefix or registry lookup is not proof of safety; traversal or an attacker-controlled registry can still be dangerous.": "Include/Callback im Anwendungskontext und anhand vertrauenswürdiger Quellen prüfen. Konstanter Präfix oder Registry-Zugriff belegt keine Sicherheit; Traversal oder eine angreiferkontrollierte Registry kann gefährlich bleiben.",
    "Use only a reviewed, protected local baseline. Only identical path, SHA256 and indicator matches are accepted; changed files and coverage gaps remain findings.": "Nur geprüfte geschützte lokale Baseline verwenden. Nur identischer Pfad, SHA256 und Indikator werden akzeptiert; geänderte Dateien und Prüflücken bleiben Befunde.",
    "PHP webshell indicator scan": "PHP-Webshell-Indikatorprüfung",
    "--redact supports --check, --doctor, --discover and --scan-webshells; review change previews locally without redaction": "--redact unterstützt --check, --doctor, --discover und --scan-webshells; Änderungsvorschauen lokal ohne Maskierung prüfen",
    "Read-only PHP webshell indicator scan; no FPM service required": "PHP-Webshell-Indikatoren lesend prüfen; kein FPM-Dienst erforderlich",
    "Webshell scan byte limit per file (default 2097152)": "Webshell-Datenlimit je Datei (Standard 2097152)",
    "Webshell scan byte limit per root (default 134217728)": "Webshell-Datenlimit je Wurzel (Standard 134217728)",
    "Scanning local files for PHP webshell indicators": "Lokale Dateien auf PHP-Webshell-Indikatoren prüfen",
    "PHP webshell indicator": "PHP-Webshell-Indikator",
    "PHP startup reference": "PHP-Startdatei-Verweis",
    "Webshell scan coverage": "Webshell-Prüfabdeckung",
    "Indicators": "Indikatoren", "Line": "Zeile", "Examined files": "Untersuchte Dateien",
    "Indicator count": "Indikatorzahl", "Coverage reasons": "Abdeckungshinweise",
    "selected scan completed": "Ausgewählter Suchlauf abgeschlossen",
    "Request data near a code/command execution sink": "Request-Daten nahe einer Code-/Befehlsausführung",
    "Decoder output near a PHP code execution sink": "Decoder-Ausgabe nahe einer PHP-Code-Ausführung",
    "Request data near a PHP include/require": "Request-Daten nahe einem PHP-Include/Require",
    "Request-selected dynamic function call": "Durch Request gewählter dynamischer Funktionsaufruf",
    "Network connection and shell launch in one PHP file": "Netzwerkverbindung und Shell-Start in derselben PHP-Datei",
    "PHP startup-file directive requires verification": "PHP-Startdatei-Direktive muss geprüft werden",
    "Preserve the file and relevant logs; compare with a trusted deployment and review the reported line. An indicator is not a malware verdict. If compromise is confirmed, isolate and rebuild from trusted sources, close the entry point and rotate exposed credentials.": "Datei und relevante Logs sichern; mit vertrauenswürdigem Deployment vergleichen und gemeldete Zeile prüfen. Ein Indikator ist kein Malware-Nachweis. Bei bestätigter Kompromittierung isolieren, aus vertrauenswürdigen Quellen neu aufsetzen, Einstiegslücke schließen und betroffene Zugangsdaten erneuern.",
    "Verify the startup directive against trusted application configuration and inspect its target separately. A legitimate preload is possible; no file is changed automatically.": "Startdirektive mit vertrauenswürdiger Anwendungskonfiguration vergleichen und ihr Ziel separat prüfen. Ein legitimer Preload ist möglich; Dateien werden nicht automatisch geändert.",
    "Review coverage reasons, permissions and scan limits; scan skipped paths separately. A completed indicator scan cannot establish that a server is clean.": "Abdeckungshinweise, Rechte und Suchlimits prüfen; ausgelassene Pfade separat untersuchen. Ein abgeschlossener Indikator-Suchlauf belegt keinen sauberen Server.",
    "--scan-file-bytes must be between 1024 and 16777216": "--scan-file-bytes muss zwischen 1024 und 16777216 liegen",
    "--scan-total-bytes must be between 1024 and 1073741824": "--scan-total-bytes muss zwischen 1024 und 1073741824 liegen",
}
_POOL_TEMPLATES.update({
    "PHP code review {path}": "PHP-Code prüfen {path}",
    "Baseline could not be validated; no baseline entries accepted; scan continues; {message}": "Baseline nicht validierbar; keine Einträge akzeptiert; Suche läuft weiter; {message}",
    "{files} files fully examined; {incomplete} incomplete files; {indicators} indicators; {message}; absence of indicators does not establish a clean server": "{files} Dateien vollständig untersucht; {incomplete} unvollständige Dateien; {indicators} Indikatoren; {message}; fehlende Indikatoren belegen keinen sauberen Server",
    "PHP file indicator {path}": "PHP-Datei-Indikator {path}",
    "Line {line}: {message}; SHA256 {sha256}": "Zeile {line}: {message}; SHA256 {sha256}",
    "{files} files examined; {indicators} indicators; {message}; absence of indicators does not establish a clean server": "{files} Dateien untersucht; {indicators} Indikatoren; {message}; fehlende Indikatoren belegen keinen sauberen Server",
    "incomplete: {reasons}": "unvollständig: {reasons}",
})
_NEW_GERMAN.update(_WS_GERMAN)
_EVIDENCE_GERMAN.update(access="Zugriff", symlink="Symlink", mount="Dateisystemgrenze", special="Spezialdatei",
    changed="Datei geändert", depth="Verzeichnistiefe", entries="Eintragslimit", time="Zeitlimit",
    **{"file-size":"Dateigröße", "file-time":"Datei-Zeitlimit", "total-bytes":"Gesamtdatenlimit", "tokens":"Tokenlimit", "expression":"Ausdruckslimit", "findings":"Befundlimit", "config-syntax":"Konfigurationssyntax"})
_MESSAGE_TEMPLATES += tuple((en, en, de) for en, de in _POOL_TEMPLATES.items())

_NEW_GERMAN.update({
    "Skip lowering CPU/I/O priority for the webshell scan": "CPU-/I/O-Priorität für Webshell-Suche nicht absenken",
    "--no-nice supports --scan-webshells only": "--no-nice unterstützt nur --scan-webshells",
    "PHP parsing byte limit per file; opener search streams larger files (default 2097152)": "PHP-Parserlimit je Datei; größere Dateien werden nach Tags durchsucht (Standard 2097152)",
    "Exit precedence: complete (UNKNOWN first), open (OPEN first), review (OPEN or code review first); unacknowledged unknowns never pass": "Exit-Vorrang: complete (UNKNOWN zuerst), open (OPEN zuerst), review (OPEN oder Code-Review zuerst); nicht akzeptierte unbekannte Ergebnisse bestehen nie",
    "Suppress one finding/rule's OPEN or code-review exit impact; keep it visible; repeatable": "OPEN- oder Review-Exitwirkung eines Befunds/einer Regel ausnehmen; bleibt sichtbar; wiederholbar",
    "Another fix or rollback is using this backup root; wait for it to finish and rerun": "Ein anderer Fix oder Rollback verwendet dieses Backup-Verzeichnis; Abschluss abwarten und erneut ausführen",
    "Backup directory must have mode 0700 and be owned by root": "Backup-Verzeichnis muss root gehören und Modus 0700 haben",
    "Backup directory changed while acquiring transaction lock": "Backup-Verzeichnis wurde beim Erwerb der Transaktionssperre ausgetauscht",
    "Scan scheduling": "Scan-Priorität",
    "CPU priority": "CPU-Priorität",
    "I/O priority": "I/O-Priorität",
    "Scans lower CPU priority to at least nice 10 and request idle I/O with optional ionice. Missing/denied helpers do not stop checks; --no-nice opts out. Scheduling is not a hard resource limit.": "Scans senken CPU-Priorität auf mindestens nice 10 und fordern Idle-I/O mit optionalem ionice an. Fehlende/gesperrte Helfer stoppen keine Prüfungen; --no-nice deaktiviert dies. Prioritäten sind kein festes Ressourcenlimit.",
    "CPU: {cpu}; I/O: {io}; missing or denied priority helpers do not stop the scan; --no-nice opts out": "CPU: {cpu}; I/O: {io}; fehlende oder gesperrte Prioritätshelfer stoppen die Suche nicht; --no-nice deaktiviert dies"
})
_MESSAGE_TEMPLATES += (('CPU: {cpu}; I/O: {io}; missing or denied priority helpers do not stop the scan; --no-nice opts out', 'CPU: {cpu}; I/O: {io}; missing or denied priority helpers do not stop the scan; --no-nice opts out', 'CPU: {cpu}; I/O: {io}; fehlende oder gesperrte Prioritätshelfer stoppen die Suche nicht; --no-nice deaktiviert dies'),)
_EVIDENCE_GERMAN.update(lowered="abgesenkt", already_low="bereits niedrig", unavailable="nicht verfügbar", disabled="deaktiviert", idle="Leerlauf")
_NEW_GERMAN.update({
    "Multiline or unclosed INI quotes: automatic changes refused; review the file manually": "Mehrzeilige oder offene INI-Anführungszeichen: automatische Änderungen verweigert; Datei manuell prüfen",
    "PHP INI snapshot is ambiguous; automatic changes refused": "Effektive PHP-INI-Werte nicht eindeutig lesbar; automatische Änderungen verweigert",
    "Cannot verify the complete PHP INI snapshot; automatic changes refused": "Effektive PHP-INI-Werte nicht vollständig prüfbar; automatische Änderungen verweigert",
    "Complete FPM instances are required for before/after INI verification": "Vollständige FPM-Zuordnung für den INI-Vorher-/Nachhervergleich erforderlich",
    "Unrelated effective PHP INI settings changed; restoring the original configuration before reload": "Andere effektive PHP-INI-Werte wurden verändert; ursprüngliche Konfiguration wird vor dem Reload wiederhergestellt",
    "Transaction lock and backup directories must have mode 0700 and be owned by root": "Transaktionssperr- und Backup-Verzeichnisse müssen root gehören und Modus 0700 haben",
    "Another fix or rollback is running; wait for it to finish and rerun": "Ein anderer Fix oder Rollback läuft; Abschluss abwarten und erneut ausführen",
    "Transaction lock directory changed while acquiring the lock": "Verzeichnis der Transaktionssperre wurde beim Sperren ausgetauscht",
    "Reviewed coverage exceptions require an explicit schema 1 baseline": "Geprüfte Abdeckungsausnahmen benötigen eine explizite Schema-1-Baseline",
    "Baseline requires files or explicit reviewed_files": "Baseline benötigt files oder ausdrücklich reviewed_files",
    "Coverage exceptions require reviewed=true after trusted full-file comparison": "Abdeckungsausnahmen benötigen reviewed=true nach vertrauenswürdigem Vergleich der vollständigen Datei",
    "Reviewed baseline loaded; exact path, full-file SHA256 and indicator/reviewed-coverage matches only": "Geprüfte Baseline geladen; nur exakter Pfad, vollständiger SHA256 und Indikator bzw. geprüfte Abdeckungsausnahme werden akzeptiert",
    "Reviewed incomplete files": "Geprüfte unvollständige Dateien",
    "Windowed files": "Dateien mit Fensteranalyse",
    "Prefixed PHP include": "PHP-Include mit Präfix",
    "Request-derived PHP include with a constant prefix; traversal requires review": "Request-basierter PHP-Include mit konstantem Präfix; Traversal muss geprüft werden",
    "Review the request-derived include and its validation against trusted source. A constant directory prefix does not prevent path traversal; accept only a reviewed exact file hash and indicator.": "Request-basierten Include und Validierung mit vertrauenswürdigem Quellstand vergleichen. Ein konstantes Verzeichnispräfix verhindert keine Pfad-Traversal; nur geprüften exakten Dateihash und Indikator akzeptieren."
})
_MESSAGE_TEMPLATES = (('{files} files fully examined; {incomplete} incomplete files; {indicators} indicators; {message}; {accepted} incomplete files accepted by reviewed full-file hash; absence of indicators does not establish a clean server', '{files} files fully examined; {incomplete} incomplete files; {indicators} indicators; {message}; {accepted} incomplete files accepted by reviewed full-file hash; absence of indicators does not establish a clean server', '{files} Dateien vollständig untersucht; {incomplete} unvollständige Dateien; {indicators} Indikatoren; {message}; {accepted} unvollständige Dateien durch geprüften vollständigen Dateihash akzeptiert; fehlende Indikatoren belegen keinen sauberen Server'),) + _MESSAGE_TEMPLATES
_EVIDENCE_GERMAN.update(window="Fensteranalyse")
_NEW_GERMAN['Use a protected reviewed baseline. Indicator exceptions bind path, full-file SHA256 and indicator. Coverage exceptions additionally require explicit reviewed_files entries; unreadable, unstable, timed-out or unvisited content cannot be accepted.'] = 'Geschützte geprüfte Baseline verwenden. Indikator-Ausnahmen binden Pfad, vollständigen SHA256 und Indikator. Abdeckungsausnahmen benötigen zusätzlich ausdrückliche reviewed_files-Einträge; unlesbare, instabile, zeitlich abgebrochene oder unbesuchte Inhalte können nicht akzeptiert werden.'
_MESSAGES.update({en: (en, de) for en, de in _NEW_GERMAN.items()})
_COMPILED_MESSAGES = [(*_compile_message(source), en, de)
                      for source, en, de in _MESSAGE_TEMPLATES]
_COMPILED_MESSAGES.extend((*_compile_message(en), en, de)
                          for source, en, de in _MESSAGE_TEMPLATES if source != en)


_EVIDENCE_GERMAN.update({'manager_policy': 'Manager-Policy', 'not_assessed': 'nicht bewertet', 'unavailable': 'nicht verfügbar', 'configured': 'konfiguriert', 'empty': 'leer', 'static_directory_rejection': 'statische Präfixsperre', 'php_fastcgi_mapping': 'PHP-FastCGI-Zuordnung', 'unmapped': 'ohne Zuordnung', 'limit': 'Limit', 'redirect_or_conditional': 'Umleitung oder Bedingung', 'nested_location': 'verschachtelte Location', 'unsupported_location': 'nicht unterstützte Location', 'dynamic_path': 'dynamischer Pfad', 'duplicate_location': 'doppelte Location', 'unsupported_regex': 'nicht unterstützte Regex', 'no_proven_handler': 'kein belegter Handler', 'location_filesystem_mapping': 'Location-Dateisystemzuordnung', 'unsupported_directive': 'nicht unterstützte Direktive'})


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

_MESSAGES.update({en: (en, de) for en, de in {'Nginx review': 'Nginx-Review',
 'Review entries': 'Review-Einträge',
 'Reviewed Nginx UNKNOWN exceptions bound to the complete configuration; --check only': 'Reviewte '
                                                                                        'Nginx-UNKNOWN-Ausnahmen '
                                                                                        'mit Bindung an die '
                                                                                        'komplette '
                                                                                        'Konfiguration; nur '
                                                                                        '--check',
 'Create a private unreviewed Nginx UNKNOWN draft; --check only': 'Privaten ungeprüften '
                                                                  'Nginx-UNKNOWN-Entwurf erstellen; nur '
                                                                  '--check',
 'Nginx review options support --check only': 'Nginx-Review-Optionen unterstützen nur --check',
 'Nginx review drafts contain configuration identities; use locally without --redact': 'Nginx-Review-Entwürfe '
                                                                                       'enthalten '
                                                                                       'Konfigurationskennungen; '
                                                                                       'lokal ohne --redact '
                                                                                       'verwenden',
 'Nginx review file is unreviewed, invalid, unsafe or unreadable; no exceptions accepted.': 'Nginx-Review-Datei '
                                                                                            'ist ungeprüft, '
                                                                                            'ungültig, '
                                                                                            'unsicher oder '
                                                                                            'nicht lesbar; '
                                                                                            'keine Ausnahme '
                                                                                            'akzeptiert.',
 'Private unreviewed Nginx draft written; no existing file is overwritten and no exception is accepted automatically.': 'Privaten '
                                                                                                                        'ungeprüften '
                                                                                                                        'Nginx-Entwurf '
                                                                                                                        'geschrieben; '
                                                                                                                        'keine '
                                                                                                                        'vorhandene '
                                                                                                                        'Datei '
                                                                                                                        'überschrieben '
                                                                                                                        'und '
                                                                                                                        'keine '
                                                                                                                        'Ausnahme '
                                                                                                                        'automatisch '
                                                                                                                        'akzeptiert.',
 'Nginx review draft could not be written safely; the audit results are retained.': 'Nginx-Review-Entwurf '
                                                                                    'konnte nicht sicher '
                                                                                    'geschrieben werden; die '
                                                                                    'Prüfergebnisse bleiben '
                                                                                    'erhalten.',
 'Review the complete Nginx include closure and real routes before accepting a draft. An acknowledgement retains UNKNOWN and never proves blocking. Changed configuration invalidates it.': 'Vor '
                                                                                                                                                                                            'Freigabe '
                                                                                                                                                                                            'sämtliche '
                                                                                                                                                                                            'Nginx-Includes '
                                                                                                                                                                                            'und '
                                                                                                                                                                                            'tatsächliche '
                                                                                                                                                                                            'Routen '
                                                                                                                                                                                            'prüfen. '
                                                                                                                                                                                            'Akzeptanz '
                                                                                                                                                                                            'behält '
                                                                                                                                                                                            'UNKNOWN '
                                                                                                                                                                                            'bei '
                                                                                                                                                                                            'und '
                                                                                                                                                                                            'belegt '
                                                                                                                                                                                            'keine '
                                                                                                                                                                                            'Sperre. '
                                                                                                                                                                                            'Konfigurationsänderungen '
                                                                                                                                                                                            'machen '
                                                                                                                                                                                            'sie '
                                                                                                                                                                                            'ungültig.',
 'The upload denial uses .* without DOTALL; a URL-decoded line break can bypass it and select the PHP handler. An upload PHP URI has a FastCGI script mapping in the parsed configuration. An existing uploaded PHP file may execute; live application reachability is not tested. No upload file or HTTP probe is created.': 'Die '
                                                                                                                                                                                                                                                                                                                              'Upload-Sperre '
                                                                                                                                                                                                                                                                                                                              'nutzt '
                                                                                                                                                                                                                                                                                                                              '.* '
                                                                                                                                                                                                                                                                                                                              'ohne '
                                                                                                                                                                                                                                                                                                                              'DOTALL; '
                                                                                                                                                                                                                                                                                                                              'ein '
                                                                                                                                                                                                                                                                                                                              'URL-dekodierter '
                                                                                                                                                                                                                                                                                                                              'Zeilenumbruch '
                                                                                                                                                                                                                                                                                                                              'kann '
                                                                                                                                                                                                                                                                                                                              'sie '
                                                                                                                                                                                                                                                                                                                              'umgehen '
                                                                                                                                                                                                                                                                                                                              'und '
                                                                                                                                                                                                                                                                                                                              'den '
                                                                                                                                                                                                                                                                                                                              'PHP-Handler '
                                                                                                                                                                                                                                                                                                                              'auswählen. '
                                                                                                                                                                                                                                                                                                                              'Eine '
                                                                                                                                                                                                                                                                                                                              'vorhandene '
                                                                                                                                                                                                                                                                                                                              'Upload-PHP-Datei '
                                                                                                                                                                                                                                                                                                                              'könnte '
                                                                                                                                                                                                                                                                                                                              'ausgeführt '
                                                                                                                                                                                                                                                                                                                              'werden; '
                                                                                                                                                                                                                                                                                                                              'tatsächliche '
                                                                                                                                                                                                                                                                                                                              'Erreichbarkeit '
                                                                                                                                                                                                                                                                                                                              'ist '
                                                                                                                                                                                                                                                                                                                              'nicht '
                                                                                                                                                                                                                                                                                                                              'geprüft. '
                                                                                                                                                                                                                                                                                                                              'Keine '
                                                                                                                                                                                                                                                                                                                              'Upload-Datei '
                                                                                                                                                                                                                                                                                                                              'oder '
                                                                                                                                                                                                                                                                                                                              'HTTP-Probe '
                                                                                                                                                                                                                                                                                                                              'wird '
                                                                                                                                                                                                                                                                                                                              'erstellt.'}.items()})

_EVIDENCE_GERMAN.update(ordered_php_rejection="geordnete PHP-Sperre", nested_php_rejection="verschachtelte PHP-Sperre", competing_location="konkurrierende Location", regex_line_break_gap="Regex-Lücke bei Zeilenumbrüchen", configuration_snapshot_incomplete="Konfigurationssnapshot unvollständig")


# Source: src/report_paths.py
"""Interoperable Unicode display with lossless Linux filesystem byte metadata."""


PATH_ENCODING = "utf-8-replacement+bytes-hex"


def unicode_display(value):
    return re.sub(r"[\ud800-\udfff]", "\ufffd", value)


def json_paths(value):
    """Project output only; identities and filesystem operations keep raw paths."""
    if isinstance(value, str):
        return unicode_display(value)
    if isinstance(value, (list, tuple)):
        return [json_paths(item) for item in value]
    if not isinstance(value, dict):
        return value
    # Escaped key spellings avoid collapsing distinct byte-valued map keys.
    result = {re.sub(r"[\ud800-\udfff]", lambda match: "\\u%04x" % ord(match[0]), key) if isinstance(key, str) else key: json_paths(item)
              for key, item in value.items()}
    for key in ("path", "root"):
        path = value.get(key)
        if isinstance(path, str) and re.search(r"[\udc80-\udcff]", path):
            result[key + "_bytes_hex"] = path.encode("utf-8", "surrogateescape").hex()
            result[key + "_encoding"] = PATH_ENCODING
    return result


def baseline_path(entry):
    """Decode exact bytes only if the display spelling and encoding agree."""
    path = entry.get("path")
    if "path_bytes_hex" not in entry:
        if "path_encoding" in entry:
            raise CheckError("Baseline path encoding requires matching path_bytes_hex")
        return path  # Legacy local reports/baselines remain readable.
    raw = entry["path_bytes_hex"]
    if (type(raw) is not str or not 2 <= len(raw) <= 65536 or len(raw) % 2 or
            re.fullmatch(r"[a-f0-9]+", raw) is None or entry.get("path_encoding") != PATH_ENCODING):
        raise CheckError("Invalid baseline path byte encoding")
    decoded = bytes.fromhex(raw).decode("utf-8", "surrogateescape")
    if type(path) is not str or path != unicode_display(decoded):
        raise CheckError("Baseline display path does not match its exact bytes")
    return decoded


# Source: src/report.py
RULES = {
    "ENV001": ("info", "Run on a Linux target with readable /proc; use --ssh from other systems."),
    "ENV002": ("info", "Provide Python 3.8 or later on the Linux target, then rerun."),
    "ENV003": ("info", "Use sudo or an existing root SSH login for complete checks and changes."),
    "ENV004": ("info", "HTTP checks use the Python standard library; no curl installation is needed."),
    "ENV005": ("info", "Use --doctor for the helper's purpose and the suggested package command."),
    "ENV006": ("info", "Process discovery uses /proc when ps is unavailable."),
    "ENV007": ("info", "Automatic INI changes need a matching active systemd FPM service."),
    "DISC001": ("info", "Review discovery issues; supply --nginx-config or explicit --root/--site mappings."),
    "DISC002": ("info", "Check the running FPM master and its protected configuration; unsupported contexts require separate assessment."),
    "DISC003": ("info", "Repair the reported FPM configuration/provenance and rerun; other instances remain independently checked."),
    "DISC004": ("info", "Review skipped paths or increase the traversal budget; no skipped subtree is certified."),
    "PHP001": ("high", "Review --dry-run, test application compatibility, then apply --fix --yes or set the required function restrictions manually."),
    "PHP002": ("high", "Set allow_url_include=Off in the effective FPM INI/pool and reload the matching service."),
    "PHP003": ("medium", "Review a narrow per-pool open_basedir with application testing; it is an additional restriction, not a sandbox."),
    "PHP004": ("high", "Review whether FFI is needed; set ffi.enable=Off in the effective FPM configuration when compatible, then reload and test the application."),
    "PHP005": ("info", "disable_functions is defense in depth, not isolation. Review mail/helper commands, environment and file access, FFI policy and OS confinement against application requirements. Policy does not prove function availability or exploitability. No extra functions are disabled automatically."),
    "NGX001": ("high", "Keep untrusted uploads outside executable code paths. Review an explicit Nginx rejection for upload PHP and all aliases/locations, validate with nginx -t and test the real virtual hosts. This tool changes no Nginx configuration and creates no upload probes."),
    "NGX002": ("info", "Review the complete Nginx include closure and real routes before accepting a draft. An acknowledgement retains UNKNOWN and never proves blocking. Changed configuration invalidates it."),
    "FPM001": ("high", "Prefer a Unix socket or loopback bind; for required TCP access set listen.allowed_clients to the intended proxy IPs and verify firewall/container publication."),
    "FPM002": ("high", "Restrict the Unix socket to the web-server identity, normally mode 0660 or 0600; review named ACL grants and verify the live socket after restart."),
    "FPM003": ("medium", "Set security.limit_extensions=.php after checking application requirements; fix upload execution rules in the web server as well."),
    "FPM004": ("medium", "Use clear_env=yes and declare only required env[] variables; test application configuration before reloading."),
    "FPM005": ("info", "Use distinct Unix accounts and code ownership for mutually untrusted applications; shared pools may be intentional for one trust domain."),
    "FS001": ("high", "Remove PHP-user write access to application code and verify ACLs; keep required runtime data separate."),
    "FS002": ("high", "Separate code from runtime storage; use --runtime-dir only for reviewed storage and --protect-dir only for an explicit code directory."),
    "FS003": ("info", "Resolve the reported user/access/coverage issue or narrow the scope; an incomplete walk cannot pass."),
    "FS004": ("info", "Verify that declared upload/cache paths cannot execute uploaded PHP and cannot replace application code."),
    "FS005": ("high", "Run the FPM pool as a dedicated non-root account and restart the service after reviewing ownership."),
    "HTTP001": ("high", "Deny HTTP access to the reported sensitive file/path, remove public backups/debug scripts, and recheck both HTTP and HTTPS."),
    "HTTP002": ("info", "Provide an explicit --site mapping or sufficient HTTP budget; inspect every unknown result."),
    "HTTP003": ("info", "Correct the URL/document-root mapping and retry the intended local virtual host."),
    "SYS001": ("medium", "Review the host ptrace policy against operational needs; this tool does not change sysctl settings."),
    "SYS002": ("info", "Review NoNewPrivileges, ProtectSystem and PrivateTmp for the actual FPM unit, including write exceptions, shared temporary files and mail compatibility. Inspect worker/kernel enforcement separately. These options do not prevent all execution; this tool changes no systemd unit."),
    "IM001": ("info", "Review ImageMagick policy rules and delegates for the installed version and application requirements."),
    "FIX001": ("info", "Resolve the specific fix preflight blocker, inspect the full proposed diff, and rerun."),
    "TX001": ("info", "Keep the backup ID; a repeated implicit rollback never selects an older transaction."),
    "EXEC001": ("info", "Resolve the execution error and rerun; consult transaction state before retrying a change."),
    "WS001": ("high", "Preserve the file and relevant logs; compare with a trusted deployment and review the reported line. An indicator is not a malware verdict. If compromise is confirmed, isolate and rebuild from trusted sources, close the entry point and rotate exposed credentials."),
    "WS002": ("medium", "Verify the startup directive against trusted application configuration and inspect its target separately. A legitimate preload is possible; no file is changed automatically."),
    "WS003": ("info", "Review coverage reasons, permissions and scan limits; scan skipped paths separately. A completed indicator scan cannot establish that a server is clean."),
    "WS004": ("info", "Review this include/callback in application context and compare with trusted source. A constant prefix or registry lookup is not proof of safety; traversal or an attacker-controlled registry can still be dangerous."),
    "WS005": ("info", "Use a protected reviewed baseline. Indicator exceptions bind path, full-file SHA256 and indicator. Coverage exceptions additionally require explicit reviewed_files entries; unreadable, unstable, timed-out or unvisited content cannot be accepted."),
    "WS006": ("info", "Scans lower CPU priority to at least nice 10 and request idle I/O with optional ionice. Missing/denied helpers do not stop checks; --no-nice opts out. Scheduling is not a hard resource limit."),
    "WS007": ("medium", "Review the request-derived include and its validation against trusted source. A constant directory prefix does not prevent path traversal; accept only a reviewed exact file hash and indicator."),
    "CUSTOM": ("info", "Review this diagnostic in its reported context."),
}


def safe_evidence(rule_id, evidence):
    """Only rule-owned, finite values may survive report redaction."""
    if not isinstance(evidence, dict):
        return {}
    boolean = lambda value: type(value) is bool
    count = lambda value: type(value) is int and 0 <= value <= 1000000
    choices = lambda *allowed: lambda value: type(value) is str and value in allowed
    names = lambda *allowed: lambda value: (type(value) is list and len(value) <= len(allowed)
                                            and all(type(v) is str and v in allowed for v in value))
    fields = {
        "PHP001": dict(missing_functions=names(*sorted(REQUIRED)), affected_pool_count=count),
        "PHP002": dict(allow_url_include=boolean, affected_pool_count=count),
        "PHP003": dict(unrestricted=boolean),
        "PHP004": dict(ffi_policy=choices("off", "on", "preload", "unknown")),
        "PHP005": dict(not_disabled_functions=names(*RESIDUAL_FUNCTIONS), enable_dl=choices("off", "on", "unknown"),
                       sendmail_path=choices("empty", "configured", "unknown"), policy_only=boolean, affected_pool_count=count),
        "NGX001": dict(outcome=choices("not_assessed", "limit", "static_directory_rejection", "php_fastcgi_mapping", "unmapped",
                        "redirect_or_conditional", "nested_location", "unsupported_location", "dynamic_path", "duplicate_location",
                        "unsupported_regex", "no_proven_handler", "location_filesystem_mapping", "unsupported_directive", "ordered_php_rejection", "nested_php_rejection", "competing_location", "regex_line_break_gap", "configuration_snapshot_incomplete"),
                       declared=boolean, candidate_count=count, configuration_only=boolean),
        "NGX002": dict(review_entries=count),
        "SYS002": dict(assessment=choices("not_assessed", "manager_policy", "unavailable"),
                       no_new_privileges=choices("yes", "no"), protect_system=choices("no", "yes", "full", "strict"),
                       private_tmp=choices("no", "yes", "disconnected"), worker_attestation=boolean),
        "FPM001": dict(binding=choices("loopback", "network", "unverified"), client_allowlist=boolean,
                       hostname_resolution=choices("loopback", "non_loopback", "unavailable")),
        "FPM002": dict(socket_mode=lambda value: type(value) is str and re.fullmatch(r"0[0-7]{3}", value) is not None,
                       source=choices("configured", "observed", "acl"), named_acl=boolean),
        "FPM003": dict(unrestricted=boolean, allowed_known_extensions=names(".php", ".phar"), other_extension_count=count),
        "FPM004": dict(clear_env=boolean),
        "FPM005": dict(pool_count=count),
        "FS001": dict(writable_files=count),
        "FS002": dict(writable_directories=count),
        "FS004": dict(runtime_directories=count),
        "HTTP001": dict(http_status=lambda value: type(value) is int and 100 <= value <= 599),
        "SYS001": dict(ptrace_scope=lambda value: type(value) is int and 0 <= value <= 3),
        "WS001": dict(indicators=names(*WEBSHELL_INDICATORS), line=count),
        "WS002": dict(indicators=names("startup-reference"), line=count),
        "WS003": dict(examined_files=count, attempted_files=count, incomplete_files=count, indicator_count=count,
                      baseline_accepted_count=count, accepted_incomplete_files=count, windowed_files=count,
                      omitted_coverage_paths=count, coverage_reasons=names(*WEBSHELL_REASONS),
                      coverage_counts=lambda value: type(value) is dict and len(value) <= len(WEBSHELL_REASONS) and
                          all(type(k) is str and k in WEBSHELL_REASONS and count(v) for k,v in value.items())),
        "WS004": dict(indicators=names("prefixed-include", "registry-callable"), line=count, review_required=boolean),
        "WS005": dict(baseline_entries=count),
        "WS007": dict(indicators=names("request-prefixed-include"), line=count),
        "WS006": dict(cpu_priority=choices("lowered", "already_low", "unavailable", "disabled"),
                      io_priority=choices("idle", "unavailable", "disabled")),
    }.get(rule_id[4:], {})
    return {name: value for name, value in evidence.items() if name in fields and fields[name](value)}


RULE_NAMES = {"PHP001": "Shell function restrictions", "PHP002": "URL includes", "PHP003": "Filesystem restriction",
              "PHP004": "PHP FFI", "PHP005": "Residual PHP capabilities", "NGX001": "Nginx upload execution", "NGX002": "Nginx review", "SYS002": "FPM systemd hardening", "FPM001": "FPM TCP listener", "FPM002": "FPM Unix socket",
              "FPM003": "FPM script extensions", "FPM004": "FPM environment clearing", "FPM005": "Shared FPM account",
              "FS001": "Writable PHP files", "FS002": "Writable directories", "FS004": "Declared runtime storage",
              "HTTP001": "Sensitive HTTP path", "SYS001": "ptrace_scope",
              "WS001": "PHP webshell indicator", "WS002": "PHP startup reference", "WS003": "Webshell scan coverage",
              "WS004": "PHP code review", "WS005": "Webshell baseline", "WS006": "Scan scheduling", "WS007": "Prefixed PHP include"}


def evidence_summary(rule_id, evidence, lang="en"):
    facts = safe_evidence(rule_id, evidence)
    say = lambda value: _EVIDENCE_GERMAN.get(value, value) if lang == "de" else {
        "non_loopback":"outside loopback", "acl":"ACL", "not_assessed":"not assessed", "manager_policy":"manager policy",
        "ordered_php_rejection":"ordered PHP rejection", "nested_php_rejection":"nested PHP rejection", "competing_location":"competing location", "regex_line_break_gap":"regex permits a line-break bypass",
        "static_directory_rejection":"static URI prefix rejected", "php_fastcgi_mapping":"PHP FastCGI mapping",
        "redirect_or_conditional":"redirect or conditional", "nested_location":"nested location", "unsupported_location":"unsupported location",
        "dynamic_path":"dynamic path", "duplicate_location":"duplicate location", "unsupported_regex":"unsupported regex",
        "no_proven_handler":"no proven handler", "location_filesystem_mapping":"location filesystem mapping", "unsupported_directive":"unsupported directive"}.get(value, value)
    labels = dict(missing_functions="Missing", allow_url_include="URL includes", unrestricted="Unrestricted",
                  ffi_policy="ffi.enable", binding="TCP binding", client_allowlist="Client allowlist",
                  hostname_resolution="Name resolution", socket_mode="Socket mode", source="Source",
                  named_acl="Named ACL", allowed_known_extensions="Known script extensions",
                  other_extension_count="Other script extensions", clear_env="clear_env", pool_count="Pools",
                  writable_files="Writable PHP files", writable_directories="Writable directories",
                  runtime_directories="Runtime directories", http_status="HTTP status", ptrace_scope="ptrace_scope",
                  indicators="Indicators", line="Line", examined_files="Examined files",
                  indicator_count="Indicator count", coverage_reasons="Coverage reasons", attempted_files="Attempted files",
                  incomplete_files="Incomplete files", baseline_accepted_count="Baseline accepted", baseline_entries="Baseline entries",
                  omitted_coverage_paths="Omitted coverage paths", coverage_counts="Coverage counts", review_required="Review required",
                  cpu_priority="CPU priority", io_priority="I/O priority", accepted_incomplete_files="Reviewed incomplete files", windowed_files="Windowed files",
                  not_disabled_functions="Not disabled by policy", enable_dl="enable_dl", sendmail_path="Mail helper command",
                  policy_only="Policy only", outcome="Assessment", candidate_count="Storage candidates", declared="Declared storage",
                  assessment="Assessment", no_new_privileges="NoNewPrivileges", protect_system="ProtectSystem", private_tmp="PrivateTmp", worker_attestation="Worker attestation", configuration_only="Configuration only", review_entries="Review entries")
    parts = []
    for key, value in facts.items():
        if key == "affected_pool_count":
            continue
        if isinstance(value, list):
            value = ", ".join(localize(WEBSHELL_INDICATORS[item], lang) if key == "indicators" else say(item) for item in value) or say("none")
        elif isinstance(value, dict):
            value = ", ".join(say(reason) + ": " + str(number) for reason, number in sorted(value.items())) or say("none")
        elif type(value) is bool:
            value = say("yes" if value else "no")
        elif type(value) is str and key != "socket_mode":
            value = say(value)
        parts.append(localize(labels[key], lang) + ": " + str(value))
    result = "; ".join(parts) or localize("Host details omitted; rerun locally without --redact", lang)
    if "affected_pool_count" in facts:
        count = facts["affected_pool_count"]
        result += " (" + str(count) + " " + say("pool" if count == 1 else "pools") + ")"
    return result


class Report:
    def __init__(self):
        self.rows = []
        self.discovery = {}

    def add(self, status, title, detail, *, rule_id="P2S-CUSTOM", resource=None, evidence=None):
        key = rule_id[4:]
        severity, remediation = RULES[key]
        resource = title if resource is None else resource
        identity = json.dumps([rule_id, resource], ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        finding_id = rule_id + "-" + digest(identity.encode())[:16]
        self.rows.append(dict(id=finding_id, rule_id=rule_id, resource=resource,
                              status=status, title=title, detail=detail,
                              severity=severity if status == "OPEN" else "unknown" if status == "UNKNOWN" else "info",
                              remediation=remediation, suppressed=False, evidence=safe_evidence(rule_id, evidence)))
        return self.rows[-1]

    def configure(self, fail_on="complete", ignore=()):
        self.fail_on = fail_on
        for row in self.rows:
            row["suppressed"] = (row["status"] == "OPEN" or self.review_row(row)) and (row.get("baseline_accepted") is True or row["id"] in ignore or row["rule_id"] in ignore)

    @staticmethod
    def review_row(row):
        return row["status"] == "INFO" and row["rule_id"] == "P2S-WS004" and row["evidence"].get("review_required") is True

    def has_review(self):
        return any(self.review_row(row) and not row["suppressed"] and not row.get("baseline_accepted") for row in self.rows)

    def has(self, status):
        return any(r["status"] == status and not r["suppressed"] for r in self.rows)

    def exit_code(self):
        policy = getattr(self, "fail_on", "complete")
        if policy in ("open", "review") and (self.has("OPEN") or policy == "review" and self.has_review()):
            return 1
        if self.has_unaccepted_unknown():
            return 2
        return int(self.has("OPEN"))

    def has_unaccepted_unknown(self):
        return any(row["status"] == "UNKNOWN" and not (row["rule_id"] == "P2S-NGX001" and row.get("review_accepted") is True) for row in self.rows)

    def show(self, as_json=False, verbose=False, lang="en", redact=False):
        configure_output(as_json)
        rows = [dict(row, title=localize(row["title"], lang), detail=localize(row["detail"], lang),
                     remediation=localize(row["remediation"], lang)) for row in self.rows]
        if not as_json:
            for row in rows:
                if row["rule_id"] in ("P2S-PHP005", "P2S-SYS002"):
                    row["detail"] = evidence_summary(row["rule_id"], row["evidence"], lang) + "; " + row["detail"]
        discovery = localized_discovery(self.discovery, lang)
        if redact:
            # Allowlist projection, not regex replacement: even exception text,
            # arbitrary discovery metadata and future resource shapes are omitted.
            nonce = uuid.uuid4().hex
            def project(index, row):
                evidence = safe_evidence(row["rule_id"], row.get("evidence"))
                if as_json:
                    detail = json.dumps(evidence, sort_keys=True) if evidence else localize("Host details omitted; rerun locally without --redact", lang)
                else:
                    detail = evidence_summary(row["rule_id"], evidence, lang)
                return dict(id=row["rule_id"] + "-" + digest((nonce + str(index)).encode())[:16],
                            rule_id=row["rule_id"], resource=None, status=row["status"],
                            title=localize(RULE_NAMES.get(row["rule_id"][4:], row["rule_id"]), lang),
                            detail=detail,
                            severity=row["severity"], remediation=localize(RULES[row["rule_id"][4:]][1], lang),
                            evidence=evidence, suppressed=row["suppressed"],
                            **({"baseline_accepted":row["baseline_accepted"] is True} if "baseline_accepted" in row else {}),
                            **({"review_accepted":True} if row.get("review_accepted") is True else {}))
            rows = [project(index, row) for index, row in enumerate(self.rows)]
            discovery = dict(redacted=True, doctor=bool(self.discovery.get("doctor")),
                             inventory_only=bool(self.discovery.get("inventory_only")))
        if as_json:
            print(json.dumps(json_paths(dict(schema_version=2, version=VERSION, language=lang, redacted=redact, findings=rows,
                                  has_open=self.has("OPEN"), has_unknown=self.has("UNKNOWN"),
                                  has_unaccepted_unknown=self.has_unaccepted_unknown(),
                                  accepted_unknown=sum(row.get("review_accepted") is True for row in rows),
                                  counts={state: sum(r["status"] == state for r in rows) for state in ("OK", "OPEN", "UNKNOWN", "INFO")},
                                  suppressed_open=sum(r["suppressed"] and r["status"] == "OPEN" for r in rows),
                                  has_review=self.has_review(),
                                  suppressed_review=sum(r["suppressed"] and self.review_row(r) for r in rows),
                                  fail_on=getattr(self, "fail_on", "complete"),
                                  discovery=discovery, plan=None if redact else getattr(self, "plan", None),
                                  transaction=None if redact else getattr(self, "transaction", None),
                                  path_encoding=PATH_ENCODING,
                                  exit_code=self.exit_code())), ensure_ascii=True, indent=2))
            return
        def emit(line):
            # Configured names/paths must not inject terminal escape sequences.
            print("".join(c if c.isprintable() else "?" for c in line))
        label = "Prerequisites" if discovery.get("doctor") else "Discovered inventory" if discovery.get("inventory_only") else "PHP webshell indicator scan" if self.discovery.get("webshell_scan") else "Configuration audit"
        emit(f"p2s-harden {VERSION} - {localize(label, lang)}")
        cap = discovery.get("capabilities", {})
        missing_tools = [name for name, present in cap.get("tools", {}).items() if not present and name != "curl"]
        if missing_tools:
            emit(("Fehlende Helfer: " if lang == "de" else "Missing helpers: ") + ", ".join(missing_tools) +
                 ("; --doctor zeigt Zweck und nächste Schritte." if lang == "de" else "; --doctor explains their purpose and next steps."))
        if self.discovery and not self.discovery.get("doctor") and not redact:
            pools = sum(len(i["pools"]) for i in self.discovery.get("fpm_instances", []))
            instance_count, site_count = len(self.discovery.get('fpm_instances', [])), len(self.discovery.get('selected_sites', []))
            if not self.discovery.get("webshell_scan"):
                emit(f"Erkannt: {instance_count} Host-FPM-Instanzen, {pools} Pools, {site_count} HTTP-Zuordnungen" if lang == "de" else
                     f"Discovered: {instance_count} host FPM instances, {pools} pools, {site_count} HTTP mappings")
            roots = self.discovery.get("scan_roots", [])
            emit(("Prüfpfade: " if lang == "de" else "Audit paths: ") + ", ".join(roots[:8]))
            if len(roots) > 8:
                emit(f"Weitere {len(roots) - 8} Pfade im vollständigen --json-Inventar." if lang == "de" else
                     f"{len(roots) - 8} more paths in the complete --json inventory.")
            if self.discovery.get("inventory_only"):
                for instance in discovery.get("fpm_instances", []):
                    for pool in instance["pools"]:
                        emit(f"POOL    {pool['name']} | " + ("Benutzer" if lang == "de" else "User") +
                             f": {pool['user']} | Listener: {pool['listen']}")
                for site in self.discovery.get("selected_sites", []):
                    emit("SITE    " + site)
        if not redact:
            coverage_paths = [item for root in self.discovery.get("webshell_coverage", []) for item in root["paths"]]
            for item in coverage_paths if verbose else coverage_paths[:20]:
                reason = _EVIDENCE_GERMAN.get(item["reason"], item["reason"]) if lang == "de" else item["reason"]
                emit(localize("Incomplete path ({reason}): {path}", lang).format(reason=reason, path=item["path"]))
            if not verbose and len(coverage_paths) > 20:
                emit(localize("More incomplete paths: use --verbose or --json", lang))
            if any(root["omitted_paths"] for root in self.discovery.get("webshell_coverage", [])):
                emit(localize("Coverage path list truncated at 1000 entries per root; narrow --root to resolve remaining paths", lang))
        shown = rows if verbose or self.discovery.get("doctor") else [r for r in rows if r["status"] != "OK" and not r.get("baseline_accepted")]
        if self.discovery.get("webshell_scan"):
            # Coverage remains visible even when a noisy tree hits the human
            # output limit. Full finding details stay in --verbose/--json.
            shown.sort(key=lambda row: row["rule_id"] != "P2S-WS003")
        for row in shown if verbose else shown[:40]:
            emit(f"{row['status']:7} {row['title']}: {row['detail']}")
            if row["status"] in ("OPEN", "UNKNOWN") or row["rule_id"] == "P2S-WS004":
                marker = " [reviewed UNKNOWN]" if row.get("review_accepted") else " [baseline]" if row.get("baseline_accepted") else " [ignored review]" if row["suppressed"] and self.review_row(row) else " [ignored OPEN]" if row["suppressed"] else ""
                emit("        " + row["id"] + marker)
                if row.get("affected_pools"):
                    count = len(row["affected_pools"])
                    emit(f"        Unverändert für {count} Pools; --json nennt die zugehörigen Pools." if lang == "de" else
                         f"        Applies unchanged to {count} pools; --json lists the related pools.")
                emit("        " + row["remediation"])
        if not verbose and len(shown) > 40:
            emit(f"Weitere {len(shown) - 40} Befunde: --verbose oder --json zeigt alle Details." if lang == "de" else
                 f"{len(shown) - 40} more findings: --verbose or --json shows all details.")
        counts = {s: sum(r["status"] == s for r in self.rows) for s in ("OK", "OPEN", "UNKNOWN", "INFO", "N/A")}
        print("\n" + "   ".join(f"{s}: {n}" for s, n in counts.items()))
        accepted = sum(r.get("baseline_accepted") is True for r in self.rows)
        if accepted:
            emit(localize("Baseline accepted: {count} unchanged indicator rows; --verbose or --json retains them", lang).format(count=accepted))
        acknowledged = sum(row.get("review_accepted") is True for row in rows)
        if acknowledged:
            emit(("Reviewte UNKNOWN-Befunde: " if lang == "de" else "Acknowledged UNKNOWN findings: ") + str(acknowledged) +
                 ("; keine nachgewiesene Sperre." if lang == "de" else "; blocking remains unproven."))
        emit("Nur die ausgewiesenen Host-Pfade/Instanzen wurden geprüft; keine Sicherheitszertifizierung." if lang == "de" else
             "Only the reported host paths and instances were checked; this is not a security certification.")
        if self.discovery.get("assessment"):
            emit("Datenträger-Konfiguration geprüft; bestehende Worker, Netzwerk-Erreichbarkeit und Anwendungsschwachstellen bleiben ungeprüft." if lang == "de" else
                 "Disk configuration inspected; existing workers, network reachability and application vulnerabilities remain unverified.")


# Source: src/pool_security.py
"""Read-only FPM boundaries; never infer Internet reachability or tenant intent."""


def pool_effective(values, settings, key):
    value = values.get(key)
    for prefix in ("php_value", "php_flag", "php_admin_value", "php_admin_flag"):
        override = settings.get(prefix + "[" + key + "]")
        if override is not None and override != "undefined":
            value = override
    return value


def localhost_loopback(name, cache):
    key = name.lower()
    if key not in cache:
        try:
            code = "import json,socket,sys; print(json.dumps(sorted({v[4][0] for v in socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))"
            output, _ = command([sys.executable, "-I", "-B", "-c", code, name], timeout=2)
            addresses = json.loads(output)
            if not isinstance(addresses, list) or not 1 <= len(addresses) <= 64 or any(type(value) is not str for value in addresses):
                raise ValueError()
            cache[key] = all(ipaddress.ip_address(value).is_loopback for value in addresses)
        except (ValueError, TypeError, CheckError):
            cache[key] = None
    if cache[key] is None:
        raise CheckError("localhost resolution is unavailable; use a literal loopback IP or verify the host name-service configuration")
    return cache[key]


def pool_security(report, instance):
    name_cache = {}
    for pool, settings in instance["pools"].items():
        resource = dict(config=instance["config"], pool=pool)
        title = "FPM listener [" + pool + "] " + instance["config"]
        listener = settings.get("listen", "").strip()
        if listener.startswith("/"):
            raw_mode = settings.get("listen.mode", "0660")
            if raw_mode == "undefined":
                raw_mode = "0660"
            if not re.fullmatch(r"0?[0-7]{3}", raw_mode):
                status, detail = "UNKNOWN", "Cannot parse the configured Unix socket mode"
                mode_evidence = dict(source="configured")
            else:
                world = int(raw_mode, 8) & 0o002
                status = "OPEN" if world else "OK"
                detail = "Configured Unix socket mode: " + raw_mode
                mode_evidence = dict(source="configured", socket_mode=format(int(raw_mode, 8), "04o"))
            report.add(status, title, detail, rule_id="P2S-FPM002", resource=dict(resource, source="configured"), evidence=mode_evidence)
            try:
                path = Path(listener)
                if any(p.is_symlink() for p in (path, *path.parents)):
                    raise CheckError("Unix socket path has a symlink; verify the effective endpoint separately")
                actual = path.lstat()
                if not stat.S_ISSOCK(actual.st_mode):
                    raise CheckError("Configured Unix socket is missing or is not a socket")
                mode = stat.S_IMODE(actual.st_mode)
                report.add("OPEN" if mode & 0o002 else "OK", title,
                           "Observed Unix socket mode: " + format(mode, "04o") + "; " + listener,
                           rule_id="P2S-FPM002", resource=dict(resource, source="observed"), evidence=dict(source="observed", socket_mode=format(mode, "04o")))
            except (OSError, CheckError) as exc:
                report.add("UNKNOWN", title, str(exc), rule_id="P2S-FPM002", resource=dict(resource, source="observed"))
            if any(settings.get(key, "") not in ("", "undefined") for key in ("listen.acl_users", "listen.acl_groups")):
                report.add("INFO", title, "Named Unix socket ACL grants require individual review; owner/group settings may be ignored",
                           rule_id="P2S-FPM002", resource=dict(resource, source="acl"), evidence=dict(source="acl", named_acl=True))
        else:
            resolution = None
            try:
                if listener.isdigit():
                    host, port = "0.0.0.0", listener
                elif listener.startswith("[") and "]:" in listener:
                    host, port = listener[1:].rsplit("]:", 1)
                elif listener.count(":") == 1:
                    host, port = listener.rsplit(":", 1)
                    host = "0.0.0.0" if host in ("", "*") else host
                else:
                    raise ValueError()
                if not port.isdigit() or not 1 <= int(port) <= 65535:
                    raise ValueError()
                if host.lower() in ("localhost", "localhost."):
                    local = localhost_loopback(host, name_cache)
                    resolution = "loopback" if local else "non_loopback"
                else:
                    address = ipaddress.ip_address(host)
                    local = address.is_loopback or (getattr(address, "ipv4_mapped", None) is not None and address.ipv4_mapped.is_loopback)
                clients = settings.get("listen.allowed_clients", "").strip()
                restricted = clients not in ("", "undefined")
                if restricted:
                    # PHP documents individual IPs, not hostnames/CIDR/wildcards.
                    # Never resolve names or claim that a firewall was inspected.
                    for client in clients.split(","):
                        ipaddress.ip_address(client.strip())
                status = "OPEN" if resolution == "non_loopback" else "OK" if local or restricted else "OPEN"
                detail = ("localhost resolves outside loopback; inspect the host name-service configuration" if resolution == "non_loopback" else
                          "Loopback TCP bind; local processes can still connect" if local else
                          "Network TCP bind with an explicit client allowlist; verify firewall and network reachability separately" if restricted else
                          "Network TCP bind accepts any client address; firewall and Internet reachability were not assessed")
                report.add(status, title, detail + "; " + listener, rule_id="P2S-FPM001", resource=resource,
                           evidence=dict(binding="loopback" if local else "network", client_allowlist=restricted, hostname_resolution=resolution))
            except (ValueError, CheckError) as exc:
                report.add("UNKNOWN", title, "Cannot classify the TCP listener or client allowlist; use literal IP addresses and verify the effective endpoint",
                           rule_id="P2S-FPM001", resource=resource, evidence=dict(binding="unverified", hostname_resolution="unavailable" if isinstance(exc, CheckError) else None))
        extensions = settings.get("security.limit_extensions", ".php .phar")
        tokens = extensions.split() if extensions != "undefined" else []
        status = "OPEN" if not tokens or any(t not in (".php", ".phar") for t in tokens) else "OK" if set(tokens) == {".php"} else "INFO"
        report.add(status, "FPM script extensions [" + pool + "] " + instance["config"],
                   "Allowed main-script extensions: " + extensions + "; .php is the narrow recommended setting" if tokens else
                   "Main-script extensions are unrestricted; set security.limit_extensions=.php after application review",
                   rule_id="P2S-FPM003", resource=resource, evidence=dict(unrestricted=not tokens,
                       allowed_known_extensions=sorted(set(tokens) & {".php", ".phar"}), other_extension_count=len(set(tokens) - {".php", ".phar"})))
        clear = settings.get("clear_env", "yes").lower()
        status = "OK" if clear in ("yes", "on", "1", "true") else "OPEN" if clear in ("no", "off", "0", "false", "") else "UNKNOWN"
        report.add(status, "FPM environment clearing [" + pool + "] " + instance["config"],
                   "clear_env=" + clear + "; explicit pool env[] values are not printed",
                   rule_id="P2S-FPM004", resource=resource, evidence=dict(clear_env=True if status == "OK" else False if status == "OPEN" else None))
        ffi = pool_effective(instance["values"], settings, "ffi.enable") if "ffi.enable" in instance["values"] else None
        if ffi is not None:
            value = ffi.lower()
            status = "OK" if value in ("off", "0", "false", "no", "") else "INFO" if value == "preload" else "OPEN" if value in ("on", "1", "true", "yes") else "UNKNOWN"
            report.add(status, "PHP FFI [" + pool + "] " + instance["config"],
                       "ffi.enable=" + ffi + "; native/preloaded code requires separate review; function restrictions are defense in depth",
                       rule_id="P2S-PHP004", resource=resource, evidence=dict(ffi_policy="off" if status == "OK" else "on" if status == "OPEN" else "preload" if status == "INFO" else "unknown"))


def shared_pool_users(report, instances):
    identities = {}
    for instance in instances:
        for pool, settings in instance["pools"].items():
            try:
                user = pwd.getpwnam(settings.get("user", ""))
            except KeyError:
                continue  # The independent permission checks report missing users.
            identities.setdefault(user.pw_uid, []).append(dict(config=instance["config"], pool=pool))
    for uid, pools in sorted(identities.items()):
        if len(pools) > 1:
            report.add("INFO", "Shared FPM account", str(len(pools)) + " pools share UID " + str(uid) + "; they do not form a Unix-user isolation boundary",
                       rule_id="P2S-FPM005", resource=dict(uid=uid, pools=pools), evidence=dict(pool_count=len(pools)))


# Source: src/defense_posture.py
"""Read-only policy observations, never a sandbox or exploitability verdict."""

RESIDUAL_FUNCTIONS = ("putenv", "mail", "error_log", "dl", "pcntl_fork", "symlink", "link", "file_put_contents")


def residual_php_policy(report, instance):
    groups = {}
    for name, settings in instance["pools"].items():
        disabled = functions(instance["values"].get("disable_functions", ""))
        for prefix in ("php_value", "php_admin_value"):
            disabled |= functions(settings.get(prefix + "[disable_functions]", ""))
        remaining = tuple(value for value in RESIDUAL_FUNCTIONS if value not in disabled)
        dl = pool_effective(instance["values"], settings, "enable_dl")
        dl = "unknown" if dl is None else "off" if dl.lower() in ("", "off", "0", "no", "false") else "on"
        mail = pool_effective(instance["values"], settings, "sendmail_path")
        mail = "unknown" if mail is None else "empty" if mail.strip().lower() in ("", "no value", "none") else "configured"
        groups.setdefault((remaining, dl, mail), []).append(name)
    for (remaining, dl, mail), pools in sorted(groups.items()):
        row = report.add("INFO", "Residual PHP capabilities " + instance["config"],
            "Function restrictions are not a sandbox. Function availability and indirect execution are not tested; dl is unavailable in FPM. Mail, environment and file APIs may be required by the application. No extra functions or settings are changed.",
            rule_id="P2S-PHP005", resource=dict(config=instance["config"], pools=sorted(pools)),
            evidence=dict(not_disabled_functions=list(remaining), enable_dl=dl, sendmail_path=mail,
                          affected_pool_count=len(pools), policy_only=True))
        row["affected_pools"] = sorted(pools)


def fpm_service_posture(report, instance, cap):
    service = instance.get("service")
    resource = dict(config=instance["config"], service=service)
    title = "FPM systemd hardening " + instance["config"]
    if not service or not cap.get("systemd") or not cap.get("tools", {}).get("systemctl"):
        report.add("INFO", title, "No verified active systemd context; service hardening is not assessed. Audit the actual service/container boundary separately.",
                   rule_id="P2S-SYS002", resource=resource, evidence=dict(assessment="not_assessed", worker_attestation=False))
        return
    try:
        if re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", service) is None or service.startswith("-"):
            raise CheckError("Invalid FPM service identity")
        helper = shutil.which("systemctl")
        if helper is None:
            raise CheckError("systemctl is unavailable")
        helper = str(trusted(Path(helper).resolve(strict=True)))
        props = ("Id", "LoadState", "ActiveState", "MainPID", "NoNewPrivileges", "ProtectSystem", "PrivateTmp")
        output, _ = command([helper, "show", "--no-pager", "--property=" + ",".join(props), "--", service], timeout=5)
        values = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in props and key not in values:
                values[key] = value
            else:
                raise CheckError("Ambiguous systemd property output")
        if (set(values) != set(props) or values["Id"] != service or values["LoadState"] != "loaded" or
                values["ActiveState"] != "active" or values["MainPID"] != str(instance["pid"])):
            raise CheckError("systemd properties do not match the active FPM master")
        if (values["NoNewPrivileges"] not in ("yes", "no") or values["ProtectSystem"] not in ("no", "yes", "full", "strict") or
                values["PrivateTmp"] not in ("no", "yes", "disconnected")):
            raise CheckError("Unknown systemd hardening property value")
        report.add("INFO", title,
            "Manager-reported policy only; existing workers, exceptions and kernel enforcement are not attested. Review application writes, mail and shared temporary-file requirements before changing a service. No unit is changed.",
            rule_id="P2S-SYS002", resource=resource,
            evidence=dict(assessment="manager_policy", no_new_privileges=values["NoNewPrivileges"],
                          protect_system=values["ProtectSystem"], private_tmp=values["PrivateTmp"], worker_attestation=False))
    except (OSError, ValueError, CheckError):
        report.add("UNKNOWN", title, "Active FPM service properties could not be verified; inspect systemctl show and the running worker boundary separately. No unit is changed.",
                   rule_id="P2S-SYS002", resource=resource, evidence=dict(assessment="unavailable", worker_attestation=False))


# Source: src/nginx_uploads.py
"""Conservative upload-route checks. No arbitrary PCRE evaluation or probes."""


def nginx_directives(nodes, name):
    return [node["args"] for node in nodes if node["name"] == name and node["children"] is None]


def nginx_php_pattern(pattern, insensitive=False):
    """Parse a finite grammar, never compile configuration text as a regex.

    Prefixes are literal ASCII path segments with at most one literal choice
    per segment (64 expanded paths total). Only PHP-family suffixes are known.
    """
    if len(pattern) > 2048:
        return None
    dot_all = pattern.startswith("(?s)")
    if dot_all:
        pattern = pattern[4:]
    suffix = next((end for end in ("$", "(/|$)", "(?:/|$)") if pattern.endswith(end)), None)
    if suffix is None:
        return None
    stem = pattern[:-len(suffix)]
    if r"\." not in stem:
        return None
    head, extensions = stem.rsplit(r"\.", 1)
    if extensions.startswith("(?:") and extensions.endswith(")"):
        extensions = extensions[3:-1]
    elif extensions.startswith("(") and extensions.endswith(")"):
        extensions = extensions[1:-1]
    extensions = extensions.split("|")
    if not extensions or any(value not in ("php", "phtml", "phar") for value in extensions):
        return None
    if head == "":
        prefixes = [""]
        dot_all = True  # Unanchored suffixes do not exclude earlier line breaks.
    elif head.startswith("^/") and head.endswith("/.*"):
        prefixes = ["/"]
        for segment in head[2:-3].split("/"):
            if segment.startswith("(?:") and segment.endswith(")"):
                values = segment[3:-1].split("|")
            elif segment.startswith("(") and segment.endswith(")"):
                values = segment[1:-1].split("|")
            else:
                values = [segment]
            if not values or any(re.fullmatch(r"[A-Za-z0-9_-]+", value) is None for value in values):
                return None
            if len(prefixes) * len(values) > 64:
                return None
            prefixes = [prefix + value + "/" for prefix in prefixes for value in values]
    else:
        return None
    return dict(prefixes=prefixes, extensions=set(extensions), insensitive=insensitive, path_info=suffix != "$", dot_all=dot_all)


def nginx_rejection(body):
    """An unconditional leaf: no access bypasses, redirects or content modules."""
    allowed = {"deny", "return", "access_log", "log_not_found", "add_header", "expires"}
    if any(node["children"] is not None or node["name"] not in allowed for node in body):
        return False
    returns, denies = nginx_directives(body, "return"), nginx_directives(body, "deny")
    if returns:
        return len(returns) == 1 and len(returns[0]) == 1 and returns[0][0] in ("403", "404", "410", "444")
    return denies == [["all"]]


def nginx_fastcgi_mapping(body):
    allowed = {"try_files", "set", "access_log", "error_log", "log_not_found", "expires", "add_header", "default_type"}
    if any(node["children"] is not None or (node["name"] not in allowed and not node["name"].startswith(("fastcgi_", "client_"))) for node in body):
        return False
    if (any(args not in (["$uri", "=404"], ["$fastcgi_script_name", "=404"]) for args in nginx_directives(body, "try_files")) or
            any(args != ["$path_info", "$fastcgi_path_info"] for args in nginx_directives(body, "set")) or
            any(args not in ([r"^(.+?\.php)(/.*)$"], [r"^(.+\.php)(/.*)$"], [r"^(.+\.php)(/.+)$"]) for args in nginx_directives(body, "fastcgi_split_path_info"))):
        return False
    passes = nginx_directives(body, "fastcgi_pass")
    scripts = [args[1:] for args in nginx_directives(body, "fastcgi_param") if args[:1] == ["SCRIPT_FILENAME"]]
    return (len(passes) == 1 and len(passes[0]) == 1 and "$" not in passes[0][0] and len(scripts) == 1 and
            scripts[0] in (["$document_root$fastcgi_script_name"], ["$realpath_root$fastcgi_script_name"]))


def nginx_upload_route(http, server, uri):
    """Prove rejection over a bounded URI language, not one lucky filename."""
    nodes = server["children"]
    if any(char in uri for char in ("?", "#", "%", "$")) or not uri.isascii() or not uri.isprintable():
        return "UNKNOWN", "dynamic_path"
    uncertain = {"if", "rewrite", "error_page", "__p2s_unresolved_include__"}
    if any(node["name"] in uncertain for node in http["children"] + nodes):
        return "UNKNOWN", "redirect_or_conditional"
    if any(args != ["on"] for body in (http["children"], nodes) for args in nginx_directives(body, "merge_slashes")):
        return "UNKNOWN", "unsupported_directive"
    parent_names = {"server", "location", "root", "index", "listen", "server_name", "access_log", "error_log", "log_format",
                    "types", "default_type", "charset", "autoindex", "expires", "add_header", "log_not_found", "merge_slashes",
                    "map", "upstream", "geo", "sendfile", "tcp_nopush", "tcp_nodelay", "keepalive_timeout", "keepalive_requests",
                    "server_tokens", "server_names_hash_bucket_size", "server_names_hash_max_size", "types_hash_max_size"}
    if any(node["name"] not in parent_names and not node["name"].startswith(("ssl_", "gzip", "client_")) for node in http["children"] + nodes):
        return "UNKNOWN", "unsupported_directive"
    prefix, regex = [], []
    for node in (n for n in nodes if n["name"] == "location" and n["children"] is not None):
        args = node["args"]
        if len(args) == 1 and args[0].startswith("/"):
            modifier, path = "", args[0]
        elif len(args) == 2 and args[0] in ("=", "^~", "~", "~*"):
            modifier, path = args
        else:
            return "UNKNOWN", "unsupported_location"
        if nginx_directives(node["children"], "alias"):
            return "UNKNOWN", "location_filesystem_mapping"
        if modifier in ("~", "~*"):
            regex.append((path, modifier, node))
        else:
            if not path.startswith("/") or not path.isascii() or any(char in path for char in "$?#%"):
                return "UNKNOWN", "dynamic_path"
            prefix.append((path, modifier, node))
    if len({(path, modifier == "=") for path, modifier, node in prefix}) != len(prefix):
        return "UNKNOWN", "duplicate_location"
    # Competing exact/descendant prefixes can bypass regex selection for a
    # different filename. Never certify a directory using just one witness.
    matches = [(path, modifier, node) for path, modifier, node in prefix if modifier != "=" and uri.startswith(path)]
    selected = max(matches, key=lambda item: len(item[0])) if matches else None
    competing = any(path.startswith(uri) and (selected is None or node is not selected[2]) for path, modifier, node in prefix)
    nested = [(path, modifier, node) for path, modifier, node in prefix if any(child["name"] == "location" for child in node["children"])]
    if nested and (len(nested) != 1 or selected != nested[0] or selected[1] != "^~"):
        return "UNKNOWN", "nested_location"
    if selected and selected[1] == "^~":
        body = selected[2]["children"]
        if not competing and nginx_rejection(body):
            return "OK", "static_directory_rejection"
        if nested and not competing:
            static = [node for node in body if node["name"] != "location"]
            if any(node["children"] is not None or node["name"] not in {"access_log", "log_not_found", "expires", "add_header", "try_files"} for node in static):
                return "UNKNOWN", "unsupported_directive"
            if any(args != ["$uri", "=404"] for args in nginx_directives(static, "try_files")):
                return "UNKNOWN", "redirect_or_conditional"
            guarded_php = False
            for child in (node for node in body if node["name"] == "location"):
                args = child["args"]
                parsed = nginx_php_pattern(args[1], args[0] == "~*") if len(args) == 2 and args[0] in ("~", "~*") else None
                if not parsed or parsed["prefixes"] != [""] or not nginx_rejection(child["children"]):
                    return "UNKNOWN", "nested_location"
                guarded_php |= "php" in parsed["extensions"]
            if guarded_php:
                return "OK", "nested_php_rejection"
        return "UNKNOWN", "no_proven_handler"
    if nested:
        return "UNKNOWN", "nested_location"
    guards, handlers = [], 0
    def relevant(pattern):
        return any(uri.lower().startswith(path.lower()) or path.lower().startswith(uri.lower()) if pattern["insensitive"] else
                   uri.startswith(path) or path.startswith(uri) for path in pattern["prefixes"])
    def covers(guard, handler, check_lines=True):
        if not handler["extensions"].issubset(guard["extensions"]) or handler["insensitive"] and not guard["insensitive"] or handler["path_info"] and not guard["path_info"]:
            return False
        if check_lines and handler["dot_all"] and not guard["dot_all"]:
            return False
        # Only a guard that covers the complete selected directory can approve
        # a handler. Narrow partial guards never turn uncovered paths green.
        return any((uri.lower().startswith(path.lower()) if guard["insensitive"] else uri.startswith(path)) for path in guard["prefixes"])
    for text, modifier, node in regex:
        if text in (r"/\.(env|git)", r"/\.ht", r"/\.htaccess", r"/\.") and nginx_rejection(node["children"]):
            continue
        parsed = nginx_php_pattern(text, modifier == "~*")
        if parsed is None:
            return "UNKNOWN", "unsupported_regex"
        if not relevant(parsed):
            continue
        if nginx_rejection(node["children"]):
            guards.append(parsed)
        elif nginx_fastcgi_mapping(node["children"]):
            handlers += 1
            if not any(covers(guard, parsed) for guard in guards):
                return "OPEN", "regex_line_break_gap" if any(covers(guard, parsed, check_lines=False) for guard in guards) else "php_fastcgi_mapping"
        else:
            return "UNKNOWN", "no_proven_handler"
    if handlers and guards:
        if selected and any(node["children"] is not None or node["name"] not in
                            {"access_log", "error_log", "log_not_found", "add_header", "expires", "try_files", "index", "default_type"}
                            for node in selected[2]["children"]):
            return "UNKNOWN", "unsupported_directive"
        return ("UNKNOWN", "competing_location") if competing else ("OK", "ordered_php_rejection")
    return "UNKNOWN", "no_proven_handler"


def nginx_upload_security(report, args):
    requested = list(getattr(args, "runtime_dirs", []))
    tree = getattr(args, "nginx_tree", None)
    config = getattr(args, "nginx_config", None)
    if tree is None and config:
        try:
            tree = read_nginx(Path(config), partial=True)
        except (OSError, UnicodeError, CheckError):
            tree = None
    if tree is None:
        report.add("UNKNOWN" if requested else "INFO", "Nginx upload execution", "No parsed Nginx configuration for upload checks; provide --nginx-config and declare storage with --runtime-dir. No upload file or HTTP probe is created.",
                   rule_id="P2S-NGX001", resource="upload_scope", evidence=dict(outcome="not_assessed", candidate_count=len(requested)))
        return
    pending, alias_present = list(tree), False
    while pending:
        node = pending.pop()
        alias_present |= node["name"] == "alias"
        pending.extend(node["children"] or [])
    seen, mapped, server_index = set(), set(), 0
    for http in [node for node in tree if node["name"] == "http" and node["children"] is not None]:
        inherited = nginx_directives(http["children"], "root")
        for server in [node for node in http["children"] if node["name"] == "server" and node["children"] is not None]:
            server_index += 1
            roots = nginx_directives(server["children"], "root") or inherited
            if len(roots) != 1 or len(roots[0]) != 1 or "$" in roots[0][0] or not Path(roots[0][0]).is_absolute():
                continue
            root = os.path.normpath(roots[0][0])
            targets = set(requested)
            for suffix in ("uploads", "wp-content/uploads"):
                candidate = str(Path(root) / suffix)
                if Path(candidate).is_dir():
                    targets.add(candidate)
            for target in sorted(targets):
                if not any(os.path.commonpath([target, selected]) == selected for selected in getattr(args, "roots", [args.root])):
                    continue
                if os.path.commonpath([root, target]) != root:
                    continue
                key = (server_index, target)
                if key in seen:
                    continue
                if len(seen) >= 128:
                    report.add("UNKNOWN", "Nginx upload execution", "Upload mapping limit reached; narrow the selected scope.", rule_id="P2S-NGX001", resource="upload_limit", evidence=dict(outcome="limit"))
                    return
                seen.add(key); mapped.add(target)
                uri = "/" if target == root else "/" + str(Path(target).relative_to(root)).replace(os.sep, "/").rstrip("/") + "/"
                status, outcome = nginx_upload_route(http, server, uri)
                if not getattr(tree, "snapshot_complete", True):
                    status, outcome = "UNKNOWN", "configuration_snapshot_incomplete"
                if status == "OK" and alias_present:
                    status, outcome = "UNKNOWN", "location_filesystem_mapping"
                details = {"OK": "A static rejection guards the selected upload URI prefix in this parsed server block; alternate application includes and live-worker/network enforcement are not attested.",
                           "OPEN": "An upload PHP URI has a FastCGI script mapping in the parsed configuration. An existing uploaded PHP file may execute; live application reachability is not tested.",
                           "UNKNOWN": "Upload execution could not be established from the supported static Nginx subset; inspect aliases, regex order, nested locations and internal redirects manually."}
                row = report.add(status, "Nginx upload execution " + target, (("The upload denial uses .* without DOTALL; a URL-decoded line break can bypass it and select the PHP handler. " if outcome == "regex_line_break_gap" else "") + details[status]) + " No upload file or HTTP probe is created.",
                           rule_id="P2S-NGX001", resource=dict(path=target, root=root, uri=uri, config=server["source"], line=server["line"], server_index=server_index),
                           evidence=dict(outcome=outcome, declared=target in requested, candidate_count=1, configuration_only=True))
                snapshot = getattr(tree, "snapshot_sha256", None)
                if status == "UNKNOWN" and outcome in NGINX_REVIEWABLE and snapshot:
                    row["nginx_review"] = dict(finding_id=row["id"], snapshot_sha256=snapshot, outcome=outcome)
    for target in requested:
        if target not in mapped:
            report.add("UNKNOWN", "Nginx upload execution " + target, "Declared storage has no unambiguous static Nginx root mapping; inspect aliases and the intended virtual host manually.",
                       rule_id="P2S-NGX001", resource=dict(path=target), evidence=dict(outcome="unmapped", declared=True))
    if not seen and not requested:
        report.add("INFO", "Nginx upload execution", "No upload storage identified; use --runtime-dir for actual writable storage. Directory names alone do not establish an application's upload paths.",
                   rule_id="P2S-NGX001", resource="upload_scope", evidence=dict(outcome="not_assessed", candidate_count=0))


# Source: src/nginx_review.py
"""Explicit acknowledgement of unresolved static routing, never an OK verdict."""

NGINX_REVIEWABLE = frozenset(("redirect_or_conditional", "nested_location", "unsupported_location", "unsupported_regex",
                            "no_proven_handler", "location_filesystem_mapping", "unsupported_directive", "competing_location"))


def nginx_review_entries(data):
    if (type(data) is not dict or data.get("schema_version") != 1 or data.get("kind") != "nginx-upload-review" or
            data.get("requires_review") is not True or type(data.get("entries")) is not list or len(data["entries"]) > 128):
        raise CheckError("Nginx review requires an explicit schema 1 nginx-upload-review draft")
    result = set()
    for entry in data["entries"]:
        if (type(entry) is not dict or set(entry) != {"finding_id", "snapshot_sha256", "outcome", "reviewed", "reason"} or
                entry.get("reviewed") is not True or type(entry.get("reason")) is not str or not entry["reason"].strip() or len(entry["reason"]) > 1024 or
                type(entry.get("finding_id")) is not str or re.fullmatch(r"P2S-NGX001-[a-f0-9]{16}", entry["finding_id"]) is None or
                type(entry.get("snapshot_sha256")) is not str or re.fullmatch(r"[a-f0-9]{64}", entry["snapshot_sha256"]) is None or
                type(entry.get("outcome")) is not str or entry["outcome"] not in NGINX_REVIEWABLE):
            raise CheckError("Nginx review entries require reviewed=true, a reason and an unchanged complete configuration identity")
        key = (entry["finding_id"], entry["snapshot_sha256"], entry["outcome"])
        if key in result:
            raise CheckError("Duplicate Nginx review entry")
        result.add(key)
    return result


def nginx_review_report(report, args):
    if getattr(args, "nginx_baseline", None):
        try:
            entries = read_webshell_baseline(args.nginx_baseline, nginx_review_entries)
            for row in report.rows:
                token = row.get("nginx_review")
                if token and (token["finding_id"], token["snapshot_sha256"], token["outcome"]) in entries:
                    row["review_accepted"] = True
        except (OSError, UnicodeError, ValueError, CheckError):
            report.add("UNKNOWN", "Nginx review", "Nginx review file is unreviewed, invalid, unsafe or unreadable; no exceptions accepted.",
                       rule_id="P2S-NGX002", resource="nginx_review")
    if getattr(args, "write_nginx_review_draft", None):
        entries = [dict(row["nginx_review"], reviewed=False, reason="") for row in report.rows if row.get("nginx_review")]
        draft = dict(schema_version=1, kind="nginx-upload-review", requires_review=True, entries=entries,
                     instructions="Review all virtual hosts, aliases, redirects and the complete include closure. Test the real routes. Add a reason and set reviewed=true only for entries you accept. UNKNOWN stays visible; this is not a blocking or safety proof.")
        try:
            path = write_private_json(args.write_nginx_review_draft, draft)
            report.add("INFO", "Nginx review", "Private unreviewed Nginx draft written; no existing file is overwritten and no exception is accepted automatically.",
                       rule_id="P2S-NGX002", resource=dict(path=path), evidence=dict(review_entries=len(entries)))
        except (OSError, ValueError, CheckError):
            report.add("UNKNOWN", "Nginx review", "Nginx review draft could not be written safely; the audit results are retained.",
                       rule_id="P2S-NGX002", resource="nginx_review")


# Source: src/webshells.py
"""Local indicator triage. Never execute, decode payloads, upload or alter files."""

WEBSHELL_INDICATORS = {
    "request-execution": "Request data near a code/command execution sink",
    "encoded-execution": "Decoder output near a PHP code execution sink",
    "request-include": "Request data near a PHP include/require",
    "request-prefixed-include": "Request-derived PHP include with a constant prefix; traversal requires review",
    "request-callable": "Request-selected dynamic function call",
    "network-shell": "Network connection and shell launch in one PHP file",
    "startup-reference": "PHP startup-file directive requires verification",
    "prefixed-include": "Indirect input in a constant-prefixed PHP include requires review",
    "registry-callable": "Request-selected registry callback requires review",
}
WEBSHELL_REASONS = ("access", "symlink", "mount", "special", "changed", "depth",
                   "entries", "time", "file-time", "file-size", "total-bytes", "tokens", "expression", "findings", "config-syntax", "window")
WEBSHELL_REVIEWABLE_REASONS = frozenset(("file-size", "tokens", "expression", "window"))
_WS_SOURCE = frozenset(("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES"))
_WS_SINKS = REQUIRED | frozenset(("eval", "assert", "create_function"))
_WS_DECODERS = frozenset(("base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "hex2bin"))
_WS_NETWORK = frozenset(("fsockopen", "pfsockopen", "stream_socket_client", "socket_connect"))
_WS_CALLBACKS = frozenset(("call_user_func", "call_user_func_array", "array_map"))
_WS_CALLS = _WS_SINKS | _WS_NETWORK | _WS_CALLBACKS
_WS_TOKEN = re.compile(r"\$[A-Za-z_][A-Za-z_0-9]*|\\?[A-Za-z_][A-Za-z_0-9\\]*|->|\?->|::|==|=>|!=|<=|>=|\?\?|&&|\|\||[^\s]", re.ASCII)
_WS_OPEN = re.compile(r"<\?(?:php\b|=|(?!xml\b))", re.I | re.ASCII)
_WS_EXPLICIT_OPEN = re.compile(r"<\?(?:php\b|=)", re.I | re.ASCII)
# These transformations do not establish that an include is safe. Preserve
# direct-input priority through them, as well as through copies and casts.
_WS_INPUT_TRANSFORMS = frozenset(("basename", "dirname", "trim", "ltrim", "rtrim", "strval", "intval",
    "floatval", "boolval", "strtolower", "strtoupper", "urldecode", "rawurldecode", "str_replace",
    "preg_replace", "sprintf", "filter_input", "file_get_contents")) | _WS_DECODERS
_WS_HEREDOC = re.compile(r"<<<[ \t]*(?:'([A-Za-z_][A-Za-z_0-9]{0,127})'|\"([A-Za-z_][A-Za-z_0-9]{0,127})\"|([A-Za-z_][A-Za-z_0-9]{0,127}))[ \t]*\r?\n")
_WS_LINE_END = re.compile(r"\n|\?>")
_WS_WHITESPACE = re.compile(r"\s+")


def webshell_tokens(source, deadline, short_tags=True):
    """Small lexical filter, not a PHP parser. Strings/comments are not code."""
    tokens, pos, active = [], 0, False
    while pos < len(source):
        if len(tokens) >= 100000:
            return tokens, "tokens"
        if time.monotonic() > deadline:
            return tokens, "time"
        if not active:
            opening = (_WS_OPEN if short_tags else _WS_EXPLICIT_OPEN).search(source, pos)
            if not opening:
                break
            pos, active = opening.end(), True
            continue
        if source.startswith("?>", pos):
            pos, active = pos + 2, False
            continue
        if source[pos].isspace():
            pos = _WS_WHITESPACE.match(source, pos).end()
            continue
        if source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            pos = len(source) if end < 0 else end + 2
            continue
        if source.startswith("//", pos) or source[pos] == "#" and not source.startswith("#[", pos):
            # Search only as far as this line's end. Repeated suffix searches
            # for a nonexistent closing tag made comment-heavy input quadratic.
            end = _WS_LINE_END.search(source, pos)
            pos = (end.start() if end[0] == "?>" else end.end()) if end else len(source)
            continue
        start = pos
        quote = source[pos]
        if quote in ("'", '"', "`"):
            pos += 1
            while pos < len(source):
                if pos % 4096 == 0 and time.monotonic() > deadline:
                    return tokens, "time"
                if source[pos] == "\\":
                    pos += 2
                elif source[pos] == quote:
                    pos += 1
                    break
                else:
                    pos += 1
            value = source[start + 1:pos - 1]
            # Only function-name constants are decoded; payloads stay opaque.
            if quote == '"' and len(value) <= 128:
                value = re.sub(r"\\x([0-9a-fA-F]{1,2})|\\([0-7]{1,3})",
                    lambda m: chr(int(m[1], 16) if m[1] else int(m[2], 8) % 256), value)
            tokens.append(("backtick" if quote == "`" else "interpolated" if quote == '"' else "string", value, start))
            continue
        if source.startswith("<<<", pos):
            header = _WS_HEREDOC.match(source, pos)
            if header:
                label = next(item for item in header.groups() if item)
                begin = header.end()
                end = re.compile(r"(?m)^[ \t]*" + re.escape(label) + r"\b").search(source, begin)
                stop = end.start() if end else len(source)
                tokens.append(("string" if header[1] else "interpolated", source[begin:stop], start))
                pos = end.end() if end else len(source)
                continue
        match = _WS_TOKEN.match(source, pos)
        if match:
            value = match[0]
            tokens.append(("variable" if value.startswith("$") else "code", value, pos))
            pos = match.end()
        else:
            pos += 1
    return tokens, None


def webshell_indicators(data, deadline=None, short_tags=True):
    """Bounded syntactic proximity and simple aliases; no exploitability claim."""
    source = data.decode("latin-1")
    deadline = deadline if deadline is not None else time.monotonic() + 10
    tokens, incomplete = webshell_tokens(source, deadline, short_tags)
    direct_aliases = set()
    hits, aliases, registry_aliases, decoded, complex_values, constants, pairs, stack = {}, set(), set(), set(), set(), {}, {}, []
    for index, token in enumerate(tokens):
        if index % 1024 == 0 and time.monotonic() > deadline:
            return {}, "time"
        if token[0] != "code":
            continue
        if token[1] in ("(", "["):
            stack.append(index)
            if len(stack) > 128:
                incomplete = incomplete or "expression"
                break
        elif token[1] in (")", "]") and stack:
            opening = stack.pop()
            if (tokens[opening][1], token[1]) in (("(", ")"), ("[", "]")):
                pairs[opening] = index
    closing = {end: begin for begin, end in pairs.items()}
    def request(items, with_aliases=True):
        selected_aliases = aliases if with_aliases is True else set() if with_aliases is False else with_aliases
        for kind, value, _ in items:
            if kind == "variable" and (value in _WS_SOURCE or value in selected_aliases):
                return True
            if kind in ("interpolated", "backtick"):
                if any(m[0] in _WS_SOURCE or m[0] in selected_aliases for m in re.finditer(r"\$[A-Za-z_][A-Za-z_0-9]*", value, re.ASCII)):
                    return True
        return any(kind == "code" and value.lower().lstrip("\\") in ("filter_input", "file_get_contents")
                   and j + 1 < len(items) and items[j + 1][1] == "("
                   and (value.lower().lstrip("\\") == "filter_input" or any(t[0] in ("string", "interpolated") and t[1] == "php://input" for t in items[j + 2:j + 5]))
                   for j, (kind, value, _) in enumerate(items))
    def direct_input(begin, end):
        # Unknown helper calls may validate/resolve a path. Their return value
        # requires review; a plain alias, cast or basename is not such evidence.
        visible, position = [], begin
        while position < end:
            kind, value, _ = tokens[position]
            callable_name = kind == "variable" or kind == "code" and re.fullmatch(r"\\?[A-Za-z_][A-Za-z_0-9\\]*", value, re.ASCII) is not None
            if (callable_name and position + 1 < end and tokens[position + 1][1] == "(" and
                    constants.get(value, value.lower().lstrip("\\")) not in _WS_INPUT_TRANSFORMS):
                stop = pairs.get(position + 1)
                if stop is not None and stop < end:
                    position = stop + 1
                    continue
            visible.append(tokens[position])
            position += 1
        return request(visible, direct_aliases)
    def encoded(items):
        return any(kind == "variable" and value in decoded or
                   constants.get(value, value.lower().lstrip("\\")) in _WS_DECODERS
                   and kind in ("code", "variable") and j + 1 < len(items) and items[j + 1][1] == "("
                   for j, (kind, value, _) in enumerate(items))
    def uncertain(items):
        return any(kind == "variable" and value in complex_values or
                   kind in ("interpolated", "backtick") and any(m[0] in complex_values for m in re.finditer(r"\$[A-Za-z_][A-Za-z_0-9]*", value, re.ASCII))
                   for kind, value, _ in items)
    def add(indicator, offset):
        # One row per rule/file, earliest line; no attacker-controlled excerpt.
        if indicator not in hits:
            hits[indicator] = source.count("\n", 0, offset) + 1
    def registry(items):
        if len(items) == 1 and items[0][0] == "variable":
            return items[0][1] in registry_aliases
        if (len(items) <= 3 or items[0][0] != "variable" or items[0][1] in _WS_SOURCE or
                items[0][1] in aliases and items[0][1] not in registry_aliases):
            return False
        position = 1
        while position < len(items):
            if items[position][:2] != ("code", "["):
                return False
            nesting = 1
            position += 1
            while position < len(items) and nesting:
                if items[position][0] == "code":
                    nesting += int(items[position][1] == "[") - int(items[position][1] == "]")
                position += 1
            if nesting:
                return False
        return True
    def prefixed(items):
        # This changes triage priority only, never asserts that a prefix stops
        # traversal. Direct request expressions retain the higher-priority rule.
        if items and items[0][:2] == ("code", "("):
            items = items[1:]
        return (len(items) > 2 and items[1][:2] == ("code", ".") and
                (items[0][0] == "string" and items[0][1].endswith("/") or
                 items[0][0] == "code" and re.fullmatch(r"[A-Z_][A-Z_0-9]*", items[0][1]) is not None))
    depth, pending_function, scopes = 0, False, []
    network_offset, shell_offset = None, None
    for index, (kind, value, offset) in enumerate(tokens):
        if index % 256 == 0 and time.monotonic() > deadline:
            incomplete = "time"
            break
        if kind == "code" and value.lower() == "function":
            pending_function = True
        if kind == "code" and value == "{":
            depth += 1
            if pending_function:
                scopes.append((depth, aliases, direct_aliases, registry_aliases, decoded, complex_values, constants))
                aliases, registry_aliases, decoded, complex_values, constants, pending_function = set(), set(), set(), set(), {}, False
                direct_aliases = set()
        if kind == "code" and value == "}":
            if scopes and scopes[-1][0] == depth:
                _, aliases, direct_aliases, registry_aliases, decoded, complex_values, constants = scopes.pop()
            depth = max(0, depth - 1)
        if kind == "variable" and index + 1 < len(tokens) and tokens[index + 1][1] == "=":
            end = index + 2
            while end < min(len(tokens), index + 514) and tokens[end][:2] != ("code", ";"):
                end += 1
            expression = tokens[index + 2:end]
            tainted = request(expression)
            from_registry = registry(expression) or len(expression) == 1 and expression[0][0] == "variable" and expression[0][1] in registry_aliases
            direct_value = not from_registry and direct_input(index + 2, end)
            packed = encoded(expression)
            complex_value = end == index + 514 or uncertain(expression)
            aliases.discard(value)
            direct_aliases.discard(value)
            registry_aliases.discard(value)
            decoded.discard(value)
            complex_values.discard(value)
            constants.pop(value, None)
            if tainted:
                aliases.add(value)
            if direct_value:
                direct_aliases.add(value)
            if from_registry:
                registry_aliases.add(value)
            if packed:
                decoded.add(value)
            if complex_value:
                complex_values.add(value)
            if expression and all(t[0] == "string" or t[0] == "interpolated" and "$" not in t[1] or t[0] == "code" and t[1] == "." for t in expression):
                name = "".join(t[1] for t in expression if t[1] != ".")
                if len(name) <= 128:
                    constants[value] = name.lower().lstrip("\\")
        if kind == "backtick" and request([(kind, value, offset)]):
            add("request-execution", offset)
        if kind not in ("code", "variable"):
            continue
        name = constants.get(value, value.lower().lstrip("\\"))
        # A method named system/eval is not a call to that global function.
        if index and tokens[index - 1][1] in ("->", "?->", "::", "function", "new"):
            continue
        if name in ("include", "include_once", "require", "require_once") and kind == "code":
            end = index + 1
            while end < min(len(tokens), index + 513) and tokens[end][:2] != ("code", ";"):
                end += 1
            if end == index + 513:
                incomplete = incomplete or "expression"
            if request(tokens[index + 1:end]):
                expression = tokens[index + 1:end]
                indicator = ("request-prefixed-include" if direct_input(index + 1, end) else "prefixed-include") if prefixed(expression) else "request-include"
                add(indicator, offset)
            if uncertain(tokens[index + 1:end]):
                incomplete = incomplete or "expression"
        if index + 1 >= len(tokens) or tokens[index + 1][1] != "(":
            continue
        if name not in _WS_CALLS and not (kind == "variable" and (value in aliases or value in complex_values)) and value != "]":
            continue
        end = pairs.get(index + 1)
        if end is None or end - index > 512:
            incomplete = incomplete or "expression"
            continue
        arguments = tokens[index + 2:end]
        if name in _WS_SINKS and uncertain(arguments) or kind == "variable" and value in complex_values:
            incomplete = incomplete or "expression"
        if name in _WS_NETWORK:
            network_offset = offset if network_offset is None else network_offset
        if name in REQUIRED:
            for arg_kind, arg_value, _ in arguments:
                if arg_kind in ("string", "interpolated") and len(arg_value) <= 1024 and re.search(r"(?:^|[\s/])(?:ba|da|a|k|z)?sh(?:\s|$)|cmd\.exe|powershell(?:\.exe)?", arg_value, re.I):
                    shell_offset = offset if shell_offset is None else shell_offset
                    if "/dev/tcp/" in arg_value:
                        network_offset = offset if network_offset is None else network_offset
        if kind == "variable" and value in aliases:
            add("registry-callable" if value in registry_aliases else "request-callable", offset)
        if name in _WS_CALLBACKS:
            # Inspect the first callback argument, without conflating request
            # data passed as a later argument with a request-selected function.
            argument_end, nesting = 0, 0
            for argument_end, item in enumerate(arguments):
                if item[0] == "code":
                    if item[1] in ("(", "["):
                        nesting += 1
                    elif item[1] in (")", "]"):
                        nesting -= 1
                    elif item[1] == "," and nesting == 0:
                        break
            else:
                argument_end = len(arguments)
            if request(arguments[:argument_end]):
                add("registry-callable" if registry(arguments[:argument_end]) else "request-callable", offset)
            if uncertain(arguments[:argument_end]):
                incomplete = incomplete or "expression"
        if value == "]" and index in closing:
            begin = closing[index]
            base = begin - 1
            while base in closing and tokens[base][1] == "]":
                base = closing[base] - 1
            if base >= 0 and request(tokens[base:index + 1]):
                add("registry-callable" if registry(tokens[base:index + 1]) else "request-callable", offset)
        if name in _WS_SINKS and request(arguments):
            add("request-execution", offset)
        if name in ("eval", "assert", "create_function"):
            if encoded(arguments):
                add("encoded-execution", offset)
    if network_offset is not None and shell_offset is not None:
        add("network-shell", min(network_offset, shell_offset))
    return hits, incomplete


# Source: src/webshell_windows.py
"""Bounded leads from explicit PHP openers; windows never certify full coverage."""


def webshell_collect_openers(probe, offset, preceding_lines, openers, maximum, complete=False):
    if len(openers) >= maximum:
        return
    for match in _WS_EXPLICIT_OPEN.finditer(probe):
        if not complete and match.start() >= len(probe)-8:
            break
        position = offset + match.start()
        if not openers or position > openers[-1][0]:
            openers.append((position, preceding_lines + probe.count("\n", 0, match.start()) + 1))
            if len(openers) >= maximum:
                break


def webshell_window_indicators(fd, openers, deadline, budget, total_remaining):
    """Read at most 64 KiB/opener and the parser budget in total, with full gaps."""
    hits, consumed = {}, 0
    for position, first_line in openers:
        if time.monotonic() > deadline:
            return hits, "time", consumed
        if consumed >= budget:
            break
        if consumed >= total_remaining:
            return hits, "total-bytes", consumed
        length = min(65536, budget-consumed, total_remaining-consumed)
        data = os.pread(fd, length, position)
        consumed += len(data)
        observed, partial = webshell_indicators(data, deadline, short_tags=False)
        for indicator, line in observed.items():
            hits[indicator] = min(hits.get(indicator, first_line+line-1), first_line+line-1)
        if partial == "time":
            return hits, "time", consumed
    # A bounded window can omit aliases/control flow elsewhere in the file.
    # Even apparently complete individual blocks cannot upgrade this to full.
    return hits, "window", consumed


# Source: src/webshell_scan.py
"""Read-only filesystem scan, finite coverage diagnostics and exact baselines."""


def webshell_priority(disabled=False):
    """Lower this engine's priority without restarting its stdin/SSH payload."""
    if disabled:
        return dict(cpu_priority="disabled", io_priority="disabled")
    result = dict(cpu_priority="unavailable", io_priority="unavailable")
    try:
        current = os.getpriority(os.PRIO_PROCESS, 0)
        if current < 10:
            os.setpriority(os.PRIO_PROCESS, 0, 10)
        result["cpu_priority"] = "lowered" if current < 10 else "already_low"
    except (OSError, AttributeError):
        pass
    helper = shutil.which("ionice")
    if helper:
        try:
            helper = trusted(Path(helper).resolve(strict=True))
            command([str(helper), "-c", "3", "-p", str(os.getpid())], timeout=2)
            result["io_priority"] = "idle"
        except (OSError, CheckError):
            pass
    return result


def webshell_baseline_entries(data):
    """Accept explicit reviewed entries or a local, nonredacted scan JSON."""
    from pathlib import PurePosixPath
    if not isinstance(data, dict) or data.get("redacted"):
        raise CheckError("Baseline must be a local, nonredacted webshell report or schema 1 file list")
    if "requires_review" in data and data["requires_review"] is not True:
        raise CheckError("Baseline requires_review marker must be true")
    reviewed = []
    if data.get("schema_version") == 2 and isinstance(data.get("discovery"), dict) and data["discovery"].get("webshell_scan") is True:
        if data.get("reviewed_files"):
            raise CheckError("Reviewed coverage exceptions require an explicit schema 1 baseline")
        rows = data.get("findings")
        if not isinstance(rows, list) or len(rows) > 10000:
            raise CheckError("Baseline finding limit exceeded or invalid finding list")
        entries = []
        for row in rows:
            if not isinstance(row, dict):
                raise CheckError("Invalid baseline finding")
            if row.get("rule_id") not in ("P2S-WS001", "P2S-WS002", "P2S-WS004", "P2S-WS007"):
                continue
            resource = row.get("resource")
            if not isinstance(resource, dict):
                raise CheckError("Invalid baseline resource")
            entries.append(dict(resource, sha256=row.get("sha256"), indicators=[resource.get("indicator")]))
    elif data.get("schema_version") == 1:
        entries = data.get("files", [])
        reviewed = data.get("reviewed_files", [])
        if "files" not in data and "reviewed_files" not in data:
            raise CheckError("Baseline requires files or explicit reviewed_files")
    else:
        raise CheckError("Baseline must be a local, nonredacted webshell report or schema 1 file list")
    if not isinstance(entries, list) or not isinstance(reviewed, list) or len(entries) + len(reviewed) > 10000:
        raise CheckError("Baseline entry limit exceeded or invalid file list")
    result = {}
    for entry, coverage_entry in [(entry, False) for entry in entries] + [(entry, True) for entry in reviewed]:
        if not isinstance(entry, dict):
            raise CheckError("Invalid baseline entry")
        path, fingerprint = baseline_path(entry), entry.get("sha256")
        indicators = entry.get("coverage_reasons" if coverage_entry else "indicators")
        allowed = WEBSHELL_REVIEWABLE_REASONS if coverage_entry else WEBSHELL_INDICATORS
        if (data.get("requires_review") is True or "reviewed" in entry) and entry.get("reviewed") is not True:
            raise CheckError("Unreviewed baseline draft: compare complete files with trusted source and set reviewed=true explicitly")
        if coverage_entry and entry.get("reviewed") is not True:
            raise CheckError("Coverage exceptions require reviewed=true after trusted full-file comparison")
        if (type(path) is not str or "\x00" in path or not PurePosixPath(path).is_absolute() or
                str(PurePosixPath(path)) != path or ".." in PurePosixPath(path).parts or path.startswith("//") or
                type(fingerprint) is not str or re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None or
                type(indicators) is not list or not indicators or len(indicators) > len(allowed) or
                any(type(value) is not str or value not in allowed for value in indicators)):
            raise CheckError("Baseline entries require an absolute canonical path, SHA256 and known indicator names")
        for indicator in indicators:
            key = (path, "coverage:" + indicator if coverage_entry else indicator)
            if key in result and result[key] != fingerprint:
                raise CheckError("Conflicting baseline entries")
            result[key] = fingerprint
            if len(result) > 10000:
                raise CheckError("Baseline entry limit exceeded or invalid file list")
    return result


def read_webshell_baseline(name, validator=None):
    """Do not let an application-writable baseline approve attacker changes."""
    path = Path(os.path.abspath(name))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            directory = index < len(path.parts) - 2
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0), dir_fd=fd)
            os.close(fd)
            fd = child
            metadata = os.fstat(fd)
            if metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022:
                raise CheckError("Baseline and ancestors must be owned by root/current user without group/other write access")
            if not directory and not stat.S_ISREG(metadata.st_mode):
                raise CheckError("Baseline must be a regular file")
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 2 * 1024 * 1024:
            raise CheckError("Baseline must be a regular JSON file no larger than 2 MiB")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, 2 * 1024 * 1024 - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > 2 * 1024 * 1024:
                raise CheckError("Baseline must be a regular JSON file no larger than 2 MiB")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise CheckError("Baseline changed while reading")
        return (validator or webshell_baseline_entries)(json.loads(b"".join(chunks).decode("utf-8")))
    finally:
        os.close(fd)


def webshell_startup_lines(data, filename, deadline):
    """Apache comments are whole logical # lines; semicolons are ordinary."""
    def apache_fields(text):
        fields, position = [], 0
        while position < len(text):
            if text[position].isspace():
                position += 1
                continue
            quote = text[position] if text[position] in ("'", '"') else None
            if quote:
                position += 1
            value = []
            while position < len(text):
                char = text[position]
                if quote and char == "\\" and position + 1 < len(text) and text[position+1] in (quote, "\\"):
                    value.append(text[position+1])
                    position += 2
                elif quote and char == quote:
                    position += 1
                    quote = None
                    break
                elif not quote and char.isspace():
                    break
                else:
                    value.append(char)
                    position += 1
            if quote:
                raise ValueError("Unclosed Apache argument")
            fields.append("".join(value))
            if len(fields) > 3:
                break
        return fields
    hits, partial = {}, None
    pending, logical_length, logical_start = [], 0, 1
    for line, text in enumerate(data.decode("latin-1").splitlines(), 1):
        if line % 128 == 0 and time.monotonic() > deadline:
            return hits, "time"
        value = None
        if filename == ".htaccess":
            if not pending:
                logical_start = line
            continued = text.endswith("\\")
            piece = text[:-1] if continued else text
            if logical_length <= 8190:
                pending.append(piece[:8191-logical_length])
            logical_length += len(piece)
            if continued:
                continue
            text, length = "".join(pending), logical_length
            pending, logical_length = [], 0
            if not re.match(r"\s*php_(?:admin_)?value\s+auto_(?:prepend|append)_file\b", text, re.I):
                continue
            if length > 8190:
                partial = "config-syntax"
                continue
            try:
                fields = apache_fields(text)
            except ValueError:
                partial = "config-syntax"
                continue
            if len(fields) != 3:
                partial = "config-syntax"
                continue
            value, line = fields[2], logical_start
        else:
            directive = re.match(r"\s*auto_(?:prepend|append)_file\s*=\s*(.*)", text, re.I)
            if not directive:
                continue
            raw, quote, escaped, end = directive[1], None, False, len(directive[1])
            for index, char in enumerate(raw):
                if escaped:
                    escaped = False
                elif char == "\\" and quote:
                    escaped = True
                elif char in ("'", '"'):
                    quote = None if quote == char else char if quote is None else quote
                elif char == ";" and quote is None:
                    end = index
                    break
            if quote:
                partial = "config-syntax"
            value = raw[:end].strip().strip("\"'")
        if value is not None and value.strip().lower() not in ("", "none", "off"):
            hits.setdefault("startup-reference", line)
    if pending and re.match(r"\s*php_(?:admin_)?value\s+auto_(?:prepend|append)_file\b", "".join(pending), re.I):
        partial = "config-syntax"
    return hits, partial


def scan_webshells(args):
    """Pin traversed directories; bound each file independently of root time."""
    report = Report()
    report.discovery = dict(getattr(args, "discovery", {}), webshell_scan=True, webshell_coverage=[])
    for issue in report.discovery.get("issues", []):
        report.add("UNKNOWN", "Automatic discovery", issue, rule_id="P2S-DISC001", resource=issue)
    baseline = {}
    if getattr(args, "baseline", None):
        try:
            baseline = read_webshell_baseline(args.baseline)
            report.add("INFO", "Webshell baseline", "Reviewed baseline loaded; exact path, full-file SHA256 and indicator/reviewed-coverage matches only",
                       rule_id="P2S-WS005", resource="baseline", evidence=dict(baseline_entries=len(baseline)))
        except (OSError, ValueError, RecursionError, CheckError) as exc:
            reason = str(exc) if isinstance(exc, CheckError) else "Baseline path is unreadable or unsafe" if isinstance(exc, OSError) else "Baseline JSON or encoding is invalid"
            report.add("UNKNOWN", "Webshell baseline", "Baseline could not be validated; no baseline entries accepted; scan continues; " + reason,
                       rule_id="P2S-WS005", resource=dict(path=os.path.abspath(args.baseline)))
    stage(args, "Scanning local files for PHP webshell indicators")
    file_seconds = getattr(args, "scan_file_seconds", 2)
    for root in args.roots:
        reasons, seen, examined, attempted, read_bytes, findings, active, accepted = set(), 0, 0, 0, 0, 0, 0, 0
        accepted_incomplete, windowed_files = 0, 0
        deadline = time.monotonic() + args.walk_seconds if args.walk_seconds else float("inf")
        frames = []
        coverage = dict(root=root, paths=[], issue_count=0, omitted_paths=0, reason_counts={})
        report.discovery["webshell_coverage"].append(coverage)
        def record(path, reason, fingerprint=None):
            nonlocal accepted_incomplete
            approved = fingerprint is not None and reason in WEBSHELL_REVIEWABLE_REASONS and baseline.get((path, "coverage:" + reason)) == fingerprint
            if approved:
                accepted_incomplete += 1
            else:
                reasons.add(reason)
            coverage["issue_count"] += 1
            counts = coverage["reason_counts"]
            counts[reason] = counts.get(reason, 0) + 1
            if len(coverage["paths"]) < 1000:
                item = dict(path=path, reason=reason)
                if fingerprint is not None:
                    item.update(sha256=fingerprint, baseline_accepted=approved)
                coverage["paths"].append(item)
            else:
                coverage["omitted_paths"] += 1
        def open_root():
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in Path(root).parts[1:]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    os.close(fd)
                    fd = child
                return fd
            except BaseException:
                os.close(fd)
                raise
        try:
            fd = open_root()
            try:
                device = os.fstat(fd).st_dev
                entries = os.scandir(fd)
            except BaseException:
                os.close(fd)
                raise
            frames.append((fd, entries, root))
            while frames:
                if time.monotonic() > deadline:
                    record(frames[-1][2], "time")
                    break
                parent_fd, entries, parent = frames[-1]
                entry = next(entries, None)
                if entry is None:
                    entries.close()
                    os.close(parent_fd)
                    frames.pop()
                    continue
                seen += 1
                path = os.path.join(parent, entry.name)
                if seen > args.max_paths:
                    record(parent, "entries")
                    break
                file_fd, read_problem = None, None
                file_deadline = min(deadline, time.monotonic() + file_seconds)
                timeout_reason = "file-time" if file_deadline < deadline else "time"
                try:
                    before = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(before.st_mode):
                        record(path, "symlink")
                        continue
                    if before.st_dev != device:
                        record(path, "mount")
                        continue
                    if not stat.S_ISREG(before.st_mode) and not stat.S_ISDIR(before.st_mode):
                        record(path, "special")
                        continue
                    if stat.S_ISREG(before.st_mode):
                        attempted += 1
                    file_fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                    opened = os.fstat(file_fd)
                    if (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode)) != (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)):
                        record(path, "changed")
                        continue
                    if stat.S_ISDIR(opened.st_mode):
                        if len(frames) >= 64:
                            record(path, "depth")
                            continue
                        frames.append((file_fd, os.scandir(file_fd), path))
                        file_fd = None
                        continue
                    # Stream every byte before deciding whether parsing is
                    # necessary. Large JS/assets without PHP openers do not
                    # consume the PHP materialization budget, but still consume
                    # the root byte/time budgets and receive the race checks.
                    chunks, size, materialized, tail, lines, openers = [], 0, 0, b"", 0, []
                    max_openers = max(1, min(256, args.scan_file_bytes // 65536))
                    has_open, explicit_open, binary = False, False, False
                    fingerprint = hashlib.sha256()
                    while True:
                        if time.monotonic() > file_deadline:
                            read_problem = timeout_reason
                            break
                        chunk = os.read(file_fd, min(65536, args.scan_total_bytes - read_bytes + 1))
                        if not chunk:
                            probe = tail.decode("latin-1")
                            webshell_collect_openers(probe, size-len(tail), lines-tail.count(b"\n"), openers, max_openers, complete=True)
                            has_open = has_open or _WS_OPEN.search(probe) is not None
                            explicit_open = explicit_open or _WS_EXPLICIT_OPEN.search(probe) is not None
                            break
                        size += len(chunk)
                        read_bytes += len(chunk)
                        if read_bytes > args.scan_total_bytes:
                            read_problem = "total-bytes"
                            break
                        fingerprint.update(chunk)
                        probe = (tail + chunk).decode("latin-1")
                        webshell_collect_openers(probe, size-len(chunk)-len(tail), lines-tail.count(b"\n"), openers, max_openers)
                        opening = _WS_OPEN.search(probe)
                        explicit = _WS_EXPLICIT_OPEN.search(probe)
                        # Defer trailing starts until the next chunk/EOF, so
                        # <?xml and <?phpSuffix at boundaries are not openers.
                        has_open = has_open or opening is not None and opening.start() < len(probe) - 8
                        explicit_open = explicit_open or explicit is not None and explicit.start() < len(probe) - 8
                        binary = binary or re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]", chunk) is not None
                        lines += chunk.count(b"\n")
                        tail = (tail + chunk)[-8:]
                        if materialized < args.scan_file_bytes:
                            part = chunk[:args.scan_file_bytes - materialized]
                            chunks.append(part)
                            materialized += len(part)
                    after = os.fstat(file_fd)
                    if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        record(path, "changed")
                        continue
                    if read_problem:
                        record(path, read_problem)
                        if read_problem in ("total-bytes", "time"):
                            break
                        continue
                    data = b"".join(chunks)
                    fingerprint = fingerprint.hexdigest()
                    startup_file = entry.name.lower() in (".user.ini", ".htaccess", "php.ini")
                    parse_php = explicit_open or has_open and not binary
                    if size > args.scan_file_bytes and (startup_file or parse_php and not openers):
                        record(path, "file-size", fingerprint)
                        continue
                    used_windows = False
                    if parse_php and size > args.scan_file_bytes:
                        windowed_files += 1
                        used_windows = True
                        hits, partial, extra_bytes = webshell_window_indicators(file_fd, openers, file_deadline,
                            args.scan_file_bytes, args.scan_total_bytes-read_bytes)
                        read_bytes += extra_bytes
                    else:
                        hits, partial = webshell_indicators(data, file_deadline, short_tags=not binary) if parse_php else ({}, None)
                        if binary and partial in ("tokens", "expression") and openers:
                            used_windows = True
                            windowed_files += 1
                            extra_hits, partial, extra_bytes = webshell_window_indicators(file_fd, openers, file_deadline,
                                args.scan_file_bytes, args.scan_total_bytes-read_bytes)
                            read_bytes += extra_bytes
                            for indicator, line in extra_hits.items():
                                hits[indicator] = min(hits.get(indicator, line), line)
                    if used_windows:
                        latest = os.fstat(file_fd)
                        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (latest.st_size, latest.st_mtime_ns, latest.st_ctime_ns):
                            record(path, "changed")
                            continue
                    if startup_file:
                        startup, startup_partial = webshell_startup_lines(data, entry.name.lower(), file_deadline)
                        hits.update({key:value for key,value in startup.items() if key not in hits})
                        partial = partial or startup_partial
                    if partial:
                        record(path, timeout_reason if partial == "time" else partial, fingerprint)
                    else:
                        examined += 1
                    for indicator, line in sorted(hits.items()):
                        approved = baseline.get((path, indicator)) == fingerprint
                        if not approved and active >= 200:
                            break
                        review = indicator in ("prefixed-include", "registry-callable")
                        rule = "P2S-WS004" if review else "P2S-WS007" if indicator == "request-prefixed-include" else "P2S-WS002" if indicator == "startup-reference" else "P2S-WS001"
                        row = report.add("INFO" if review else "OPEN", "PHP code review " + path if review else "PHP file indicator " + path,
                            "Line " + str(line) + ": " + WEBSHELL_INDICATORS[indicator] + "; SHA256 " + fingerprint,
                            rule_id=rule, resource=dict(path=path, indicator=indicator),
                            evidence=dict(indicators=[indicator], line=line, review_required=review))
                        row.update(sha256=fingerprint, baseline_accepted=approved)
                        row["suppressed"] = approved and row["status"] == "OPEN"
                        findings += 1
                        accepted += int(approved)
                        active += int(not approved)
                    if active >= 200:
                        record(parent, "findings")
                        break
                    if partial == "total-bytes" or partial == "time" and timeout_reason == "time":
                        break
                except OSError:
                    record(path, "access")
                finally:
                    if file_fd is not None:
                        os.close(file_fd)
        except OSError:
            record(frames[-1][2] if frames else root, "access")
        finally:
            for fd, entries, _ in frames:
                entries.close()
                os.close(fd)
        facts = dict(examined_files=examined, attempted_files=attempted, incomplete_files=attempted-examined,
                     indicator_count=findings, baseline_accepted_count=accepted, coverage_reasons=sorted(reasons),
                     accepted_incomplete_files=accepted_incomplete, windowed_files=windowed_files,
                     coverage_counts=coverage["reason_counts"], omitted_coverage_paths=coverage["omitted_paths"])
        report.add("UNKNOWN" if reasons else "INFO", "Webshell scan coverage",
            str(examined) + " files fully examined; " + str(attempted-examined) + " incomplete files; " + str(findings) + " indicators; " +
            ("incomplete: " + ", ".join(sorted(reasons)) if reasons else "selected scan completed") +
            "; " + str(accepted_incomplete) + " incomplete files accepted by reviewed full-file hash; absence of indicators does not establish a clean server",
            rule_id="P2S-WS003", resource=dict(root=root), evidence=facts)
    return report


# Source: src/webshell_baseline.py
"""Explicit, unreviewed baseline drafts; no approval or target-file changes."""


def webshell_baseline_draft(report):
    indicators, coverage = {}, {}
    for row in report.rows:
        if row["rule_id"] not in ("P2S-WS001", "P2S-WS002", "P2S-WS004", "P2S-WS007"):
            continue
        resource, fingerprint = row.get("resource"), row.get("sha256")
        if not isinstance(resource, dict) or not isinstance(fingerprint, str) or re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None:
            continue
        path, indicator = resource.get("path"), resource.get("indicator")
        if isinstance(path, str) and indicator in WEBSHELL_INDICATORS:
            indicators.setdefault((path, fingerprint), set()).add(indicator)
    omitted, unreviewable = 0, 0
    for root in report.discovery.get("webshell_coverage", []):
        omitted += root.get("omitted_paths", 0)
        for item in root.get("paths", []):
            fingerprint, reason = item.get("sha256"), item.get("reason")
            if (reason in WEBSHELL_REVIEWABLE_REASONS and isinstance(fingerprint, str) and
                    re.fullmatch(r"[a-f0-9]{64}", fingerprint) and isinstance(item.get("path"), str)):
                coverage.setdefault((item["path"], fingerprint), set()).add(reason)
            else:
                unreviewable += 1
    draft = dict(schema_version=1, requires_review=True,
        instructions="Compare every complete file with trusted source before setting reviewed=true. Remove entries you cannot approve. This draft never proves a clean server.",
        source=dict(version=VERSION, has_unknown=report.has("UNKNOWN"), omitted_coverage_paths=omitted,
                    unreviewable_coverage_paths=unreviewable),
        files=[dict(path=path, sha256=fingerprint, indicators=sorted(values), reviewed=False)
               for (path, fingerprint), values in sorted(indicators.items())],
        reviewed_files=[dict(path=path, sha256=fingerprint, coverage_reasons=sorted(values), reviewed=False)
                        for (path, fingerprint), values in sorted(coverage.items())])
    if len(draft["files"]) + len(draft["reviewed_files"]) > 10000:
        raise CheckError("Baseline draft entry limit exceeded; narrow the scan scope")
    return json_paths(draft)


def write_baseline_draft(name, report):
    """Create mode 0600 exclusively through pinned, non-symlink directories."""
    draft = webshell_baseline_draft(report)
    path = write_private_json(name, draft)
    return dict(path=path, indicator_files=len(draft["files"]), coverage_files=len(draft["reviewed_files"]))


def write_private_json(name, draft):
    """Exclusive private JSON output, shared by explicitly unreviewed drafts."""
    data = (json.dumps(draft, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    if len(data) > 2 * 1024 * 1024:
        raise CheckError("Baseline draft exceeds 2 MiB; narrow the scan scope")
    path = Path(os.path.abspath(name))
    if path == Path("/"):
        raise CheckError("Baseline draft requires a new file path")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    file_fd, identity = None, None
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            os.close(parent)
            parent = child
        file_fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        identity = os.fstat(file_fd)
        os.fchmod(file_fd, 0o600)
        pending = memoryview(data)
        while pending:
            count = os.write(file_fd, pending)
            if count <= 0:
                raise OSError("Baseline draft write made no progress")
            pending = pending[count:]
        os.fsync(file_fd)
        os.fsync(parent)
    except BaseException:
        if identity is not None:
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                os.unlink(path.name, dir_fd=parent)
        raise
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent)
    return str(path)


# Source: src/audit.py
def scan(args, inventory_only=False):
    report, updates = Report(), {}
    report.discovery = dict(getattr(args, "discovery", {}))
    cap = capabilities()
    report.discovery["capabilities"] = cap
    for message in report.discovery.get("issues", []):
        report.add("UNKNOWN", 'Automatic discovery', message, rule_id='P2S-DISC001', resource=message)
    stage(args, 'Discovering FPM instances and pools')
    try:
        instances, unknown = discover()
    except (OSError, ValueError, CheckError) as exc:
        instances, unknown = [], [str(exc)]
    for message in unknown:
        report.add("UNKNOWN", 'FPM coverage', message, rule_id='P2S-DISC002', resource=message)
    users = set(args.web_user)
    if report.discovery:
        report.discovery["fpm_instances"] = [dict(pid=i["pid"], config=i["config"], service=i.get("service"),
            pools=[dict(name=name, user=settings.get("user", 'unknown'), listen=settings.get("listen", 'unknown'))
                   for name, settings in i["pools"].items()]) for i in instances]
    if inventory_only:
        report.discovery["inventory_only"] = True
        for instance in instances:
            users.update(v["user"] for v in instance["pools"].values() if v.get("user"))
        return report, {}, instances, users
    nginx_upload_security(report, args)
    for instance in instances:
        saved_updates = {name: dict(values) for name, values in updates.items()}
        try:
            pool_security(report, instance)
            residual_php_policy(report, instance)
            fpm_service_posture(report, instance, cap)
            label = instance["config"]
            values = instance["values"]
            disabled = functions(values.get("disable_functions", ""))
            missing = REQUIRED - disabled
            function_row = report.add("OPEN" if missing else "OK", f"disable_functions {label}",
                       f"Missing: {','.join(sorted(missing))}" if missing else 'The 7 selected shell functions are disabled', rule_id='P2S-PHP001', resource=dict(config=label), evidence=dict(missing_functions=sorted(missing)))
            function_row["affected_pools"] = []
            desired = {}
            if missing:
                desired["disable_functions"] = ",".join(sorted(disabled | REQUIRED))
            url_include = values.get("allow_url_include")
            if url_include is None:
                include_row = report.add("UNKNOWN", f"allow_url_include {label}", 'Value missing', rule_id='P2S-PHP002', resource=dict(config=label))
            else:
                enabled = url_include.lower() not in ("off", "0", "no", "false", "")
                include_row = report.add("OPEN" if enabled else "OK", f"allow_url_include {label}", url_include, rule_id='P2S-PHP002', resource=dict(config=label), evidence=dict(allow_url_include=enabled))
                if enabled:
                    desired["allow_url_include"] = "Off"
            include_row["affected_pools"] = []
            for pool, settings in instance["pools"].items():
                user = settings.get("user")
                if user and user != "undefined":
                    users.add(user)
                combined = disabled | functions(settings.get("php_admin_value[disable_functions]", "")) | functions(settings.get("php_value[disable_functions]", ""))
                absent = REQUIRED - combined
                if absent != missing:
                    report.add("OPEN" if absent else "OK", f"Pool {label} [{pool}]",
                               f"Missing: {','.join(sorted(absent))}" if absent else 'Global and pool restrictions evaluated together', rule_id='P2S-PHP001', resource=dict(config=label, pool=pool), evidence=dict(missing_functions=sorted(absent)))
                else:
                    function_row["affected_pools"].append(pool)
                include_value = url_include
                include_override = False
                for prefix in ("php_value", "php_flag", "php_admin_value", "php_admin_flag"):
                    override = settings.get(prefix + "[allow_url_include]")
                    if override is not None and override != "undefined":
                        include_value = override
                        include_override = True
                pool_enabled = None if include_value is None else include_value.lower() not in ("off", "0", "no", "false", "")
                global_enabled = None if url_include is None else url_include.lower() not in ("off", "0", "no", "false", "")
                # An explicit unsafe override survives a global fix, even when
                # its current value matches the global value: a separate cause.
                if pool_enabled == global_enabled and not (pool_enabled and include_override):
                    include_row["affected_pools"].append(pool)
                elif include_value is None:
                    report.add("UNKNOWN", f"allow_url_include [{pool}] {label}", 'Value missing', rule_id='P2S-PHP002', resource=dict(config=label, pool=pool))
                else:
                    report.add("OPEN" if pool_enabled else "OK", f"allow_url_include [{pool}] {label}",
                               include_value + ('; correct the pool override manually' if pool_enabled else ""), rule_id='P2S-PHP002', resource=dict(config=label, pool=pool), evidence=dict(allow_url_include=pool_enabled))
                ob = settings.get("php_admin_value[open_basedir]", settings.get("php_value[open_basedir]", values.get("open_basedir", "")))
                unrestricted = not ob or ob.lower() in ("none", "no value", "undefined") or "/" in [p.strip() for p in ob.split(":")]
                report.add("OPEN" if unrestricted else "OK", f"open_basedir [{pool}] {label}",
                           'Unrestricted' if unrestricted else f'{ob} (an additional restriction, not a sandbox)', rule_id='P2S-PHP003', resource=dict(config=label, pool=pool), evidence=dict(unrestricted=unrestricted))
            for row in (function_row, include_row):
                row["affected_pools"].sort()
                row["evidence"]["affected_pool_count"] = len(row["affected_pools"])
            for key, value in desired.items():
                owners = [p for p in instance["inis"] if active_ini_lines(Path(p).read_text(), key)]
                target = owners[-1] if owners else instance["inis"][0]
                if os.path.commonpath([target, str(Path(instance["inis"][0]).parent)]) != str(Path(instance["inis"][0]).parent):
                    report.add("OPEN", 'Automatic INI fix skipped', f'{key}: shared file outside the FPM INI root: {target}', rule_id='P2S-FIX001', resource=dict(path=target, key=key))
                    continue
                existing = updates.setdefault(target, {})
                if key in existing and existing[key] != value:
                    raise CheckError('Conflicting INI values across FPM instances')
                existing[key] = value
        except (OSError, UnicodeError, ValueError, CheckError) as exc:
            updates = saved_updates
            report.add("UNKNOWN", f"FPM configuration {instance['config']}", str(exc), rule_id='P2S-DISC003', resource=instance["config"])
    shared_pool_users(report, instances)
    report.discovery["assessment"] = dict(configuration="disk", worker_attestation=False,
        network_reachability=False, application_vulnerabilities=False)
    if not users:
        report.add("UNKNOWN", 'File permissions', 'No verified FPM user; specify --web-user', rule_id='P2S-FS003', resource="missing_user")
    stage(args, 'Checking file permissions as the discovered FPM users')
    roots = getattr(args, "roots", None) or [args.root]
    ready_users = []
    for user in sorted(users):
        try:
            uid = pwd.getpwnam(user).pw_uid
            if uid == 0:
                report.add("OPEN", 'FPM user', f'{user} has UID 0', rule_id='P2S-FS005', resource=user)
            elif uid != os.geteuid() and not cap["root"]:
                report.add("UNKNOWN", f'File permissions ({user})', 'Cannot check another UID; use sudo/root. Other checks continue.', rule_id='P2S-FS003', resource=user)
            elif uid != os.geteuid() and not cap["tools"]["runuser"]:
                report.add("UNKNOWN", f'File permissions ({user})', f"runuser missing; {install_hint('util-linux')}. Other checks continue.", rule_id='P2S-FS003', resource=user)
            else:
                ready_users.append(user)
        except KeyError:
            report.add("UNKNOWN", f'File permissions ({user})', 'User does not exist on this host; correct --web-user or audit the container separately', rule_id='P2S-FS003', resource=user)
    for user, scan_root in [(user, root) for user in ready_users for root in roots]:
        try:
            if pwd.getpwnam(user).pw_uid == 0:
                report.add("OPEN", 'FPM user', f'{user} has UID 0', rule_id='P2S-FS005', resource=user)
                continue
            options = json.dumps(dict(runtime_dirs=getattr(args, "runtime_dirs", []),
                                      max_paths=getattr(args, "max_paths", 250000),
                                      max_seconds=getattr(args, "walk_seconds", 10)))
            data = json.loads(as_user(user, [sys.executable, "-B", "-c", PERMISSION_SCAN, scan_root, options]))
            for key, title in (("files", "Writable PHP files"), ("directories", "Writable directories")):
                count = data[key]
                sample = data["file_sample" if key == "files" else "directory_sample"]
                report.add("OPEN" if count else "OK", f"{title} ({user})", f"{scan_root}: {count}; " + "; ".join(sample), rule_id="P2S-FS001" if key == "files" else "P2S-FS002", resource=dict(root=scan_root, user=user), evidence={"writable_files" if key == "files" else "writable_directories":count})
            if data.get("runtime_directories"):
                report.add("INFO", "Declared runtime storage (" + user + ")",
                           str(data["runtime_directories"]) + " writable directories; PHP files remain checked; execution restrictions require separate verification; " + "; ".join(data.get("runtime_sample", [])), rule_id='P2S-FS004', resource=dict(root=scan_root, user=user))
            if data["errors"]:
                report.add("UNKNOWN", f'Filesystem coverage ({user})', f"{data.get('error_count', len(data['errors']))} unreadable or skipped paths; " + "; ".join(data["errors"][:4]), rule_id='P2S-FS003', resource=dict(root=scan_root, user=user))
        except (KeyError, OSError, ValueError, CheckError) as exc:
            report.add("UNKNOWN", f'File permissions ({user})', str(exc), rule_id='P2S-FS003', resource=dict(root=scan_root, user=user))
    if not args.site:
        report.add("UNKNOWN", 'HTTP coverage', 'No --site URL=DOCUMENT_ROOT specified', rule_id='P2S-HTTP002', resource="missing_site")
    stage(args, 'Checking HTTP endpoints and other host settings')
    git_cache, baseline_cache = {}, {}
    http_count, http_limit = 0, getattr(args, "max_http_probes", 128)
    def fetch(target, address):
        nonlocal http_count
        if http_count >= http_limit:
            raise HttpBudgetExceeded("HTTP probe budget reached; use --max-http-probes or narrow --site")
        http_count += 1
        return http_observation(target, connect_ip=address)
    exhausted = False
    for site in args.site:
        try:
            url, document_root = site.split("=", 1)
            from urllib.parse import quote, urlsplit
            parts = urlsplit(url)
            if parts.query or parts.fragment or parts.username or parts.password or parts.scheme not in ("http", "https") or not parts.hostname:
                raise CheckError('--site requires an HTTP(S) base URL without query, fragment or credentials')
            root = Path(document_root)
            if not root.is_absolute() or not root.is_dir():
                raise CheckError('Document root is missing or relative')
            if str(root) not in git_cache:
                git_cache[str(root)] = git_endpoints(root, max_paths=getattr(args, "max_paths", 250000),
                    max_seconds=getattr(args, "walk_seconds", 10))
            endpoints, walk_errors = git_cache[str(root)]
            if walk_errors:
                report.add("UNKNOWN", 'Git path coverage', "; ".join(walk_errors[:3]), rule_id='P2S-DISC004', resource=document_root)
            address = getattr(args, "site_addresses", {}).get(url, "127.0.0.1")
            for endpoint in sorted(endpoints):
                target = url.rstrip("/") + "/" + quote(endpoint, safe="/")
                try:
                    observation = fetch(target, address)
                    baselines = []
                    if 200 <= observation["status"] < 300:
                        if url not in baseline_cache:
                            baselines = []
                            for _ in range(2):
                                missing = url.rstrip("/") + "/.p2s-missing-" + uuid.uuid4().hex
                                try:
                                    baselines.append(fetch(missing, address))
                                except HttpBudgetExceeded:
                                    raise
                                except CheckError as exc:
                                    baselines.append(dict(error=str(exc)))
                            baseline_cache[url] = baselines
                        baselines = baseline_cache[url]
                    status, detail = classify_http(observation, baselines)
                    report.add(status, "HTTP " + target, detail, rule_id='P2S-HTTP001', resource=target, evidence=dict(http_status=observation["status"]))
                except HttpBudgetExceeded as exc:
                    report.add("UNKNOWN", "HTTP coverage", str(exc), rule_id='P2S-HTTP002', resource="budget")
                    exhausted = True
                    break
                except CheckError as exc:
                    report.add("UNKNOWN", "HTTP " + target, str(exc), rule_id='P2S-HTTP001', resource=target)
        except (OSError, ValueError, CheckError) as exc:
            report.add("UNKNOWN", 'HTTP configuration', str(exc), rule_id='P2S-HTTP003', resource=site)
        if exhausted:
            break
    report.discovery["http_budget"] = dict(requests=http_count, limit=http_limit, exhausted=exhausted)
    try:
        ptrace = int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text())
        report.add("OK" if ptrace >= 1 else "OPEN", "ptrace_scope", str(ptrace), rule_id='P2S-SYS001', resource="ptrace_scope", evidence=dict(ptrace_scope=ptrace))
    except (OSError, ValueError):
        report.add("UNKNOWN", "ptrace_scope", 'Unreadable', rule_id='P2S-SYS001', resource="ptrace_scope")
    # Manual policy assessment is outside the selected automated checks. It
    # must stay visible without making a complete automated audit impossible.
    policies = [str(p) for p in (Path("/etc/ImageMagick-6/policy.xml"), Path("/etc/ImageMagick-7/policy.xml")) if p.exists()]
    imagick = any(i["values"].get("imagick module", "").lower() in ("enabled", "on", "yes") for i in instances)
    report.discovery["manual_checks"] = []
    if policies or imagick:
        report.discovery["manual_checks"].append(dict(name="ImageMagick policy", status="not_assessed", paths=policies))
        report.add("INFO", "ImageMagick policy", "Not assessed automatically; review rules and delegates separately" + ("; " + ", ".join(policies) if policies else ""), rule_id='P2S-IM001', resource=policies)
    return report, updates, instances, users


# Source: src/transactions.py
def metadata(path):
    st = Path(path).lstat()
    if stat.S_ISLNK(st.st_mode):
        raise CheckError(f'Symlink refused as a change target: {path}')
    return dict(uid=st.st_uid, gid=st.st_gid, mode=stat.S_IMODE(st.st_mode),
                dev=st.st_dev, ino=st.st_ino,
                atime_ns=st.st_atime_ns, mtime_ns=st.st_mtime_ns,
                xattrs={k: base64.b64encode(os.getxattr(path, k)).decode() for k in os.listxattr(path)})


def same_permissions(first, second):
    return all(first[k] == second[k] for k in ("uid", "gid", "mode", "xattrs"))


def atomic_bytes(path, data, meta, preserve_timestamps=True, before_replace=None):
    """Replace a file, optionally checkpointing its durable replacement first."""
    fd, temp = tempfile.mkstemp(prefix=".p2s-", dir=str(Path(path).parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), meta["uid"], meta["gid"])
            os.fchmod(stream.fileno(), meta["mode"])
            for key in os.listxattr(stream.fileno()):
                if key not in meta["xattrs"]:
                    os.removexattr(stream.fileno(), key)
            for key, value in meta["xattrs"].items():
                os.setxattr(stream.fileno(), key, base64.b64decode(value))
            os.fchmod(stream.fileno(), meta["mode"])
            if preserve_timestamps and "mtime_ns" in meta:
                os.utime(stream.fileno(), ns=(meta["atime_ns"], meta["mtime_ns"]))
            os.fsync(stream.fileno())
            if before_replace is not None:
                before_replace(metadata(temp))
        os.replace(temp, path)
        parent_fd = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def reload_instances(instances):
    for item in instances:
        if start_identity(item["pid"]) != item["start"]:
            raise CheckError('FPM master changed; reload cancelled')
        command([item["binary"], "-t", "-y", item["config"]], env=item.get("env"))
        pid, _ = command(["systemctl", "show", "--property=MainPID", "--value", item["service"]])
        if pid.strip() != str(item["pid"]):
            raise CheckError('Service and FPM master do not match')
    for item in instances:
        if start_identity(item["pid"]) != item["start"]:
            raise CheckError('FPM master changed; reload cancelled')
        command(["systemctl", "reload", item["service"]])
        command(["systemctl", "is-active", "--quiet", item["service"]])


def fix_blockers(updates, protect_dirs, instances, users):
    """Preflight the complete explicit plan before creating a transaction."""
    reasons = []
    if not updates and not protect_dirs:
        return reasons
    cap = capabilities()
    if not cap["root"]:
        reasons.append('Changes require root; use sudo or --ssh root@SERVER')
    affected = [i for i in instances if set(updates).intersection(i["inis"])]
    if updates:
        if not affected or set(updates) - {p for i in affected for p in i["inis"]}:
            reasons.append('Not all INI changes have a complete FPM mapping')
        if not cap["systemd"] or not cap["tools"]["systemctl"] or any(not i.get("service") for i in affected):
            reasons.append('A verified systemd reload is unavailable for some affected FPM instances; INI fixes are blocked, the audit continues')
        else:
            for item in affected:
                try:
                    active, _ = command(["systemctl", "show", "--property=MainPID", "--value", item["service"]])
                    if active.strip() != str(item["pid"]) or start_identity(item["pid"]) != item["start"]:
                        raise CheckError('FPM master and service no longer match')
                except (OSError, CheckError) as exc:
                    reasons.append(f"Reload preflight {item['service']}: {str(exc)}")
    if protect_dirs:
        if not users:
            reasons.append('--protect-dir requires a discovered or explicit --web-user for verification')
        for user in sorted(users):
            try:
                uid = pwd.getpwnam(user).pw_uid
                if uid == 0:
                    reasons.append(f'Cannot restrict UID 0 with file permissions: {user}')
                elif uid != os.geteuid() and not cap["tools"]["runuser"]:
                    reasons.append(f"Permission verification for {user}: runuser missing; {install_hint('util-linux')}")
            except KeyError:
                reasons.append(f'Permission verification: unknown user {user}')
    return reasons


def change_plan(updates, protect_dirs, blockers):
    entries = []
    for name, values in sorted(updates.items()):
        path = trusted(name)
        if path.stat().st_size > 2 * 1024 * 1024:
            raise CheckError("INI preview exceeds 2 MiB; review this file manually")
        before = path.read_bytes()
        original = before.decode("utf-8")
        after = set_ini(original, values)
        # Zero context: show actual directive values without disclosing nearby
        # unrelated INI settings that could contain application secrets.
        def preview_lines(text):
            # Adding a directive after a final line without a newline can make
            # unified_diff include that unrelated line even with n=0. Redact
            # every non-target line before diffing, retaining line positions.
            return [line.rstrip("\r\n") + "\n" if any(active_ini_lines(line, key) for key in values) else "\n"
                    for line in text.splitlines(True)]
        difference = "".join(difflib.unified_diff(preview_lines(original), preview_lines(after),
                              fromfile=str(path), tofile=str(path) + " (planned)", n=0))
        entries.append(dict(path=str(path), values=values, before_sha256=digest(before), diff=difference))
    return dict(ini=entries, directories=list(protect_dirs), blockers=list(blockers))


INI_UPGRADE_NOTICE = "Changing an existing INI such as php.ini may cause a package-upgrade configuration prompt if local and package versions both change."


def confirm_fix(args, ini_changes=False):
    if args.yes:
        return True
    if args.json:
        raise CheckError("Review --dry-run --json first; --fix --json requires --yes")
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as terminal:
            if ini_changes:
                terminal.write(localize(INI_UPGRADE_NOTICE, args.lang) + "\n")
            terminal.write(localize("Apply this displayed plan? [y/N] ", args.lang))
            terminal.flush()
            return terminal.readline().strip().lower() in ("y", "yes", "j", "ja")
    except OSError as exc:
        raise CheckError("No controlling terminal; review --dry-run first, then use --fix --yes") from exc


TRANSACTION_LOCK_ROOT = "/run/p2s-harden"


@contextlib.contextmanager
def transaction_directory_lock(path, create=False):
    """Lock a protected directory inode without a replaceable lock file."""
    import fcntl
    path = Path(path)
    if not path.is_absolute():
        raise CheckError('Backup directory must be absolute')
    trusted(path.parent)
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if opened.st_uid != 0 or stat.S_IMODE(opened.st_mode) != 0o700:
            raise CheckError('Transaction lock and backup directories must have mode 0700 and be owned by root')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CheckError('Another fix or rollback is running; wait for it to finish and rerun') from exc
        current = path.lstat()
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise CheckError('Transaction lock directory changed while acquiring the lock')
        yield fd
    finally:
        os.close(fd)


class Transaction:
    def __init__(self, backup_root):
        self.root = Path(backup_root)
        self.path = None
        self.noop = False
        self._lock_fd = None
        self.data = dict(version=1, status="prepared", files=[], directories=[], instances=[])

    @contextlib.contextmanager
    def locked(self, create=False):
        """One system-wide writer plus the legacy backup-root lock.

        Both protected directory inodes are pinned; no configurable global
        path, replaceable lock file or stale PID. Reentrant only for this object.
        """
        if self._lock_fd is not None:
            yield
            return
        if os.geteuid() != 0:
            raise CheckError('Changes and rollback require root')
        with transaction_directory_lock(TRANSACTION_LOCK_ROOT, create=True) as fd, transaction_directory_lock(self.root, create=create):
            self._lock_fd = fd
            try:
                yield
            finally:
                self._lock_fd = None

    def begin(self):
        import time
        if os.geteuid() != 0:
            raise CheckError('Changes and rollback require root')
        if not self.root.is_absolute():
            raise CheckError('Backup directory must be absolute')
        trusted(self.root.parent)
        if not self.root.exists():
            self.root.mkdir(mode=0o700)
        trusted(self.root)
        if self.root.stat().st_mode & 0o077:
            raise CheckError('Backup directory must have mode 0700')
        self.path = self.root / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:10])
        self.path.mkdir(mode=0o700)
        self.data["created_ns"] = time.time_ns()
        self.save()

    def save(self):
        atomic_bytes(self.path / "manifest.json", json.dumps(self.data, indent=2).encode(),
                     dict(uid=0, gid=0, mode=0o600, xattrs={}))

    @staticmethod
    def same_state(current, expected, identity=True):
        keys = ("mtime_ns", "dev", "ino") if identity else ("mtime_ns",)
        return same_permissions(current, expected) and all(current[k] == expected[k] for k in keys)

    def checkpoint(self, item, key, value):
        item[key] = value
        self.save()

    def prepare(self, updates, protect_dirs, instances, expected=None):
        with self.locked(create=True):
            return self._prepare(updates, protect_dirs, instances, expected)

    def _prepare(self, updates, protect_dirs, instances, expected=None):
        # Guard callers other than main as well: never edit first and discover
        # a missing reload/user-switch capability during recovery.
        affected = [i for i in instances if set(updates).intersection(i["inis"])]
        if any(not i.get("service") for i in affected):
            raise CheckError('No verified FPM service for INI changes')
        self.begin()
        for target, values in sorted(updates.items()):
            path = trusted(target)
            before_meta = metadata(path)
            original = path.read_bytes()
            if expected is not None and digest(original) != expected.get(str(path)):
                raise CheckError("Configuration changed after the displayed preview; rerun --dry-run")
            changed = set_ini(original.decode(), values).encode()
            backup = f"file-{len(self.data['files'])}.bin"
            atomic_bytes(self.path / backup, original, dict(uid=0, gid=0, mode=0o600, xattrs={}))
            self.data["files"].append(dict(path=str(path), backup=backup, before=digest(original),
                                           after=digest(changed), meta=before_meta, values=values))
        for name in sorted(set(protect_dirs), key=lambda p: len(Path(p).parts)):
            path = Path(name)
            if not path.is_absolute() or not path.is_dir():
                raise CheckError('--protect-dir requires an existing absolute directory')
            # No path component may be a symlink. Protecting a directory is
            # explicit and non-recursive; children/runtime storage stay intact.
            for part in [path, *path.parents]:
                if part.is_symlink():
                    raise CheckError('Symlink in --protect-dir refused')
            self.data["directories"].append(dict(path=str(path), meta=metadata(path)))
        changed_inis = set(updates)
        self.data["instances"] = [{k: i[k] for k in ("pid", "start", "binary", "config", "service")} for i in instances if changed_inis.intersection(i["inis"])]
        self.save()

    def apply(self, instances, users):
        with self.locked():
            return self._apply(instances, users)

    def _apply(self, instances, users):
        try:
            affected = [i for i in instances if i["pid"] in {r["pid"] for r in self.data["instances"]}]
            if {i["pid"] for i in affected} != {i["pid"] for i in self.data["instances"]}:
                raise CheckError("Complete FPM instances are required for before/after INI verification")
            snapshots = {i["pid"]: ini_snapshot(command([i["binary"], "-i"], env=i["env"])[0]) for i in affected}
            for item in self.data["files"]:
                path = trusted(item["path"])
                original = path.read_bytes()
                if digest(original) != item["before"] or not self.same_state(metadata(path), item["meta"]):
                    raise CheckError('Configuration changed since preflight')
                item["started"] = True
                self.save()
                atomic_bytes(path, set_ini(original.decode(), item["values"]).encode(), item["meta"],
                             preserve_timestamps=False,
                             before_replace=lambda meta: self.checkpoint(item, "after_meta", meta))
                item["after_meta"] = metadata(path)
                self.save()
            for item in self.data["directories"]:
                path, before = Path(item["path"]), item["meta"]
                now = metadata(path)
                if not self.same_state(now, before):
                    raise CheckError('Directory changed since preflight')
                # Refuse a replaceable parent; explicitly protect higher-level
                # code directories first instead of traversing them as root.
                trusted(path.parent)
                item["started"] = True
                self.save()
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    current = os.fstat(fd)
                    if (current.st_dev, current.st_ino) != (before["dev"], before["ino"]):
                        raise CheckError('Directory identity changed')
                    os.fchown(fd, 0, before["gid"])
                    os.fchmod(fd, before["mode"] & ~0o022)
                finally:
                    os.close(fd)
                item["after"] = metadata(path)
                self.save()
                for user in users:
                    output = as_user(user, [sys.executable, "-B", "-c", "import os,sys; print(int(os.access(sys.argv[1], os.W_OK)))", str(path)])
                    if output.strip() != "0":
                        raise CheckError(f'{path} remains writable by {user}')
            for i in affected:
                command([i["binary"], "-t", "-y", i["config"]], env=i["env"])
                out, _ = command([i["binary"], "-i"], env=i["env"])
                before_settings, after_settings = snapshots[i["pid"]], ini_snapshot(out)
                allowed = {key for item in self.data["files"] if item["path"] in i["inis"] for key in item["values"]}
                if ({key: value for key, value in before_settings.items() if key not in allowed} !=
                        {key: value for key, value in after_settings.items() if key not in allowed}):
                    raise CheckError("Unrelated effective PHP INI settings changed; restoring the original configuration before reload")
                values = info_values(out)
                if not REQUIRED <= functions(values.get("disable_functions", "")) or "allow_url_include" not in values or values["allow_url_include"].lower() not in ("off", "0", "no", "false", ""):
                    raise CheckError('Expected PHP settings did not take effect')
            reload_instances(affected)
            self.data["status"] = "applied"
            self.save()
            print(f"Backup: {self.path}")
        except BaseException:
            self.restore(allow_partial=True, recover_service=True)
            raise

    @staticmethod
    def directory_states(before, after=None):
        protected = dict(before, uid=0, mode=before["mode"] & ~0o022,
                         xattrs=dict(before["xattrs"]))
        # chmod updates the POSIX ACL mask as well as the visible mode. These
        # are the exact intermediate states of our two permission operations.
        acl_name = "system.posix_acl_access"
        if acl_name in protected["xattrs"]:
            acl = bytearray(base64.b64decode(protected["xattrs"][acl_name]))
            has_mask = any(int.from_bytes(acl[n:n + 2], "little") == 16 for n in range(4, len(acl), 8))
            for n in range(4, len(acl), 8):
                tag = int.from_bytes(acl[n:n + 2], "little")
                shift = 6 if tag == 1 else 3 if tag == 16 or (tag == 4 and not has_mask) else 0 if tag == 32 else None
                if shift is not None:
                    acl[n + 2:n + 4] = ((protected["mode"] >> shift) & 7).to_bytes(2, "little")
            protected["xattrs"][acl_name] = base64.b64encode(acl).decode()
        states = [before, dict(before, uid=0), protected,
                  dict(protected, uid=before["uid"])]
        if after is not None:
            states.append(after)
        return states

    def restore(self, allow_partial=False, recover_service=False):
        with self.locked():
            return self._restore(allow_partial, recover_service)

    def _restore(self, allow_partial=False, recover_service=False):
        # Preflight ALL entries before touching anything, so a conflict does
        # not leave a half-restored configuration or overwrite a newer edit.
        files = [i for i in self.data["files"] if i.get("started")]
        directories = [i for i in self.data["directories"] if i.get("started")]
        restore_files, restore_directories = [], []
        for item in files:
            trusted(item["path"])
            now = metadata(item["path"])
            current = digest(Path(item["path"]).read_bytes())
            original = (self.path / item["backup"]).read_bytes()
            if digest(original) != item["before"]:
                raise CheckError(f"Rollback conflict or damaged backup: {item['path']}")
            before_states = [item["meta"]] + ([item["restored_meta"]] if "restored_meta" in item else [])
            if allow_partial and current == item["before"] and any(self.same_state(now, state) for state in before_states):
                continue
            expected = item.get("after_meta", item["meta"])
            if current != item["after"] or not self.same_state(now, expected, identity="after_meta" in item):
                raise CheckError(f"Rollback conflict in content, file metadata or timestamps: {item['path']}")
            restore_files.append((item, original))
        for item in directories:
            now, before = metadata(item["path"]), item["meta"]
            expected = item.get("after", before)
            if (now["dev"], now["ino"]) != (before["dev"], before["ino"]):
                raise CheckError('Rollback directory was replaced')
            states = self.directory_states(before, item.get("after")) if allow_partial else [expected]
            if not any(self.same_state(now, state) for state in states):
                raise CheckError('Rollback conflict in directory permissions or timestamps')
            if not self.same_state(now, before):
                restore_directories.append(item)
        # A crash during restoration must remain resumable, including when all
        # bytes are restored but service recovery still needs another attempt.
        self.data["status"] = "rolling_back"
        self.save()
        for item in reversed(restore_directories):
            path, meta = item["path"], item["meta"]
            os.chown(path, meta["uid"], meta["gid"], follow_symlinks=False)
            os.chmod(path, meta["mode"], follow_symlinks=False)
            for key, value in meta["xattrs"].items():
                os.setxattr(path, key, base64.b64decode(value), follow_symlinks=False)
            os.utime(path, ns=(meta["atime_ns"], meta["mtime_ns"]), follow_symlinks=False)
        for item, original in restore_files:
            atomic_bytes(item["path"], original, item["meta"],
                         before_replace=lambda meta: self.checkpoint(item, "restored_meta", meta))
        # Restore bytes BEFORE attempting recovery of a failed/stopped FPM.
        # A missing master must never strand an invalid config on disk.
        for item in self.data["instances"] if files else []:
            trusted(item["binary"])
            trusted(item["config"])
            command([item["binary"], "-t", "-y", item["config"]])
            active, _ = command(["systemctl", "show", "--property=MainPID", "--value", item["service"]])
            if active.strip() == "0":
                if not recover_service:
                    raise CheckError('Files restored; FPM service is stopped (manual rollback never starts a service automatically)')
                command(["systemctl", "start", item["service"]])
            else:
                command(["systemctl", "reload", item["service"]])
            command(["systemctl", "is-active", "--quiet", item["service"]])
        self.data["status"] = "rolled_back"
        self.save()
        print(f'Restored: {self.path}')

    @classmethod
    def rollback(cls, backup_root, backup_id=None):
        tx = cls(backup_root)
        with tx.locked():
            return tx._rollback(backup_id)

    def _rollback(tx, backup_id=None):
        cls = type(tx)
        trusted(tx.root)
        if backup_id is not None and not re.fullmatch(r"\d{8}T\d{6}-[a-f0-9]{10}", backup_id):
            raise CheckError('Invalid backup ID')
        candidates = [tx.root / backup_id] if backup_id else list(tx.root.glob("????????T??????-??????????"))
        if not candidates:
            raise CheckError('No v2 backup found; legacy flat backups are never guessed')
        if backup_id is None:
            newest = max(candidate.name.split("-", 1)[0] for candidate in candidates)
            candidates = [candidate for candidate in candidates if candidate.name.split("-", 1)[0] == newest]
        loaded = []
        for candidate in candidates:
            manifest = trusted(candidate / "manifest.json")
            if not manifest.is_file() or manifest.stat().st_size > 8 * 1024 * 1024:
                raise CheckError("Invalid backup manifest: " + candidate.name)
            try:
                data = json.loads(manifest.read_text())
            except (ValueError, RecursionError) as exc:
                raise CheckError("Invalid backup manifest: " + candidate.name) from exc
            cls.validate_manifest(data, candidate.name)
            loaded.append((candidate, data))
        if len(loaded) > 1:
            times = [data.get("created_ns") for _, data in loaded]
            if any(type(value) is not int for value in times) or len(set(times)) != len(times):
                raise CheckError('Multiple backups in the same second; select one explicitly with --backup-id')
        tx.path, tx.data = max(loaded, key=lambda entry: entry[1].get("created_ns", 0))
        status = tx.data.get("status")
        if tx.data.get("version") != 1 or status not in ("prepared", "applied", "rolling_back", "rolled_back"):
            raise CheckError(f'Latest transaction is unknown; select one explicitly with --backup-id: {tx.path.name}')
        started = any(item.get("started") for item in tx.data.get("files", []) + tx.data.get("directories", []))
        if status == "rolled_back" or (status == "prepared" and not started):
            tx.noop = True
            print(f'No further changes: {tx.path} ({status}); select an older backup explicitly with --backup-id')
            return tx
        try:
            tx.restore(allow_partial=status in ("prepared", "rolling_back"))
        except BaseException as exc:
            # The caller needs the durable recovery state even if service
            # validation fails after original bytes have already been restored.
            exc.p2s_transaction = tx
            raise
        return tx

    @staticmethod
    def validate_manifest(data, name):
        def invalid():
            raise CheckError("Invalid backup manifest: " + name)
        def meta(value):
            if not isinstance(value, dict) or any(type(value.get(k)) is not int for k in
                    ("uid", "gid", "mode", "dev", "ino", "atime_ns", "mtime_ns")):
                invalid()
            if not isinstance(value.get("xattrs"), dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value["xattrs"].items()):
                invalid()
        if not isinstance(data, dict) or any(not isinstance(data.get(key), list) for key in ("files", "directories", "instances")):
            invalid()
        if "created_ns" in data and type(data["created_ns"]) is not int:
            invalid()
        for key in ("files", "directories"):
            for item in data[key]:
                if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not Path(item["path"]).is_absolute():
                    invalid()
                if "started" in item and type(item["started"]) is not bool:
                    invalid()
                meta(item.get("meta"))
                for field in (("after_meta", "restored_meta") if key == "files" else ("after",)):
                    if field in item:
                        meta(item[field])
                if key == "files":
                    if not isinstance(item.get("backup"), str) or not re.fullmatch(r"file-\d+\.bin", item["backup"]):
                        invalid()
                    if any(not isinstance(item.get(field), str) or not re.fullmatch(r"[a-f0-9]{64}", item[field]) for field in ("before", "after")):
                        invalid()
        for item in data["instances"]:
            if not isinstance(item, dict) or any(not isinstance(item.get(key), str) or not item[key] for key in ("binary", "config", "service")):
                invalid()


# Source: src/cli.py
def main(argv=None):
    configure_output()
    language = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    language.add_argument("--lang", choices=("en", "de"), default="en")
    selected, _ = language.parse_known_args(argv)
    def text(message):
        return localize(message, selected.lang)
    def emit(message):
        print("".join(c if c.isprintable() else "?" for c in text(message)))
    parser = argparse.ArgumentParser(parents=[language], allow_abbrev=False,
        description=text("Bounded PHP/FPM checks; UNKNOWN means an incomplete check."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  sudo bash p2s-harden.sh --dry-run\n  sudo bash p2s-harden.sh --fix --yes\n  bash p2s-harden.sh --ssh root@SERVER --json --fail-on open\n  sudo bash p2s-harden.sh --rollback --backup-id ID")
    mode = parser.add_mutually_exclusive_group()
    for name, help_text in (("check", "Audit selected settings, permissions and HTTP paths (default)"),
                            ("doctor", "Explain prerequisites and missing capabilities"),
                            ("discover", "Show detected FPM pools and web mappings"),
                            ("scan-webshells", "Read-only PHP webshell indicator scan; no FPM service required"),
                            ("dry-run", "Show proposed values and a unified diff without changes"),
                            ("fix", "Apply the displayed supported plan after confirmation"),
                            ("rollback", "Restore only the latest transaction, or one explicit backup ID")):
        mode.add_argument("--" + name, dest="mode", action="store_const", const=name, help=text(help_text))
    parser.set_defaults(mode="check")
    parser.add_argument("--root", help=text('Audit scope (default: discovered document roots)'))
    parser.add_argument("--web-user", action="append", default=[], help=text("Additional PHP user for permission checks; repeatable"))
    parser.add_argument("--site", action="append", default=[], metavar="URL=ROOT", help=text("Explicit virtual host and document root; repeatable"))
    parser.add_argument("--nginx-config", help=text('Custom Nginx main configuration'))
    parser.add_argument("--nginx-baseline", metavar="FILE", help=text("Reviewed Nginx UNKNOWN exceptions bound to the complete configuration; --check only"))
    parser.add_argument("--write-nginx-review-draft", metavar="FILE", help=text("Create a private unreviewed Nginx UNKNOWN draft; --check only"))
    parser.add_argument("--no-auto", action="store_true", help=text('Disable automatic document-root/domain discovery'))
    parser.add_argument("--max-sites", type=int, default=32, help=text('Maximum automatic HTTP mappings (default 32)'))
    parser.add_argument("--max-paths", type=int, default=250000, help=text("Maximum entries per filesystem walk (default 250000)"))
    parser.add_argument("--walk-seconds", type=float, help=text("Seconds per walk: audit 10, webshell scan 120; scan only: 0 disables root time limit"))
    parser.add_argument("--scan-file-seconds", type=float, default=2, help=text("Webshell time budget per file (default 2 seconds; maximum 30)"))
    parser.add_argument("--baseline", help=text("Reviewed webshell JSON baseline; exact path, SHA256 and indicator matches only"))
    parser.add_argument("--write-baseline-draft", metavar="FILE", help=text("Write a new private baseline draft; every entry is unreviewed and accepts nothing"))
    parser.add_argument("--no-nice", action="store_true", help=text("Skip lowering CPU/I/O priority for the webshell scan"))
    parser.add_argument("--scan-file-bytes", type=int, default=2 * 1024 * 1024, help=text("PHP parsing byte limit per file; opener search streams larger files (default 2097152)"))
    parser.add_argument("--scan-total-bytes", type=int, default=256 * 1024 * 1024, help=text("Webshell scan byte limit per root (default 268435456)"))
    parser.add_argument("--max-http-probes", type=int, default=128, help=text("Total HTTP request budget (default 128)"))
    parser.add_argument("--runtime-dir", action="append", default=[], help=text("Declare writable runtime storage inside selected roots; repeatable"))
    parser.add_argument("--protect-dir", action="append", default=[], help=text('Transfer explicit directory ownership to root; non-recursive'))
    parser.add_argument("--backup-root", default="/root/p2s-harden-backup-v2", help=text("Protected transaction directory (default /root/p2s-harden-backup-v2)"))
    parser.add_argument("--backup-id", help=text("Choose one transaction explicitly for rollback"))
    parser.add_argument("--yes", "-y", action="store_true", help=text("Approve the displayed fix plan without an interactive prompt"))
    parser.add_argument("--fail-on", choices=("complete", "open", "review"), default="complete", help=text("Exit precedence: complete (UNKNOWN first), open (OPEN first), review (OPEN or code review first); unacknowledged unknowns never pass"))
    parser.add_argument("--ignore", action="append", default=[], metavar="ID", help=text("Suppress one finding/rule's OPEN or code-review exit impact; keep it visible; repeatable"))
    parser.add_argument("--json", action="store_true", help=text("Structured findings, stable IDs, remediation, preview and transaction state"))
    parser.add_argument("--redact", action="store_true", help=text("Shareable read-only report: omit host details, inventory and original finding IDs"))
    parser.add_argument("--verbose", action="store_true", help=text('Show all findings, including OK'))
    parser.add_argument("--no-progress", action="store_true", help=text('Hide interactive progress messages'))
    parser.add_argument("--progress", action="store_true", help=text('Write progress to stderr even without a TTY'))
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if args.walk_seconds is None:
        args.walk_seconds = 120 if args.mode == "scan-webshells" else 10
    report, tx = None, None
    def show_report():
        report.configure(args.fail_on, args.ignore)
        report.show(args.json, verbose=args.verbose, lang=args.lang, redact=args.redact)
    def summarize(transaction):
        import shlex
        undo = ("sudo bash p2s-harden.sh --rollback --backup-id " + shlex.quote(transaction.path.name) +
                " --backup-root " + shlex.quote(str(transaction.root))) if transaction.path else None
        return dict(id=transaction.path.name if transaction.path else None,
                    backup_path=str(transaction.path) if transaction.path else None,
                    status=transaction.data["status"], noop=transaction.noop,
                    files=len(transaction.data["files"]), directories=len(transaction.data["directories"]),
                    undo_command=undo)
    def transaction_output(action):
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                return action()
        finally:
            if not args.json:
                for line in output.getvalue().splitlines():
                    emit(line)
    try:
        if (args.nginx_baseline or args.write_nginx_review_draft) and args.mode != "check":
            raise CheckError("Nginx review options support --check only")
        if args.write_nginx_review_draft and args.redact:
            raise CheckError("Nginx review drafts contain configuration identities; use locally without --redact")
        if args.baseline and args.mode != "scan-webshells":
            raise CheckError("--baseline supports --scan-webshells only")
        if args.write_baseline_draft and args.mode != "scan-webshells":
            raise CheckError("--write-baseline-draft supports --scan-webshells only")
        if args.write_baseline_draft and args.redact:
            raise CheckError("--write-baseline-draft contains local paths and hashes; use it locally without --redact")
        if args.no_nice and args.mode != "scan-webshells":
            raise CheckError("--no-nice supports --scan-webshells only")
        if args.redact and args.mode not in ("check", "doctor", "discover", "scan-webshells"):
            raise CheckError("--redact supports --check, --doctor, --discover and --scan-webshells; review change previews locally without redaction")
        if any(not re.fullmatch(r"P2S-(?:[A-Z]+\d{3}|CUSTOM)(?:-[a-f0-9]{16})?", value) for value in args.ignore):
            raise CheckError("--ignore requires a finding id or rule_id from --json")
        if args.mode == "doctor":
            report = doctor()
            show_report()
            return report.exit_code()
        if sys.platform != "linux" or not Path("/proc/self/stat").is_file():
            raise CheckError('A Linux target with /proc is required; use --ssh root@SERVER from Windows/macOS')
        if sys.version_info < (3, 8):
            raise CheckError(f"Python 3.8 or later required; {install_hint('python3')}")
        if args.root is not None and not Path(args.root).is_absolute():
            raise CheckError('--root must be absolute')
        if args.root is not None:
            args.root = os.path.normpath(args.root)
        if not 1 <= args.max_sites <= 512:
            raise CheckError('--max-sites must be between 1 and 512')
        if not 1 <= args.max_paths <= 1000000:
            raise CheckError("--max-paths must be between 1 and 1000000")
        if args.mode == "scan-webshells":
            if not (args.walk_seconds == 0 or 0.05 <= args.walk_seconds <= 86400):
                raise CheckError("Webshell --walk-seconds must be 0 or between 0.05 and 86400")
        elif not 0.05 <= args.walk_seconds <= 120:
            raise CheckError("--walk-seconds must be between 0.05 and 120")
        if not 0.05 <= args.scan_file_seconds <= 30:
            raise CheckError("--scan-file-seconds must be between 0.05 and 30")
        if not 1 <= args.max_http_probes <= 4096:
            raise CheckError("--max-http-probes must be between 1 and 4096")
        if not 1024 <= args.scan_file_bytes <= 16 * 1024 * 1024:
            raise CheckError("--scan-file-bytes must be between 1024 and 16777216")
        if not 1024 <= args.scan_total_bytes <= 1024 * 1024 * 1024:
            raise CheckError("--scan-total-bytes must be between 1024 and 1073741824")
        if args.mode == "rollback" and os.geteuid() != 0:
            raise CheckError('Changes require root: sudo bash p2s-harden.sh --fix or --ssh root@SERVER')
        if args.mode == "rollback":
            tx = transaction_output(lambda: Transaction.rollback(args.backup_root, args.backup_id))
            report = Report()
            report.transaction = summarize(tx)
            report.add("INFO", "Rollback", "Latest transaction already restored; no changes made" if tx.noop else "Selected transaction restored", rule_id='P2S-TX001', resource="rollback")
            show_report()
            return 0
        stage(args, 'Discovering Nginx mappings and audit paths')
        if args.mode == "scan-webshells" and args.root:
            # An explicit local scan needs neither Nginx nor FPM nor HTTP.
            args.no_auto = True
        prepare_scope(args)
        if args.mode == "scan-webshells":
            priority = webshell_priority(args.no_nice)
            report = scan_webshells(args)
            report.discovery["scan_priority"] = priority
            report.add("INFO", "Scan scheduling", "CPU: " + priority["cpu_priority"] + "; I/O: " + priority["io_priority"] +
                       "; missing or denied priority helpers do not stop the scan; --no-nice opts out",
                       rule_id="P2S-WS006", resource="scheduling", evidence=priority)
            if args.write_baseline_draft:
                try:
                    report.baseline_draft = write_baseline_draft(args.write_baseline_draft, report)
                    report.add("INFO", "Webshell baseline", "Unreviewed baseline draft written; compare complete files with trusted source before setting reviewed=true; existing files are never overwritten",
                               rule_id="P2S-WS005", resource=dict(path=report.baseline_draft["path"]),
                               evidence=dict(baseline_entries=report.baseline_draft["indicator_files"] + report.baseline_draft["coverage_files"]))
                except (OSError, ValueError, CheckError) as exc:
                    reason = str(exc) if isinstance(exc, CheckError) else "Draft destination exists, is unsafe or is not writable"
                    report.add("UNKNOWN", "Webshell baseline", "Baseline draft was not written; " + reason,
                               rule_id="P2S-WS005", resource=dict(path=os.path.abspath(args.write_baseline_draft)))
            show_report()
            return report.exit_code()
        prepare_runtime_dirs(args)
        report, updates, instances, users = scan(args, inventory_only=True) if args.mode == "discover" else scan(args)
        if args.mode == "check":
            nginx_review_report(report, args)
        if args.mode in ("dry-run", "fix"):
            blockers = fix_blockers(updates, args.protect_dir, instances, users)
            plan = change_plan(updates, args.protect_dir, [text(reason) for reason in blockers])
            report.plan = plan
            for reason in blockers:
                report.add("UNKNOWN", 'Fix blocked', reason, rule_id='P2S-FIX001', resource=reason)
            if not args.json:
                for path, values in updates.items():
                    emit(f"PLANNED INI {path}: {','.join(values)}")
                for entry in plan["ini"]:
                    for line in entry["diff"].splitlines():
                        emit(line)
                for path in args.protect_dir:
                    emit(f'PLANNED DIRECTORY {path}: owner root, no g+w/o+w, non-recursive')
                if updates and (args.mode == "dry-run" or args.yes):
                    emit(INI_UPGRADE_NOTICE)
                emit('HTTP, ImageMagick, runtime and writable-storage findings require individual review; they are not changed automatically.')
            if args.mode == "fix" and not blockers and (updates or args.protect_dir):
                if not confirm_fix(args, ini_changes=bool(updates)):
                    report.add("INFO", "Fix cancelled", "No changes made; rerun --dry-run to review the plan", rule_id="P2S-TX001", resource="cancelled")
                    show_report()
                    return report.exit_code()
                tx = Transaction(args.backup_root)
                def apply():
                    with tx.locked(create=True):
                        tx.prepare(updates, args.protect_dir, instances,
                                   expected={entry["path"]: entry["before_sha256"] for entry in plan["ini"]})
                        tx.apply(instances, users)
                transaction_output(apply)
                report, _, _, _ = scan(args)
                report.plan, report.transaction = plan, summarize(tx)
                if not args.json:
                    emit("Undo this transaction: " + report.transaction["undo_command"])
        show_report()
        return report.exit_code()
    except (OSError, ValueError, KeyError, CheckError) as exc:
        report = report or Report()
        report.add("UNKNOWN", 'Execution', str(exc), rule_id='P2S-EXEC001', resource="execution")
        if tx is None:
            tx = getattr(exc, "p2s_transaction", None)
        if tx is not None:
            report.transaction = summarize(tx)
        show_report()
        return report.exit_code()


if __name__ == "__main__":
    sys.exit(main())

__P2S_ENGINE_EOF__
