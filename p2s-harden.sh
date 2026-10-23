#!/usr/bin/env bash
# p2s-harden 2.2.0-rc.3 — self-contained; engine is embedded below.
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
p2s-harden 2.2.0-rc.3 — one file, automatic discovery

  sudo bash p2s-harden.sh                     Discover and audit locally
  bash p2s-harden.sh --ssh root@SERVER         Discover and audit over SSH
  bash p2s-harden.sh --doctor                  Explain prerequisites and next steps
  sudo bash p2s-harden.sh --discover           Show discovered mappings
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
  --web-user USER              Additional FPM user
  --no-auto                   Use explicit mappings only
  --max-sites 32              Limit automatic HTTP mappings
  --max-paths COUNT           Limit filesystem traversal
  --walk-seconds SECONDS      Limit filesystem traversal time
  --max-http-probes COUNT     Limit HTTP requests
  --runtime-dir /path          Review a known upload/cache directory separately
  --protect-dir /path          Protect an explicit directory; non-recursive
  --backup-root /root/path     Custom backup directory
  --backup-id ID               Restore a specific transaction
  --json                      Machine-readable output
  --yes, -y                   Approve the fix without an interactive prompt
  --fail-on complete|open     Exit precedence; UNKNOWN never passes
  --ignore ID                 Keep a finding visible but suppress its OPEN exit
  --verbose                   Include all findings, including OK
  --no-progress               Hide interactive progress messages

Discovery never infers permission-change targets.
--check/--discover/--dry-run do not modify configuration or reload services.
Exit 0: selected checks passed; 1: open findings; 2: unknown/error.
HELP
    return
  fi
  cat <<'HELP'
p2s-harden 2.2.0-rc.3 — eine Datei, automatische Erkennung

  sudo bash p2s-harden.sh                     Lokal erkennen und prüfen
  bash p2s-harden.sh --ssh root@SERVER         Remote erkennen und prüfen
  bash p2s-harden.sh --doctor                  Voraussetzungen und nächste Schritte
  sudo bash p2s-harden.sh --discover           Erkannte Zuordnungen anzeigen
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
  --web-user BENUTZER           Zusätzlicher FPM-Benutzer
  --no-auto                    Nur explizite Zuordnungen verwenden
  --max-sites 32               Limit automatischer HTTP-Zuordnungen
  --max-paths ANZAHL           Dateisystem-Suchlauf begrenzen
  --walk-seconds SEKUNDEN      Dauer des Dateisystem-Suchlaufs begrenzen
  --max-http-probes ANZAHL     HTTP-Anfragen begrenzen
  --runtime-dir /pfad           Bekanntes Upload-/Cache-Verzeichnis gesondert bewerten
  --protect-dir /pfad           Nur explizites Verzeichnis schützen; kein Rekurs
  --backup-root /root/pfad      Anderes Backup-Verzeichnis
  --backup-id ID                Bestimmte Transaktion zurücknehmen
  --json                       Maschinenlesbare Ausgabe
  --yes, -y                    Fix ohne interaktive Rückfrage freigeben
  --fail-on complete|open      Exit-Vorrang; UNKNOWN besteht niemals
  --ignore ID                  Befund sichtbar lassen, seine OPEN-Exitwirkung ausnehmen
  --verbose                    Alle Einzelbefunde einschließlich OK anzeigen
  --no-progress                Phasenhinweise im interaktiven Terminal ausblenden

Erkennung leitet keine automatischen Rechteänderungen ab.
--check/--discover/--dry-run schreiben keine Zielkonfiguration und laden nichts neu.
Exit 0: ausgewiesene Einzelprüfungen bestanden; 1: offen; 2: unbekannt/Fehler.
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
    --version) echo 'p2s-harden 2.2.0-rc.3'; exit 0 ;;
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
    printf '{"schema_version":2,"version":"2.2.0-rc.3","language":"%s","exit_code":2,"has_open":false,"has_unknown":true,"findings":[{"id":"P2S-EXEC001-75568215812df402","rule_id":"P2S-EXEC001","resource":"bootstrap","severity":"unknown","suppressed":false,"status":"UNKNOWN","title":"%s","detail":"%s","remediation":"%s"}],"discovery":{"bootstrap":true,"capabilities":{"tools":{' "$p2s_lang" "$p2s_title" "$p2s_problem" "$p2s_problem"
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
    printf '{"schema_version":2,"version":"2.2.0-rc.3","language":"%s","exit_code":2,"has_open":false,"has_unknown":true,"findings":[{"id":"P2S-EXEC001-9773e1e8b98e2493","rule_id":"P2S-EXEC001","resource":"ssh_transport","severity":"unknown","suppressed":false,"status":"UNKNOWN","title":"SSH","detail":"%s","remediation":"%s"}],"discovery":{}}\n' "$lang" "$detail" "$detail"
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
    printf '{"schema_version":2,"version":"2.2.0-rc.3","language":"%s","exit_code":2,"has_open":false,"has_unknown":true,"findings":[{"id":"P2S-EXEC001-9773e1e8b98e2493","rule_id":"P2S-EXEC001","resource":"ssh_transport","severity":"unknown","suppressed":false,"status":"UNKNOWN","title":"SSH","detail":"%s","remediation":"%s"}],"discovery":{}}\n' "$lang" "$detail" "$detail"
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

VERSION = "2.2.0-rc.3"
DEFAULT_MAX_PATHS = 250000
REQUIRED = frozenset("exec system shell_exec passthru popen proc_open pcntl_exec".split())


class CheckError(RuntimeError):
    pass


class HttpBudgetExceeded(CheckError):
    pass


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
        elif current in pools and " = " in body:
            key, value = body.split(" = ", 1)
            pools[current][key.strip()] = value.strip()
    if not pools:
        raise CheckError('Cannot parse the FPM pool dump')
    return pools


def active_ini_lines(text, key):
    # Exclude both PHP comment syntaxes, retain only real assignments.
    pattern = re.compile(r"^\s*" + re.escape(key) + r"\s*=")
    return [i for i, line in enumerate(text.splitlines()) if pattern.match(line)]


def set_ini(text, updates):
    if re.search(r"^\s*\[(?:PATH|HOST)\s*=", text, re.M | re.I):
        raise CheckError('Conditional PATH/HOST INI sections: automatic changes refused')
    lines = text.splitlines(keepends=True)
    for key, value in updates.items():
        indices = active_ini_lines("".join(lines), key)
        replacement = f"{key} = {value}\n"
        if indices:
            lines[indices[-1]] = replacement
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.extend(["\n[PHP]\n", replacement])
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
    path = trusted(path)
    if str(path) in seen:
        return
    seen.add(str(path))
    for line in path.read_text().splitlines():
        match = re.match(r"^\s*include\s*=\s*(.*?)\s*(?:;.*)?$", line)
        if not match:
            continue
        pattern = match[1].strip().strip("\"'")
        if not os.path.isabs(pattern):
            raise CheckError('A relative FPM include requires a manual context check')
        files = sorted(glob.glob(pattern))
        if not files:
            raise CheckError(f'FPM include has no readable target: {pattern}')
        for child in files:
            validate_fpm_files(Path(child), seen)


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


def read_nginx(config, partial=False):
    """Read configs, never execute nginx or load modules during discovery."""
    import glob
    config = Path(config)
    prefix, cache, budget = config.parent, {}, [0, 0]
    def load(path, stack):
        path = Path(path)
        for component in [path, *path.parents]:
            st = component.lstat()
            if st.st_uid != 0 or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022):
                raise CheckError(f'Nginx configuration is not protected by root ownership: {component}')
        resolved = trusted(path.resolve(strict=True))
        if str(resolved) in stack:
            raise CheckError(f'Nginx: include cycle at {resolved}')
        if str(resolved) not in cache:
            if not resolved.is_file() or resolved.stat().st_size > 1024 * 1024:
                raise CheckError('Nginx: configuration file too large or not a regular file')
            budget[0] += 1
            text = resolved.read_text()
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
    return load(config, [])


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
                inventory = nginx_inventory(read_nginx(candidates[0], partial=True))
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
        if len(entries) > args.max_sites:
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
    "FS001": ("high", "Remove PHP-user write access to application code and verify ACLs; keep required runtime data separate."),
    "FS002": ("high", "Separate code from runtime storage; use --runtime-dir only for reviewed storage and --protect-dir only for an explicit code directory."),
    "FS003": ("info", "Resolve the reported user/access/coverage issue or narrow the scope; an incomplete walk cannot pass."),
    "FS004": ("info", "Verify that declared upload/cache paths cannot execute uploaded PHP and cannot replace application code."),
    "FS005": ("high", "Run the FPM pool as a dedicated non-root account and restart the service after reviewing ownership."),
    "HTTP001": ("high", "Deny HTTP access to the reported sensitive file/path, remove public backups/debug scripts, and recheck both HTTP and HTTPS."),
    "HTTP002": ("info", "Provide an explicit --site mapping or sufficient HTTP budget; inspect every unknown result."),
    "HTTP003": ("info", "Correct the URL/document-root mapping and retry the intended local virtual host."),
    "SYS001": ("medium", "Review the host ptrace policy against operational needs; this tool does not change sysctl settings."),
    "IM001": ("info", "Review ImageMagick policy rules and delegates for the installed version and application requirements."),
    "FIX001": ("info", "Resolve the specific fix preflight blocker, inspect the full proposed diff, and rerun."),
    "TX001": ("info", "Keep the backup ID; a repeated implicit rollback never selects an older transaction."),
    "EXEC001": ("info", "Resolve the execution error and rerun; consult transaction state before retrying a change."),
    "CUSTOM": ("info", "Review this diagnostic in its reported context."),
}


class Report:
    def __init__(self):
        self.rows = []
        self.discovery = {}

    def add(self, status, title, detail, *, rule_id="P2S-CUSTOM", resource=None):
        key = rule_id[4:]
        severity, remediation = RULES[key]
        resource = title if resource is None else resource
        identity = json.dumps([rule_id, resource], ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        finding_id = rule_id + "-" + digest(identity.encode())[:16]
        self.rows.append(dict(id=finding_id, rule_id=rule_id, resource=resource,
                              status=status, title=title, detail=detail,
                              severity=severity if status == "OPEN" else "unknown" if status == "UNKNOWN" else "info",
                              remediation=remediation, suppressed=False))

    def configure(self, fail_on="complete", ignore=()):
        self.fail_on = fail_on
        for row in self.rows:
            row["suppressed"] = row["status"] == "OPEN" and (row["id"] in ignore or row["rule_id"] in ignore)

    def has(self, status):
        return any(r["status"] == status and not r["suppressed"] for r in self.rows)

    def exit_code(self):
        if getattr(self, "fail_on", "complete") == "open" and self.has("OPEN"):
            return 1
        if self.has("UNKNOWN"):
            return 2
        return int(self.has("OPEN"))

    def show(self, as_json=False, verbose=False, lang="en"):
        rows = [dict(row, title=localize(row["title"], lang), detail=localize(row["detail"], lang),
                     remediation=localize(row["remediation"], lang)) for row in self.rows]
        discovery = localized_discovery(self.discovery, lang)
        if as_json:
            print(json.dumps(dict(schema_version=2, version=VERSION, language=lang, findings=rows,
                                  has_open=self.has("OPEN"), has_unknown=self.has("UNKNOWN"),
                                  counts={state: sum(r["status"] == state for r in rows) for state in ("OK", "OPEN", "UNKNOWN", "INFO")},
                                  suppressed_open=sum(r["suppressed"] for r in rows),
                                  fail_on=getattr(self, "fail_on", "complete"),
                                  discovery=discovery, plan=getattr(self, "plan", None),
                                  transaction=getattr(self, "transaction", None),
                                  exit_code=self.exit_code()), ensure_ascii=False, indent=2))
            return
        def emit(line):
            # Configured names/paths must not inject terminal escape sequences.
            print("".join(c if c.isprintable() else "?" for c in line))
        label = "Prerequisites" if discovery.get("doctor") else "Discovered inventory" if discovery.get("inventory_only") else "Configuration audit"
        emit(f"p2s-harden {VERSION} – {localize(label, lang)}")
        cap = self.discovery.get("capabilities", {})
        missing_tools = [name for name, present in cap.get("tools", {}).items() if not present and name != "curl"]
        if missing_tools:
            emit(("Fehlende Helfer: " if lang == "de" else "Missing helpers: ") + ", ".join(missing_tools) +
                 ("; --doctor zeigt Zweck und nächste Schritte." if lang == "de" else "; --doctor explains their purpose and next steps."))
        if self.discovery and not self.discovery.get("doctor"):
            pools = sum(len(i["pools"]) for i in self.discovery.get("fpm_instances", []))
            instance_count, site_count = len(self.discovery.get('fpm_instances', [])), len(self.discovery.get('selected_sites', []))
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
        shown = rows if verbose or self.discovery.get("doctor") else [r for r in rows if r["status"] != "OK"]
        for row in shown if verbose else shown[:40]:
            emit(f"{row['status']:7} {row['title']}: {row['detail']}")
            if row["status"] in ("OPEN", "UNKNOWN"):
                emit("        " + row["id"] + (" [ignored OPEN]" if row["suppressed"] else ""))
                emit("        " + row["remediation"])
        if not verbose and len(shown) > 40:
            emit(f"Weitere {len(shown) - 40} Befunde: --verbose oder --json zeigt alle Details." if lang == "de" else
                 f"{len(shown) - 40} more findings: --verbose or --json shows all details.")
        counts = {s: sum(r["status"] == s for r in self.rows) for s in ("OK", "OPEN", "UNKNOWN", "INFO", "N/A")}
        print("\n" + "   ".join(f"{s}: {n}" for s, n in counts.items()))
        emit("Nur die ausgewiesenen Host-Pfade/Instanzen wurden geprüft; keine Sicherheitszertifizierung." if lang == "de" else
             "Only the reported host paths and instances were checked; this is not a security certification.")


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
    for instance in instances:
        saved_updates = {name: dict(values) for name, values in updates.items()}
        try:
            label = instance["config"]
            values = instance["values"]
            disabled = functions(values.get("disable_functions", ""))
            missing = REQUIRED - disabled
            report.add("OPEN" if missing else "OK", f"disable_functions {label}",
                       f"Missing: {','.join(sorted(missing))}" if missing else 'The 7 selected shell functions are disabled', rule_id='P2S-PHP001', resource=dict(config=label))
            desired = {}
            if missing:
                desired["disable_functions"] = ",".join(sorted(disabled | REQUIRED))
            url_include = values.get("allow_url_include")
            if url_include is None:
                report.add("UNKNOWN", f"allow_url_include {label}", 'Value missing', rule_id='P2S-PHP002', resource=dict(config=label))
            else:
                enabled = url_include.lower() not in ("off", "0", "no", "false", "")
                report.add("OPEN" if enabled else "OK", f"allow_url_include {label}", url_include, rule_id='P2S-PHP002', resource=dict(config=label))
                if enabled:
                    desired["allow_url_include"] = "Off"
            for pool, settings in instance["pools"].items():
                user = settings.get("user")
                if user and user != "undefined":
                    users.add(user)
                combined = disabled | functions(settings.get("php_admin_value[disable_functions]", "")) | functions(settings.get("php_value[disable_functions]", ""))
                absent = REQUIRED - combined
                report.add("OPEN" if absent else "OK", f"Pool {label} [{pool}]",
                           f"Missing: {','.join(sorted(absent))}" if absent else 'Global and pool restrictions evaluated together', rule_id='P2S-PHP001', resource=dict(config=label, pool=pool))
                include_value = url_include
                for prefix in ("php_value", "php_flag", "php_admin_value", "php_admin_flag"):
                    override = settings.get(prefix + "[allow_url_include]")
                    if override is not None and override != "undefined":
                        include_value = override
                if include_value is None:
                    report.add("UNKNOWN", f"allow_url_include [{pool}] {label}", 'Value missing', rule_id='P2S-PHP002', resource=dict(config=label, pool=pool))
                else:
                    pool_enabled = include_value.lower() not in ("off", "0", "no", "false", "")
                    report.add("OPEN" if pool_enabled else "OK", f"allow_url_include [{pool}] {label}",
                               include_value + ('; correct the pool override manually' if pool_enabled else ""), rule_id='P2S-PHP002', resource=dict(config=label, pool=pool))
                ob = settings.get("php_admin_value[open_basedir]", settings.get("php_value[open_basedir]", values.get("open_basedir", "")))
                unrestricted = not ob or ob.lower() in ("none", "no value", "undefined") or "/" in [p.strip() for p in ob.split(":")]
                report.add("OPEN" if unrestricted else "OK", f"open_basedir [{pool}] {label}",
                           'Unrestricted' if unrestricted else f'{ob} (an additional restriction, not a sandbox)', rule_id='P2S-PHP003', resource=dict(config=label, pool=pool))
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
            for key, title in (("files", "schreibbare PHP-Dateien"), ("directories", "schreibbare Verzeichnisse")):
                count = data[key]
                sample = data["file_sample" if key == "files" else "directory_sample"]
                report.add("OPEN" if count else "OK", f"{title} ({user})", f"{scan_root}: {count}; " + "; ".join(sample), rule_id="P2S-FS001" if key == "files" else "P2S-FS002", resource=dict(root=scan_root, user=user))
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
                    report.add(status, "HTTP " + target, detail, rule_id='P2S-HTTP001', resource=target)
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
        report.add("OK" if ptrace >= 1 else "OPEN", "ptrace_scope", str(ptrace), rule_id='P2S-SYS001', resource="ptrace_scope")
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
        difference = "".join(difflib.unified_diff(original.splitlines(True), after.splitlines(True),
                              fromfile=str(path), tofile=str(path) + " (planned)", n=0))
        entries.append(dict(path=str(path), values=values, before_sha256=digest(before), diff=difference))
    return dict(ini=entries, directories=list(protect_dirs), blockers=list(blockers))


def confirm_fix(args):
    if args.yes:
        return True
    if args.json:
        raise CheckError("Review --dry-run --json first; --fix --json requires --yes")
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as terminal:
            terminal.write(localize("Apply this displayed plan? [y/N] ", args.lang))
            terminal.flush()
            return terminal.readline().strip().lower() in ("y", "yes", "j", "ja")
    except OSError as exc:
        raise CheckError("No controlling terminal; review --dry-run first, then use --fix --yes") from exc


class Transaction:
    def __init__(self, backup_root):
        self.root = Path(backup_root)
        self.path = None
        self.noop = False
        self.data = dict(version=1, status="prepared", files=[], directories=[], instances=[])

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
        try:
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
            affected = [i for i in instances if i["pid"] in {r["pid"] for r in self.data["instances"]}]
            for i in affected:
                command([i["binary"], "-t", "-y", i["config"]], env=i["env"])
                out, _ = command([i["binary"], "-i"], env=i["env"])
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
                            ("dry-run", "Show proposed values and a unified diff without changes"),
                            ("fix", "Apply the displayed supported plan after confirmation"),
                            ("rollback", "Restore only the latest transaction, or one explicit backup ID")):
        mode.add_argument("--" + name, dest="mode", action="store_const", const=name, help=text(help_text))
    parser.set_defaults(mode="check")
    parser.add_argument("--root", help=text('Audit scope (default: discovered document roots)'))
    parser.add_argument("--web-user", action="append", default=[], help=text("Additional PHP user for permission checks; repeatable"))
    parser.add_argument("--site", action="append", default=[], metavar="URL=ROOT", help=text("Explicit virtual host and document root; repeatable"))
    parser.add_argument("--nginx-config", help=text('Custom Nginx main configuration'))
    parser.add_argument("--no-auto", action="store_true", help=text('Disable automatic document-root/domain discovery'))
    parser.add_argument("--max-sites", type=int, default=32, help=text('Maximum automatic HTTP mappings (default 32)'))
    parser.add_argument("--max-paths", type=int, default=250000, help=text("Maximum entries per filesystem walk (default 250000)"))
    parser.add_argument("--walk-seconds", type=float, default=10, help=text("Seconds per filesystem walk (default 10)"))
    parser.add_argument("--max-http-probes", type=int, default=128, help=text("Total HTTP request budget (default 128)"))
    parser.add_argument("--runtime-dir", action="append", default=[], help=text("Declare writable runtime storage inside selected roots; repeatable"))
    parser.add_argument("--protect-dir", action="append", default=[], help=text('Transfer explicit directory ownership to root; non-recursive'))
    parser.add_argument("--backup-root", default="/root/p2s-harden-backup-v2", help=text("Protected transaction directory (default /root/p2s-harden-backup-v2)"))
    parser.add_argument("--backup-id", help=text("Choose one transaction explicitly for rollback"))
    parser.add_argument("--yes", "-y", action="store_true", help=text("Approve the displayed fix plan without an interactive prompt"))
    parser.add_argument("--fail-on", choices=("complete", "open"), default="complete", help=text("Exit precedence: complete (UNKNOWN first) or open (OPEN first); unknowns never pass"))
    parser.add_argument("--ignore", action="append", default=[], metavar="ID", help=text("Suppress one finding/rule's OPEN exit impact; keep it visible; repeatable"))
    parser.add_argument("--json", action="store_true", help=text("Structured findings, stable IDs, remediation, preview and transaction state"))
    parser.add_argument("--verbose", action="store_true", help=text('Show all findings, including OK'))
    parser.add_argument("--no-progress", action="store_true", help=text('Hide interactive progress messages'))
    parser.add_argument("--progress", action="store_true", help=text('Write progress to stderr even without a TTY'))
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    report, tx = None, None
    def show_report():
        report.configure(args.fail_on, args.ignore)
        report.show(args.json, verbose=args.verbose, lang=args.lang)
    def summarize(transaction):
        return dict(id=transaction.path.name if transaction.path else None,
                    backup_path=str(transaction.path) if transaction.path else None,
                    status=transaction.data["status"], noop=transaction.noop,
                    files=len(transaction.data["files"]), directories=len(transaction.data["directories"]))
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
        if not 0.05 <= args.walk_seconds <= 120:
            raise CheckError("--walk-seconds must be between 0.05 and 120")
        if not 1 <= args.max_http_probes <= 4096:
            raise CheckError("--max-http-probes must be between 1 and 4096")
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
        prepare_scope(args)
        prepare_runtime_dirs(args)
        report, updates, instances, users = scan(args, inventory_only=True) if args.mode == "discover" else scan(args)
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
                emit('HTTP, ImageMagick, runtime and writable-storage findings require individual review; they are not changed automatically.')
            if args.mode == "fix" and not blockers and (updates or args.protect_dir):
                if not confirm_fix(args):
                    report.add("INFO", "Fix cancelled", "No changes made; rerun --dry-run to review the plan", rule_id="P2S-TX001", resource="cancelled")
                    show_report()
                    return report.exit_code()
                tx = Transaction(args.backup_root)
                def apply():
                    tx.prepare(updates, args.protect_dir, instances,
                               expected={entry["path"]: entry["before_sha256"] for entry in plan["ini"]})
                    tx.apply(instances, users)
                transaction_output(apply)
                report, _, _, _ = scan(args)
                report.plan, report.transaction = plan, summarize(tx)
                if not args.json:
                    emit("Undo this transaction: sudo bash p2s-harden.sh --rollback --backup-id " + tx.path.name)
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
