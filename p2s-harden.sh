#!/usr/bin/env bash
# p2s-harden 2.2.0-rc.1 — self-contained; engine is embedded below.
set -uo pipefail

usage() {
  cat <<'HELP'
p2s-harden 2.2.0-rc.1 — eine Datei, automatische Erkennung

  sudo bash p2s-harden.sh                     Lokal erkennen und pruefen
  bash p2s-harden.sh --ssh root@SERVER         Remote erkennen und pruefen
  bash p2s-harden.sh --doctor                  Voraussetzungen und naechste Schritte
  sudo bash p2s-harden.sh --discover           Erkannte Zuordnungen anzeigen
  sudo bash p2s-harden.sh --dry-run            Konkrete Aenderungen anzeigen
  sudo bash p2s-harden.sh --fix                Begrenzte INI-Fixes anwenden
  sudo bash p2s-harden.sh --rollback           Letzte Transaktion zuruecknehmen

Kein separates Python-Skript, keine Installation und keine Konfigurationsdatei.
Voraussetzungen: Linux-Ziel mit Python 3.8+ und bestehender SSH-Zugang bei --ssh.
Fehlende optionale Helfer werden erklaert; unabhaengige Pruefungen laufen weiter.

Optional (automatisch erkannte Werte lassen sich ueberschreiben):
  --root /pfad                 Dateisystem-Pruefbereich einschraenken
  --site URL=DOKUMENTWURZEL     Expliziter vHost, wiederholbar
  --nginx-config /pfad          Abweichende Nginx-Hauptkonfiguration
  --web-user BENUTZER           Zusaetzlicher FPM-Benutzer
  --no-auto                    Nur explizite Zuordnungen verwenden
  --max-sites 32               Limit automatischer HTTP-Zuordnungen
  --protect-dir /pfad           Nur explizites Verzeichnis schuetzen; kein Rekurs
  --backup-root /root/pfad      Anderes Backup-Verzeichnis
  --backup-id ID                Bestimmte Transaktion zuruecknehmen
  --json                       --check/--discover maschinenlesbar ausgeben
  --verbose                    Alle Einzelbefunde einschliesslich OK anzeigen
  --no-progress                Phasenhinweise im interaktiven Terminal ausblenden

Erkennung leitet keine automatischen Rechteaenderungen ab.
--check/--discover/--dry-run schreiben keine Zielkonfiguration und laden nichts neu.
Exit 0: ausgewiesene Einzelpruefungen bestanden; 1: offen; 2: unbekannt/Fehler.
HELP
}

target=local
target_set=0
json_mode=0
args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --local)
      [ "$target_set" = 0 ] || { echo 'Ziel mehrfach angegeben' >&2; exit 2; }
      target=local; target_set=1; shift ;;
    --ssh)
      [ "$target_set" = 0 ] && [ "$#" -ge 2 ] && [ -n "$2" ] || { echo '--ssh braucht ein Ziel' >&2; exit 2; }
      target=$2; target_set=1; shift 2
      name_pattern='^[A-Za-z0-9_][A-Za-z0-9_.@:-]*$'
      ipv6_pattern='^([A-Za-z0-9_.-]+@)?\[[0-9A-Fa-f:.%]+\]$'
      [[ "$target" =~ $name_pattern || "$target" =~ $ipv6_pattern ]] || { echo 'Ungueltiges SSH-Ziel' >&2; exit 2; } ;;
    --help|-h) usage; exit 0 ;;
    --version) echo 'p2s-harden 2.2.0-rc.1'; exit 0 ;;
    --json) json_mode=1; args+=("$1"); shift ;;
    --yes|-y|--no-self-guard)
      echo "Hinweis: $1 ist wirkungslos; keine Firewall-/Fail2ban-Aenderungen." >&2; shift ;;
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
  if [ -r /proc/sys/kernel/ostype ]; then IFS= read -r p2s_kernel < /proc/sys/kernel/ostype; fi
  [ "$p2s_kernel" = Linux ] && [ -r /proc/self/stat ] || p2s_problem='Linux-Ziel mit lesbarem /proc erforderlich; Windows/macOS koennen per --ssh pruefen.'
  if ! command -v python3 >/dev/null 2>&1; then
    p2s_problem="${p2s_problem:+$p2s_problem }Python 3.8+ fehlt; Paket python3 bereitstellen. Ohne Python sind die Konfigurationspruefungen nicht ausfuehrbar."
  elif ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    p2s_problem="${p2s_problem:+$p2s_problem }Python 3.8+ erforderlich; vorhandenes python3 ist zu alt oder nicht ausfuehrbar."
  fi
  [ -n "$p2s_problem" ] || return 0
  if [ "$1" = 1 ]; then
    printf '{"schema_version":1,"version":"2.2.0-rc.1","exit_code":2,"findings":[{"status":"UNKNOWN","title":"Voraussetzungen","detail":"%s"}],"discovery":{"bootstrap":true,"capabilities":{"tools":{' "$p2s_problem"
    p2s_comma=''
    for p2s_tool in python3 ps curl runuser systemctl; do
      p2s_present=false
      command -v "$p2s_tool" >/dev/null 2>&1 && p2s_present=true
      printf '%s"%s":%s' "$p2s_comma" "$p2s_tool" "$p2s_present"
      p2s_comma=,
    done
    printf '}}}}\n'
  else
    printf 'p2s-harden: Voraussetzungen unvollstaendig\n%s\n' "$p2s_problem" >&2
    for p2s_tool in python3 ps curl runuser systemctl; do
      command -v "$p2s_tool" >/dev/null 2>&1 || printf 'FEHLT   %s\n' "$p2s_tool" >&2
    done
    printf '%s\n' 'ps ist optional (/proc-Fallback). curl: HTTP-Checks. runuser: fremde FPM-Benutzer. systemctl: INI-Fixes.' 'Nach Bereitstellung von Python denselben Befehl erneut ausfuehren. Es wurde nichts installiert oder geaendert.' >&2
  fi
  return 2
}
if [ "$target" = local ]; then
  bootstrap "$json_mode" || exit 2
  payload | python3 -B - "${args[@]}"
  exit "$?"
fi
default_ssh=ssh
[ -x C:/Windows/System32/OpenSSH/ssh.exe ] && default_ssh=C:/Windows/System32/OpenSSH/ssh.exe
ssh_bin=${SSH_BIN:-$default_ssh}
if ! command -v "$ssh_bin" >/dev/null 2>&1; then
  if [ "$json_mode" = 1 ]; then
    printf '%s\n' '{"schema_version":1,"version":"2.2.0-rc.1","exit_code":2,"findings":[{"status":"UNKNOWN","title":"SSH","detail":"OpenSSH-Client fehlt; Client bereitstellen oder SSH_BIN setzen."}],"discovery":{}}'
  else
    printf '%s\n' 'Voraussetzung fehlt: OpenSSH-Client (oder SSH_BIN setzen).' >&2
  fi
  exit 2
fi
remote="$(declare -f bootstrap); bootstrap $json_mode || exit 2; exec python3 -B -"
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
    printf '%s\n' '{"schema_version":1,"version":"2.2.0-rc.1","exit_code":2,"findings":[{"status":"UNKNOWN","title":"SSH","detail":"Ziel nicht erreichbar oder Anmeldung fehlgeschlagen; vorhandenen SSH-Zugang pruefen und erneut ausfuehren."}],"discovery":{}}'
  else
    printf '%s\n' 'SSH-Verbindung nicht verfuegbar. Vorhandenen SSH-Zugang pruefen; danach denselben Befehl erneut ausfuehren.' >&2
  fi
  exit 2
fi
exit "$result"

: <<'__P2S_ENGINE_EOF__'
# __P2S_PYTHON__
"""p2s-harden 2: bounded Linux checks and reversible, explicit changes.

The shell launcher streams this standard-library-only module over one SSH
connection. Importing it has no side effects; check/dry-run create no files.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:  # Keep --help and the unsupported-platform explanation usable.
    pwd = None
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

VERSION = "2.2.0-rc.1"
REQUIRED = frozenset("exec system shell_exec passthru popen proc_open pcntl_exec".split())


class CheckError(RuntimeError):
    pass


def install_hint(package):
    """Suggestions only; never run a package manager or install anything."""
    try:
        release = Path("/etc/os-release").read_text()
    except OSError:
        release = ""
    identifiers = " ".join(re.findall(r'^ID(?:_LIKE)?=["\']?([^\n"\']+)', release, re.M)).split()
    if any(i in identifiers for i in ("debian", "ubuntu")):
        return "Bei Bedarf installieren: sudo apt-get install " + package
    if any(i in identifiers for i in ("fedora", "rhel", "centos", "rocky", "almalinux")):
        return "Bei Bedarf installieren: sudo dnf install " + ("procps-ng" if package == "procps" else package)
    if "alpine" in identifiers:
        return "Bei Bedarf installieren: sudo apk add " + package
    return "Bei Bedarf Paket '" + package + "' mit dem Paketmanager bereitstellen"


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
               "verfuegbar" if sys.platform == "linux" and cap["proc"] else "Linux-Ziel mit lesbarem /proc erforderlich; von Windows/macOS --ssh verwenden")
    report.add("OK" if sys.version_info >= (3, 8) else "UNKNOWN", "Python", cap["python"] + "; mindestens 3.8 erforderlich")
    report.add("OK" if cap["root"] else "UNKNOWN", "Berechtigungen",
               "root: volle Host-Pruefung moeglich" if cap["root"] else "Lesbare Teilpruefungen laufen; fuer fremde FPM-Benutzer und Fixes sudo/root verwenden")
    for name, purpose, package in (("curl", "HTTP-Statuspruefungen", "curl"), ("runuser", "Dateirechte als fremder FPM-Benutzer", "util-linux")):
        report.add("OK" if cap["tools"][name] else "UNKNOWN", name,
                   purpose + ": verfuegbar" if cap["tools"][name] else purpose + ": fehlt; " + install_hint(package))
    report.add("OK", "FPM-Prozesserkennung", "ps verfuegbar" if cap["tools"]["ps"] else "ps fehlt; /proc-Fallback wird verwendet (keine Installation noetig)")
    managed = cap["tools"]["systemctl"] and cap["systemd"]
    report.add("OK" if managed else "UNKNOWN", "Automatische INI-Fixes",
               "systemd-Dienstzuordnung kann geprueft werden" if managed else "systemd/systemctl fehlt oder ist nicht aktiv; Audit laeuft, automatische INI-Fixes gesperrt")
    return report


def stage(args, message):
    if not getattr(args, "no_progress", False) and (sys.stderr.isatty() or getattr(args, "progress", False)):
        print("[p2s] " + message, file=sys.stderr, flush=True)


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
        raise CheckError("FPM-Erkennung: /proc nicht lesbar; andere Module laufen weiter") from exc
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
    issues = ["FPM-Prozesserkennung teilweise ohne Leserecht; sudo/root verwenden"] if denied else []
    return "\n".join(lines), issues


def command(argv, *, env=None, timeout=30):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, env=env,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckError(f"{argv[0]} nicht ausfuehrbar: {type(exc).__name__}") from exc
    if result.returncode:
        # Do not print config dumps, application environment, or HTTP bodies.
        raise CheckError(f"{argv[0]} fehlgeschlagen (Exit {result.returncode})")
    return result.stdout, result.stderr


def digest(data):
    return hashlib.sha256(data).hexdigest()


def functions(value):
    return {item.strip().lower() for item in value.split(",") if item.strip()}


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
        raise CheckError("FPM-Pool-Dump nicht auswertbar")
    return pools


def active_ini_lines(text, key):
    # Exclude both PHP comment syntaxes, retain only real assignments.
    pattern = re.compile(r"^\s*" + re.escape(key) + r"\s*=")
    return [i for i, line in enumerate(text.splitlines()) if pattern.match(line)]


def set_ini(text, updates):
    if re.search(r"^\s*\[(?:PATH|HOST)\s*=", text, re.M | re.I):
        raise CheckError("Bedingte PATH/HOST-INI: automatische Aenderung abgelehnt")
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
        raise CheckError(f"Absoluter Pfad erforderlich: {p}")
    for item in [p, *p.parents]:
        st = item.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise CheckError(f"Nicht vertrauenswuerdiger Root-Pfad: {item}")
        # Extended ACLs must not provide a hidden write grant.
        if "system.posix_acl_access" in os.listxattr(item):
            acl = os.getxattr(item, "system.posix_acl_access")
            # Group-class access is bounded by the mode's mask. 0o022 above
            # rejects writable ACL masks and writable 'other' alike.
            if not acl:
                raise CheckError(f"ACL nicht lesbar: {item}")
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
                unknown.append(f"FPM PID {pid}: Container/anderer Dateisystem-Namensraum")
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
                raise CheckError("Abweichender INI-Kontext: separate Laufzeitpruefung erforderlich")
            trusted(conventional / "php.ini")
            trusted(conventional / "conf.d")
            extra_inis = []
            for ini in sorted((conventional / "conf.d").glob("*.ini")):
                try:
                    extra_inis.append(trusted(ini.resolve(strict=True)))
                except FileNotFoundError:
                    # PHP ignores dangling *.ini links. Keep the operational
                    # defect visible without inventing a loaded configuration.
                    unknown.append(f"FPM PID {pid}: haengender INI-Verweis {ini}")
            # Includes are untrusted until their full include closure is checked.
            validate_fpm_files(Path(config))
            out, _ = command([binary, "-i"], env=env)
            info = info_values(out)
            loaded = info.get("Loaded Configuration File", "")
            if loaded != str(conventional / "php.ini"):
                raise CheckError("INI-Kontext weicht vom erwarteten FPM-Kontext ab")
            if info.get("Scan this dir for additional .ini files") != str(conventional / "conf.d"):
                raise CheckError("INI-Scan-Verzeichnis weicht vom erwarteten FPM-Kontext ab")
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
        unknown.append("Kein laufender FPM-Master gefunden")
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
            raise CheckError("Relativer FPM-Include erfordert manuelle Kontextpruefung")
        files = sorted(glob.glob(pattern))
        if not files:
            raise CheckError(f"FPM-Include ohne lesbares Ziel: {pattern}")
        for child in files:
            validate_fpm_files(Path(child), seen)


PERMISSION_SCAN = r'''
import json, os, sys
root = sys.argv[1]
result = dict(files=0, directories=0, file_sample=[], directory_sample=[], errors=[])
def error(exc):
    result['errors'].append(str(exc.filename))
try:
    if not os.path.isdir(root):
        raise OSError('Kein lesbares Verzeichnis')
    device = os.stat(root).st_dev
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=error):
        if os.stat(parent).st_dev != device:
            result['errors'].append(parent + ' (anderes Dateisystem)')
            dirs[:] = []
            continue
        if os.access(parent, os.W_OK | os.X_OK):
            result['directories'] += 1
            if len(result['directory_sample']) < 6: result['directory_sample'].append(parent)
        for name in dirs[:]:
            p = os.path.join(parent, name)
            if os.path.islink(p):
                result['errors'].append(p + ' (Symlink nicht verfolgt)')
                dirs.remove(name)
            elif name == '.git':
                dirs.remove(name)
        for name in files:
            if name.lower().endswith('.php'):
                p = os.path.join(parent, name)
                if os.access(p, os.W_OK):
                    result['files'] += 1
                    if len(result['file_sample']) < 6: result['file_sample'].append(p)
except OSError:
    result['errors'].append(root)
print(json.dumps(result))
'''


def as_user(user, argv):
    account = pwd.getpwnam(user)
    if os.geteuid() == account.pw_uid:
        return command(argv, timeout=120)[0]
    if os.geteuid() != 0:
        raise CheckError(f"Kann UID fuer {user} nicht wechseln")
    return command(["runuser", "-u", user, "--", *argv], timeout=120)[0]


def probe(url, connect_ip="127.0.0.1"):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise CheckError("HTTP(S)-URL ohne Zugangsdaten erforderlich")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    import ipaddress
    address = ipaddress.ip_address(connect_ip)
    connect = f"[{address}]" if address.version == 6 else str(address)
    # Explicit local resolution, correct Host and TLS SNI; no redirect following.
    out, _ = command(["curl", "--disable", "--silent", "--show-error", "--insecure", "--noproxy", "*",
                      "--connect-timeout", "3", "--max-time", "8", "--output", "/dev/null",
                      "--write-out", "%{http_code}", "--resolve",
                      f"{parts.hostname}:{port}:{connect}", url], timeout=12)
    if not re.fullmatch(r"[1-5]\d\d", out):
        raise CheckError("Kein gueltiger HTTP-Status")
    return int(out)


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
                raise CheckError("Nginx: unvollstaendiges Escape")
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
                raise CheckError("Nginx: unvollstaendige Variable")
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
        if len(tokens) > 200000:
            raise CheckError("Nginx: Tokenlimit erreicht")
    if quote:
        raise CheckError("Nginx: nicht abgeschlossene Zeichenkette")
    flush()
    return tokens


def parse_nginx(text, source="<config>"):
    tokens, index = nginx_tokens(text), 0
    def block(depth=0, nested=False):
        nonlocal index
        if depth > 64:
            raise CheckError("Nginx: Verschachtelungslimit erreicht")
        nodes = []
        while index < len(tokens):
            if tokens[index][:2] == ("symbol", "}"):
                if not nested:
                    raise CheckError("Nginx: unerwartetes Blockende")
                index += 1
                return nodes
            words = []
            start_line = tokens[index][2]
            while index < len(tokens) and tokens[index][0] == "word":
                words.append(tokens[index][1])
                index += 1
            if not words or index == len(tokens):
                raise CheckError(f"Nginx: unvollstaendige Direktive ({source}:{start_line})")
            kind, symbol, _ = tokens[index]
            index += 1
            if symbol not in (";", "{"):
                raise CheckError(f"Nginx: unerwartetes Trennzeichen ({source}:{start_line})")
            children = block(depth + 1, True) if symbol == "{" else None
            nodes.append(dict(name=words[0], args=words[1:], children=children,
                              source=source, line=start_line))
        if nested:
            raise CheckError("Nginx: fehlendes Blockende")
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
                raise CheckError(f"Nginx-Konfiguration ist nicht rootgeschuetzt: {component}")
        resolved = trusted(path.resolve(strict=True))
        if str(resolved) in stack:
            raise CheckError(f"Nginx: Include-Zyklus bei {resolved}")
        if str(resolved) not in cache:
            if not resolved.is_file() or resolved.stat().st_size > 1024 * 1024:
                raise CheckError("Nginx: Konfigurationsdatei zu gross oder kein regulaerer Dateityp")
            budget[0] += 1
            text = resolved.read_text()
            budget[1] += len(text)
            if budget[0] > 2048 or budget[1] > 8 * 1024 * 1024:
                raise CheckError("Nginx: Leselimit erreicht")
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
                        raise CheckError("Nginx: dynamischer oder ungueltiger Include")
                    unresolved(node, "Nginx: dynamischer oder ungueltiger Include")
                    continue
                pattern = Path(node["args"][0])
                pattern = str(pattern if pattern.is_absolute() else prefix / pattern)
                paths = sorted(glob.glob(pattern))
                if not paths and not glob.has_magic(pattern):
                    if not partial:
                        raise CheckError(f"Nginx-Include fehlt: {pattern}")
                    unresolved(node, f"Nginx-Include fehlt: {pattern}")
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
                raise CheckError("Nginx: Expansionslimit erreicht")
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
            issue(f"{source}: dynamischer oder relativer Dokumentpfad")
            return None
        path = Path(value)
        if not path.is_dir():
            issue(f"{source}: Dokumentpfad fehlt: {path}")
            return None
        if str(path) == "/" or path.parts[1] in ("etc", "proc", "sys", "dev", "run", "root", "usr"):
            issue(f"{source}: Systempfad wird nicht automatisch durchsucht: {path}")
            return None
        if path.is_symlink() or str(path.resolve()) != str(path):
            issue(f"{source}: Dokumentpfad enthaelt Symlinks: {path}")
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
                issue(f"{source}: Server mit unvollstaendigen Includes wird nicht automatisch per HTTP zugeordnet")
                continue
            names = []
            for name in [v for group in values(nodes, "server_name") for v in group]:
                if re.fullmatch(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", name) and ".." not in name:
                    names.append(name.lower())
                else:
                    issue(f"{source}: Wildcard/Regex/Default-Hostname braucht eine explizite --site-Angabe")
            listeners = []
            for args in values(nodes, "listen") or [["80"]]:
                if not args:
                    continue
                address = args[0]
                if address.startswith("unix:") or any(v in args for v in ("quic", "udp")):
                    issue(f"{source}: Unix-/UDP-Listener wird nicht per HTTP geprueft")
                    continue
                if address.isdigit():
                    ip, port = "127.0.0.1", int(address)
                elif re.fullmatch(r"(?:\*|0\.0\.0\.0|127\.\d+\.\d+\.\d+):\d+", address):
                    ip, value = address.rsplit(":", 1)
                    ip, port = ("127.0.0.1" if ip in ("*", "0.0.0.0") else ip), int(value)
                elif re.fullmatch(r"\[(?:::|::1)\]:\d+", address):
                    ip, port = "::1", int(address.rsplit(":", 1)[1])
                else:
                    issue(f"{source}: spezifischer Listener erfordert manuelle lokale Zuordnung")
                    continue
                if not 1 <= port <= 65535:
                    issue(f"{source}: ungueltiger Listener-Port")
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
                            issue(f"{source}: bedingter Dokumentpfad ist nicht eindeutig")
                        continue
                    args, body = node["args"], node["children"]
                    candidate = args[-1] if args else ""
                    own_root, alias = values(body, "root"), values(body, "alias")
                    literal = candidate.startswith("/") and not any(x in candidate for x in ("$", "?", "#")) and args[:1] not in (["~"], ["~*"])
                    chosen_root = own_root[-1][0] if own_root and len(own_root[-1]) == 1 else inherited_root
                    if alias or own_root:
                        if not literal:
                            issue(f"{source}: Regex-/dynamischer Location-Pfad braucht manuelle Zuordnung")
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
                    issue(f"{source}: Redirect ohne Dokumentwurzel wird nicht als Dateipruefung gewertet")
                else:
                    inventory["skipped_proxy_servers"] += 1
                    issue(f"{source}: Proxy/fehlende Dokumentwurzel benoetigt eigene Backend-Pruefung")
    for url, entries in sorted(mappings.items()):
        if len({e["root"] for e in entries}) > 1:
            issue(f"Mehrdeutige Dokumentwurzel fuer {url}; automatische HTTP-Pruefung ausgespart")
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
                inventory["issues"].append(f"Automatische Nginx-Erkennung unvollstaendig: {exc}")
        else:
            inventory["issues"].append("Keine eindeutige Nginx-Hauptkonfiguration; --nginx-config oder --site/--root angeben")
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
            inventory["issues"].append(f"HTTP-Limit: {len(entries) - args.max_sites} Zuordnungen ausgelassen; --max-sites erhoehen oder --site eingrenzen")
        for entry in entries[:args.max_sites]:
            sites.append(entry["url"] + "=" + entry["root"])
            addresses[entry["url"]] = entry["connect_ip"]
        roots = inventory["roots"]
    if explicit_root:
        roots = [explicit_root]
    if not roots:
        roots = ["/var/www"]
        inventory["issues"].append("Kein eindeutiger Webroot; /var/www dient nur als ausgewiesener Dateisystem-Fallback")
    args.roots, args.site, args.site_addresses = minimal_roots(roots), sites, addresses
    args.root = explicit_root or args.roots[0]
    inventory["scan_roots"], inventory["selected_sites"] = args.roots, sites
    inventory["automatic_changes"] = "Keine Rechteziele aus Erkennung abgeleitet"
    args.discovery = inventory
    return args


class Report:
    def __init__(self):
        self.rows = []
        self.discovery = {}

    def add(self, status, title, detail):
        self.rows.append(dict(status=status, title=title, detail=detail))

    def exit_code(self):
        if any(r["status"] == "UNKNOWN" for r in self.rows):
            return 2
        return int(any(r["status"] == "OPEN" for r in self.rows))

    def show(self, as_json=False, verbose=False):
        if as_json:
            print(json.dumps(dict(schema_version=1, version=VERSION, findings=self.rows,
                                  discovery=self.discovery,
                                  exit_code=self.exit_code()), ensure_ascii=False, indent=2))
            return
        label = "Voraussetzungen" if self.discovery.get("doctor") else "Erkanntes Inventar" if self.discovery.get("inventory_only") else "Konfigurationspruefung"
        print(f"p2s-harden {VERSION} – {label}")
        cap = self.discovery.get("capabilities", {})
        missing_tools = [name for name, present in cap.get("tools", {}).items() if not present]
        if missing_tools:
            print("Fehlende Helfer: " + ", ".join(missing_tools) + "; --doctor zeigt Zweck und naechste Schritte.")
        if self.discovery and not self.discovery.get("doctor"):
            pools = sum(len(i["pools"]) for i in self.discovery.get("fpm_instances", []))
            print(f"Erkannt: {len(self.discovery.get('fpm_instances', []))} Host-FPM-Instanzen, {pools} Pools, "
                  f"{len(self.discovery.get('selected_sites', []))} HTTP-Zuordnungen")
            roots = self.discovery.get("scan_roots", [])
            print("Pruefpfade: " + ", ".join(roots[:8]))
            if len(roots) > 8:
                print(f"Weitere {len(roots) - 8} Pfade im vollstaendigen --json-Inventar.")
            if self.discovery.get("inventory_only"):
                for instance in self.discovery.get("fpm_instances", []):
                    for pool in instance["pools"]:
                        print(f"POOL    {pool['name']} | Benutzer: {pool['user']} | Listener: {pool['listen']}")
                for site in self.discovery.get("selected_sites", []):
                    print("SITE    " + site)
        shown = self.rows if verbose or self.discovery.get("doctor") else [r for r in self.rows if r["status"] != "OK"]
        for row in shown if verbose else shown[:40]:
            # Configured names/paths must not inject terminal escape sequences.
            line = f"{row['status']:7} {row['title']}: {row['detail']}"
            print("".join(c if c.isprintable() else "?" for c in line))
        if not verbose and len(shown) > 40:
            print(f"Weitere {len(shown) - 40} Befunde: --verbose oder --json zeigt alle Details.")
        counts = {s: sum(r["status"] == s for r in self.rows) for s in ("OK", "OPEN", "UNKNOWN", "N/A")}
        print("\n" + "   ".join(f"{s}: {n}" for s, n in counts.items()))
        print("Nur die ausgewiesenen Host-Pfade/Instanzen wurden geprueft; keine Sicherheitszertifizierung.")


def scan(args, inventory_only=False):
    report, updates = Report(), {}
    report.discovery = dict(getattr(args, "discovery", {}))
    cap = capabilities()
    report.discovery["capabilities"] = cap
    for message in report.discovery.get("issues", []):
        report.add("UNKNOWN", "Automatische Erkennung", message)
    stage(args, "FPM-Instanzen und Pools erkennen")
    try:
        instances, unknown = discover()
    except (OSError, ValueError, CheckError) as exc:
        instances, unknown = [], [str(exc)]
    for message in unknown:
        report.add("UNKNOWN", "FPM-Abdeckung", message)
    users = set(args.web_user)
    if report.discovery:
        report.discovery["fpm_instances"] = [dict(pid=i["pid"], config=i["config"], service=i.get("service"),
            pools=[dict(name=name, user=settings.get("user", "unbekannt"), listen=settings.get("listen", "unbekannt"))
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
                       "fehlt: " + ",".join(sorted(missing)) if missing else "7 definierte Shell-Funktionen gesperrt")
            desired = {}
            if missing:
                desired["disable_functions"] = ",".join(sorted(disabled | REQUIRED))
            url_include = values.get("allow_url_include")
            if url_include is None:
                report.add("UNKNOWN", f"allow_url_include {label}", "Wert fehlt")
            else:
                enabled = url_include.lower() not in ("off", "0", "no", "false", "")
                report.add("OPEN" if enabled else "OK", f"allow_url_include {label}", url_include)
                if enabled:
                    desired["allow_url_include"] = "Off"
            for pool, settings in instance["pools"].items():
                user = settings.get("user")
                if user and user != "undefined":
                    users.add(user)
                combined = disabled | functions(settings.get("php_admin_value[disable_functions]", "")) | functions(settings.get("php_value[disable_functions]", ""))
                absent = REQUIRED - combined
                report.add("OPEN" if absent else "OK", f"Pool {label} [{pool}]",
                           "fehlt: " + ",".join(sorted(absent)) if absent else "globale + Pool-Sperren zusammen ausgewertet")
                include_value = url_include
                for prefix in ("php_value", "php_flag", "php_admin_value", "php_admin_flag"):
                    override = settings.get(prefix + "[allow_url_include]")
                    if override is not None and override != "undefined":
                        include_value = override
                if include_value is None:
                    report.add("UNKNOWN", f"allow_url_include [{pool}] {label}", "Wert fehlt")
                else:
                    pool_enabled = include_value.lower() not in ("off", "0", "no", "false", "")
                    report.add("OPEN" if pool_enabled else "OK", f"allow_url_include [{pool}] {label}",
                               include_value + ("; Pool-Override manuell korrigieren" if pool_enabled else ""))
                ob = settings.get("php_admin_value[open_basedir]", settings.get("php_value[open_basedir]", values.get("open_basedir", "")))
                unrestricted = not ob or ob.lower() in ("none", "no value", "undefined") or "/" in [p.strip() for p in ob.split(":")]
                report.add("OPEN" if unrestricted else "OK", f"open_basedir [{pool}] {label}",
                           "nicht einschraenkend" if unrestricted else ob + " (zusaetzliche Schranke, keine Sandbox)")
            for key, value in desired.items():
                owners = [p for p in instance["inis"] if active_ini_lines(Path(p).read_text(), key)]
                target = owners[-1] if owners else instance["inis"][0]
                if os.path.commonpath([target, str(Path(instance["inis"][0]).parent)]) != str(Path(instance["inis"][0]).parent):
                    report.add("OPEN", "Automatischer INI-Fix ausgespart", f"{key}: geteilte Datei ausserhalb der FPM-INI-Wurzel: {target}")
                    continue
                existing = updates.setdefault(target, {})
                if key in existing and existing[key] != value:
                    raise CheckError("Widerspruechliche INI-Werte mehrerer Instanzen")
                existing[key] = value
        except (OSError, UnicodeError, ValueError, CheckError) as exc:
            updates = saved_updates
            report.add("UNKNOWN", "FPM-Konfiguration " + instance["config"], str(exc))
    if not users:
        report.add("UNKNOWN", "Dateirechte", "Kein gepruefter FPM-Benutzer; --web-user erforderlich")
    stage(args, "Dateirechte unter den erkannten FPM-Benutzern pruefen")
    roots = getattr(args, "roots", None) or [args.root]
    ready_users = []
    for user in sorted(users):
        try:
            uid = pwd.getpwnam(user).pw_uid
            if uid == 0:
                report.add("OPEN", "FPM-Benutzer", f"{user} hat UID 0")
            elif uid != os.geteuid() and not cap["root"]:
                report.add("UNKNOWN", f"Dateirechte ({user})", "Fremde UID nicht pruefbar; sudo/root verwenden. Andere Module laufen weiter.")
            elif uid != os.geteuid() and not cap["tools"]["runuser"]:
                report.add("UNKNOWN", f"Dateirechte ({user})", "runuser fehlt; " + install_hint("util-linux") + ". Andere Module laufen weiter.")
            else:
                ready_users.append(user)
        except KeyError:
            report.add("UNKNOWN", f"Dateirechte ({user})", "Benutzer existiert nicht auf diesem Host; --web-user korrigieren oder Container separat pruefen")
    for user, scan_root in [(user, root) for user in ready_users for root in roots]:
        try:
            if pwd.getpwnam(user).pw_uid == 0:
                report.add("OPEN", "FPM-Benutzer", f"{user} hat UID 0")
                continue
            data = json.loads(as_user(user, [sys.executable, "-B", "-c", PERMISSION_SCAN, scan_root]))
            for key, title in (("files", "schreibbare PHP-Dateien"), ("directories", "schreibbare Verzeichnisse")):
                count = data[key]
                sample = data["file_sample" if key == "files" else "directory_sample"]
                report.add("OPEN" if count else "OK", f"{title} ({user})", f"{scan_root}: {count}; " + "; ".join(sample))
            if data["errors"]:
                report.add("UNKNOWN", f"Dateisystem-Abdeckung ({user})", f"{len(data['errors'])} unlesbare/ausgelassene Pfade; " + "; ".join(data["errors"][:4]))
        except (KeyError, OSError, ValueError, CheckError) as exc:
            report.add("UNKNOWN", f"Dateirechte ({user})", str(exc))
    if not args.site:
        report.add("UNKNOWN", "HTTP-Abdeckung", "Keine --site URL=DOKUMENTWURZEL angegeben")
    elif not cap["tools"]["curl"]:
        report.add("UNKNOWN", "HTTP-Abdeckung", "curl fehlt; HTTP-Pruefungen ausgelassen. " + install_hint("curl") + ". Dateisystem-/FPM-Pruefungen laufen weiter.")
    stage(args, "HTTP-Endpunkte und weitere Host-Einstellungen pruefen")
    git_cache = {}
    for site in args.site if cap["tools"]["curl"] else []:
        try:
            url, document_root = site.split("=", 1)
            from urllib.parse import quote, urlsplit
            parts = urlsplit(url)
            if parts.query or parts.fragment or parts.username or parts.password or parts.scheme not in ("http", "https") or not parts.hostname:
                raise CheckError("--site benoetigt HTTP(S)-Basis-URL ohne Query, Fragment oder Zugangsdaten")
            root = Path(document_root)
            if not root.is_absolute() or not root.is_dir():
                raise CheckError("Dokumentwurzel fehlt oder ist relativ")
            if str(root) not in git_cache:
                endpoints, walk_errors = {".git/config", ".env"}, []
                for parent, dirs, _ in os.walk(root, followlinks=False, onerror=lambda e: walk_errors.append(str(e.filename))):
                    if ".git" in dirs:
                        relative = (Path(parent) / ".git/config").relative_to(root).as_posix()
                        endpoints.add(relative)
                        dirs.remove(".git")
                git_cache[str(root)] = endpoints, walk_errors
            endpoints, walk_errors = git_cache[str(root)]
            if walk_errors:
                report.add("UNKNOWN", "Git-Pfadabdeckung", "; ".join(walk_errors[:3]))
            for endpoint in sorted(endpoints):
                target = url.rstrip("/") + "/" + quote(endpoint, safe="/")
                try:
                    address = getattr(args, "site_addresses", {}).get(url, "127.0.0.1")
                    code = probe(target) if address == "127.0.0.1" else probe(target, connect_ip=address)
                    status = "OPEN" if 200 <= code < 300 else "OK" if code in (401, 403, 404, 410) else "UNKNOWN"
                    report.add(status, "HTTP " + target, str(code) + ("; moeglicher Dateizugriff, Inhalt nicht bewertet" if status == "OPEN" else ""))
                except CheckError as exc:
                    report.add("UNKNOWN", "HTTP " + target, str(exc))
        except (OSError, ValueError, CheckError) as exc:
            report.add("UNKNOWN", "HTTP-Konfiguration", str(exc))
    try:
        ptrace = int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text())
        report.add("OK" if ptrace >= 1 else "OPEN", "ptrace_scope", str(ptrace))
    except (OSError, ValueError):
        report.add("UNKNOWN", "ptrace_scope", "nicht lesbar")
    # Merely finding the word 'coder' proves no restriction. XML rules can be
    # overridden and delegates are version-dependent; do not auto-edit them.
    policies = [p for p in (Path("/etc/ImageMagick-6/policy.xml"), Path("/etc/ImageMagick-7/policy.xml")) if p.exists()]
    if policies:
        report.add("UNKNOWN", "ImageMagick-Policy", "regel- und versionsbezogene manuelle Pruefung erforderlich; " + ", ".join(map(str, policies)))
    else:
        report.add("UNKNOWN", "ImageMagick-Policy", "keine bekannte Policy; Modul-/Container-Abdeckung offen")
    return report, updates, instances, users


def metadata(path):
    st = Path(path).lstat()
    if stat.S_ISLNK(st.st_mode):
        raise CheckError(f"Symlink als Aenderungsziel abgelehnt: {path}")
    return dict(uid=st.st_uid, gid=st.st_gid, mode=stat.S_IMODE(st.st_mode),
                dev=st.st_dev, ino=st.st_ino,
                atime_ns=st.st_atime_ns, mtime_ns=st.st_mtime_ns,
                xattrs={k: base64.b64encode(os.getxattr(path, k)).decode() for k in os.listxattr(path)})


def same_permissions(first, second):
    return all(first[k] == second[k] for k in ("uid", "gid", "mode", "xattrs"))


def atomic_bytes(path, data, meta):
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
            if "mtime_ns" in meta:
                os.utime(stream.fileno(), ns=(meta["atime_ns"], meta["mtime_ns"]))
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def reload_instances(instances):
    for item in instances:
        if start_identity(item["pid"]) != item["start"]:
            raise CheckError("FPM-Master hat gewechselt; Reload abgebrochen")
        command([item["binary"], "-t", "-y", item["config"]], env=item.get("env"))
        pid, _ = command(["systemctl", "show", "--property=MainPID", "--value", item["service"]])
        if pid.strip() != str(item["pid"]):
            raise CheckError("Dienst und FPM-Master stimmen nicht ueberein")
    for item in instances:
        if start_identity(item["pid"]) != item["start"]:
            raise CheckError("FPM-Master hat gewechselt; Reload abgebrochen")
        command(["systemctl", "reload", item["service"]])
        command(["systemctl", "is-active", "--quiet", item["service"]])


def fix_blockers(updates, protect_dirs, instances, users):
    """Preflight the complete explicit plan before creating a transaction."""
    reasons = []
    if not updates and not protect_dirs:
        return reasons
    cap = capabilities()
    if not cap["root"]:
        reasons.append("Aenderungen erfordern root; sudo oder --ssh root@SERVER verwenden")
    affected = [i for i in instances if set(updates).intersection(i["inis"])]
    if updates:
        if not affected or set(updates) - {p for i in affected for p in i["inis"]}:
            reasons.append("Keine vollstaendige FPM-Zuordnung fuer alle INI-Aenderungen")
        if not cap["systemd"] or not cap["tools"]["systemctl"] or any(not i.get("service") for i in affected):
            reasons.append("Kein gepruefter systemd-Reload fuer alle betroffenen FPM-Instanzen; INI-Fixes gesperrt, Audit weiterhin moeglich")
        else:
            for item in affected:
                try:
                    active, _ = command(["systemctl", "show", "--property=MainPID", "--value", item["service"]])
                    if active.strip() != str(item["pid"]) or start_identity(item["pid"]) != item["start"]:
                        raise CheckError("FPM-Master und Dienst stimmen nicht mehr ueberein")
                except (OSError, CheckError) as exc:
                    reasons.append("Reload-Vorpruefung " + item["service"] + ": " + str(exc))
    if protect_dirs:
        if not users:
            reasons.append("--protect-dir erfordert einen erkannten oder expliziten --web-user zur Verifikation")
        for user in sorted(users):
            try:
                uid = pwd.getpwnam(user).pw_uid
                if uid == 0:
                    reasons.append("Rechteschutz gegen UID 0 ist nicht moeglich: " + user)
                elif uid != os.geteuid() and not cap["tools"]["runuser"]:
                    reasons.append("Rechteverifikation fuer " + user + ": runuser fehlt; " + install_hint("util-linux"))
            except KeyError:
                reasons.append("Rechteverifikation: unbekannter Benutzer " + user)
    return reasons


class Transaction:
    def __init__(self, backup_root):
        self.root = Path(backup_root)
        self.path = None
        self.data = dict(version=1, status="prepared", files=[], directories=[], instances=[])

    def begin(self):
        if os.geteuid() != 0:
            raise CheckError("Aenderungen und Rollback erfordern root")
        if not self.root.is_absolute():
            raise CheckError("Backup-Verzeichnis muss absolut sein")
        trusted(self.root.parent)
        if not self.root.exists():
            self.root.mkdir(mode=0o700)
        trusted(self.root)
        if self.root.stat().st_mode & 0o077:
            raise CheckError("Backup-Verzeichnis muss Modus 0700 haben")
        self.path = self.root / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:10])
        self.path.mkdir(mode=0o700)
        self.save()

    def save(self):
        atomic_bytes(self.path / "manifest.json", json.dumps(self.data, indent=2).encode(),
                     dict(uid=0, gid=0, mode=0o600, xattrs={}))

    def prepare(self, updates, protect_dirs, instances):
        # Guard callers other than main as well: never edit first and discover
        # a missing reload/user-switch capability during recovery.
        affected = [i for i in instances if set(updates).intersection(i["inis"])]
        if any(not i.get("service") for i in affected):
            raise CheckError("Kein gepruefter FPM-Dienst fuer INI-Aenderungen")
        self.begin()
        for target, values in sorted(updates.items()):
            path = trusted(target)
            before_meta = metadata(path)
            original = path.read_bytes()
            changed = set_ini(original.decode(), values).encode()
            backup = f"file-{len(self.data['files'])}.bin"
            atomic_bytes(self.path / backup, original, dict(uid=0, gid=0, mode=0o600, xattrs={}))
            self.data["files"].append(dict(path=str(path), backup=backup, before=digest(original),
                                           after=digest(changed), meta=before_meta, values=values))
        for name in sorted(set(protect_dirs), key=lambda p: len(Path(p).parts)):
            path = Path(name)
            if not path.is_absolute() or not path.is_dir():
                raise CheckError("--protect-dir braucht ein bestehendes absolutes Verzeichnis")
            # No path component may be a symlink. Protecting a directory is
            # explicit and non-recursive; children/runtime storage stay intact.
            for part in [path, *path.parents]:
                if part.is_symlink():
                    raise CheckError("Symlink in --protect-dir abgelehnt")
            self.data["directories"].append(dict(path=str(path), meta=metadata(path)))
        changed_inis = set(updates)
        self.data["instances"] = [{k: i[k] for k in ("pid", "start", "binary", "config", "service")} for i in instances if changed_inis.intersection(i["inis"])]
        self.save()

    def apply(self, instances, users):
        try:
            for item in self.data["files"]:
                path = trusted(item["path"])
                original = path.read_bytes()
                if digest(original) != item["before"] or not same_permissions(metadata(path), item["meta"]):
                    raise CheckError("Konfiguration wurde zwischenzeitlich geaendert")
                item["started"] = True
                self.save()
                atomic_bytes(path, set_ini(original.decode(), item["values"]).encode(), item["meta"])
                item["after_meta"] = metadata(path)
                self.save()
            for item in self.data["directories"]:
                path, before = Path(item["path"]), item["meta"]
                now = metadata(path)
                if (now["dev"], now["ino"], now["uid"], now["gid"], now["mode"]) != tuple(before[k] for k in ("dev", "ino", "uid", "gid", "mode")):
                    raise CheckError("Verzeichnis wurde zwischenzeitlich geaendert")
                # Refuse a replaceable parent; explicitly protect higher-level
                # code directories first instead of traversing them as root.
                trusted(path.parent)
                item["started"] = True
                self.save()
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    current = os.fstat(fd)
                    if (current.st_dev, current.st_ino) != (before["dev"], before["ino"]):
                        raise CheckError("Verzeichnisidentitaet hat gewechselt")
                    os.fchown(fd, 0, before["gid"])
                    os.fchmod(fd, before["mode"] & ~0o022)
                finally:
                    os.close(fd)
                item["after"] = metadata(path)
                self.save()
                for user in users:
                    output = as_user(user, [sys.executable, "-B", "-c", "import os,sys; print(int(os.access(sys.argv[1], os.W_OK)))", str(path)])
                    if output.strip() != "0":
                        raise CheckError(f"{path} bleibt fuer {user} schreibbar")
            affected = [i for i in instances if i["pid"] in {r["pid"] for r in self.data["instances"]}]
            for i in affected:
                command([i["binary"], "-t", "-y", i["config"]], env=i["env"])
                out, _ = command([i["binary"], "-i"], env=i["env"])
                values = info_values(out)
                if not REQUIRED <= functions(values.get("disable_functions", "")) or "allow_url_include" not in values or values["allow_url_include"].lower() not in ("off", "0", "no", "false", ""):
                    raise CheckError("Erwartete PHP-Einstellungen greifen nicht")
            reload_instances(affected)
            self.data["status"] = "applied"
            self.save()
            print(f"Backup: {self.path}")
        except BaseException:
            self.restore(allow_partial=True, recover_service=True)
            raise

    def restore(self, allow_partial=False, recover_service=False):
        # Preflight ALL entries before touching anything, so a conflict does
        # not leave a half-restored configuration or overwrite a newer edit.
        files = [i for i in self.data["files"] if i.get("started")]
        directories = [i for i in self.data["directories"] if i.get("started")]
        for item in files:
            trusted(item["path"])
            current = digest(Path(item["path"]).read_bytes())
            allowed = (item["before"], item["after"]) if allow_partial else (item["after"],)
            if current not in allowed or digest((self.path / item["backup"]).read_bytes()) != item["before"]:
                raise CheckError("Rollback-Konflikt oder beschaedigtes Backup: " + item["path"])
            expected = item["meta"] if current == item["before"] else item.get("after_meta", item["meta"])
            if not same_permissions(metadata(item["path"]), expected):
                raise CheckError("Rollback-Konflikt bei Dateimetadaten: " + item["path"])
        for item in directories:
            now, before = metadata(item["path"]), item["meta"]
            expected = item.get("after", before)
            if (now["dev"], now["ino"]) != (before["dev"], before["ino"]):
                raise CheckError("Rollback-Verzeichnis wurde ersetzt")
            if not allow_partial and any(now[k] != expected[k] for k in ("uid", "gid", "mode", "xattrs")):
                raise CheckError("Rollback-Konflikt bei Verzeichnisrechten")
            if allow_partial and any(now[k] != before[k] for k in ("gid",)):
                raise CheckError("Rollback-Konflikt bei Verzeichnisrechten")
            if allow_partial:
                allowed = {(before["uid"], before["gid"], before["mode"]),
                           (0, before["gid"], before["mode"]),
                           (0, before["gid"], before["mode"] & ~0o022)}
                if (now["uid"], now["gid"], now["mode"]) not in allowed:
                    raise CheckError("Rollback-Konflikt bei begonnenen Verzeichnisrechten")
                if now["xattrs"] != expected["xattrs"]:
                    raise CheckError("Rollback-Konflikt bei Verzeichnis-ACL")
        for item in reversed(directories):
            path, meta = item["path"], item["meta"]
            os.chown(path, meta["uid"], meta["gid"], follow_symlinks=False)
            os.chmod(path, meta["mode"], follow_symlinks=False)
            for key, value in meta["xattrs"].items():
                os.setxattr(path, key, base64.b64decode(value), follow_symlinks=False)
            os.utime(path, ns=(meta["atime_ns"], meta["mtime_ns"]), follow_symlinks=False)
        for item in files:
            atomic_bytes(item["path"], (self.path / item["backup"]).read_bytes(), item["meta"])
        self.data["status"] = "rolled_back"
        self.save()
        print(f"Wiederhergestellt: {self.path}")
        # Restore bytes BEFORE attempting recovery of a failed/stopped FPM.
        # A missing master must never strand an invalid config on disk.
        for item in self.data["instances"] if files else []:
            trusted(item["binary"])
            trusted(item["config"])
            command([item["binary"], "-t", "-y", item["config"]])
            active, _ = command(["systemctl", "show", "--property=MainPID", "--value", item["service"]])
            if active.strip() == "0":
                if not recover_service:
                    raise CheckError("Dateien wiederhergestellt; FPM-Dienst ist gestoppt (kein automatischer Start beim manuellen Rollback)")
                command(["systemctl", "start", item["service"]])
            else:
                command(["systemctl", "reload", item["service"]])
            command(["systemctl", "is-active", "--quiet", item["service"]])

    @classmethod
    def rollback(cls, backup_root, backup_id=None):
        tx = cls(backup_root)
        trusted(tx.root)
        if backup_id is not None and not re.fullmatch(r"\d{8}T\d{6}-[a-f0-9]{10}", backup_id):
            raise CheckError("Ungueltige Backup-ID")
        candidates = [tx.root / backup_id] if backup_id else sorted(tx.root.glob("????????T??????-??????????"), reverse=True)
        for candidate in candidates:
            trusted(candidate / "manifest.json")
            data = json.loads((candidate / "manifest.json").read_text())
            partial = data.get("status") == "prepared" and any(i.get("started") for i in data.get("files", []) + data.get("directories", []))
            if data.get("version") == 1 and (data.get("status") == "applied" or partial):
                tx.path, tx.data = candidate, data
                tx.restore(allow_partial=partial)
                return
        raise CheckError("Kein angewendetes v2-Backup gefunden; alte flache Backups werden nicht geraten")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Begrenzte PHP/FPM-Pruefung; UNKNOWN ist kein bestandenes Ergebnis.")
    mode = parser.add_mutually_exclusive_group()
    for name in ("check", "doctor", "discover", "dry-run", "fix", "rollback"):
        mode.add_argument("--" + name, dest="mode", action="store_const", const=name)
    parser.set_defaults(mode="check")
    parser.add_argument("--root", help="Pruefbereich (Standard: erkannte Webroots)")
    parser.add_argument("--web-user", action="append", default=[])
    parser.add_argument("--site", action="append", default=[], metavar="URL=DOKUMENTWURZEL")
    parser.add_argument("--nginx-config", help="Abweichende Nginx-Hauptkonfiguration")
    parser.add_argument("--no-auto", action="store_true", help="Automatische Webroot-/Domain-Erkennung deaktivieren")
    parser.add_argument("--max-sites", type=int, default=32, help="Maximale automatische HTTP-Zuordnungen (Standard 32)")
    parser.add_argument("--protect-dir", action="append", default=[], help="Explizit root-uebertragen; nicht rekursiv")
    parser.add_argument("--backup-root", default="/root/p2s-harden-backup-v2")
    parser.add_argument("--backup-id")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="Alle Einzelbefunde einschliesslich OK ausgeben")
    parser.add_argument("--no-progress", action="store_true", help="Phasenhinweise im interaktiven Terminal ausblenden")
    parser.add_argument("--progress", action="store_true", help="Phasenhinweise auch ohne TTY auf stderr ausgeben")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    try:
        if args.mode == "doctor":
            report = doctor()
            report.show(args.json, verbose=args.verbose)
            return report.exit_code()
        if sys.platform != "linux" or not Path("/proc/self/stat").is_file():
            raise CheckError("Linux-Ziel mit /proc erforderlich; unter Windows/macOS --ssh root@SERVER verwenden")
        if sys.version_info < (3, 8):
            raise CheckError("Python 3.8+ erforderlich; " + install_hint("python3"))
        if args.root is not None and not Path(args.root).is_absolute():
            raise CheckError("--root muss absolut sein")
        if not 1 <= args.max_sites <= 512:
            raise CheckError("--max-sites muss zwischen 1 und 512 liegen")
        if args.mode == "rollback" and os.geteuid() != 0:
            raise CheckError("Aenderungen erfordern root: sudo bash p2s-harden.sh --fix oder --ssh root@SERVER")
        if args.mode == "rollback":
            Transaction.rollback(args.backup_root, args.backup_id)
            return 0
        stage(args, "Nginx-Zuordnungen und Pruefpfade erkennen")
        prepare_scope(args)
        report, updates, instances, users = scan(args, inventory_only=True) if args.mode == "discover" else scan(args)
        if args.mode in ("dry-run", "fix"):
            if args.json:
                raise CheckError("--json ist bei --check, --doctor und --discover verfuegbar")
            blockers = fix_blockers(updates, args.protect_dir, instances, users)
            for reason in blockers:
                report.add("UNKNOWN", "Fix gesperrt", reason)
            for path, values in updates.items():
                print(f"GEPLANT INI {path}: {','.join(values)}")
            for path in args.protect_dir:
                print(f"GEPLANT VERZEICHNIS {path}: Eigentuemer root, kein g+w/o+w, nicht rekursiv")
            print("Offene HTTP-/ImageMagick-/Runtime-/Speicherpfad-Befunde werden nicht pauschal veraendert.")
            if args.mode == "fix" and not blockers and (updates or args.protect_dir):
                tx = Transaction(args.backup_root)
                tx.prepare(updates, args.protect_dir, instances)
                tx.apply(instances, users)
                report, _, _, _ = scan(args)
        report.show(args.json, verbose=args.verbose)
        return report.exit_code()
    except (OSError, ValueError, KeyError, CheckError) as exc:
        if args.json:
            failure = Report()
            failure.add("UNKNOWN", "Ausfuehrung", str(exc))
            failure.show(True)
        else:
            print(f"FEHLER: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

__P2S_ENGINE_EOF__
