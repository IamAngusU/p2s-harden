"""p2s-harden 2: bounded Linux checks and reversible, explicit changes.

The shell launcher streams this standard-library-only module over one SSH
connection. Importing it has no side effects; check/dry-run create no files.
"""
import argparse
import base64
import contextlib
import datetime
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

VERSION = "2.2.0-rc.2"
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
    report.add("INFO", "HTTP backend", "Python standard library; curl is optional, response bodies are not saved")
    for name, purpose, package in (("runuser", "Dateirechte als fremder FPM-Benutzer", "util-linux"),):
        report.add("OK" if cap["tools"][name] else "UNKNOWN", name,
                   purpose + ": verfuegbar" if cap["tools"][name] else purpose + ": fehlt; " + install_hint(package))
    report.add("OK", "FPM-Prozesserkennung", "ps verfuegbar" if cap["tools"]["ps"] else "ps fehlt; /proc-Fallback wird verwendet (keine Installation noetig)")
    managed = cap["tools"]["systemctl"] and cap["systemd"]
    report.add("OK" if managed else "UNKNOWN", "Automatische INI-Fixes",
               "systemd-Dienstzuordnung kann geprueft werden" if managed else "systemd/systemctl fehlt oder ist nicht aktiv; Audit laeuft, automatische INI-Fixes gesperrt")
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
import json, os, sys, time
root = sys.argv[1]
options = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
runtime = options.get('runtime_dirs', [])
max_paths, max_seconds = options.get('max_paths', 20000), options.get('max_seconds', 10)
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
        raise CheckError(f"Kann UID fuer {user} nicht wechseln")
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
        raise CheckError("HTTP(S)-URL ohne Zugangsdaten erforderlich")
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


def git_endpoints(root, *, max_paths=20000, max_seconds=10, max_endpoints=128):
    """Bounded scandir traversal; includes skipped coverage in the result."""
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
        except OSError:
            issue("Unreadable path: " + str(current))
    return endpoints, issues


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


# The audit keeps canonical findings so tests, fix decisions and stored state do
# not depend on the display language. Translate complete messages only: captured
# paths, URLs, users and function names are opaque and must stay byte-for-byte.
# A {message} capture is the one exception, for a nested diagnostic we own.
_MESSAGES = {
    "Invalid backup manifest: {name}": ("Invalid backup manifest: {name}", "Ungültiges Backup-Manifest: {name}"),
    "verfuegbar": ("available", "verfügbar"),
    "unbekannt": ("unknown", "unbekannt"),
    "Berechtigungen": ("Permissions", "Berechtigungen"),
    "Automatische INI-Fixes": ("Automatic INI fixes", "Automatische INI-Fixes"),
    "FPM-Prozesserkennung": ("FPM process discovery", "FPM-Prozesserkennung"),
    "Automatische Erkennung": ("Automatic discovery", "Automatische Erkennung"),
    "FPM-Abdeckung": ("FPM coverage", "FPM-Abdeckung"),
    "Dateirechte": ("File permissions", "Dateirechte"),
    "FPM-Benutzer": ("FPM user", "FPM-Benutzer"),
    "HTTP-Abdeckung": ("HTTP coverage", "HTTP-Abdeckung"),
    "HTTP-Konfiguration": ("HTTP configuration", "HTTP-Konfiguration"),
    "Git-Pfadabdeckung": ("Git path coverage", "Git-Pfadabdeckung"),
    "ImageMagick-Policy": ("ImageMagick policy", "ImageMagick-Regeln"),
    "Automatischer INI-Fix ausgespart": ("Automatic INI fix skipped", "Automatischer INI-Fix ausgespart"),
    "Fix gesperrt": ("Fix blocked", "Fix gesperrt"),
    "Ausfuehrung": ("Execution", "Ausführung"),
    "Voraussetzungen": ("Prerequisites", "Voraussetzungen"),
    "Bounded PHP/FPM checks; UNKNOWN means an incomplete check.": ("Bounded PHP/FPM checks; UNKNOWN means an incomplete check.", "Begrenzte PHP/FPM-Prüfung; UNKNOWN bedeutet eine unvollständige Prüfung."),
    "Pruefbereich (Standard: erkannte Webroots)": ("Audit scope (default: discovered document roots)", "Prüfbereich (Standard: erkannte Webroots)"),
    "Abweichende Nginx-Hauptkonfiguration": ("Custom Nginx main configuration", "Abweichende Nginx-Hauptkonfiguration"),
    "Automatische Webroot-/Domain-Erkennung deaktivieren": ("Disable automatic document-root/domain discovery", "Automatische Webroot-/Domain-Erkennung deaktivieren"),
    "Maximale automatische HTTP-Zuordnungen (Standard 32)": ("Maximum automatic HTTP mappings (default 32)", "Maximale automatische HTTP-Zuordnungen (Standard 32)"),
    "Maximum entries per filesystem walk (default 20000)": ("Maximum entries per filesystem walk (default 20000)", "Maximale Einträge pro Dateisystem-Suchlauf (Standard 20000)"),
    "Seconds per filesystem walk (default 10)": ("Seconds per filesystem walk (default 10)", "Sekunden pro Dateisystem-Suchlauf (Standard 10)"),
    "Total HTTP request budget (default 128)": ("Total HTTP request budget (default 128)", "Gesamtlimit für HTTP-Anfragen (Standard 128)"),
    "Declare writable runtime storage inside selected roots; repeatable": ("Declare writable runtime storage inside selected roots; repeatable", "Schreibbaren Laufzeitspeicher innerhalb der ausgewählten Wurzeln deklarieren; wiederholbar"),
    "Explizit root-uebertragen; nicht rekursiv": ("Transfer explicit directory ownership to root; non-recursive", "Explizites Verzeichnis an root übertragen; nicht rekursiv"),
    "Alle Einzelbefunde einschliesslich OK ausgeben": ("Show all findings, including OK", "Alle Einzelbefunde einschließlich OK ausgeben"),
    "Phasenhinweise im interaktiven Terminal ausblenden": ("Hide interactive progress messages", "Phasenhinweise im interaktiven Terminal ausblenden"),
    "Phasenhinweise auch ohne TTY auf stderr ausgeben": ("Write progress to stderr even without a TTY", "Phasenhinweise auch ohne TTY auf stderr ausgeben"),
    "--max-paths must be between 1 and 1000000": ("--max-paths must be between 1 and 1000000", "--max-paths muss zwischen 1 und 1000000 liegen"),
    "--walk-seconds must be between 0.05 and 120": ("--walk-seconds must be between 0.05 and 120", "--walk-seconds muss zwischen 0.05 und 120 liegen"),
    "--max-http-probes must be between 1 and 4096": ("--max-http-probes must be between 1 and 4096", "--max-http-probes muss zwischen 1 und 4096 liegen"),
    "Latest transaction already restored; no changes made": ("Latest transaction already restored; no changes made", "Neueste Transaktion bereits wiederhergestellt; keine Änderungen vorgenommen"),
    "Selected transaction restored": ("Selected transaction restored", "Ausgewählte Transaktion wiederhergestellt"),
    "Incomplete HTTP response": ("Incomplete HTTP response", "Unvollständige HTTP-Antwort"),
    "HTTP backend": ("HTTP backend", "HTTP-Verbindung"),
    "HTTP coverage": ("HTTP coverage", "HTTP-Abdeckung"),
    "ImageMagick policy": ("ImageMagick policy", "ImageMagick-Regeln"),
    "Python standard library; curl is optional, response bodies are not saved": ("Python standard library; curl is optional, response bodies are not saved", "Python-Standardbibliothek; curl ist optional, Antwortinhalte werden nicht gespeichert"),
    "Invalid HTTP status": ("Invalid HTTP status", "Ungültiger HTTP-Status"),
    "HTTP response time budget exceeded": ("HTTP response time budget exceeded", "Zeitlimit für HTTP-Antwort überschritten"),
    "HTTP response byte budget exceeded": ("HTTP response byte budget exceeded", "Größenlimit für HTTP-Antwort überschritten"),
    "HTTP probe budget reached; use --max-http-probes or narrow --site": ("HTTP probe budget reached; use --max-http-probes or narrow --site", "HTTP-Anfragelimit erreicht; --max-http-probes anpassen oder --site eingrenzen"),
    "Git discovery budget reached; use --max-paths/--walk-seconds or narrow --root": ("Git discovery budget reached; use --max-paths/--walk-seconds or narrow --root", "Limit der Git-Pfadsuche erreicht; --max-paths/--walk-seconds anpassen oder --root eingrenzen"),
    "Git endpoint budget reached; narrow --root": ("Git endpoint budget reached; narrow --root", "Limit der Git-Endpunkte erreicht; --root eingrenzen"),
    "Filesystem time budget reached; use --walk-seconds or narrow --root": ("Filesystem time budget reached; use --walk-seconds or narrow --root", "Zeitlimit der Dateisystemsuche erreicht; --walk-seconds anpassen oder --root eingrenzen"),
    "Filesystem discovery budget reached; use --max-paths/--walk-seconds or narrow --root": ("Filesystem discovery budget reached; use --max-paths/--walk-seconds or narrow --root", "Limit der Dateisystemsuche erreicht; --max-paths/--walk-seconds anpassen oder --root eingrenzen"),
    "Not assessed automatically; review rules and delegates separately": ("Not assessed automatically; review rules and delegates separately", "Nicht automatisch bewertet; Regeln und Delegates gesondert prüfen"),
    "Kein v2-Backup gefunden; alte flache Backups werden nicht geraten": ("No v2 backup found; legacy flat backups are never guessed", "Kein v2-Backup gefunden; alte flache Backups werden nicht geraten"),
    "Rollback-Konflikt bei Verzeichnisrechten oder Zeitstempel": ("Rollback conflict in directory permissions or timestamps", "Rollback-Konflikt bei Verzeichnisrechten oder Zeitstempel"),
    "Mehrere Backups in derselben Sekunde; eindeutige Auswahl mit --backup-id erforderlich": ("Multiple backups in the same second; select one explicitly with --backup-id", "Mehrere Backups in derselben Sekunde; eindeutige Auswahl mit --backup-id erforderlich"),
    "Erkanntes Inventar": ("Discovered inventory", "Erkanntes Inventar"),
    "Konfigurationspruefung": ("Configuration audit", "Konfigurationsprüfung"),
    "Linux-Ziel mit lesbarem /proc erforderlich; von Windows/macOS --ssh verwenden": ("A Linux target with readable /proc is required; use --ssh from Windows/macOS", "Linux-Ziel mit lesbarem /proc erforderlich; von Windows/macOS --ssh verwenden"),
    "root: volle Host-Pruefung moeglich": ("root: full host audit available", "root: vollständige Host-Prüfung möglich"),
    "Lesbare Teilpruefungen laufen; fuer fremde FPM-Benutzer und Fixes sudo/root verwenden": ("Readable checks continue; use sudo/root to check other FPM users and apply fixes", "Lesbare Teilprüfungen laufen; für fremde FPM-Benutzer und Fixes sudo/root verwenden"),
    "ps verfuegbar": ("ps available", "ps verfügbar"),
    "ps fehlt; /proc-Fallback wird verwendet (keine Installation noetig)": ("ps missing; using the /proc fallback (no installation needed)", "ps fehlt; /proc-Fallback wird verwendet (keine Installation nötig)"),
    "systemd-Dienstzuordnung kann geprueft werden": ("The systemd service mapping can be verified", "systemd-Dienstzuordnung kann geprüft werden"),
    "systemd/systemctl fehlt oder ist nicht aktiv; Audit laeuft, automatische INI-Fixes gesperrt": ("systemd/systemctl is missing or inactive; the audit continues, automatic INI fixes are blocked", "systemd/systemctl fehlt oder ist nicht aktiv; Audit läuft, automatische INI-Fixes gesperrt"),
    "FPM-Erkennung: /proc nicht lesbar; andere Module laufen weiter": ("FPM discovery: /proc is unreadable; other checks continue", "FPM-Erkennung: /proc nicht lesbar; andere Module laufen weiter"),
    "FPM-Prozesserkennung teilweise ohne Leserecht; sudo/root verwenden": ("Some FPM processes cannot be read; use sudo/root", "FPM-Prozesserkennung teilweise ohne Leserecht; sudo/root verwenden"),
    "FPM-Pool-Dump nicht auswertbar": ("Cannot parse the FPM pool dump", "FPM-Pool-Dump nicht auswertbar"),
    "Bedingte PATH/HOST-INI: automatische Aenderung abgelehnt": ("Conditional PATH/HOST INI sections: automatic changes refused", "Bedingte PATH/HOST-INI: automatische Änderung abgelehnt"),
    "Abweichender INI-Kontext: separate Laufzeitpruefung erforderlich": ("Custom INI context: a separate runtime check is required", "Abweichender INI-Kontext: separate Laufzeitprüfung erforderlich"),
    "INI-Kontext weicht vom erwarteten FPM-Kontext ab": ("INI context differs from the expected FPM context", "INI-Kontext weicht vom erwarteten FPM-Kontext ab"),
    "INI-Scan-Verzeichnis weicht vom erwarteten FPM-Kontext ab": ("INI scan directory differs from the expected FPM context", "INI-Scan-Verzeichnis weicht vom erwarteten FPM-Kontext ab"),
    "Kein laufender FPM-Master gefunden": ("No running FPM master found", "Kein laufender FPM-Master gefunden"),
    "Relativer FPM-Include erfordert manuelle Kontextpruefung": ("A relative FPM include requires a manual context check", "Relativer FPM-Include erfordert manuelle Kontextprüfung"),
    "HTTP(S)-URL ohne Zugangsdaten erforderlich": ("An HTTP(S) URL without credentials is required", "HTTP(S)-URL ohne Zugangsdaten erforderlich"),
    "Kein gueltiger HTTP-Status": ("No valid HTTP status received", "Kein gültiger HTTP-Status"),
    "Nginx: unvollstaendiges Escape": ("Nginx: incomplete escape sequence", "Nginx: unvollständiges Escape"),
    "Nginx: unvollstaendige Variable": ("Nginx: incomplete variable", "Nginx: unvollständige Variable"),
    "Nginx: Tokenlimit erreicht": ("Nginx: token limit reached", "Nginx: Tokenlimit erreicht"),
    "Nginx: nicht abgeschlossene Zeichenkette": ("Nginx: unterminated string", "Nginx: nicht abgeschlossene Zeichenkette"),
    "Nginx: Verschachtelungslimit erreicht": ("Nginx: nesting limit reached", "Nginx: Verschachtelungslimit erreicht"),
    "Nginx: unerwartetes Blockende": ("Nginx: unexpected block end", "Nginx: unerwartetes Blockende"),
    "Nginx: fehlendes Blockende": ("Nginx: missing block end", "Nginx: fehlendes Blockende"),
    "Nginx: Konfigurationsdatei zu gross oder kein regulaerer Dateityp": ("Nginx: configuration file too large or not a regular file", "Nginx: Konfigurationsdatei zu groß oder kein regulärer Dateityp"),
    "Nginx: Leselimit erreicht": ("Nginx: read limit reached", "Nginx: Leselimit erreicht"),
    "Nginx: dynamischer oder ungueltiger Include": ("Nginx: dynamic or invalid include", "Nginx: dynamischer oder ungültiger Include"),
    "Nginx: Expansionslimit erreicht": ("Nginx: expansion limit reached", "Nginx: Expansionslimit erreicht"),
    "Keine eindeutige Nginx-Hauptkonfiguration; --nginx-config oder --site/--root angeben": ("No unique Nginx main configuration; specify --nginx-config or --site/--root", "Keine eindeutige Nginx-Hauptkonfiguration; --nginx-config oder --site/--root angeben"),
    "Kein eindeutiger Webroot; /var/www dient nur als ausgewiesener Dateisystem-Fallback": ("No unique document root; /var/www is only an explicitly reported filesystem fallback", "Kein eindeutiger Webroot; /var/www dient nur als ausgewiesener Dateisystem-Fallback"),
    "Keine Rechteziele aus Erkennung abgeleitet": ("No permission-change targets inferred from discovery", "Keine Rechteziele aus Erkennung abgeleitet"),
    "Wert fehlt": ("Value missing", "Wert fehlt"),
    "7 definierte Shell-Funktionen gesperrt": ("The 7 selected shell functions are disabled", "7 definierte Shell-Funktionen gesperrt"),
    "globale + Pool-Sperren zusammen ausgewertet": ("Global and pool restrictions evaluated together", "Globale und Pool-Sperren zusammen ausgewertet"),
    "nicht einschraenkend": ("Unrestricted", "Nicht einschränkend"),
    "Widerspruechliche INI-Werte mehrerer Instanzen": ("Conflicting INI values across FPM instances", "Widersprüchliche INI-Werte mehrerer Instanzen"),
    "Kein gepruefter FPM-Benutzer; --web-user erforderlich": ("No verified FPM user; specify --web-user", "Kein geprüfter FPM-Benutzer; --web-user erforderlich"),
    "Fremde UID nicht pruefbar; sudo/root verwenden. Andere Module laufen weiter.": ("Cannot check another UID; use sudo/root. Other checks continue.", "Fremde UID nicht prüfbar; sudo/root verwenden. Andere Module laufen weiter."),
    "Benutzer existiert nicht auf diesem Host; --web-user korrigieren oder Container separat pruefen": ("User does not exist on this host; correct --web-user or audit the container separately", "Benutzer existiert nicht auf diesem Host; --web-user korrigieren oder Container separat prüfen"),
    "Keine --site URL=DOKUMENTWURZEL angegeben": ("No --site URL=DOCUMENT_ROOT specified", "Keine --site URL=DOKUMENTWURZEL angegeben"),
    "--site benoetigt HTTP(S)-Basis-URL ohne Query, Fragment oder Zugangsdaten": ("--site requires an HTTP(S) base URL without query, fragment or credentials", "--site benötigt HTTP(S)-Basis-URL ohne Query, Fragment oder Zugangsdaten"),
    "Dokumentwurzel fehlt oder ist relativ": ("Document root is missing or relative", "Dokumentwurzel fehlt oder ist relativ"),
    "nicht lesbar": ("Unreadable", "Nicht lesbar"),
    "keine bekannte Policy; Modul-/Container-Abdeckung offen": ("No known policy found; module/container coverage remains unverified", "Keine bekannte Policy; Modul-/Container-Abdeckung offen"),
    "FPM-Master hat gewechselt; Reload abgebrochen": ("FPM master changed; reload cancelled", "FPM-Master hat gewechselt; Reload abgebrochen"),
    "Dienst und FPM-Master stimmen nicht ueberein": ("Service and FPM master do not match", "Dienst und FPM-Master stimmen nicht überein"),
    "FPM-Master und Dienst stimmen nicht mehr ueberein": ("FPM master and service no longer match", "FPM-Master und Dienst stimmen nicht mehr überein"),
    "Aenderungen erfordern root; sudo oder --ssh root@SERVER verwenden": ("Changes require root; use sudo or --ssh root@SERVER", "Änderungen erfordern root; sudo oder --ssh root@SERVER verwenden"),
    "Keine vollstaendige FPM-Zuordnung fuer alle INI-Aenderungen": ("Not all INI changes have a complete FPM mapping", "Keine vollständige FPM-Zuordnung für alle INI-Änderungen"),
    "Kein gepruefter systemd-Reload fuer alle betroffenen FPM-Instanzen; INI-Fixes gesperrt, Audit weiterhin moeglich": ("A verified systemd reload is unavailable for some affected FPM instances; INI fixes are blocked, the audit continues", "Kein geprüfter systemd-Reload für alle betroffenen FPM-Instanzen; INI-Fixes gesperrt, Audit weiterhin möglich"),
    "--protect-dir erfordert einen erkannten oder expliziten --web-user zur Verifikation": ("--protect-dir requires a discovered or explicit --web-user for verification", "--protect-dir erfordert einen erkannten oder expliziten --web-user zur Verifikation"),
    "Aenderungen und Rollback erfordern root": ("Changes and rollback require root", "Änderungen und Rollback erfordern root"),
    "Backup-Verzeichnis muss absolut sein": ("Backup directory must be absolute", "Backup-Verzeichnis muss absolut sein"),
    "Backup-Verzeichnis muss Modus 0700 haben": ("Backup directory must have mode 0700", "Backup-Verzeichnis muss Modus 0700 haben"),
    "Kein gepruefter FPM-Dienst fuer INI-Aenderungen": ("No verified FPM service for INI changes", "Kein geprüfter FPM-Dienst für INI-Änderungen"),
    "--protect-dir braucht ein bestehendes absolutes Verzeichnis": ("--protect-dir requires an existing absolute directory", "--protect-dir braucht ein bestehendes absolutes Verzeichnis"),
    "Symlink in --protect-dir abgelehnt": ("Symlink in --protect-dir refused", "Symlink in --protect-dir abgelehnt"),
    "Konfiguration wurde zwischenzeitlich geaendert": ("Configuration changed since preflight", "Konfiguration wurde zwischenzeitlich geändert"),
    "Verzeichnis wurde zwischenzeitlich geaendert": ("Directory changed since preflight", "Verzeichnis wurde zwischenzeitlich geändert"),
    "Verzeichnisidentitaet hat gewechselt": ("Directory identity changed", "Verzeichnisidentität hat gewechselt"),
    "Erwartete PHP-Einstellungen greifen nicht": ("Expected PHP settings did not take effect", "Erwartete PHP-Einstellungen greifen nicht"),
    "Rollback-Verzeichnis wurde ersetzt": ("Rollback directory was replaced", "Rollback-Verzeichnis wurde ersetzt"),
    "Rollback-Konflikt bei Verzeichnisrechten": ("Rollback conflict in directory permissions", "Rollback-Konflikt bei Verzeichnisrechten"),
    "Rollback-Konflikt bei begonnenen Verzeichnisrechten": ("Rollback conflict in partially changed directory permissions", "Rollback-Konflikt bei begonnenen Verzeichnisrechten"),
    "Rollback-Konflikt bei Verzeichnis-ACL": ("Rollback conflict in directory ACL", "Rollback-Konflikt bei Verzeichnis-ACL"),
    "Dateien wiederhergestellt; FPM-Dienst ist gestoppt (kein automatischer Start beim manuellen Rollback)": ("Files restored; FPM service is stopped (manual rollback never starts a service automatically)", "Dateien wiederhergestellt; FPM-Dienst ist gestoppt (kein automatischer Start beim manuellen Rollback)"),
    "Ungueltige Backup-ID": ("Invalid backup ID", "Ungültige Backup-ID"),
    "Kein angewendetes v2-Backup gefunden; alte flache Backups werden nicht geraten": ("No applied v2 backup found; legacy flat backups are never guessed", "Kein angewendetes v2-Backup gefunden; alte flache Backups werden nicht geraten"),
    "Linux-Ziel mit /proc erforderlich; unter Windows/macOS --ssh root@SERVER verwenden": ("A Linux target with /proc is required; use --ssh root@SERVER from Windows/macOS", "Linux-Ziel mit /proc erforderlich; unter Windows/macOS --ssh root@SERVER verwenden"),
    "--root muss absolut sein": ("--root must be absolute", "--root muss absolut sein"),
    "--max-sites muss zwischen 1 und 512 liegen": ("--max-sites must be between 1 and 512", "--max-sites muss zwischen 1 und 512 liegen"),
    "Aenderungen erfordern root: sudo bash p2s-harden.sh --fix oder --ssh root@SERVER": ("Changes require root: sudo bash p2s-harden.sh --fix or --ssh root@SERVER", "Änderungen erfordern root: sudo bash p2s-harden.sh --fix oder --ssh root@SERVER"),
    "--json ist bei --check, --doctor und --discover verfuegbar": ("--json supports --check, --doctor and --discover; omit --json for this mode", "--json unterstützt --check, --doctor und --discover; für diesen Modus --json weglassen"),
    "Offene HTTP-/ImageMagick-/Runtime-/Speicherpfad-Befunde werden nicht pauschal veraendert.": ("HTTP, ImageMagick, runtime and writable-storage findings require individual review; they are not changed automatically.", "Offene HTTP-/ImageMagick-/Laufzeit-/Speicherpfad-Befunde werden nicht pauschal verändert."),
    "Nginx-Zuordnungen und Pruefpfade erkennen": ("Discovering Nginx mappings and audit paths", "Nginx-Zuordnungen und Prüfpfade erkennen"),
    "FPM-Instanzen und Pools erkennen": ("Discovering FPM instances and pools", "FPM-Instanzen und Pools erkennen"),
    "Dateirechte unter den erkannten FPM-Benutzern pruefen": ("Checking file permissions as the discovered FPM users", "Dateirechte unter den erkannten FPM-Benutzern prüfen"),
    "HTTP-Endpunkte und weitere Host-Einstellungen pruefen": ("Checking HTTP endpoints and other host settings", "HTTP-Endpunkte und weitere Host-Einstellungen prüfen"),
}

_MESSAGE_TEMPLATES = (
    ("Additional skipped paths: {count}", "Additional skipped paths: {count}", "Weitere ausgelassene Pfade: {count}"),
    ("HTTP request failed: {kind}", "HTTP request failed: {kind}", "HTTP-Anfrage fehlgeschlagen: {kind}"),
    ("{code}; unexpected HTTP status", "{code}; unexpected HTTP status", "{code}; unerwarteter HTTP-Status"),
    ("{code}; missing-path baseline unavailable", "{code}; missing-path baseline unavailable", "{code}; Vergleich mit einem fehlenden Pfad nicht verfügbar"),
    ("{code}; possible file access; missing paths were rejected", "{code}; possible file access; missing paths were rejected", "{code}; möglicher Dateizugriff; fehlende Pfade wurden abgewiesen"),
    ("{code}; ambiguous missing-path baseline", "{code}; ambiguous missing-path baseline", "{code}; Vergleich mit fehlenden Pfaden ist uneindeutig"),
    ("{code}; dynamic soft-404 fallback; file exposure not established", "{code}; dynamic soft-404 fallback; file exposure not established", "{code}; dynamischer Soft-404-Fallback; Dateizugriff nicht nachgewiesen"),
    ("{code}; matches soft-404 fallback; file exposure not established", "{code}; matches soft-404 fallback; file exposure not established", "{code}; entspricht Soft-404-Fallback; Dateizugriff nicht nachgewiesen"),
    ("{code}; response differs from missing-path fallback; possible file access", "{code}; response differs from missing-path fallback; possible file access", "{code}; Antwort weicht vom Fallback für fehlende Pfade ab; möglicher Dateizugriff"),
    ("Different filesystem skipped: {path}", "Different filesystem skipped: {path}", "Anderes Dateisystem ausgelassen: {path}"),
    ("Symlink skipped: {path}", "Symlink skipped: {path}", "Symlink ausgelassen: {path}"),
    ("Unreadable path: {path}", "Unreadable path: {path}", "Nicht lesbarer Pfad: {path}"),
    ("Runtime directory must be an existing absolute path without symlinks: {path}", "Runtime directory must be an existing absolute path without symlinks: {path}", "Laufzeitverzeichnis muss ein bestehender absoluter Pfad ohne Symlinks sein: {path}"),
    ("Runtime directory must be a strict subdirectory of the selected roots: {path}", "Runtime directory must be a strict subdirectory of the selected roots: {path}", "Laufzeitverzeichnis muss ein echtes Unterverzeichnis der ausgewählten Wurzeln sein: {path}"),
    ("Declared runtime storage ({user})", "Declared runtime storage ({user})", "Deklarierter Laufzeitspeicher ({user})"),
    ("{count} writable directories; PHP files remain checked; execution restrictions require separate verification; {paths}", "{count} writable directories; PHP files remain checked; execution restrictions require separate verification; {paths}", "{count} schreibbare Verzeichnisse; PHP-Dateien werden weiter geprüft; Ausführungsbeschränkungen erfordern eine gesonderte Prüfung; {paths}"),
    ("Not assessed automatically; review rules and delegates separately; {paths}", "Not assessed automatically; review rules and delegates separately; {paths}", "Nicht automatisch bewertet; Regeln und Delegates gesondert prüfen; {paths}"),
    ("Rollback-Konflikt bei Inhalt, Dateimetadaten oder Zeitstempel: {path}", "Rollback conflict in content, file metadata or timestamps: {path}", "Rollback-Konflikt bei Inhalt, Dateimetadaten oder Zeitstempel: {path}"),
    ("Neueste Transaktion ist unbekannt; gezielte Auswahl mit --backup-id erforderlich: {path}", "Latest transaction is unknown; select one explicitly with --backup-id: {path}", "Neueste Transaktion ist unbekannt; gezielte Auswahl mit --backup-id erforderlich: {path}"),
    ("Keine weiteren Aenderungen: {path} ({status}); aelteres Backup nur mit --backup-id auswaehlen", "No further changes: {path} ({status}); select an older backup explicitly with --backup-id", "Keine weiteren Änderungen: {path} ({status}); älteres Backup nur mit --backup-id auswählen"),
    ("Bei Bedarf installieren: {command}", "Install if needed: {command}", "Bei Bedarf installieren: {command}"),
    ("Bei Bedarf Paket '{package}' mit dem Paketmanager bereitstellen", "Install package '{package}' with your package manager if needed", "Bei Bedarf Paket '{package}' mit dem Paketmanager bereitstellen"),
    ("{version}; mindestens 3.8 erforderlich", "{version}; version 3.8 or later required", "{version}; mindestens 3.8 erforderlich"),
    ("HTTP-Statuspruefungen: verfuegbar", "HTTP status checks: available", "HTTP-Statusprüfungen: verfügbar"),
    ("Dateirechte als fremder FPM-Benutzer: verfuegbar", "File permission checks as another FPM user: available", "Dateirechte als fremder FPM-Benutzer: verfügbar"),
    ("HTTP-Statuspruefungen: fehlt; {message}", "HTTP status checks: missing; {message}", "HTTP-Statusprüfungen: fehlt; {message}"),
    ("Dateirechte als fremder FPM-Benutzer: fehlt; {message}", "File permission checks as another FPM user: missing; {message}", "Dateirechte als fremder FPM-Benutzer: fehlt; {message}"),
    ("{program} nicht ausfuehrbar: {kind}", "Cannot execute {program}: {kind}", "{program} nicht ausführbar: {kind}"),
    ("{program} fehlgeschlagen (Exit {code})", "{program} failed (exit {code})", "{program} fehlgeschlagen (Exit {code})"),
    ("Absoluter Pfad erforderlich: {path}", "Absolute path required: {path}", "Absoluter Pfad erforderlich: {path}"),
    ("Nicht vertrauenswuerdiger Root-Pfad: {path}", "Untrusted path or ancestor: {path}", "Nicht vertrauenswürdiger Root-Pfad: {path}"),
    ("ACL nicht lesbar: {path}", "Cannot read ACL: {path}", "ACL nicht lesbar: {path}"),
    ("FPM PID {pid}: Container/anderer Dateisystem-Namensraum", "FPM PID {pid}: container or different filesystem namespace", "FPM PID {pid}: Container/anderer Dateisystem-Namensraum"),
    ("FPM PID {pid}: haengender INI-Verweis {path}", "FPM PID {pid}: dangling INI reference {path}", "FPM PID {pid}: hängender INI-Verweis {path}"),
    ("FPM PID {pid}: {message}", "FPM PID {pid}: {message}", "FPM PID {pid}: {message}"),
    ("FPM-Include ohne lesbares Ziel: {path}", "FPM include has no readable target: {path}", "FPM-Include ohne lesbares Ziel: {path}"),
    ("Kann UID fuer {user} nicht wechseln", "Cannot switch UID for {user}", "Kann UID für {user} nicht wechseln"),
    ("Nginx: unvollstaendige Direktive ({source})", "Nginx: incomplete directive ({source})", "Nginx: unvollständige Direktive ({source})"),
    ("Nginx: unerwartetes Trennzeichen ({source})", "Nginx: unexpected delimiter ({source})", "Nginx: unerwartetes Trennzeichen ({source})"),
    ("Nginx-Konfiguration ist nicht rootgeschuetzt: {path}", "Nginx configuration is not protected by root ownership: {path}", "Nginx-Konfiguration ist nicht rootgeschützt: {path}"),
    ("Nginx: Include-Zyklus bei {path}", "Nginx: include cycle at {path}", "Nginx: Include-Zyklus bei {path}"),
    ("Nginx-Include fehlt: {path}", "Nginx include missing: {path}", "Nginx-Include fehlt: {path}"),
    ("{source}: dynamischer oder relativer Dokumentpfad", "{source}: dynamic or relative document path", "{source}: dynamischer oder relativer Dokumentpfad"),
    ("{source}: Dokumentpfad fehlt: {path}", "{source}: document path missing: {path}", "{source}: Dokumentpfad fehlt: {path}"),
    ("{source}: Systempfad wird nicht automatisch durchsucht: {path}", "{source}: system path excluded from automatic scanning: {path}", "{source}: Systempfad wird nicht automatisch durchsucht: {path}"),
    ("{source}: Dokumentpfad enthaelt Symlinks: {path}", "{source}: document path contains symlinks: {path}", "{source}: Dokumentpfad enthält Symlinks: {path}"),
    ("{source}: Server mit unvollstaendigen Includes wird nicht automatisch per HTTP zugeordnet", "{source}: server with unresolved includes excluded from automatic HTTP mapping", "{source}: Server mit unvollständigen Includes wird nicht automatisch per HTTP zugeordnet"),
    ("{source}: Wildcard/Regex/Default-Hostname braucht eine explizite --site-Angabe", "{source}: wildcard, regex or default hostname requires an explicit --site", "{source}: Wildcard/Regex/Default-Hostname braucht eine explizite --site-Angabe"),
    ("{source}: Unix-/UDP-Listener wird nicht per HTTP geprueft", "{source}: Unix/UDP listener excluded from HTTP checks", "{source}: Unix-/UDP-Listener wird nicht per HTTP geprüft"),
    ("{source}: spezifischer Listener erfordert manuelle lokale Zuordnung", "{source}: a specific listener requires an explicit local mapping", "{source}: spezifischer Listener erfordert manuelle lokale Zuordnung"),
    ("{source}: ungueltiger Listener-Port", "{source}: invalid listener port", "{source}: ungültiger Listener-Port"),
    ("{source}: bedingter Dokumentpfad ist nicht eindeutig", "{source}: conditional document path is ambiguous", "{source}: bedingter Dokumentpfad ist nicht eindeutig"),
    ("{source}: Regex-/dynamischer Location-Pfad braucht manuelle Zuordnung", "{source}: regex or dynamic location path requires an explicit mapping", "{source}: Regex-/dynamischer Location-Pfad braucht manuelle Zuordnung"),
    ("{source}: Redirect ohne Dokumentwurzel wird nicht als Dateipruefung gewertet", "{source}: redirect without a document root does not count as a file check", "{source}: Redirect ohne Dokumentwurzel wird nicht als Dateiprüfung gewertet"),
    ("{source}: Proxy/fehlende Dokumentwurzel benoetigt eigene Backend-Pruefung", "{source}: proxy or missing document root requires a separate backend audit", "{source}: Proxy/fehlende Dokumentwurzel benötigt eigene Backend-Prüfung"),
    ("Mehrdeutige Dokumentwurzel fuer {url}; automatische HTTP-Pruefung ausgespart", "Ambiguous document root for {url}; automatic HTTP check skipped", "Mehrdeutige Dokumentwurzel für {url}; automatische HTTP-Prüfung ausgespart"),
    ("Automatische Nginx-Erkennung unvollstaendig: {message}", "Automatic Nginx discovery incomplete: {message}", "Automatische Nginx-Erkennung unvollständig: {message}"),
    ("HTTP-Limit: {count} Zuordnungen ausgelassen; --max-sites erhoehen oder --site eingrenzen", "HTTP limit: {count} mappings omitted; increase --max-sites or narrow the scope with --site", "HTTP-Limit: {count} Zuordnungen ausgelassen; --max-sites erhöhen oder --site eingrenzen"),
    ("fehlt: {functions}", "Missing: {functions}", "Fehlt: {functions}"),
    ("{value}; Pool-Override manuell korrigieren", "{value}; correct the pool override manually", "{value}; Pool-Override manuell korrigieren"),
    ("{value} (zusaetzliche Schranke, keine Sandbox)", "{value} (an additional restriction, not a sandbox)", "{value} (zusätzliche Schranke, keine Sandbox)"),
    ("{key}: geteilte Datei ausserhalb der FPM-INI-Wurzel: {path}", "{key}: shared file outside the FPM INI root: {path}", "{key}: geteilte Datei außerhalb der FPM-INI-Wurzel: {path}"),
    ("FPM-Konfiguration {path}", "FPM configuration {path}", "FPM-Konfiguration {path}"),
    ("{user} hat UID 0", "{user} has UID 0", "{user} hat UID 0"),
    ("Dateirechte ({user})", "File permissions ({user})", "Dateirechte ({user})"),
    ("schreibbare PHP-Dateien ({user})", "Writable PHP files ({user})", "Schreibbare PHP-Dateien ({user})"),
    ("schreibbare Verzeichnisse ({user})", "Writable directories ({user})", "Schreibbare Verzeichnisse ({user})"),
    ("Dateisystem-Abdeckung ({user})", "Filesystem coverage ({user})", "Dateisystem-Abdeckung ({user})"),
    ("runuser fehlt; {message}. Andere Module laufen weiter.", "runuser missing; {message}. Other checks continue.", "runuser fehlt; {message}. Andere Module laufen weiter."),
    ("{count} unlesbare/ausgelassene Pfade; {message}", "{count} unreadable or skipped paths; {message}", "{count} unlesbare/ausgelassene Pfade; {message}"),
    ("curl fehlt; HTTP-Pruefungen ausgelassen. {message}. Dateisystem-/FPM-Pruefungen laufen weiter.", "curl missing; HTTP checks skipped. {message}. Filesystem and FPM checks continue.", "curl fehlt; HTTP-Prüfungen ausgelassen. {message}. Dateisystem-/FPM-Prüfungen laufen weiter."),
    ("{code}; moeglicher Dateizugriff, Inhalt nicht bewertet", "{code}; possible file exposure, content not evaluated", "{code}; möglicher Dateizugriff, Inhalt nicht bewertet"),
    ("regel- und versionsbezogene manuelle Pruefung erforderlich; {paths}", "Manual review of rules and versions required; {paths}", "Regel- und versionsbezogene manuelle Prüfung erforderlich; {paths}"),
    ("Symlink als Aenderungsziel abgelehnt: {path}", "Symlink refused as a change target: {path}", "Symlink als Änderungsziel abgelehnt: {path}"),
    ("Reload-Vorpruefung {service}: {message}", "Reload preflight {service}: {message}", "Reload-Vorprüfung {service}: {message}"),
    ("Rechteschutz gegen UID 0 ist nicht moeglich: {user}", "Cannot restrict UID 0 with file permissions: {user}", "Rechteschutz gegen UID 0 ist nicht möglich: {user}"),
    ("Rechteverifikation fuer {user}: runuser fehlt; {message}", "Permission verification for {user}: runuser missing; {message}", "Rechteverifikation für {user}: runuser fehlt; {message}"),
    ("Rechteverifikation: unbekannter Benutzer {user}", "Permission verification: unknown user {user}", "Rechteverifikation: unbekannter Benutzer {user}"),
    ("{path} bleibt fuer {user} schreibbar", "{path} remains writable by {user}", "{path} bleibt für {user} schreibbar"),
    ("Rollback-Konflikt oder beschaedigtes Backup: {path}", "Rollback conflict or damaged backup: {path}", "Rollback-Konflikt oder beschädigtes Backup: {path}"),
    ("Rollback-Konflikt bei Dateimetadaten: {path}", "Rollback conflict in file metadata: {path}", "Rollback-Konflikt bei Dateimetadaten: {path}"),
    ("Wiederhergestellt: {path}", "Restored: {path}", "Wiederhergestellt: {path}"),
    ("Python 3.8+ erforderlich; {message}", "Python 3.8 or later required; {message}", "Python 3.8+ erforderlich; {message}"),
    ("GEPLANT INI {path}: {keys}", "PLANNED INI {path}: {keys}", "GEPLANT INI {path}: {keys}"),
    ("GEPLANT VERZEICHNIS {path}: Eigentuemer root, kein g+w/o+w, nicht rekursiv", "PLANNED DIRECTORY {path}: owner root, no g+w/o+w, non-recursive", "GEPLANT VERZEICHNIS {path}: Eigentümer root, kein g+w/o+w, nicht rekursiv"),
    ("FEHLER: {message}", "ERROR: {message}", "FEHLER: {message}"),
)


def _compile_message(template):
    import string
    parts, names = [], []
    for literal, name, _, _ in string.Formatter().parse(template):
        parts.append(re.escape(literal))
        if name is not None:
            names.append(name)
            parts.append("(.*?)")
    return re.compile("".join(parts), re.S), names


_ENGLISH_MESSAGES = {en: (en, de) for en, de in _MESSAGES.values()}
_COMPILED_MESSAGES = [(*_compile_message(source), en, de)
                      for source, en, de in _MESSAGE_TEMPLATES]
_COMPILED_MESSAGES.extend((*_compile_message(en), en, de)
                          for source, en, de in _MESSAGE_TEMPLATES if source != en)


def localize(message, lang="en"):
    """Translate a diagnostic, preserving every captured technical value."""
    if lang not in ("en", "de"):
        raise ValueError("Unsupported language; choose en or de")
    if message in _MESSAGES:
        return _MESSAGES[message][lang == "de"]
    if message in _ENGLISH_MESSAGES:
        return _ENGLISH_MESSAGES[message][lang == "de"]
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

    def show(self, as_json=False, verbose=False, lang="en"):
        rows = [dict(row, title=localize(row["title"], lang),
                     detail=localize(row["detail"], lang)) for row in self.rows]
        discovery = localized_discovery(self.discovery, lang)
        if as_json:
            print(json.dumps(dict(schema_version=1, version=VERSION, language=lang, findings=rows,
                                  discovery=discovery, plan=getattr(self, "plan", None),
                                  transaction=getattr(self, "transaction", None),
                                  exit_code=self.exit_code()), ensure_ascii=False, indent=2))
            return
        def emit(line):
            # Configured names/paths must not inject terminal escape sequences.
            print("".join(c if c.isprintable() else "?" for c in line))
        label = "Voraussetzungen" if discovery.get("doctor") else "Erkanntes Inventar" if discovery.get("inventory_only") else "Konfigurationspruefung"
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
        if not verbose and len(shown) > 40:
            emit(f"Weitere {len(shown) - 40} Befunde: --verbose oder --json zeigt alle Details." if lang == "de" else
                 f"{len(shown) - 40} more findings: --verbose or --json shows all details.")
        counts = {s: sum(r["status"] == s for r in self.rows) for s in ("OK", "OPEN", "UNKNOWN", "INFO", "N/A")}
        print("\n" + "   ".join(f"{s}: {n}" for s, n in counts.items()))
        emit("Nur die ausgewiesenen Host-Pfade/Instanzen wurden geprüft; keine Sicherheitszertifizierung." if lang == "de" else
             "Only the reported host paths and instances were checked; this is not a security certification.")


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
            options = json.dumps(dict(runtime_dirs=getattr(args, "runtime_dirs", []),
                                      max_paths=getattr(args, "max_paths", 20000),
                                      max_seconds=getattr(args, "walk_seconds", 10)))
            data = json.loads(as_user(user, [sys.executable, "-B", "-c", PERMISSION_SCAN, scan_root, options]))
            for key, title in (("files", "schreibbare PHP-Dateien"), ("directories", "schreibbare Verzeichnisse")):
                count = data[key]
                sample = data["file_sample" if key == "files" else "directory_sample"]
                report.add("OPEN" if count else "OK", f"{title} ({user})", f"{scan_root}: {count}; " + "; ".join(sample))
            if data.get("runtime_directories"):
                report.add("INFO", "Declared runtime storage (" + user + ")",
                           str(data["runtime_directories"]) + " writable directories; PHP files remain checked; execution restrictions require separate verification; " + "; ".join(data.get("runtime_sample", [])))
            if data["errors"]:
                report.add("UNKNOWN", f"Dateisystem-Abdeckung ({user})", f"{data.get('error_count', len(data['errors']))} unlesbare/ausgelassene Pfade; " + "; ".join(data["errors"][:4]))
        except (KeyError, OSError, ValueError, CheckError) as exc:
            report.add("UNKNOWN", f"Dateirechte ({user})", str(exc))
    if not args.site:
        report.add("UNKNOWN", "HTTP-Abdeckung", "Keine --site URL=DOKUMENTWURZEL angegeben")
    stage(args, "HTTP-Endpunkte und weitere Host-Einstellungen pruefen")
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
                raise CheckError("--site benoetigt HTTP(S)-Basis-URL ohne Query, Fragment oder Zugangsdaten")
            root = Path(document_root)
            if not root.is_absolute() or not root.is_dir():
                raise CheckError("Dokumentwurzel fehlt oder ist relativ")
            if str(root) not in git_cache:
                git_cache[str(root)] = git_endpoints(root, max_paths=getattr(args, "max_paths", 20000),
                    max_seconds=getattr(args, "walk_seconds", 10))
            endpoints, walk_errors = git_cache[str(root)]
            if walk_errors:
                report.add("UNKNOWN", "Git-Pfadabdeckung", "; ".join(walk_errors[:3]))
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
                    report.add(status, "HTTP " + target, detail)
                except HttpBudgetExceeded as exc:
                    report.add("UNKNOWN", "HTTP coverage", str(exc))
                    exhausted = True
                    break
                except CheckError as exc:
                    report.add("UNKNOWN", "HTTP " + target, str(exc))
        except (OSError, ValueError, CheckError) as exc:
            report.add("UNKNOWN", "HTTP-Konfiguration", str(exc))
        if exhausted:
            break
    report.discovery["http_budget"] = dict(requests=http_count, limit=http_limit, exhausted=exhausted)
    try:
        ptrace = int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text())
        report.add("OK" if ptrace >= 1 else "OPEN", "ptrace_scope", str(ptrace))
    except (OSError, ValueError):
        report.add("UNKNOWN", "ptrace_scope", "nicht lesbar")
    # Manual policy assessment is outside the selected automated checks. It
    # must stay visible without making a complete automated audit impossible.
    policies = [str(p) for p in (Path("/etc/ImageMagick-6/policy.xml"), Path("/etc/ImageMagick-7/policy.xml")) if p.exists()]
    report.discovery["manual_checks"] = [dict(name="ImageMagick policy", status="not_assessed", paths=policies)]
    report.add("INFO", "ImageMagick policy", "Not assessed automatically; review rules and delegates separately" + ("; " + ", ".join(policies) if policies else ""))
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
        self.noop = False
        self.data = dict(version=1, status="prepared", files=[], directories=[], instances=[])

    def begin(self):
        import time
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
                if digest(original) != item["before"] or not self.same_state(metadata(path), item["meta"]):
                    raise CheckError("Konfiguration wurde zwischenzeitlich geaendert")
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
                raise CheckError("Rollback-Konflikt oder beschaedigtes Backup: " + item["path"])
            before_states = [item["meta"]] + ([item["restored_meta"]] if "restored_meta" in item else [])
            if allow_partial and current == item["before"] and any(self.same_state(now, state) for state in before_states):
                continue
            expected = item.get("after_meta", item["meta"])
            if current != item["after"] or not self.same_state(now, expected, identity="after_meta" in item):
                raise CheckError("Rollback-Konflikt bei Inhalt, Dateimetadaten oder Zeitstempel: " + item["path"])
            restore_files.append((item, original))
        for item in directories:
            now, before = metadata(item["path"]), item["meta"]
            expected = item.get("after", before)
            if (now["dev"], now["ino"]) != (before["dev"], before["ino"]):
                raise CheckError("Rollback-Verzeichnis wurde ersetzt")
            states = self.directory_states(before, item.get("after")) if allow_partial else [expected]
            if not any(self.same_state(now, state) for state in states):
                raise CheckError("Rollback-Konflikt bei Verzeichnisrechten oder Zeitstempel")
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
                    raise CheckError("Dateien wiederhergestellt; FPM-Dienst ist gestoppt (kein automatischer Start beim manuellen Rollback)")
                command(["systemctl", "start", item["service"]])
            else:
                command(["systemctl", "reload", item["service"]])
            command(["systemctl", "is-active", "--quiet", item["service"]])
        self.data["status"] = "rolled_back"
        self.save()
        print(f"Wiederhergestellt: {self.path}")

    @classmethod
    def rollback(cls, backup_root, backup_id=None):
        tx = cls(backup_root)
        trusted(tx.root)
        if backup_id is not None and not re.fullmatch(r"\d{8}T\d{6}-[a-f0-9]{10}", backup_id):
            raise CheckError("Ungueltige Backup-ID")
        candidates = [tx.root / backup_id] if backup_id else list(tx.root.glob("????????T??????-??????????"))
        if not candidates:
            raise CheckError("Kein v2-Backup gefunden; alte flache Backups werden nicht geraten")
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
                raise CheckError("Mehrere Backups in derselben Sekunde; eindeutige Auswahl mit --backup-id erforderlich")
        tx.path, tx.data = max(loaded, key=lambda entry: entry[1].get("created_ns", 0))
        status = tx.data.get("status")
        if tx.data.get("version") != 1 or status not in ("prepared", "applied", "rolling_back", "rolled_back"):
            raise CheckError("Neueste Transaktion ist unbekannt; gezielte Auswahl mit --backup-id erforderlich: " + tx.path.name)
        started = any(item.get("started") for item in tx.data.get("files", []) + tx.data.get("directories", []))
        if status == "rolled_back" or (status == "prepared" and not started):
            tx.noop = True
            print(f"Keine weiteren Aenderungen: {tx.path} ({status}); aelteres Backup nur mit --backup-id auswaehlen")
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


def main(argv=None):
    language = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    language.add_argument("--lang", choices=("en", "de"), default="en")
    selected, _ = language.parse_known_args(argv)
    def text(message):
        return localize(message, selected.lang)
    def emit(message):
        print("".join(c if c.isprintable() else "?" for c in text(message)))
    parser = argparse.ArgumentParser(parents=[language], allow_abbrev=False,
        description=text("Bounded PHP/FPM checks; UNKNOWN means an incomplete check."))
    mode = parser.add_mutually_exclusive_group()
    for name in ("check", "doctor", "discover", "dry-run", "fix", "rollback"):
        mode.add_argument("--" + name, dest="mode", action="store_const", const=name)
    parser.set_defaults(mode="check")
    parser.add_argument("--root", help=text("Pruefbereich (Standard: erkannte Webroots)"))
    parser.add_argument("--web-user", action="append", default=[])
    parser.add_argument("--site", action="append", default=[], metavar="URL=ROOT")
    parser.add_argument("--nginx-config", help=text("Abweichende Nginx-Hauptkonfiguration"))
    parser.add_argument("--no-auto", action="store_true", help=text("Automatische Webroot-/Domain-Erkennung deaktivieren"))
    parser.add_argument("--max-sites", type=int, default=32, help=text("Maximale automatische HTTP-Zuordnungen (Standard 32)"))
    parser.add_argument("--max-paths", type=int, default=20000, help=text("Maximum entries per filesystem walk (default 20000)"))
    parser.add_argument("--walk-seconds", type=float, default=10, help=text("Seconds per filesystem walk (default 10)"))
    parser.add_argument("--max-http-probes", type=int, default=128, help=text("Total HTTP request budget (default 128)"))
    parser.add_argument("--runtime-dir", action="append", default=[], help=text("Declare writable runtime storage inside selected roots; repeatable"))
    parser.add_argument("--protect-dir", action="append", default=[], help=text("Explizit root-uebertragen; nicht rekursiv"))
    parser.add_argument("--backup-root", default="/root/p2s-harden-backup-v2")
    parser.add_argument("--backup-id")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true", help=text("Alle Einzelbefunde einschliesslich OK ausgeben"))
    parser.add_argument("--no-progress", action="store_true", help=text("Phasenhinweise im interaktiven Terminal ausblenden"))
    parser.add_argument("--progress", action="store_true", help=text("Phasenhinweise auch ohne TTY auf stderr ausgeben"))
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    report, tx = None, None
    def show_report():
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
        if args.mode == "doctor":
            report = doctor()
            show_report()
            return report.exit_code()
        if sys.platform != "linux" or not Path("/proc/self/stat").is_file():
            raise CheckError("Linux-Ziel mit /proc erforderlich; unter Windows/macOS --ssh root@SERVER verwenden")
        if sys.version_info < (3, 8):
            raise CheckError("Python 3.8+ erforderlich; " + install_hint("python3"))
        if args.root is not None and not Path(args.root).is_absolute():
            raise CheckError("--root muss absolut sein")
        if args.root is not None:
            args.root = os.path.normpath(args.root)
        if not 1 <= args.max_sites <= 512:
            raise CheckError("--max-sites muss zwischen 1 und 512 liegen")
        if not 1 <= args.max_paths <= 1000000:
            raise CheckError("--max-paths must be between 1 and 1000000")
        if not 0.05 <= args.walk_seconds <= 120:
            raise CheckError("--walk-seconds must be between 0.05 and 120")
        if not 1 <= args.max_http_probes <= 4096:
            raise CheckError("--max-http-probes must be between 1 and 4096")
        if args.mode == "rollback" and os.geteuid() != 0:
            raise CheckError("Aenderungen erfordern root: sudo bash p2s-harden.sh --fix oder --ssh root@SERVER")
        if args.mode == "rollback":
            tx = transaction_output(lambda: Transaction.rollback(args.backup_root, args.backup_id))
            report = Report()
            report.transaction = summarize(tx)
            report.add("INFO", "Rollback", "Latest transaction already restored; no changes made" if tx.noop else "Selected transaction restored")
            show_report()
            return 0
        stage(args, "Nginx-Zuordnungen und Pruefpfade erkennen")
        prepare_scope(args)
        prepare_runtime_dirs(args)
        report, updates, instances, users = scan(args, inventory_only=True) if args.mode == "discover" else scan(args)
        if args.mode in ("dry-run", "fix"):
            blockers = fix_blockers(updates, args.protect_dir, instances, users)
            plan = dict(ini=[dict(path=path, values=values) for path, values in sorted(updates.items())],
                        directories=list(args.protect_dir), blockers=[text(reason) for reason in blockers])
            report.plan = plan
            for reason in blockers:
                report.add("UNKNOWN", "Fix gesperrt", reason)
            if not args.json:
                for path, values in updates.items():
                    emit(f"GEPLANT INI {path}: {','.join(values)}")
                for path in args.protect_dir:
                    emit(f"GEPLANT VERZEICHNIS {path}: Eigentuemer root, kein g+w/o+w, nicht rekursiv")
                emit("Offene HTTP-/ImageMagick-/Runtime-/Speicherpfad-Befunde werden nicht pauschal veraendert.")
            if args.mode == "fix" and not blockers and (updates or args.protect_dir):
                tx = Transaction(args.backup_root)
                def apply():
                    tx.prepare(updates, args.protect_dir, instances)
                    tx.apply(instances, users)
                transaction_output(apply)
                report, _, _, _ = scan(args)
                report.plan, report.transaction = plan, summarize(tx)
        show_report()
        return report.exit_code()
    except (OSError, ValueError, KeyError, CheckError) as exc:
        report = report or Report()
        report.add("UNKNOWN", "Ausfuehrung", str(exc))
        if tx is None:
            tx = getattr(exc, "p2s_transaction", None)
        if tx is not None:
            report.transaction = summarize(tx)
        show_report()
        return 2


if __name__ == "__main__":
    sys.exit(main())
