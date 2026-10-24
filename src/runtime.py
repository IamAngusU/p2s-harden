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

VERSION = "2.3.0-dev.5"
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
