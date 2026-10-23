#!/usr/bin/env python3
"""Exercise PHP-FPM pool settings through real, bounded FastCGI requests.

Linux + Python 3.8+ + access to a local Docker daemon are required. No pip,
webserver, production mounts, privileged container, or published port is used.
Each case starts a disposable official PHP-FPM container: 0.5 CPU, 128 MiB,
32 PIDs, no network, read-only rootfs, unprivileged UID, and a private fixture
mount. Cleanup removes only containers carrying this run's exact label.

Run from the source root:
  python3 -B tools/test_fpm_runtime.py --image php:8.4-fpm-bookworm
  python3 -B tools/test_fpm_runtime.py --json --engine p2s_harden.py

The default matrix covers 8.1 (EOL compatibility only), 8.4, and 8.5. Tags may
move; the report records local image IDs, repository digests and web PHP versions.
Use --image php@sha256:... to reproduce an exact previously recorded image.
No image is silently skipped. Exit 0 = all requested observations/assertions
passed; 1 = an observed runtime/audit mismatch; 2 = incomplete evidence or an
infrastructure/protocol error. This tests settings, not overall server safety.

Primary references checked 2026-10-23:
  https://www.php.net/supported-versions.php
  https://www.php.net/eol.php
  https://www.php.net/manual/en/install.fpm.configuration.php
  https://github.com/php/php-src/blob/PHP-8.4/sapi/fpm/fpm/fpm_php.c
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from unittest.mock import patch


REQUIRED = ("exec", "system", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec")
DEFAULT_IMAGES = ("php:8.1-fpm-bookworm", "php:8.4-fpm-bookworm", "php:8.5-fpm-bookworm")
LABEL = "org.p2s-harden.runtime-test"
PHP_PROBE = r'''<?php
declare(strict_types=1);
header('Content-Type: application/json');
$names = ['exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec'];
$functions = [];
foreach ($names as $name) {
    $exists = function_exists($name);
    $functions[$name] = ['exists' => $exists,
        'internal' => $exists ? (new ReflectionFunction($name))->isInternal() : null];
}
$operations = [];
if (function_exists('exec')) {
    $lines = []; $exit = -1;
    exec('printf P2S_RUNTIME_SENTINEL', $lines, $exit);
    $operations['exec'] = ['output' => implode("\n", $lines), 'exit' => $exit];
}
if (function_exists('system')) {
    ob_start(); $exit = -1;
    system('printf P2S_RUNTIME_SENTINEL', $exit);
    $operations['system'] = ['output' => ob_get_clean(), 'exit' => $exit];
}
if (function_exists('shell_exec')) {
    $operations['shell_exec'] = ['output' => shell_exec('printf P2S_RUNTIME_SENTINEL')];
}
$warnings = [];
set_error_handler(static function (int $level, string $message) use (&$warnings): bool {
    $warnings[] = $message; return true;
});
try {
    $included = include 'data://text/plain;base64,' . base64_encode('<?php return "P2S_INCLUDE_ALLOWED";');
} finally {
    restore_error_handler();
}
$all = ini_get_all();
echo json_encode(['sapi' => PHP_SAPI, 'php_version' => PHP_VERSION,
    'parent_env_visible' => getenv('P2S_PARENT_CANARY') !== false,
    'disable_functions' => ini_get('disable_functions'),
    'disable_functions_access' => $all['disable_functions']['access'],
    'allow_url_include' => ini_get('allow_url_include'),
    'allow_url_include_access' => $all['allow_url_include']['access'],
    'functions' => $functions, 'operations' => (object) $operations,
    'data_include_allowed' => $included === 'P2S_INCLUDE_ALLOWED',
    'include_warning_count' => count($warnings)], JSON_THROW_ON_ERROR);
'''


class EvidenceError(RuntimeError):
    """The requested runtime observation could not be established."""


def run(argv, timeout=30, check=True):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError("{}: {}".format(argv[0], type(exc).__name__)) from exc
    if check and result.returncode:
        raise EvidenceError("{} exited {}: {}".format(argv[0], result.returncode, result.stderr.strip()[-1800:]))
    return result


def record(kind, body=b"", request_id=1):
    if len(body) > 65535:
        raise EvidenceError("FastCGI record exceeds 65535 bytes")
    return struct.pack("!BBHHBB", 1, kind, request_id, len(body), 0, 0) + body


def encoded_length(length):
    return bytes([length]) if length < 128 else struct.pack("!I", length | 0x80000000)


def receive_exact(stream, count):
    chunks = bytearray()
    while len(chunks) < count:
        chunk = stream.recv(count - len(chunks))
        if not chunk:
            raise EvidenceError("FastCGI connection closed before END_REQUEST")
        chunks.extend(chunk)
    return bytes(chunks)


def fastcgi_request(socket_path, timeout=3, script="/lab/probe.php", status_only=False):
    """Minimal FastCGI Responder client; rejects truncated/non-success replies."""
    params = {"GATEWAY_INTERFACE": "CGI/1.1", "REQUEST_METHOD": "GET",
              "SCRIPT_FILENAME": script, "SCRIPT_NAME": "/" + Path(script).name,
              "REQUEST_URI": "/probe.php", "SERVER_PROTOCOL": "HTTP/1.1",
              "SERVER_NAME": "p2s-runtime.test", "SERVER_PORT": "80",
              "REMOTE_ADDR": "127.0.0.1", "QUERY_STRING": "", "CONTENT_LENGTH": "0"}
    encoded = bytearray()
    for name, value in params.items():
        key, data = name.encode(), value.encode()
        encoded.extend(encoded_length(len(key)) + encoded_length(len(data)) + key + data)
    stdout, stderr = bytearray(), bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(str(socket_path))
        stream.sendall(record(1, struct.pack("!HB5x", 1, 0)) + record(4, bytes(encoded)) + record(4) + record(5))
        while True:
            version, kind, request_id, length, padding, _ = struct.unpack("!BBHHBB", receive_exact(stream, 8))
            if version != 1 or request_id != 1:
                raise EvidenceError("Unexpected FastCGI version/request ID")
            body = receive_exact(stream, length)
            receive_exact(stream, padding)
            if kind == 6:
                stdout.extend(body)
            elif kind == 7:
                stderr.extend(body)
            elif kind == 3:
                if len(body) != 8 or struct.unpack("!IB3x", body) != (0, 0):
                    raise EvidenceError("FastCGI application/protocol failure")
                break
            else:
                raise EvidenceError("Unexpected FastCGI record type {}".format(kind))
            if len(stdout) > 1024 * 1024 or len(stderr) > 16384:
                raise EvidenceError("FastCGI response exceeded fixture limit")
    header, separator, body = bytes(stdout).partition(b"\r\n\r\n")
    if not separator:
        header, separator, body = bytes(stdout).partition(b"\n\n")
    status = re.search(br"(?im)^Status:[ \t]*(\d{3})\b", header)
    if status_only and separator:
        code = int(status.group(1)) if status else 200
        try:
            executed = json.loads(body.decode()).get("sapi") == "fpm-fcgi"
        except (UnicodeError, ValueError, AttributeError):
            executed = False
        return dict(http_status=code, script_executed=executed)
    if not separator or (status is not None and status.group(1) != b"200"):
        raise EvidenceError("Missing/successless CGI headers: " + header.decode(errors="replace")[:500])
    if b"content-type: application/json" not in header.lower():
        raise EvidenceError("FPM did not return the JSON fixture")
    try:
        data = json.loads(body.decode())
    except (UnicodeError, ValueError) as exc:
        raise EvidenceError("FPM returned invalid fixture JSON") from exc
    if data.get("sapi") != "fpm-fcgi" or not isinstance(data.get("functions"), dict):
        raise EvidenceError("Response is not real FPM fixture evidence")
    return data


def cases():
    """Expected effective function removal, not misleading ini_get strings."""
    all_functions = ",".join(REQUIRED)
    return [
        dict(name="baseline", global_disabled="", pool={}, disabled=set(), include=False),
        dict(name="global-inherited", global_disabled="exec", pool={}, disabled={"exec"}, include=False),
        dict(name="admin-additive", global_disabled="exec", pool={"php_admin_value[disable_functions]": "system"}, disabled={"exec", "system"}, include=False),
        dict(name="value-additive-ini-system", global_disabled="exec", pool={"php_value[disable_functions]": "system"}, disabled={"exec", "system"}, include=False),
        dict(name="admin-empty-preserves-global", global_disabled="exec", pool={"php_admin_value[disable_functions]": ""}, disabled={"exec"}, include=False),
        dict(name="value-empty-preserves-global", global_disabled="exec", pool={"php_value[disable_functions]": ""}, disabled={"exec"}, include=False),
        dict(name="admin-short-preserves-global", global_disabled=all_functions, pool={"php_admin_value[disable_functions]": "exec"}, disabled=set(REQUIRED), include=False),
        dict(name="value-short-preserves-global", global_disabled=all_functions, pool={"php_value[disable_functions]": "exec"}, disabled=set(REQUIRED), include=False),
        dict(name="global-value-admin-all-additive", global_disabled="exec", pool={"php_value[disable_functions]": "system", "php_admin_value[disable_functions]": "shell_exec"}, disabled={"exec", "system", "shell_exec"}, include=False),
        dict(name="admin-only-complete", global_disabled="", pool={"php_admin_value[disable_functions]": all_functions}, disabled=set(REQUIRED), include=False),
        dict(name="value-only-complete", global_disabled="", pool={"php_value[disable_functions]": all_functions}, disabled=set(REQUIRED), include=False),
        *[dict(name=prefix + "-url-on", global_disabled="", pool={prefix + "[allow_url_include]": "On"}, disabled=set(), include=True)
          for prefix in ("php_value", "php_flag", "php_admin_value", "php_admin_flag")],
        dict(name="admin-url-off-wins", global_disabled="", pool={"php_value[allow_url_include]": "On", "php_admin_flag[allow_url_include]": "Off"}, disabled=set(), include=False),
        dict(name="global-uppercase-not-disabled", global_disabled=all_functions.upper(), pool={}, disabled=set(), include=False),
        dict(name="pool-uppercase-not-disabled", global_disabled="", pool={"php_admin_value[disable_functions]": all_functions.upper()}, disabled=set(), include=False),
        dict(name="global-space-separated", global_disabled=" ".join(REQUIRED), pool={}, disabled=set(REQUIRED), include=False),
        dict(name="pool-space-separated", global_disabled="", pool={"php_value[disable_functions]": " ".join(REQUIRED)}, disabled=set(REQUIRED), include=False),
        dict(name="environment-inheritance", global_disabled="", pool={"clear_env":"no"}, disabled=set(), include=False, parent_env=True),
        dict(name="unrestricted-script-extensions", global_disabled="", pool={"security.limit_extensions":""}, disabled=set(), include=False, txt=True),
        dict(name="non-php-script-extension", global_disabled="", pool={"security.limit_extensions":".php .txt"}, disabled=set(), include=False, txt=True),
        dict(name="default-php-phar-extensions", global_disabled="", pool={"security.limit_extensions":".php .phar"}, disabled=set(), include=False),
        dict(name="network-listener-unrestricted", global_disabled="", pool={}, disabled=set(), include=False, network={"listen":"0.0.0.0:9000"}, listener_status="OPEN"),
        dict(name="network-listener-allowlist", global_disabled="", pool={}, disabled=set(), include=False, network={"listen":"0.0.0.0:9000", "listen.allowed_clients":"127.0.0.1"}, listener_status="OK"),
    ]


def write_fixture(directory, case):
    os.chmod(directory, 0o755)
    (directory / "socket").mkdir(mode=0o777)
    os.chmod(directory / "socket", 0o777)
    (directory / "probe.php").write_text(PHP_PROBE)
    (directory / "probe.txt").write_text(PHP_PROBE)
    (directory / "php.ini").write_text("[PHP]\ndisplay_errors=Off\nlog_errors=On\nallow_url_fopen=On\nallow_url_include=Off\ndisable_functions={}\n".format(case["global_disabled"]))
    settings = "\n".join('{} = {}'.format(k, v if k.startswith(("php_flag[", "php_admin_flag[")) else '"' + v + '"')
                         for k, v in case["pool"].items())
    (directory / "fpm.conf").write_text("[global]\nerror_log=/proc/self/fd/2\ndaemonize=no\n[fixture]\nuser=www-data\ngroup=www-data\nlisten=/lab/socket/fpm.sock\nlisten.mode=0600\npm=static\npm.max_children=1\ncatch_workers_output=yes\nclear_env=yes\nsecurity.limit_extensions=.php\n" + settings + "\n")
    if case.get("network"):
        with (directory / "fpm.conf").open("a") as stream:
            stream.write("\n[network]\nuser=www-data\ngroup=www-data\npm=static\npm.max_children=1\n" +
                         "\n".join(key + "=" + value for key,value in case["network"].items()) + "\n")
    for name in ("probe.php", "probe.txt", "php.ini", "fpm.conf"):
        (directory / name).chmod(0o644)


def cleanup_container(name, run_id):
    owned = run(["docker", "inspect", "--format", '{{index .Config.Labels "' + LABEL + '"}}', name], check=False)
    if owned.returncode == 0:
        if owned.stdout.strip() != run_id:
            raise EvidenceError("Refusing cleanup: container label does not match this run")
        run(["docker", "rm", "--force", name])


def container_user():
    """Let the host client read its 0600 socket without running FPM as root."""
    uid = os.geteuid()
    return "33:33" if uid == 0 else "{}:{}".format(uid, os.getegid())


def observe(image_id, case, run_id):
    name = "p2s-fpm-runtime-" + uuid.uuid4().hex[:16]
    with tempfile.TemporaryDirectory(prefix="p2s-fpm-runtime-") as temporary:
        directory = Path(temporary)
        write_fixture(directory, case)
        try:
            run(["docker", "run", "--detach", "--name", name, "--label", LABEL + "=" + run_id,
                 "--cpus", "0.5", "--memory", "128m", "--memory-swap", "128m", "--pids-limit", "32",
                 "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--user", container_user(), "--mount", "type=bind,src=" + str(directory) + ",dst=/lab",
                 "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m", "--env", "PHP_INI_SCAN_DIR=",
                 "--env", "P2S_PARENT_CANARY=fixture-only-nonsecret",
                 image_id, "php-fpm", "-F", "-y", "/lab/fpm.conf", "-c", "/lab/php.ini"])
            deadline, last_error = time.monotonic() + 15, "not ready"
            while time.monotonic() < deadline:
                try:
                    evidence = fastcgi_request(directory / "socket/fpm.sock")
                    evidence["txt_script"] = fastcgi_request(directory / "socket/fpm.sock", script="/lab/probe.txt", status_only=True)
                    # A dump is auxiliary configuration provenance, never the
                    # success oracle. The assertions above use the web reply.
                    dump = run(["docker", "exec", name, "php-fpm", "-tt", "-y", "/lab/fpm.conf", "-c", "/lab/php.ini"])
                    evidence["fpm_pool_dump"] = "\n".join(line for line in (dump.stdout + dump.stderr).splitlines()
                        if re.search(r"NOTICE:\s+(?:\[(?:fixture|network)\]|(?:user|listen(?:\.(?:mode|allowed_clients))?|clear_env|security\.limit_extensions|php_(?:admin_)?(?:value|flag)\[(?:disable_functions|allow_url_include)\])\s*=)", line))
                    return evidence
                except (OSError, EvidenceError) as exc:
                    last_error = str(exc)
                    state = run(["docker", "inspect", "--format", "{{.State.Running}}", name], check=False)
                    if state.stdout.strip() != "true":
                        break
                    time.sleep(0.15)
            logs = run(["docker", "logs", name], check=False)
            raise EvidenceError(last_error + "; fixture logs: " + (logs.stdout + logs.stderr)[-1800:])
        finally:
            cleanup_container(name, run_id)


def assert_observation(case, data, baseline):
    failures = []
    if data["parent_env_visible"] != case.get("parent_env", False):
        failures.append("clear_env runtime inheritance mismatch")
    expected_txt = case.get("txt", False)
    if data["txt_script"] != dict(http_status=200 if expected_txt else 403, script_executed=expected_txt):
        failures.append("security.limit_extensions runtime enforcement mismatch")
    for name in REQUIRED:
        expected = baseline["functions"][name]["exists"] and name not in case["disabled"]
        observed = data["functions"].get(name)
        if observed is None or observed["exists"] != expected or (expected and observed["internal"] is not True):
            failures.append("{} availability: expected {}, got {}".format(name, expected, observed))
    if data["data_include_allowed"] != case["include"]:
        failures.append("data:// include: expected {}, got {}".format(case["include"], data["data_include_allowed"]))
    for name, value in data["operations"].items():
        if value.get("output") != "P2S_RUNTIME_SENTINEL" or value.get("exit", 0) != 0:
            failures.append(name + " harmless runtime operation failed")
    if data["disable_functions_access"] != 4 or data["allow_url_include_access"] != 4:
        failures.append("Expected INI_SYSTEM access metadata (4)")
    return failures


def audit_comparison(engine, case, data, directory):
    """Exercise real scan() pool decisions; isolate unrelated host checks only."""
    # Use the real dump: FPM normalizes php_flag into php_value and admin flags
    # into admin values. Testing input spelling alone would miss that boundary.
    pools = engine.pool_values(data["fpm_pool_dump"])
    instance = dict(pid=123, start="fixture", binary="/fixture/php-fpm", service=None,
                    config="/fixture/fpm.conf", inis=[str(directory / "php.ini")], env={},
                    values={"disable_functions": case["global_disabled"], "allow_url_include": "Off", "open_basedir": "/lab"},
                    pools=pools)
    args = argparse.Namespace(web_user=[], root=str(directory), roots=[str(directory)], site=[], discovery={})
    permissions = json.dumps(dict(files=0, directories=0, file_sample=[], directory_sample=[], errors=[]))
    with patch.object(engine, "discover", return_value=([instance], [])), patch.object(engine, "as_user", return_value=permissions):
        report, _, _, _ = engine.scan(args)
    def effective(rule):
        rows = [row for row in report.rows if row["rule_id"] == rule and row["resource"].get("pool") in (None, "fixture")]
        return next((row for row in rows if row["resource"].get("pool") == "fixture"), rows[0])
    pool = effective("P2S-PHP001")
    include = effective("P2S-PHP002")
    runtime_pool = "OPEN" if any(v["exists"] for v in data["functions"].values()) else "OK"
    runtime_include = "OPEN" if data["data_include_allowed"] else "OK"
    failures = []
    def state(rule, pool="fixture", source=None):
        return [row["status"] for row in report.rows if row["rule_id"] == rule and row["resource"].get("pool") == pool
                and (source is None or row["resource"].get("source") == source)]
    expected_extension = "OPEN" if case.get("txt", False) else "INFO" if case["pool"].get("security.limit_extensions") == ".php .phar" else "OK"
    if state("P2S-FPM003") != [expected_extension]:
        failures.append("audit script-extension policy differs from real FPM fixture")
    if state("P2S-FPM004") != ["OPEN" if data["parent_env_visible"] else "OK"]:
        failures.append("audit environment policy differs from real FPM inheritance")
    if state("P2S-FPM002", source="configured") != ["OK"]:
        failures.append("audit configured socket mode differs from real FPM fixture")
    if case.get("network") and state("P2S-FPM001", "network") != [case["listener_status"]]:
        failures.append("audit TCP listener policy differs from real FPM dump")
    if pool["status"] != runtime_pool:
        failures.append("audit pool {} differs from real runtime {}".format(pool["status"], runtime_pool))
    if include["status"] != runtime_include:
        failures.append("audit allow_url_include {} differs from real runtime {}".format(include["status"], runtime_include))
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", action="append", help="Official PHP-FPM image/digest; repeat for a matrix")
    parser.add_argument("--pull", choices=("missing", "never"), default="missing")
    parser.add_argument("--json", action="store_true", help="Full bounded runtime evidence on stdout; progress on stderr")
    parser.add_argument("--engine", type=Path, help="Also compare this engine's scan() pool decisions to real runtime")
    args = parser.parse_args(argv)
    report = dict(schema_version=1, captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  audit_comparison=bool(args.engine), images=[], exit_code=2)
    try:
        if sys.platform != "linux" or not hasattr(socket, "AF_UNIX") or not shutil.which("docker"):
            raise EvidenceError("Linux, AF_UNIX, and a working local Docker CLI/daemon are required")
        run(["docker", "version", "--format", "{{.Server.Version}}"])
        engine = None
        if args.engine:
            report["audit_engine_sha256"] = hashlib.sha256(args.engine.read_bytes()).hexdigest()
            spec = importlib.util.spec_from_file_location("p2s_runtime_audit", args.engine)
            engine = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(engine)
        run_id = uuid.uuid4().hex
        for image in args.image or DEFAULT_IMAGES:
            entry = dict(image=image, cases=[])
            report["images"].append(entry)
            try:
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", image):
                    raise EvidenceError("Invalid image reference")
                inspection = run(["docker", "image", "inspect", image], check=False)
                if inspection.returncode and args.pull == "missing":
                    print("Pulling " + image, file=sys.stderr, flush=True)
                    run(["docker", "pull", image], timeout=240)
                    inspection = run(["docker", "image", "inspect", image])
                if inspection.returncode:
                    raise EvidenceError("Requested image is unavailable: " + image)
                identity = json.loads(inspection.stdout)[0]
                entry.update(image_id=identity["Id"], repo_digests=identity.get("RepoDigests", []))
                baseline = None
                for case in cases():
                    print(image + " " + case["name"], file=sys.stderr, flush=True)
                    observed = observe(entry["image_id"], case, run_id)
                    if baseline is None:
                        baseline = observed
                        if not all(baseline["functions"][f]["exists"] for f in ("exec", "system", "shell_exec")):
                            raise EvidenceError("Baseline lacks the three runtime-operation controls")
                    failures = assert_observation(case, observed, baseline)
                    if engine:
                        with tempfile.TemporaryDirectory(prefix="p2s-fpm-audit-") as temporary:
                            directory = Path(temporary)
                            (directory / "php.ini").write_text("disable_functions=" + case["global_disabled"] + "\n")
                            failures.extend(audit_comparison(engine, case, observed, directory))
                    entry["cases"].append(dict(name=case["name"], status="FAIL" if failures else "PASS", failures=failures,
                        input=dict(global_disabled=case["global_disabled"], pool=case["pool"]), runtime=observed))
            except (EvidenceError, OSError, ValueError, KeyError, TypeError, AttributeError, StopIteration) as exc:
                entry["error"] = str(exc)
        unknown = any(e.get("error") or len(e["cases"]) != len(cases()) for e in report["images"])
        failed = any(c["status"] == "FAIL" for e in report["images"] for c in e["cases"])
        report["exit_code"] = 2 if unknown else 1 if failed else 0
    except (EvidenceError, OSError, ValueError, ImportError, TypeError, AttributeError) as exc:
        report["error"] = str(exc)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for image in report["images"]:
            for case in image["cases"]:
                print("{} {} {} (PHP {})".format(case["status"], image["image"], case["name"], case["runtime"]["php_version"]))
                for failure in case["failures"]:
                    print("  " + failure)
            if image.get("error"):
                print("UNKNOWN " + image["image"] + ": " + image["error"])
        if report.get("error"):
            print("UNKNOWN " + report["error"])
        print("Exit {}: runtime test evidence only; no server security certification".format(report["exit_code"]))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
