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
