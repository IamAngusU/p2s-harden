"""Local indicator triage. Never execute, decode payloads, upload or alter files."""

WEBSHELL_INDICATORS = {
    "request-execution": "Request data near a code/command execution sink",
    "encoded-execution": "Decoder output near a PHP code execution sink",
    "request-include": "Request data near a PHP include/require",
    "request-callable": "Request-selected dynamic function call",
    "network-shell": "Network connection and shell launch in one PHP file",
    "startup-reference": "PHP startup-file directive requires verification",
}
WEBSHELL_REASONS = ("access", "symlink", "mount", "special", "changed", "depth",
                   "entries", "time", "file-size", "total-bytes", "tokens", "expression", "findings")
_WS_SOURCE = frozenset(("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES"))
_WS_SINKS = REQUIRED | frozenset(("eval", "assert", "create_function"))
_WS_DECODERS = frozenset(("base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "hex2bin"))
_WS_TOKEN = re.compile(r"\$[A-Za-z_][A-Za-z_0-9]*|\\?[A-Za-z_][A-Za-z_0-9\\]*|->|\?->|::|==|=>|!=|<=|>=|\?\?|&&|\|\||[^\s]", re.ASCII)
_WS_OPEN = re.compile(r"<\?(?:php\b|=|(?!xml\b))", re.I | re.ASCII)
_WS_HEREDOC = re.compile(r"<<<[ \t]*(?:'([A-Za-z_][A-Za-z_0-9]{0,127})'|\"([A-Za-z_][A-Za-z_0-9]{0,127})\"|([A-Za-z_][A-Za-z_0-9]{0,127}))[ \t]*\r?\n")


def webshell_tokens(source, deadline):
    """Small lexical filter, not a PHP parser. Strings/comments are not code."""
    tokens, pos, active = [], 0, False
    while pos < len(source):
        if len(tokens) >= 100000:
            return tokens, "tokens"
        if time.monotonic() > deadline:
            return tokens, "time"
        if not active:
            opening = _WS_OPEN.search(source, pos)
            if not opening:
                break
            pos, active = opening.end(), True
            continue
        if source.startswith("?>", pos):
            pos, active = pos + 2, False
            continue
        if source[pos].isspace():
            pos += 1
            continue
        if source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            pos = len(source) if end < 0 else end + 2
            continue
        if source.startswith("//", pos) or source[pos] == "#" and not source.startswith("#[", pos):
            end = source.find("\n", pos)
            close = source.find("?>", pos)
            pos = min(end if end >= 0 else len(source), close if close >= 0 else len(source))
            continue
        start = pos
        quote = source[pos]
        if quote in ("'", '"', "`"):
            pos += 1
            while pos < len(source):
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


def webshell_indicators(data, deadline=None):
    """Bounded syntactic proximity and simple aliases; no exploitability claim."""
    source = data.decode("latin-1")
    deadline = deadline if deadline is not None else time.monotonic() + 10
    tokens, incomplete = webshell_tokens(source, deadline)
    hits, aliases, decoded, constants, pairs, stack = {}, set(), set(), {}, {}, []
    for index, token in enumerate(tokens):
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
    def request(items):
        for kind, value, _ in items:
            if kind == "variable" and (value in _WS_SOURCE or value in aliases):
                return True
            if kind in ("interpolated", "backtick"):
                if any(m[0] in _WS_SOURCE or m[0] in aliases for m in re.finditer(r"\$[A-Za-z_][A-Za-z_0-9]*", value, re.ASCII)):
                    return True
        return any(kind == "code" and value.lower().lstrip("\\") in ("filter_input", "file_get_contents")
                   and j + 1 < len(items) and items[j + 1][1] == "("
                   and (value.lower().lstrip("\\") == "filter_input" or any(t[0] in ("string", "interpolated") and t[1] == "php://input" for t in items[j + 2:j + 5]))
                   for j, (kind, value, _) in enumerate(items))
    def encoded(items):
        return any(kind == "variable" and value in decoded or
                   constants.get(value, value.lower().lstrip("\\")) in _WS_DECODERS
                   and kind in ("code", "variable") and j + 1 < len(items) and items[j + 1][1] == "("
                   for j, (kind, value, _) in enumerate(items))
    def add(indicator, offset):
        # One row per rule/file, earliest line; no attacker-controlled excerpt.
        hits.setdefault(indicator, source.count("\n", 0, offset) + 1)
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
                scopes.append((depth, aliases, decoded, constants))
                aliases, decoded, constants, pending_function = set(), set(), {}, False
        if kind == "code" and value == "}":
            if scopes and scopes[-1][0] == depth:
                _, aliases, decoded, constants = scopes.pop()
            depth = max(0, depth - 1)
        if kind == "variable" and index + 1 < len(tokens) and tokens[index + 1][1] == "=":
            end = index + 2
            while end < min(len(tokens), index + 514) and tokens[end][:2] != ("code", ";"):
                end += 1
            if end == index + 514:
                incomplete = incomplete or "expression"
            expression = tokens[index + 2:end]
            tainted = request(expression)
            packed = encoded(expression)
            aliases.discard(value)
            decoded.discard(value)
            constants.pop(value, None)
            if tainted:
                aliases.add(value)
            if packed:
                decoded.add(value)
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
                add("request-include", offset)
        if index + 1 >= len(tokens) or tokens[index + 1][1] != "(":
            continue
        end = pairs.get(index + 1)
        if end is None or end - index > 512:
            incomplete = incomplete or "expression"
            continue
        arguments = tokens[index + 2:end]
        if name in ("fsockopen", "pfsockopen", "stream_socket_client", "socket_connect"):
            network_offset = offset if network_offset is None else network_offset
        if name in REQUIRED:
            for arg_kind, arg_value, _ in arguments:
                if arg_kind in ("string", "interpolated") and len(arg_value) <= 1024 and re.search(r"(?:^|[\s/])(?:ba|da|a|k|z)?sh(?:\s|$)|cmd\.exe|powershell(?:\.exe)?", arg_value, re.I):
                    shell_offset = offset if shell_offset is None else shell_offset
                    if "/dev/tcp/" in arg_value:
                        network_offset = offset if network_offset is None else network_offset
        if kind == "variable" and value in aliases:
            add("request-callable", offset)
        if name in ("call_user_func", "call_user_func_array", "array_map"):
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
                add("request-callable", offset)
        if value == "]" and index in closing:
            begin = closing[index]
            if begin and request(tokens[begin - 1:index + 1]):
                add("request-callable", offset)
        if name in _WS_SINKS and request(arguments):
            add("request-execution", offset)
        if name in ("eval", "assert", "create_function"):
            if encoded(arguments):
                add("encoded-execution", offset)
    if network_offset is not None and shell_offset is not None:
        add("network-shell", min(network_offset, shell_offset))
    return hits, incomplete


def scan_webshells(args):
    """Pin every traversed directory with dirfd; refuse symlinks and devices."""
    report = Report()
    report.discovery = dict(getattr(args, "discovery", {}), webshell_scan=True)
    for issue in report.discovery.get("issues", []):
        report.add("UNKNOWN", "Automatic discovery", issue, rule_id="P2S-DISC001", resource=issue)
    stage(args, "Scanning local files for PHP webshell indicators")
    for root in args.roots:
        reasons, seen, examined, read_bytes, findings = set(), 0, 0, 0, 0
        deadline = time.monotonic() + args.walk_seconds
        frames = []
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
            device = os.fstat(fd).st_dev
            frames.append((fd, os.scandir(fd), root))
            while frames:
                if time.monotonic() > deadline:
                    reasons.add("time")
                    break
                parent_fd, entries, parent = frames[-1]
                entry = next(entries, None)
                if entry is None:
                    entries.close()
                    os.close(parent_fd)
                    frames.pop()
                    continue
                seen += 1
                if seen > args.max_paths:
                    reasons.add("entries")
                    break
                path = os.path.join(parent, entry.name)
                file_fd = None
                try:
                    before = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(before.st_mode):
                        reasons.add("symlink")
                        continue
                    if before.st_dev != device:
                        reasons.add("mount")
                        continue
                    if not stat.S_ISREG(before.st_mode) and not stat.S_ISDIR(before.st_mode):
                        reasons.add("special")
                        continue
                    file_fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                    opened = os.fstat(file_fd)
                    if (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode)) != (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)):
                        reasons.add("changed")
                        continue
                    if stat.S_ISDIR(opened.st_mode):
                        if len(frames) >= 64:
                            reasons.add("depth")
                            continue
                        frames.append((file_fd, os.scandir(file_fd), path))
                        file_fd = None
                        continue
                    if opened.st_size > args.scan_file_bytes:
                        reasons.add("file-size")
                        continue
                    chunks, size = [], 0
                    while True:
                        if time.monotonic() > deadline:
                            reasons.add("time")
                            break
                        chunk = os.read(file_fd, min(65536, args.scan_file_bytes - size + 1, args.scan_total_bytes - read_bytes + 1))
                        if not chunk:
                            break
                        size += len(chunk)
                        read_bytes += len(chunk)
                        if size > args.scan_file_bytes or read_bytes > args.scan_total_bytes:
                            reasons.add("file-size" if size > args.scan_file_bytes else "total-bytes")
                            break
                        chunks.append(chunk)
                    after = os.fstat(file_fd)
                    if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        reasons.add("changed")
                        continue
                    if size > args.scan_file_bytes or read_bytes > args.scan_total_bytes or "time" in reasons:
                        if "total-bytes" in reasons or "time" in reasons:
                            break
                        continue
                    data = b"".join(chunks)
                    examined += 1
                    hits, partial = webshell_indicators(data, deadline)
                    if partial:
                        reasons.add(partial)
                    # These directives can be legitimate. Report the location,
                    # never their target value or any adjacent credentials.
                    if entry.name.lower() in (".user.ini", ".htaccess", "php.ini"):
                        for line, text in enumerate(data.decode("latin-1").splitlines(), 1):
                            directive = re.match(r"\s*(?:(?:php_value|php_admin_value)\s+)?auto_(?:prepend|append)_file\b\s*(?:=|\s)\s*(.*)", text, re.I)
                            if directive and directive[1].split(";", 1)[0].strip().strip("\"'").lower() not in ("", "none", "off"):
                                hits.setdefault("startup-reference", line)
                    fingerprint = digest(data)
                    for indicator, line in sorted(hits.items()):
                        if findings >= 200:
                            break
                        rule = "P2S-WS002" if indicator == "startup-reference" else "P2S-WS001"
                        row = report.add("OPEN", "PHP file indicator " + path,
                            "Line " + str(line) + ": " + WEBSHELL_INDICATORS[indicator] + "; SHA256 " + fingerprint,
                            rule_id=rule, resource=dict(path=path, indicator=indicator),
                            evidence=dict(indicators=[indicator], line=line))
                        row["sha256"] = fingerprint
                        findings += 1
                    if findings >= 200:
                        reasons.add("findings")
                        break
                except OSError:
                    reasons.add("access")
                finally:
                    if file_fd is not None:
                        os.close(file_fd)
        except OSError:
            reasons.add("access")
        finally:
            for fd, entries, _ in frames:
                entries.close()
                os.close(fd)
        facts = dict(examined_files=examined, indicator_count=findings, coverage_reasons=sorted(reasons))
        report.add("UNKNOWN" if reasons else "INFO", "Webshell scan coverage",
            str(examined) + " files examined; " + str(findings) + " indicators; " +
            ("incomplete: " + ", ".join(sorted(reasons)) if reasons else "selected scan completed") +
            "; absence of indicators does not establish a clean server",
            rule_id="P2S-WS003", resource=dict(root=root), evidence=facts)
    return report
