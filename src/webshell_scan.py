"""Read-only filesystem scan, finite coverage diagnostics and exact baselines."""


def webshell_baseline_entries(data):
    """Accept explicit reviewed entries or a local, nonredacted scan JSON."""
    from pathlib import PurePosixPath
    if not isinstance(data, dict) or data.get("redacted"):
        raise CheckError("Baseline must be a local, nonredacted webshell report or schema 1 file list")
    if data.get("schema_version") == 2 and isinstance(data.get("discovery"), dict) and data["discovery"].get("webshell_scan") is True:
        rows = data.get("findings")
        if not isinstance(rows, list) or len(rows) > 10000:
            raise CheckError("Baseline finding limit exceeded or invalid finding list")
        entries = []
        for row in rows:
            if not isinstance(row, dict):
                raise CheckError("Invalid baseline finding")
            if row.get("rule_id") not in ("P2S-WS001", "P2S-WS002", "P2S-WS004"):
                continue
            resource = row.get("resource")
            if not isinstance(resource, dict):
                raise CheckError("Invalid baseline resource")
            entries.append(dict(path=resource.get("path"), sha256=row.get("sha256"), indicators=[resource.get("indicator")]))
    elif data.get("schema_version") == 1:
        entries = data.get("files")
    else:
        raise CheckError("Baseline must be a local, nonredacted webshell report or schema 1 file list")
    if not isinstance(entries, list) or len(entries) > 10000:
        raise CheckError("Baseline entry limit exceeded or invalid file list")
    result = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise CheckError("Invalid baseline entry")
        path, fingerprint, indicators = entry.get("path"), entry.get("sha256"), entry.get("indicators")
        if (type(path) is not str or "\x00" in path or not PurePosixPath(path).is_absolute() or
                str(PurePosixPath(path)) != path or ".." in PurePosixPath(path).parts or path.startswith("//") or
                type(fingerprint) is not str or re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None or
                type(indicators) is not list or not indicators or len(indicators) > len(WEBSHELL_INDICATORS) or
                any(type(value) is not str or value not in WEBSHELL_INDICATORS for value in indicators)):
            raise CheckError("Baseline entries require an absolute canonical path, SHA256 and known indicator names")
        for indicator in indicators:
            key = (path, indicator)
            if key in result and result[key] != fingerprint:
                raise CheckError("Conflicting baseline entries")
            result[key] = fingerprint
            if len(result) > 10000:
                raise CheckError("Baseline entry limit exceeded or invalid file list")
    return result


def read_webshell_baseline(name):
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
        return webshell_baseline_entries(json.loads(b"".join(chunks).decode("utf-8")))
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
            report.add("INFO", "Webshell baseline", "Reviewed baseline loaded; exact path, SHA256 and indicator matches only; coverage is never accepted",
                       rule_id="P2S-WS005", resource="baseline", evidence=dict(baseline_entries=len(baseline)))
        except (OSError, ValueError, RecursionError, CheckError) as exc:
            reason = str(exc) if isinstance(exc, CheckError) else "Baseline path is unreadable or unsafe" if isinstance(exc, OSError) else "Baseline JSON or encoding is invalid"
            report.add("UNKNOWN", "Webshell baseline", "Baseline could not be validated; no baseline entries accepted; scan continues; " + reason,
                       rule_id="P2S-WS005", resource=dict(path=os.path.abspath(args.baseline)))
    stage(args, "Scanning local files for PHP webshell indicators")
    file_seconds = getattr(args, "scan_file_seconds", 2)
    for root in args.roots:
        reasons, seen, examined, attempted, read_bytes, findings, active, accepted = set(), 0, 0, 0, 0, 0, 0, 0
        deadline = time.monotonic() + args.walk_seconds if args.walk_seconds else float("inf")
        frames = []
        coverage = dict(root=root, paths=[], issue_count=0, omitted_paths=0, reason_counts={})
        report.discovery["webshell_coverage"].append(coverage)
        def record(path, reason):
            reasons.add(reason)
            coverage["issue_count"] += 1
            counts = coverage["reason_counts"]
            counts[reason] = counts.get(reason, 0) + 1
            if len(coverage["paths"]) < 1000:
                coverage["paths"].append(dict(path=path, reason=reason))
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
                    if opened.st_size > args.scan_file_bytes:
                        record(path, "file-size")
                        continue
                    chunks, size = [], 0
                    while True:
                        if time.monotonic() > file_deadline:
                            read_problem = timeout_reason
                            break
                        chunk = os.read(file_fd, min(65536, args.scan_file_bytes - size + 1, args.scan_total_bytes - read_bytes + 1))
                        if not chunk:
                            break
                        size += len(chunk)
                        read_bytes += len(chunk)
                        if size > args.scan_file_bytes or read_bytes > args.scan_total_bytes:
                            read_problem = "file-size" if size > args.scan_file_bytes else "total-bytes"
                            break
                        chunks.append(chunk)
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
                    hits, partial = webshell_indicators(data, file_deadline)
                    if entry.name.lower() in (".user.ini", ".htaccess", "php.ini"):
                        startup, startup_partial = webshell_startup_lines(data, entry.name.lower(), file_deadline)
                        hits.update({key:value for key,value in startup.items() if key not in hits})
                        partial = partial or startup_partial
                    if partial:
                        record(path, timeout_reason if partial == "time" else partial)
                    else:
                        examined += 1
                    fingerprint = digest(data)
                    for indicator, line in sorted(hits.items()):
                        approved = baseline.get((path, indicator)) == fingerprint
                        if not approved and active >= 200:
                            break
                        review = indicator in ("prefixed-include", "registry-callable")
                        rule = "P2S-WS004" if review else "P2S-WS002" if indicator == "startup-reference" else "P2S-WS001"
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
                     coverage_counts=coverage["reason_counts"], omitted_coverage_paths=coverage["omitted_paths"])
        report.add("UNKNOWN" if reasons else "INFO", "Webshell scan coverage",
            str(examined) + " files fully examined; " + str(attempted-examined) + " incomplete files; " + str(findings) + " indicators; " +
            ("incomplete: " + ", ".join(sorted(reasons)) if reasons else "selected scan completed") +
            "; absence of indicators does not establish a clean server",
            rule_id="P2S-WS003", resource=dict(root=root), evidence=facts)
    return report
