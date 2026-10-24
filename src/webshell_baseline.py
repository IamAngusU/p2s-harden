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
    return dict(path=str(path), indicator_files=len(draft["files"]), coverage_files=len(draft["reviewed_files"]))
