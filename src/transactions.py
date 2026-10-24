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
