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
