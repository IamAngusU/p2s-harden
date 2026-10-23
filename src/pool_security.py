"""Read-only FPM boundaries; never infer Internet reachability or tenant intent."""


def pool_effective(values, settings, key):
    value = values.get(key)
    for prefix in ("php_value", "php_flag", "php_admin_value", "php_admin_flag"):
        override = settings.get(prefix + "[" + key + "]")
        if override is not None and override != "undefined":
            value = override
    return value


def pool_security(report, instance):
    for pool, settings in instance["pools"].items():
        resource = dict(config=instance["config"], pool=pool)
        title = "FPM listener [" + pool + "] " + instance["config"]
        listener = settings.get("listen", "").strip()
        if listener.startswith("/"):
            raw_mode = settings.get("listen.mode", "0660")
            if raw_mode == "undefined":
                raw_mode = "0660"
            if not re.fullmatch(r"0?[0-7]{3}", raw_mode):
                status, detail = "UNKNOWN", "Cannot parse the configured Unix socket mode"
            else:
                world = int(raw_mode, 8) & 0o002
                status = "OPEN" if world else "OK"
                detail = "Configured Unix socket mode: " + raw_mode
            report.add(status, title, detail, rule_id="P2S-FPM002", resource=dict(resource, source="configured"))
            try:
                path = Path(listener)
                if any(p.is_symlink() for p in (path, *path.parents)):
                    raise CheckError("Unix socket path has a symlink; verify the effective endpoint separately")
                actual = path.lstat()
                if not stat.S_ISSOCK(actual.st_mode):
                    raise CheckError("Configured Unix socket is missing or is not a socket")
                mode = stat.S_IMODE(actual.st_mode)
                report.add("OPEN" if mode & 0o002 else "OK", title,
                           "Observed Unix socket mode: " + format(mode, "04o") + "; " + listener,
                           rule_id="P2S-FPM002", resource=dict(resource, source="observed"))
            except (OSError, CheckError) as exc:
                report.add("UNKNOWN", title, str(exc), rule_id="P2S-FPM002", resource=dict(resource, source="observed"))
            if any(settings.get(key, "") not in ("", "undefined") for key in ("listen.acl_users", "listen.acl_groups")):
                report.add("INFO", title, "Named Unix socket ACL grants require individual review; owner/group settings may be ignored",
                           rule_id="P2S-FPM002", resource=dict(resource, source="acl"))
        else:
            try:
                if listener.isdigit():
                    host, port = "0.0.0.0", listener
                elif listener.startswith("[") and "]:" in listener:
                    host, port = listener[1:].rsplit("]:", 1)
                elif listener.count(":") == 1:
                    host, port = listener.rsplit(":", 1)
                    host = "0.0.0.0" if host in ("", "*") else host
                else:
                    raise ValueError()
                if not port.isdigit() or not 1 <= int(port) <= 65535:
                    raise ValueError()
                address = ipaddress.ip_address(host)
                clients = settings.get("listen.allowed_clients", "").strip()
                restricted = clients not in ("", "undefined")
                if restricted:
                    # PHP documents individual IPs, not hostnames/CIDR/wildcards.
                    # Never resolve names or claim that a firewall was inspected.
                    for client in clients.split(","):
                        ipaddress.ip_address(client.strip())
                local = address.is_loopback or (getattr(address, "ipv4_mapped", None) is not None and address.ipv4_mapped.is_loopback)
                status = "OK" if local or restricted else "OPEN"
                detail = ("Loopback TCP bind; local processes can still connect" if local else
                          "Network TCP bind with an explicit client allowlist; verify firewall and network reachability separately" if restricted else
                          "Network TCP bind accepts any client address; firewall and Internet reachability were not assessed")
                report.add(status, title, detail + "; " + listener, rule_id="P2S-FPM001", resource=resource)
            except ValueError:
                report.add("UNKNOWN", title, "Cannot classify the TCP listener or client allowlist; use literal IP addresses and verify the effective endpoint",
                           rule_id="P2S-FPM001", resource=resource)
        extensions = settings.get("security.limit_extensions", ".php .phar")
        tokens = extensions.split() if extensions != "undefined" else []
        status = "OPEN" if not tokens or any(t not in (".php", ".phar") for t in tokens) else "OK" if set(tokens) == {".php"} else "INFO"
        report.add(status, "FPM script extensions [" + pool + "] " + instance["config"],
                   "Allowed main-script extensions: " + extensions + "; .php is the narrow recommended setting" if tokens else
                   "Main-script extensions are unrestricted; set security.limit_extensions=.php after application review",
                   rule_id="P2S-FPM003", resource=resource)
        clear = settings.get("clear_env", "yes").lower()
        status = "OK" if clear in ("yes", "on", "1", "true") else "OPEN" if clear in ("no", "off", "0", "false", "") else "UNKNOWN"
        report.add(status, "FPM environment clearing [" + pool + "] " + instance["config"],
                   "clear_env=" + clear + "; explicit pool env[] values are not printed",
                   rule_id="P2S-FPM004", resource=resource)
        ffi = pool_effective(instance["values"], settings, "ffi.enable") if "ffi.enable" in instance["values"] else None
        if ffi is not None:
            value = ffi.lower()
            status = "OK" if value in ("off", "0", "false", "no", "") else "INFO" if value == "preload" else "OPEN" if value in ("on", "1", "true", "yes") else "UNKNOWN"
            report.add(status, "PHP FFI [" + pool + "] " + instance["config"],
                       "ffi.enable=" + ffi + "; native/preloaded code requires separate review; function restrictions are defense in depth",
                       rule_id="P2S-PHP004", resource=resource)


def shared_pool_users(report, instances):
    identities = {}
    for instance in instances:
        for pool, settings in instance["pools"].items():
            try:
                user = pwd.getpwnam(settings.get("user", ""))
            except KeyError:
                continue  # The independent permission checks report missing users.
            identities.setdefault(user.pw_uid, []).append(dict(config=instance["config"], pool=pool))
    for uid, pools in sorted(identities.items()):
        if len(pools) > 1:
            report.add("INFO", "Shared FPM account", str(len(pools)) + " pools share UID " + str(uid) + "; they do not form a Unix-user isolation boundary",
                       rule_id="P2S-FPM005", resource=dict(uid=uid, pools=pools))
