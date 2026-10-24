"""Conservative upload-route checks. Never evaluate arbitrary PCRE or write probes."""


def nginx_directives(nodes, name):
    return [node["args"] for node in nodes if node["name"] == name and node["children"] is None]


def nginx_upload_route(http, server, uri):
    """One static URI witness; only an unambiguous leaf guard can prove a block."""
    nodes = server["children"]
    uncertain = {"if", "rewrite", "error_page", "__p2s_unresolved_include__"}
    def complex_nodes(body):
        return any(n["name"] in uncertain for n in body)
    if any(char in uri for char in ("?", "#", "%", "$")):
        return "UNKNOWN", "dynamic_path"
    if complex_nodes(http["children"]) or complex_nodes(nodes):
        return "UNKNOWN", "redirect_or_conditional"
    parent_names = {"server", "location", "root", "index", "listen", "server_name", "access_log", "error_log", "log_format",
                    "types", "default_type", "charset", "autoindex", "expires", "add_header", "log_not_found", "merge_slashes",
                    "map", "upstream", "geo", "sendfile", "tcp_nopush", "tcp_nodelay", "keepalive_timeout", "keepalive_requests",
                    "server_tokens", "server_names_hash_bucket_size", "server_names_hash_max_size", "types_hash_max_size"}
    if any(n["name"] not in parent_names and not n["name"].startswith(("ssl_", "gzip", "client_"))
           for n in http["children"] + nodes):
        return "UNKNOWN", "unsupported_directive"
    locations = [node for node in nodes if node["name"] == "location" and node["children"] is not None]
    if any(any(child["name"] == "location" for child in node["children"]) for node in locations):
        return "UNKNOWN", "nested_location"
    if any(nginx_directives(node["children"], "alias") for node in locations):
        return "UNKNOWN", "location_filesystem_mapping"
    prefix, regex = [], []
    for node in locations:
        args = node["args"]
        if len(args) == 1 and args[0].startswith("/"):
            modifier, path = "", args[0]
        elif len(args) == 2 and args[0] in ("=", "^~", "~", "~*"):
            modifier, path = args
        else:
            return "UNKNOWN", "unsupported_location"
        if modifier in ("~", "~*"):
            regex.append((path, node))
        else:
            if "$" in path or any(char in path for char in ("?", "#", "%")) or not path.startswith("/"):
                return "UNKNOWN", "dynamic_path"
            prefix.append((path, modifier, node))
    if len({(path, modifier == "=") for path, modifier, node in prefix}) != len(prefix):
        return "UNKNOWN", "duplicate_location"
    # A whole-directory guard must dominate every URI, not just one probe name.
    guards = [(path, node) for path, modifier, node in prefix if modifier == "^~" and uri.startswith(path)]
    if guards:
        path, guard = max(guards, key=lambda item: len(item[0]))
        body = guard["children"]
        returns = nginx_directives(body, "return")
        descendants = [p for p, modifier, node in prefix if node is not guard and
                       (p.startswith(uri) or modifier != "=" and uri.startswith(p) and len(p) > len(path))]
        allowed = {"return", "root", "access_log", "log_not_found", "add_header", "expires"}
        if (not descendants and not any(n["name"] not in allowed or n["children"] is not None for n in body) and
                len(returns) == 1 and len(returns[0]) == 1 and returns[0][0] in ("403", "404", "410", "444")):
            return "OK", "static_directory_rejection"
    witness = uri + "p2s-harden-probe.php"
    exact = [node for path, modifier, node in prefix if modifier == "=" and path == witness]
    matches = [(path, modifier, node) for path, modifier, node in prefix if modifier != "=" and witness.startswith(path)]
    chosen = exact[0] if exact else max(matches, key=lambda item: len(item[0]))[2] if matches else None
    selected_prefix = next((modifier for path, modifier, node in prefix if node is chosen), "")
    if not exact and selected_prefix != "^~":
        for pattern, node in regex:
            if pattern in (r"/\.(env|git)", r"/\.ht", r"/\.htaccess", r"/\.") and "/." not in witness:
                continue
            if pattern in (r"\.php$", r"\.php(/|$)", r"\.php(?:/|$)"):
                chosen = node
                break
            return "UNKNOWN", "unsupported_regex"
    if chosen is None:
        return "UNKNOWN", "no_proven_handler"
    body = chosen["children"]
    if complex_nodes(body) or any(n["children"] is not None for n in body):
        return "UNKNOWN", "redirect_or_conditional"
    body_names = {"return", "root", "alias", "try_files", "set", "access_log", "error_log", "log_not_found", "expires", "add_header", "default_type"}
    if any(n["name"] not in body_names and not n["name"].startswith(("fastcgi_", "client_")) for n in body):
        return "UNKNOWN", "unsupported_directive"
    if (any(args not in (["$uri", "=404"], ["$fastcgi_script_name", "=404"]) for args in nginx_directives(body, "try_files")) or
            any(args != ["$path_info", "$fastcgi_path_info"] for args in nginx_directives(body, "set")) or
            any(args not in ([r"^(.+?\.php)(/.*)$"], [r"^(.+\.php)(/.*)$"], [r"^(.+\.php)(/.+)$"]) for args in nginx_directives(body, "fastcgi_split_path_info"))):
        return "UNKNOWN", "redirect_or_conditional"
    if nginx_directives(body, "alias") or nginx_directives(body, "root"):
        return "UNKNOWN", "location_filesystem_mapping"
    passes = nginx_directives(body, "fastcgi_pass")
    scripts = [args[1:] for args in nginx_directives(body, "fastcgi_param") if args[:1] == ["SCRIPT_FILENAME"]]
    if (len(passes) == 1 and len(passes[0]) == 1 and "$" not in passes[0][0] and len(scripts) == 1 and
            scripts[0] in (["$document_root$fastcgi_script_name"], ["$realpath_root$fastcgi_script_name"]) and
            not nginx_directives(body, "return")):
        return "OPEN", "php_fastcgi_mapping"
    return "UNKNOWN", "no_proven_handler"


def nginx_upload_security(report, args):
    requested = list(getattr(args, "runtime_dirs", []))
    tree = getattr(args, "nginx_tree", None)
    config = getattr(args, "nginx_config", None)
    if tree is None and config:
        try:
            tree = read_nginx(Path(config), partial=True)
        except (OSError, UnicodeError, CheckError):
            tree = None
    if tree is None:
        report.add("UNKNOWN" if requested else "INFO", "Nginx upload execution", "No parsed Nginx configuration for upload checks; provide --nginx-config and declare storage with --runtime-dir. No upload file or HTTP probe is created.",
                   rule_id="P2S-NGX001", resource="upload_scope", evidence=dict(outcome="not_assessed", candidate_count=len(requested)))
        return
    pending, alias_present = list(tree), False
    while pending:
        node = pending.pop()
        alias_present |= node["name"] == "alias"
        pending.extend(node["children"] or [])
    seen, mapped, server_index = set(), set(), 0
    for http in [node for node in tree if node["name"] == "http" and node["children"] is not None]:
        inherited = nginx_directives(http["children"], "root")
        for server in [node for node in http["children"] if node["name"] == "server" and node["children"] is not None]:
            server_index += 1
            roots = nginx_directives(server["children"], "root") or inherited
            if len(roots) != 1 or len(roots[0]) != 1 or "$" in roots[0][0] or not Path(roots[0][0]).is_absolute():
                continue
            root = os.path.normpath(roots[0][0])
            targets = set(requested)
            for suffix in ("uploads", "wp-content/uploads"):
                candidate = str(Path(root) / suffix)
                if Path(candidate).is_dir():
                    targets.add(candidate)
            for target in sorted(targets):
                if not any(os.path.commonpath([target, selected]) == selected for selected in getattr(args, "roots", [args.root])):
                    continue
                if os.path.commonpath([root, target]) != root:
                    continue
                key = (server_index, target)
                if key in seen:
                    continue
                if len(seen) >= 128:
                    report.add("UNKNOWN", "Nginx upload execution", "Upload mapping limit reached; narrow the selected scope.", rule_id="P2S-NGX001", resource="upload_limit", evidence=dict(outcome="limit"))
                    return
                seen.add(key); mapped.add(target)
                uri = "/" if target == root else "/" + str(Path(target).relative_to(root)).replace(os.sep, "/").rstrip("/") + "/"
                status, outcome = nginx_upload_route(http, server, uri)
                if status == "OK" and alias_present:
                    status, outcome = "UNKNOWN", "location_filesystem_mapping"
                details = {"OK": "A static rejection guards the selected upload URI prefix in this parsed server block; alternate application includes and live-worker/network enforcement are not attested.",
                           "OPEN": "An upload PHP URI has a FastCGI script mapping in the parsed configuration. An existing uploaded PHP file may execute; live application reachability is not tested.",
                           "UNKNOWN": "Upload execution could not be established from the supported static Nginx subset; inspect aliases, regex order, nested locations and internal redirects manually."}
                report.add(status, "Nginx upload execution " + target, details[status] + " No upload file or HTTP probe is created.",
                           rule_id="P2S-NGX001", resource=dict(path=target, root=root, uri=uri, config=server["source"], line=server["line"], server_index=server_index),
                           evidence=dict(outcome=outcome, declared=target in requested, candidate_count=1, configuration_only=True))
    for target in requested:
        if target not in mapped:
            report.add("UNKNOWN", "Nginx upload execution " + target, "Declared storage has no unambiguous static Nginx root mapping; inspect aliases and the intended virtual host manually.",
                       rule_id="P2S-NGX001", resource=dict(path=target), evidence=dict(outcome="unmapped", declared=True))
    if not seen and not requested:
        report.add("INFO", "Nginx upload execution", "No upload storage identified; use --runtime-dir for actual writable storage. Directory names alone do not establish an application's upload paths.",
                   rule_id="P2S-NGX001", resource="upload_scope", evidence=dict(outcome="not_assessed", candidate_count=0))
