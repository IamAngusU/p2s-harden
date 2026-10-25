"""Conservative upload-route checks. No arbitrary PCRE evaluation or probes."""


def nginx_directives(nodes, name):
    return [node["args"] for node in nodes if node["name"] == name and node["children"] is None]


def nginx_php_pattern(pattern, insensitive=False):
    """Parse a finite grammar, never compile configuration text as a regex.

    Prefixes are literal ASCII path segments with at most one literal choice
    per segment (64 expanded paths total). Only PHP-family suffixes are known.
    """
    if len(pattern) > 2048:
        return None
    dot_all = pattern.startswith("(?s)")
    if dot_all:
        pattern = pattern[4:]
    suffix = next((end for end in ("$", "(/|$)", "(?:/|$)") if pattern.endswith(end)), None)
    if suffix is None:
        return None
    stem = pattern[:-len(suffix)]
    if r"\." not in stem:
        return None
    head, extensions = stem.rsplit(r"\.", 1)
    if extensions.startswith("(?:") and extensions.endswith(")"):
        extensions = extensions[3:-1]
    elif extensions.startswith("(") and extensions.endswith(")"):
        extensions = extensions[1:-1]
    extensions = extensions.split("|")
    if not extensions or any(value not in ("php", "phtml", "phar") for value in extensions):
        return None
    if head == "":
        prefixes = [""]
        dot_all = True  # Unanchored suffixes do not exclude earlier line breaks.
    elif head.startswith("^/") and head.endswith("/.*"):
        prefixes = ["/"]
        for segment in head[2:-3].split("/"):
            if segment.startswith("(?:") and segment.endswith(")"):
                values = segment[3:-1].split("|")
            elif segment.startswith("(") and segment.endswith(")"):
                values = segment[1:-1].split("|")
            else:
                values = [segment]
            if not values or any(re.fullmatch(r"[A-Za-z0-9_-]+", value) is None for value in values):
                return None
            if len(prefixes) * len(values) > 64:
                return None
            prefixes = [prefix + value + "/" for prefix in prefixes for value in values]
    else:
        return None
    return dict(prefixes=prefixes, extensions=set(extensions), insensitive=insensitive, path_info=suffix != "$", dot_all=dot_all)


def nginx_rejection(body):
    """An unconditional leaf: no access bypasses, redirects or content modules."""
    allowed = {"deny", "return", "access_log", "log_not_found", "add_header", "expires"}
    if any(node["children"] is not None or node["name"] not in allowed for node in body):
        return False
    returns, denies = nginx_directives(body, "return"), nginx_directives(body, "deny")
    if returns:
        return len(returns) == 1 and len(returns[0]) == 1 and returns[0][0] in ("403", "404", "410", "444")
    return denies == [["all"]]


def nginx_fastcgi_mapping(body):
    allowed = {"try_files", "set", "access_log", "error_log", "log_not_found", "expires", "add_header", "default_type"}
    if any(node["children"] is not None or (node["name"] not in allowed and not node["name"].startswith(("fastcgi_", "client_"))) for node in body):
        return False
    if (any(args not in (["$uri", "=404"], ["$fastcgi_script_name", "=404"]) for args in nginx_directives(body, "try_files")) or
            any(args != ["$path_info", "$fastcgi_path_info"] for args in nginx_directives(body, "set")) or
            any(args not in ([r"^(.+?\.php)(/.*)$"], [r"^(.+\.php)(/.*)$"], [r"^(.+\.php)(/.+)$"]) for args in nginx_directives(body, "fastcgi_split_path_info"))):
        return False
    passes = nginx_directives(body, "fastcgi_pass")
    scripts = [args[1:] for args in nginx_directives(body, "fastcgi_param") if args[:1] == ["SCRIPT_FILENAME"]]
    return (len(passes) == 1 and len(passes[0]) == 1 and "$" not in passes[0][0] and len(scripts) == 1 and
            scripts[0] in (["$document_root$fastcgi_script_name"], ["$realpath_root$fastcgi_script_name"]))


def nginx_upload_route(http, server, uri):
    """Prove rejection over a bounded URI language, not one lucky filename."""
    nodes = server["children"]
    if any(char in uri for char in ("?", "#", "%", "$")) or not uri.isascii() or not uri.isprintable():
        return "UNKNOWN", "dynamic_path"
    uncertain = {"if", "rewrite", "error_page", "__p2s_unresolved_include__"}
    if any(node["name"] in uncertain for node in http["children"] + nodes):
        return "UNKNOWN", "redirect_or_conditional"
    if any(args != ["on"] for body in (http["children"], nodes) for args in nginx_directives(body, "merge_slashes")):
        return "UNKNOWN", "unsupported_directive"
    parent_names = {"server", "location", "root", "index", "listen", "server_name", "access_log", "error_log", "log_format",
                    "types", "default_type", "charset", "autoindex", "expires", "add_header", "log_not_found", "merge_slashes",
                    "map", "upstream", "geo", "sendfile", "tcp_nopush", "tcp_nodelay", "keepalive_timeout", "keepalive_requests",
                    "server_tokens", "server_names_hash_bucket_size", "server_names_hash_max_size", "types_hash_max_size"}
    if any(node["name"] not in parent_names and not node["name"].startswith(("ssl_", "gzip", "client_")) for node in http["children"] + nodes):
        return "UNKNOWN", "unsupported_directive"
    prefix, regex = [], []
    locations = [n for n in nodes if n["name"] == "location" and n["children"] is not None]
    if len(locations) > 512:
        return "UNKNOWN", "limit"
    for node in locations:
        args = node["args"]
        if len(args) == 1 and args[0].startswith("/"):
            modifier, path = "", args[0]
        elif len(args) == 2 and args[0] in ("=", "^~", "~", "~*"):
            modifier, path = args
        else:
            return "UNKNOWN", "unsupported_location"
        if nginx_directives(node["children"], "alias"):
            return "UNKNOWN", "location_filesystem_mapping"
        if modifier in ("~", "~*"):
            regex.append((path, modifier, node))
        else:
            if not path.startswith("/") or not path.isascii() or any(char in path for char in "$?#%"):
                return "UNKNOWN", "dynamic_path"
            prefix.append((path, modifier, node))
    if len({(path, modifier == "=") for path, modifier, node in prefix}) != len(prefix):
        return "UNKNOWN", "duplicate_location"
    # Competing exact/descendant prefixes can bypass regex selection for a
    # different filename. Never certify a directory using just one witness.
    matches = [(path, modifier, node) for path, modifier, node in prefix if modifier != "=" and uri.startswith(path)]
    selected = max(matches, key=lambda item: len(item[0])) if matches else None
    competing = any(path.startswith(uri) and (selected is None or node is not selected[2]) for path, modifier, node in prefix)
    nested = [(path, modifier, node) for path, modifier, node in prefix if any(child["name"] == "location" for child in node["children"])]
    if nested and (len(nested) != 1 or selected != nested[0] or selected[1] != "^~"):
        return "UNKNOWN", "nested_location"
    if selected and selected[1] == "^~":
        body = selected[2]["children"]
        if not competing and nginx_rejection(body):
            return "OK", "static_directory_rejection"
        if nested and not competing:
            static = [node for node in body if node["name"] != "location"]
            if any(node["children"] is not None or node["name"] not in {"access_log", "log_not_found", "expires", "add_header", "try_files"} for node in static):
                return "UNKNOWN", "unsupported_directive"
            if any(args != ["$uri", "=404"] for args in nginx_directives(static, "try_files")):
                return "UNKNOWN", "redirect_or_conditional"
            guarded_php = False
            for child in (node for node in body if node["name"] == "location"):
                args = child["args"]
                parsed = nginx_php_pattern(args[1], args[0] == "~*") if len(args) == 2 and args[0] in ("~", "~*") else None
                if not parsed or parsed["prefixes"] != [""] or not nginx_rejection(child["children"]):
                    return "UNKNOWN", "nested_location"
                guarded_php |= "php" in parsed["extensions"]
            if guarded_php:
                return "OK", "nested_php_rejection"
        return "UNKNOWN", "no_proven_handler"
    if nested:
        return "UNKNOWN", "nested_location"
    guards, handlers = [], 0
    def relevant(pattern):
        return any(uri.lower().startswith(path.lower()) or path.lower().startswith(uri.lower()) if pattern["insensitive"] else
                   uri.startswith(path) or path.startswith(uri) for path in pattern["prefixes"])
    def covers(guard, handler, check_lines=True):
        if not handler["extensions"].issubset(guard["extensions"]) or handler["insensitive"] and not guard["insensitive"] or handler["path_info"] and not guard["path_info"]:
            return False
        if check_lines and handler["dot_all"] and not guard["dot_all"]:
            return False
        # Only a guard that covers the complete selected directory can approve
        # a handler. Narrow partial guards never turn uncovered paths green.
        return any((uri.lower().startswith(path.lower()) if guard["insensitive"] else uri.startswith(path)) for path in guard["prefixes"])
    for text, modifier, node in regex:
        if text in (r"/\.(env|git)", r"/\.ht", r"/\.htaccess", r"/\.") and nginx_rejection(node["children"]):
            continue
        parsed = nginx_php_pattern(text, modifier == "~*")
        if parsed is None:
            return "UNKNOWN", "unsupported_regex"
        if not relevant(parsed):
            continue
        if nginx_rejection(node["children"]):
            guards.append(parsed)
        elif nginx_fastcgi_mapping(node["children"]):
            handlers += 1
            if not any(covers(guard, parsed) for guard in guards):
                return "OPEN", "regex_line_break_gap" if any(covers(guard, parsed, check_lines=False) for guard in guards) else "php_fastcgi_mapping"
        else:
            return "UNKNOWN", "no_proven_handler"
    if handlers and guards:
        if selected and any(node["children"] is not None or node["name"] not in
                            {"access_log", "error_log", "log_not_found", "add_header", "expires", "try_files", "index", "default_type"}
                            for node in selected[2]["children"]):
            return "UNKNOWN", "unsupported_directive"
        return ("UNKNOWN", "competing_location") if competing else ("OK", "ordered_php_rejection")
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
                if not getattr(tree, "snapshot_complete", True):
                    status, outcome = "UNKNOWN", "configuration_snapshot_incomplete"
                if status == "OK" and alias_present:
                    status, outcome = "UNKNOWN", "location_filesystem_mapping"
                details = {"OK": "A static rejection guards the selected upload URI prefix in this parsed server block; alternate application includes and live-worker/network enforcement are not attested.",
                           "OPEN": "An upload PHP URI has a FastCGI script mapping in the parsed configuration. An existing uploaded PHP file may execute; live application reachability is not tested.",
                           "UNKNOWN": "Upload execution could not be established from the supported static Nginx subset; inspect aliases, regex order, nested locations and internal redirects manually."}
                row = report.add(status, "Nginx upload execution " + target, (("The upload denial uses .* without DOTALL; a URL-decoded line break can bypass it and select the PHP handler. " if outcome == "regex_line_break_gap" else "") + details[status]) + " No upload file or HTTP probe is created.",
                           rule_id="P2S-NGX001", resource=dict(path=target, root=root, uri=uri, config=server["source"], line=server["line"], server_index=server_index),
                           evidence=dict(outcome=outcome, declared=target in requested, candidate_count=1, configuration_only=True))
                snapshot = getattr(tree, "snapshot_sha256", None)
                if status == "UNKNOWN" and outcome in NGINX_REVIEWABLE and snapshot:
                    row["nginx_review"] = dict(finding_id=row["id"], snapshot_sha256=snapshot, outcome=outcome)
    for target in requested:
        if target not in mapped:
            report.add("UNKNOWN", "Nginx upload execution " + target, "Declared storage has no unambiguous static Nginx root mapping; inspect aliases and the intended virtual host manually.",
                       rule_id="P2S-NGX001", resource=dict(path=target), evidence=dict(outcome="unmapped", declared=True))
    if not seen and not requested:
        report.add("INFO", "Nginx upload execution", "No upload storage identified; use --runtime-dir for actual writable storage. Directory names alone do not establish an application's upload paths.",
                   rule_id="P2S-NGX001", resource="upload_scope", evidence=dict(outcome="not_assessed", candidate_count=0))
