def nginx_tokens(text):
    """A bounded lexer: quoted braces, comments and ${variables} stay distinct."""
    tokens, word, active, quote, line, word_line = [], [], False, None, 1, 1
    i = 0
    def flush():
        nonlocal word, active
        if active:
            tokens.append(("word", "".join(word), word_line))
            word, active = [], False
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            if i + 1 >= len(text):
                raise CheckError('Nginx: incomplete escape sequence')
            if not active:
                active, word_line = True, line
            following = text[i + 1]
            word.append({"t": "\t", "r": "\r", "n": "\n"}.get(following, following if following in "\\\"' #;{}" else "\\" + following))
            line += int(following == "\n")
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
            else:
                word.append(ch)
                line += int(ch == "\n")
            i += 1
            continue
        if ch in "\"'":
            if not active:
                active, word_line = True, line
            quote = ch
        elif ch == "#":
            flush()
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        elif ch.isspace():
            flush()
            line += int(ch == "\n")
        elif ch == "$" and text[i:i + 2] == "${":
            end = text.find("}", i + 2)
            if end < 0:
                raise CheckError('Nginx: incomplete variable')
            if not active:
                active, word_line = True, line
            word.append(text[i:end + 1])
            i = end
        elif ch in ";{}":
            flush()
            tokens.append(("symbol", ch, line))
        else:
            if not active:
                active, word_line = True, line
            word.append(ch)
        i += 1
        if len(tokens) > 2500000:
            raise CheckError('Nginx: token limit reached')
    if quote:
        raise CheckError('Nginx: unterminated string')
    flush()
    return tokens


def parse_nginx(text, source="<config>"):
    tokens, index = nginx_tokens(text), 0
    def block(depth=0, nested=False):
        nonlocal index
        if depth > 64:
            raise CheckError('Nginx: nesting limit reached')
        nodes = []
        while index < len(tokens):
            if tokens[index][:2] == ("symbol", "}"):
                if not nested:
                    raise CheckError('Nginx: unexpected block end')
                index += 1
                return nodes
            words = []
            start_line = tokens[index][2]
            while index < len(tokens) and tokens[index][0] == "word":
                words.append(tokens[index][1])
                index += 1
            if not words or index == len(tokens):
                raise CheckError(f'Nginx: incomplete directive ({source}:{start_line})')
            kind, symbol, _ = tokens[index]
            index += 1
            if symbol not in (";", "{"):
                raise CheckError(f'Nginx: unexpected delimiter ({source}:{start_line})')
            children = block(depth + 1, True) if symbol == "{" else None
            nodes.append(dict(name=words[0], args=words[1:], children=children,
                              source=source, line=start_line))
        if nested:
            raise CheckError('Nginx: missing block end')
        return nodes
    return block()


def read_nginx(config, partial=False):
    """Read configs, never execute nginx or load modules during discovery."""
    import glob
    config = Path(config)
    prefix, cache, budget = config.parent, {}, [0, 0]
    def load(path, stack):
        path = Path(path)
        for component in [path, *path.parents]:
            st = component.lstat()
            if st.st_uid != 0 or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022):
                raise CheckError(f'Nginx configuration is not protected by root ownership: {component}')
        resolved = trusted(path.resolve(strict=True))
        if str(resolved) in stack:
            raise CheckError(f'Nginx: include cycle at {resolved}')
        if str(resolved) not in cache:
            if not resolved.is_file() or resolved.stat().st_size > 1024 * 1024:
                raise CheckError('Nginx: configuration file too large or not a regular file')
            budget[0] += 1
            text = resolved.read_text()
            budget[1] += len(text)
            if budget[0] > 2048 or budget[1] > 8 * 1024 * 1024:
                raise CheckError('Nginx: read limit reached')
            cache[str(resolved)] = parse_nginx(text, str(path))
        return expand(cache[str(resolved)], [*stack, str(resolved)])
    def expand(nodes, stack):
        result = []
        def unresolved(node, message):
            result.append(dict(name="__p2s_unresolved_include__", args=[str(message)], children=None,
                               source=node["source"], line=node["line"]))
        for node in nodes:
            if node["name"] == "include" and node["children"] is None:
                if len(node["args"]) != 1 or "$" in node["args"][0]:
                    if not partial:
                        raise CheckError('Nginx: dynamic or invalid include')
                    unresolved(node, 'Nginx: dynamic or invalid include')
                    continue
                pattern = Path(node["args"][0])
                pattern = str(pattern if pattern.is_absolute() else prefix / pattern)
                paths = sorted(glob.glob(pattern))
                if not paths and not glob.has_magic(pattern):
                    if not partial:
                        raise CheckError(f'Nginx include missing: {pattern}')
                    unresolved(node, f'Nginx include missing: {pattern}')
                for child in paths:
                    try:
                        result.extend(load(child, stack))
                    except (OSError, UnicodeError, CheckError) as exc:
                        if not partial:
                            raise
                        unresolved(node, exc)
            else:
                copied = dict(node)
                if node["children"] is not None:
                    copied["children"] = expand(node["children"], stack)
                result.append(copied)
            if len(result) > 100000:
                raise CheckError('Nginx: expansion limit reached')
        return result
    return load(config, [])


def nginx_inventory(tree):
    from urllib.parse import quote
    inventory = dict(server="nginx", sites=[], roots=[], issues=[], skipped_proxy_servers=0)
    mappings, roots, issues = {}, set(), set()
    def issue(message):
        issues.add(message)
    def values(nodes, name):
        return [n["args"] for n in nodes if n["name"] == name and n["children"] is None]
    def directory(value, source):
        if not value or "$" in value or not Path(value).is_absolute():
            issue(f'{source}: dynamic or relative document path')
            return None
        path = Path(value)
        if not path.is_dir():
            issue(f'{source}: document path missing: {path}')
            return None
        if str(path) == "/" or path.parts[1] in ("etc", "proc", "sys", "dev", "run", "root", "usr"):
            issue(f'{source}: system path excluded from automatic scanning: {path}')
            return None
        if path.is_symlink() or str(path.resolve()) != str(path):
            issue(f'{source}: document path contains symlinks: {path}')
            return None
        roots.add(str(path))
        return str(path)
    def add_mapping(url, path, ip, source):
        if path is not None:
            mappings.setdefault(url, []).append(dict(url=url, root=path, connect_ip=ip, source=source))
    def unresolved(nodes):
        return [n for n in nodes if n["name"] == "__p2s_unresolved_include__"] + [u for n in nodes if n["children"] is not None for u in unresolved(n["children"])]
    for node in unresolved(tree):
        issue(node["args"][0])
    for http in [n for n in tree if n["name"] == "http" and n["children"] is not None]:
        inherited = values(http["children"], "root")
        for server in [n for n in http["children"] if n["name"] == "server" and n["children"] is not None]:
            nodes, source = server["children"], f"{server['source']}:{server['line']}"
            server_roots = values(nodes, "root") or inherited
            root = directory(server_roots[-1][0], source) if server_roots and len(server_roots[-1]) == 1 else None
            if unresolved(nodes):
                issue(f'{source}: server with unresolved includes excluded from automatic HTTP mapping')
                continue
            names = []
            for name in [v for group in values(nodes, "server_name") for v in group]:
                if re.fullmatch(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", name) and ".." not in name:
                    names.append(name.lower())
                else:
                    issue(f'{source}: wildcard, regex or default hostname requires an explicit --site')
            listeners = []
            for args in values(nodes, "listen") or [["80"]]:
                if not args:
                    continue
                address = args[0]
                if address.startswith("unix:") or any(v in args for v in ("quic", "udp")):
                    issue(f'{source}: Unix/UDP listener excluded from HTTP checks')
                    continue
                if address.isdigit():
                    ip, port = "127.0.0.1", int(address)
                elif re.fullmatch(r"(?:\*|0\.0\.0\.0|127\.\d+\.\d+\.\d+):\d+", address):
                    ip, value = address.rsplit(":", 1)
                    ip, port = ("127.0.0.1" if ip in ("*", "0.0.0.0") else ip), int(value)
                elif re.fullmatch(r"\[(?:::|::1)\]:\d+", address):
                    ip, port = "::1", int(address.rsplit(":", 1)[1])
                else:
                    issue(f'{source}: a specific listener requires an explicit local mapping')
                    continue
                if not 1 <= port <= 65535:
                    issue(f'{source}: invalid listener port')
                    continue
                listeners.append(("https" if "ssl" in args else "http", port, ip))
            # Prefer one address per URL: IPv4 if both IPv4 and IPv6 are bound.
            listeners = sorted(set(listeners), key=lambda v: v[2] != "127.0.0.1")
            variants = []
            for name in sorted(set(names)):
                seen = set()
                for scheme, port, ip in listeners:
                    url = f"{scheme}://{name}" + (f":{port}" if port != (443 if scheme == "https" else 80) else "")
                    if url not in seen:
                        variants.append((url, ip))
                        seen.add(url)
            if root is not None:
                for url, ip in variants:
                    add_mapping(url, root, ip, source)
            def locations(children, inherited_root):
                for node in children:
                    if node["children"] is None:
                        continue
                    if node["name"] != "location":
                        if values(node["children"], "root") or values(node["children"], "alias"):
                            issue(f'{source}: conditional document path is ambiguous')
                        continue
                    args, body = node["args"], node["children"]
                    candidate = args[-1] if args else ""
                    own_root, alias = values(body, "root"), values(body, "alias")
                    literal = candidate.startswith("/") and not any(x in candidate for x in ("$", "?", "#")) and args[:1] not in (["~"], ["~*"])
                    chosen_root = own_root[-1][0] if own_root and len(own_root[-1]) == 1 else inherited_root
                    if alias or own_root:
                        if not literal:
                            issue(f'{source}: regex or dynamic location path requires an explicit mapping')
                        else:
                            path = alias[-1][0] if alias and len(alias[-1]) == 1 else str(Path(chosen_root) / candidate.lstrip("/")) if chosen_root else ""
                            # Static file aliases have no directory tree to enumerate.
                            if path and "$" not in path and Path(path).is_file():
                                pass
                            else:
                                path = directory(path, source)
                                for url, ip in variants:
                                    add_mapping(url + quote(candidate.rstrip("/"), safe="/"), path, ip, source)
                    locations(body, chosen_root)
            locations(nodes, root)
            if root is None and not any(n["name"] == "location" and any(c["name"] in ("root", "alias") for c in n["children"] or []) for n in nodes):
                if values(nodes, "return"):
                    issue(f'{source}: redirect without a document root does not count as a file check')
                else:
                    inventory["skipped_proxy_servers"] += 1
                    issue(f'{source}: proxy or missing document root requires a separate backend audit')
    for url, entries in sorted(mappings.items()):
        if len({e["root"] for e in entries}) > 1:
            issue(f'Ambiguous document root for {url}; automatic HTTP check skipped')
        else:
            inventory["sites"].append(entries[0])
    inventory["roots"], inventory["issues"] = sorted(roots), sorted(issues)
    return inventory


def minimal_roots(paths):
    result = []
    for path in sorted(set(paths), key=lambda p: (len(Path(p).parts), p)):
        if not any(os.path.commonpath([path, parent]) == parent for parent in result):
            result.append(path)
    return result


def prepare_scope(args):
    """Derive read-only scope; never infer chmod/chown targets from discovery."""
    explicit_root, explicit_sites = args.root, list(args.site)
    inventory = dict(server=None, sites=[], roots=[], issues=[])
    if not explicit_sites and not args.no_auto:
        candidates = [Path(args.nginx_config)] if args.nginx_config else [p for p in map(Path, ("/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/usr/local/etc/nginx/nginx.conf")) if p.is_file()]
        if len(candidates) == 1:
            try:
                inventory = nginx_inventory(read_nginx(candidates[0], partial=True))
                inventory["config"] = str(candidates[0])
            except (OSError, UnicodeError, CheckError) as exc:
                inventory["issues"].append(f'Automatic Nginx discovery incomplete: {exc}')
        else:
            inventory["issues"].append('No unique Nginx main configuration; specify --nginx-config or --site/--root')
    sites, roots, addresses = [], [], {}
    if explicit_sites:
        sites = explicit_sites
        for site in sites:
            if "=" in site and Path(site.split("=", 1)[1]).is_absolute():
                roots.append(site.split("=", 1)[1])
    else:
        entries = inventory["sites"]
        if explicit_root:
            entries = [e for e in entries if os.path.commonpath([e["root"], explicit_root]) == explicit_root]
        # Prefer HTTPS, then shorter/root mappings before nested aliases.
        from urllib.parse import urlsplit
        entries = sorted(entries, key=lambda e: (bool(urlsplit(e["url"]).path), not e["url"].startswith("https://"), e["url"]))
        if len(entries) > args.max_sites:
            inventory["issues"].append(f'HTTP limit: {len(entries) - args.max_sites} mappings omitted; increase --max-sites or narrow the scope with --site')
        for entry in entries[:args.max_sites]:
            sites.append(entry["url"] + "=" + entry["root"])
            addresses[entry["url"]] = entry["connect_ip"]
        roots = inventory["roots"]
    if explicit_root:
        roots = [explicit_root]
    if not roots:
        roots = ["/var/www"]
        inventory["issues"].append('No unique document root; /var/www is only an explicitly reported filesystem fallback')
    args.roots, args.site, args.site_addresses = minimal_roots(roots), sites, addresses
    args.root = explicit_root or args.roots[0]
    inventory["scan_roots"], inventory["selected_sites"] = args.roots, sites
    inventory["automatic_changes"] = 'No permission-change targets inferred from discovery'
    args.discovery = inventory
    return args


def prepare_runtime_dirs(args):
    valid, issues = [], []
    for name in getattr(args, "runtime_dir", []):
        path = Path(os.path.normpath(name))
        try:
            if not path.is_absolute() or not path.is_dir() or path.resolve(strict=True) != path:
                raise CheckError("Runtime directory must be an existing absolute path without symlinks: " + name)
            if not any(os.path.commonpath([str(path), root]) == root and str(path) != root for root in getattr(args, "roots", [args.root])):
                raise CheckError("Runtime directory must be a strict subdirectory of the selected roots: " + name)
            valid.append(str(path))
        except (OSError, ValueError, CheckError) as exc:
            issues.append(str(exc))
    args.runtime_dirs = sorted(set(valid))
    if not hasattr(args, "discovery"):
        args.discovery = {}
    args.discovery["runtime_dirs"] = args.runtime_dirs
    args.discovery.setdefault("issues", []).extend(issues)
