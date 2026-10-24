"""Local indicator triage. Never execute, decode payloads, upload or alter files."""

WEBSHELL_INDICATORS = {
    "request-execution": "Request data near a code/command execution sink",
    "encoded-execution": "Decoder output near a PHP code execution sink",
    "request-include": "Request data near a PHP include/require",
    "request-callable": "Request-selected dynamic function call",
    "network-shell": "Network connection and shell launch in one PHP file",
    "startup-reference": "PHP startup-file directive requires verification",
    "prefixed-include": "Indirect input in a constant-prefixed PHP include requires review",
    "registry-callable": "Request-selected registry callback requires review",
}
WEBSHELL_REASONS = ("access", "symlink", "mount", "special", "changed", "depth",
                   "entries", "time", "file-time", "file-size", "total-bytes", "tokens", "expression", "findings", "config-syntax")
_WS_SOURCE = frozenset(("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES"))
_WS_SINKS = REQUIRED | frozenset(("eval", "assert", "create_function"))
_WS_DECODERS = frozenset(("base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "hex2bin"))
_WS_NETWORK = frozenset(("fsockopen", "pfsockopen", "stream_socket_client", "socket_connect"))
_WS_CALLBACKS = frozenset(("call_user_func", "call_user_func_array", "array_map"))
_WS_CALLS = _WS_SINKS | _WS_NETWORK | _WS_CALLBACKS
_WS_TOKEN = re.compile(r"\$[A-Za-z_][A-Za-z_0-9]*|\\?[A-Za-z_][A-Za-z_0-9\\]*|->|\?->|::|==|=>|!=|<=|>=|\?\?|&&|\|\||[^\s]", re.ASCII)
_WS_OPEN = re.compile(r"<\?(?:php\b|=|(?!xml\b))", re.I | re.ASCII)
_WS_HEREDOC = re.compile(r"<<<[ \t]*(?:'([A-Za-z_][A-Za-z_0-9]{0,127})'|\"([A-Za-z_][A-Za-z_0-9]{0,127})\"|([A-Za-z_][A-Za-z_0-9]{0,127}))[ \t]*\r?\n")
_WS_LINE_END = re.compile(r"\n|\?>")
_WS_WHITESPACE = re.compile(r"\s+")


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
            pos = _WS_WHITESPACE.match(source, pos).end()
            continue
        if source.startswith("/*", pos):
            end = source.find("*/", pos + 2)
            pos = len(source) if end < 0 else end + 2
            continue
        if source.startswith("//", pos) or source[pos] == "#" and not source.startswith("#[", pos):
            # Search only as far as this line's end. Repeated suffix searches
            # for a nonexistent closing tag made comment-heavy input quadratic.
            end = _WS_LINE_END.search(source, pos)
            pos = (end.start() if end[0] == "?>" else end.end()) if end else len(source)
            continue
        start = pos
        quote = source[pos]
        if quote in ("'", '"', "`"):
            pos += 1
            while pos < len(source):
                if pos % 4096 == 0 and time.monotonic() > deadline:
                    return tokens, "time"
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
    hits, aliases, registry_aliases, decoded, complex_values, constants, pairs, stack = {}, set(), set(), set(), set(), {}, {}, []
    for index, token in enumerate(tokens):
        if index % 1024 == 0 and time.monotonic() > deadline:
            return {}, "time"
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
    def request(items, with_aliases=True):
        for kind, value, _ in items:
            if kind == "variable" and (value in _WS_SOURCE or with_aliases and value in aliases):
                return True
            if kind in ("interpolated", "backtick"):
                if any(m[0] in _WS_SOURCE or with_aliases and m[0] in aliases for m in re.finditer(r"\$[A-Za-z_][A-Za-z_0-9]*", value, re.ASCII)):
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
    def uncertain(items):
        return any(kind == "variable" and value in complex_values or
                   kind in ("interpolated", "backtick") and any(m[0] in complex_values for m in re.finditer(r"\$[A-Za-z_][A-Za-z_0-9]*", value, re.ASCII))
                   for kind, value, _ in items)
    def add(indicator, offset):
        # One row per rule/file, earliest line; no attacker-controlled excerpt.
        if indicator not in hits:
            hits[indicator] = source.count("\n", 0, offset) + 1
    def registry(items):
        if len(items) == 1 and items[0][0] == "variable":
            return items[0][1] in registry_aliases
        if (len(items) <= 3 or items[0][0] != "variable" or items[0][1] in _WS_SOURCE or
                items[0][1] in aliases and items[0][1] not in registry_aliases):
            return False
        position = 1
        while position < len(items):
            if items[position][:2] != ("code", "["):
                return False
            nesting = 1
            position += 1
            while position < len(items) and nesting:
                if items[position][0] == "code":
                    nesting += int(items[position][1] == "[") - int(items[position][1] == "]")
                position += 1
            if nesting:
                return False
        return True
    def prefixed(items):
        # This changes triage priority only, never asserts that a prefix stops
        # traversal. Direct request expressions retain the higher-priority rule.
        if items and items[0][:2] == ("code", "("):
            items = items[1:]
        return (len(items) > 2 and items[1][:2] == ("code", ".") and
                (items[0][0] == "string" and items[0][1].endswith("/") or
                 items[0][0] == "code" and re.fullmatch(r"[A-Z_][A-Z_0-9]*", items[0][1]) is not None))
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
                scopes.append((depth, aliases, registry_aliases, decoded, complex_values, constants))
                aliases, registry_aliases, decoded, complex_values, constants, pending_function = set(), set(), set(), set(), {}, False
        if kind == "code" and value == "}":
            if scopes and scopes[-1][0] == depth:
                _, aliases, registry_aliases, decoded, complex_values, constants = scopes.pop()
            depth = max(0, depth - 1)
        if kind == "variable" and index + 1 < len(tokens) and tokens[index + 1][1] == "=":
            end = index + 2
            while end < min(len(tokens), index + 514) and tokens[end][:2] != ("code", ";"):
                end += 1
            expression = tokens[index + 2:end]
            tainted = request(expression)
            from_registry = registry(expression) or len(expression) == 1 and expression[0][0] == "variable" and expression[0][1] in registry_aliases
            packed = encoded(expression)
            complex_value = end == index + 514 or uncertain(expression)
            aliases.discard(value)
            registry_aliases.discard(value)
            decoded.discard(value)
            complex_values.discard(value)
            constants.pop(value, None)
            if tainted:
                aliases.add(value)
            if from_registry:
                registry_aliases.add(value)
            if packed:
                decoded.add(value)
            if complex_value:
                complex_values.add(value)
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
                expression = tokens[index + 1:end]
                add("prefixed-include" if prefixed(expression) and not request(expression, False) else "request-include", offset)
            if uncertain(tokens[index + 1:end]):
                incomplete = incomplete or "expression"
        if index + 1 >= len(tokens) or tokens[index + 1][1] != "(":
            continue
        if name not in _WS_CALLS and not (kind == "variable" and (value in aliases or value in complex_values)) and value != "]":
            continue
        end = pairs.get(index + 1)
        if end is None or end - index > 512:
            incomplete = incomplete or "expression"
            continue
        arguments = tokens[index + 2:end]
        if name in _WS_SINKS and uncertain(arguments) or kind == "variable" and value in complex_values:
            incomplete = incomplete or "expression"
        if name in _WS_NETWORK:
            network_offset = offset if network_offset is None else network_offset
        if name in REQUIRED:
            for arg_kind, arg_value, _ in arguments:
                if arg_kind in ("string", "interpolated") and len(arg_value) <= 1024 and re.search(r"(?:^|[\s/])(?:ba|da|a|k|z)?sh(?:\s|$)|cmd\.exe|powershell(?:\.exe)?", arg_value, re.I):
                    shell_offset = offset if shell_offset is None else shell_offset
                    if "/dev/tcp/" in arg_value:
                        network_offset = offset if network_offset is None else network_offset
        if kind == "variable" and value in aliases:
            add("registry-callable" if value in registry_aliases else "request-callable", offset)
        if name in _WS_CALLBACKS:
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
                add("registry-callable" if registry(arguments[:argument_end]) else "request-callable", offset)
            if uncertain(arguments[:argument_end]):
                incomplete = incomplete or "expression"
        if value == "]" and index in closing:
            begin = closing[index]
            base = begin - 1
            while base in closing and tokens[base][1] == "]":
                base = closing[base] - 1
            if base >= 0 and request(tokens[base:index + 1]):
                add("registry-callable" if registry(tokens[base:index + 1]) else "request-callable", offset)
        if name in _WS_SINKS and request(arguments):
            add("request-execution", offset)
        if name in ("eval", "assert", "create_function"):
            if encoded(arguments):
                add("encoded-execution", offset)
    if network_offset is not None and shell_offset is not None:
        add("network-shell", min(network_offset, shell_offset))
    return hits, incomplete
