"""Interoperable Unicode display with lossless Linux filesystem byte metadata."""


PATH_ENCODING = "utf-8-replacement+bytes-hex"


def unicode_display(value):
    return re.sub(r"[\ud800-\udfff]", "\ufffd", value)


def json_paths(value):
    """Project output only; identities and filesystem operations keep raw paths."""
    if isinstance(value, str):
        return unicode_display(value)
    if isinstance(value, (list, tuple)):
        return [json_paths(item) for item in value]
    if not isinstance(value, dict):
        return value
    # Escaped key spellings avoid collapsing distinct byte-valued map keys.
    result = {re.sub(r"[\ud800-\udfff]", lambda match: "\\u%04x" % ord(match[0]), key) if isinstance(key, str) else key: json_paths(item)
              for key, item in value.items()}
    for key in ("path", "root"):
        path = value.get(key)
        if isinstance(path, str) and re.search(r"[\udc80-\udcff]", path):
            result[key + "_bytes_hex"] = path.encode("utf-8", "surrogateescape").hex()
            result[key + "_encoding"] = PATH_ENCODING
    return result


def baseline_path(entry):
    """Decode exact bytes only if the display spelling and encoding agree."""
    path = entry.get("path")
    if "path_bytes_hex" not in entry:
        if "path_encoding" in entry:
            raise CheckError("Baseline path encoding requires matching path_bytes_hex")
        return path  # Legacy local reports/baselines remain readable.
    raw = entry["path_bytes_hex"]
    if (type(raw) is not str or not 2 <= len(raw) <= 65536 or len(raw) % 2 or
            re.fullmatch(r"[a-f0-9]+", raw) is None or entry.get("path_encoding") != PATH_ENCODING):
        raise CheckError("Invalid baseline path byte encoding")
    decoded = bytes.fromhex(raw).decode("utf-8", "surrogateescape")
    if type(path) is not str or path != unicode_display(decoded):
        raise CheckError("Baseline display path does not match its exact bytes")
    return decoded
