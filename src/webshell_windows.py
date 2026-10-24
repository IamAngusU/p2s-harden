"""Bounded leads from explicit PHP openers; windows never certify full coverage."""


def webshell_collect_openers(probe, offset, preceding_lines, openers, maximum, complete=False):
    if len(openers) >= maximum:
        return
    for match in _WS_EXPLICIT_OPEN.finditer(probe):
        if not complete and match.start() >= len(probe)-8:
            break
        position = offset + match.start()
        if not openers or position > openers[-1][0]:
            openers.append((position, preceding_lines + probe.count("\n", 0, match.start()) + 1))
            if len(openers) >= maximum:
                break


def webshell_window_indicators(fd, openers, deadline, budget, total_remaining):
    """Read at most 64 KiB/opener and the parser budget in total, with full gaps."""
    hits, consumed = {}, 0
    for position, first_line in openers:
        if time.monotonic() > deadline:
            return hits, "time", consumed
        if consumed >= budget:
            break
        if consumed >= total_remaining:
            return hits, "total-bytes", consumed
        length = min(65536, budget-consumed, total_remaining-consumed)
        data = os.pread(fd, length, position)
        consumed += len(data)
        observed, partial = webshell_indicators(data, deadline, short_tags=False)
        for indicator, line in observed.items():
            hits[indicator] = min(hits.get(indicator, first_line+line-1), first_line+line-1)
        if partial == "time":
            return hits, "time", consumed
    # A bounded window can omit aliases/control flow elsewhere in the file.
    # Even apparently complete individual blocks cannot upgrade this to full.
    return hits, "window", consumed
