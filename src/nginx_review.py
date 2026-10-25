"""Explicit acknowledgement of unresolved static routing, never an OK verdict."""

NGINX_REVIEWABLE = frozenset(("redirect_or_conditional", "nested_location", "unsupported_location", "unsupported_regex",
                            "no_proven_handler", "location_filesystem_mapping", "unsupported_directive", "competing_location"))


def nginx_review_entries(data):
    if (type(data) is not dict or data.get("schema_version") != 1 or data.get("kind") != "nginx-upload-review" or
            data.get("requires_review") is not True or type(data.get("entries")) is not list or len(data["entries"]) > 128):
        raise CheckError("Nginx review requires an explicit schema 1 nginx-upload-review draft")
    result = set()
    for entry in data["entries"]:
        if (type(entry) is not dict or set(entry) != {"finding_id", "snapshot_sha256", "outcome", "reviewed", "reason"} or
                entry.get("reviewed") is not True or type(entry.get("reason")) is not str or not entry["reason"].strip() or len(entry["reason"]) > 1024 or
                type(entry.get("finding_id")) is not str or re.fullmatch(r"P2S-NGX001-[a-f0-9]{16}", entry["finding_id"]) is None or
                type(entry.get("snapshot_sha256")) is not str or re.fullmatch(r"[a-f0-9]{64}", entry["snapshot_sha256"]) is None or
                type(entry.get("outcome")) is not str or entry["outcome"] not in NGINX_REVIEWABLE):
            raise CheckError("Nginx review entries require reviewed=true, a reason and an unchanged complete configuration identity")
        key = (entry["finding_id"], entry["snapshot_sha256"], entry["outcome"])
        if key in result:
            raise CheckError("Duplicate Nginx review entry")
        result.add(key)
    return result


def nginx_review_report(report, args):
    if getattr(args, "nginx_baseline", None):
        try:
            entries = read_webshell_baseline(args.nginx_baseline, nginx_review_entries)
            for row in report.rows:
                token = row.get("nginx_review")
                if token and (token["finding_id"], token["snapshot_sha256"], token["outcome"]) in entries:
                    row["review_accepted"] = True
        except (OSError, UnicodeError, ValueError, CheckError):
            report.add("UNKNOWN", "Nginx review", "Nginx review file is unreviewed, invalid, unsafe or unreadable; no exceptions accepted.",
                       rule_id="P2S-NGX002", resource="nginx_review")
    if getattr(args, "write_nginx_review_draft", None):
        entries = [dict(row["nginx_review"], reviewed=False, reason="") for row in report.rows if row.get("nginx_review")]
        draft = dict(schema_version=1, kind="nginx-upload-review", requires_review=True, entries=entries,
                     instructions="Review all virtual hosts, aliases, redirects and the complete include closure. Test the real routes. Add a reason and set reviewed=true only for entries you accept. UNKNOWN stays visible; this is not a blocking or safety proof.")
        try:
            path = write_private_json(args.write_nginx_review_draft, draft)
            report.add("INFO", "Nginx review", "Private unreviewed Nginx draft written; no existing file is overwritten and no exception is accepted automatically.",
                       rule_id="P2S-NGX002", resource=dict(path=path), evidence=dict(review_entries=len(entries)))
        except (OSError, ValueError, CheckError):
            report.add("UNKNOWN", "Nginx review", "Nginx review draft could not be written safely; the audit results are retained.",
                       rule_id="P2S-NGX002", resource="nginx_review")
