RULES = {
    "ENV001": ("info", "Run on a Linux target with readable /proc; use --ssh from other systems."),
    "ENV002": ("info", "Provide Python 3.8 or later on the Linux target, then rerun."),
    "ENV003": ("info", "Use sudo or an existing root SSH login for complete checks and changes."),
    "ENV004": ("info", "HTTP checks use the Python standard library; no curl installation is needed."),
    "ENV005": ("info", "Use --doctor for the helper's purpose and the suggested package command."),
    "ENV006": ("info", "Process discovery uses /proc when ps is unavailable."),
    "ENV007": ("info", "Automatic INI changes need a matching active systemd FPM service."),
    "DISC001": ("info", "Review discovery issues; supply --nginx-config or explicit --root/--site mappings."),
    "DISC002": ("info", "Check the running FPM master and its protected configuration; unsupported contexts require separate assessment."),
    "DISC003": ("info", "Repair the reported FPM configuration/provenance and rerun; other instances remain independently checked."),
    "DISC004": ("info", "Review skipped paths or increase the traversal budget; no skipped subtree is certified."),
    "PHP001": ("high", "Review --dry-run, test application compatibility, then apply --fix --yes or set the required function restrictions manually."),
    "PHP002": ("high", "Set allow_url_include=Off in the effective FPM INI/pool and reload the matching service."),
    "PHP003": ("medium", "Review a narrow per-pool open_basedir with application testing; it is an additional restriction, not a sandbox."),
    "PHP004": ("high", "Review whether FFI is needed; set ffi.enable=Off in the effective FPM configuration when compatible, then reload and test the application."),
    "FPM001": ("high", "Prefer a Unix socket or loopback bind; for required TCP access set listen.allowed_clients to the intended proxy IPs and verify firewall/container publication."),
    "FPM002": ("high", "Restrict the Unix socket to the web-server identity, normally mode 0660 or 0600; review named ACL grants and verify the live socket after restart."),
    "FPM003": ("medium", "Set security.limit_extensions=.php after checking application requirements; fix upload execution rules in the web server as well."),
    "FPM004": ("medium", "Use clear_env=yes and declare only required env[] variables; test application configuration before reloading."),
    "FPM005": ("info", "Use distinct Unix accounts and code ownership for mutually untrusted applications; shared pools may be intentional for one trust domain."),
    "FS001": ("high", "Remove PHP-user write access to application code and verify ACLs; keep required runtime data separate."),
    "FS002": ("high", "Separate code from runtime storage; use --runtime-dir only for reviewed storage and --protect-dir only for an explicit code directory."),
    "FS003": ("info", "Resolve the reported user/access/coverage issue or narrow the scope; an incomplete walk cannot pass."),
    "FS004": ("info", "Verify that declared upload/cache paths cannot execute uploaded PHP and cannot replace application code."),
    "FS005": ("high", "Run the FPM pool as a dedicated non-root account and restart the service after reviewing ownership."),
    "HTTP001": ("high", "Deny HTTP access to the reported sensitive file/path, remove public backups/debug scripts, and recheck both HTTP and HTTPS."),
    "HTTP002": ("info", "Provide an explicit --site mapping or sufficient HTTP budget; inspect every unknown result."),
    "HTTP003": ("info", "Correct the URL/document-root mapping and retry the intended local virtual host."),
    "SYS001": ("medium", "Review the host ptrace policy against operational needs; this tool does not change sysctl settings."),
    "IM001": ("info", "Review ImageMagick policy rules and delegates for the installed version and application requirements."),
    "FIX001": ("info", "Resolve the specific fix preflight blocker, inspect the full proposed diff, and rerun."),
    "TX001": ("info", "Keep the backup ID; a repeated implicit rollback never selects an older transaction."),
    "EXEC001": ("info", "Resolve the execution error and rerun; consult transaction state before retrying a change."),
    "WS001": ("high", "Preserve the file and relevant logs; compare with a trusted deployment and review the reported line. An indicator is not a malware verdict. If compromise is confirmed, isolate and rebuild from trusted sources, close the entry point and rotate exposed credentials."),
    "WS002": ("medium", "Verify the startup directive against trusted application configuration and inspect its target separately. A legitimate preload is possible; no file is changed automatically."),
    "WS003": ("info", "Review coverage reasons, permissions and scan limits; scan skipped paths separately. A completed indicator scan cannot establish that a server is clean."),
    "WS004": ("info", "Review this include/callback in application context and compare with trusted source. A constant prefix or registry lookup is not proof of safety; traversal or an attacker-controlled registry can still be dangerous."),
    "WS005": ("info", "Use only a reviewed, protected local baseline. Only identical path, SHA256 and indicator matches are accepted; changed files and coverage gaps remain findings."),
    "CUSTOM": ("info", "Review this diagnostic in its reported context."),
}


def safe_evidence(rule_id, evidence):
    """Only rule-owned, finite values may survive report redaction."""
    if not isinstance(evidence, dict):
        return {}
    boolean = lambda value: type(value) is bool
    count = lambda value: type(value) is int and 0 <= value <= 1000000
    choices = lambda *allowed: lambda value: type(value) is str and value in allowed
    names = lambda *allowed: lambda value: (type(value) is list and len(value) <= len(allowed)
                                            and all(type(v) is str and v in allowed for v in value))
    fields = {
        "PHP001": dict(missing_functions=names(*sorted(REQUIRED)), affected_pool_count=count),
        "PHP002": dict(allow_url_include=boolean, affected_pool_count=count),
        "PHP003": dict(unrestricted=boolean),
        "PHP004": dict(ffi_policy=choices("off", "on", "preload", "unknown")),
        "FPM001": dict(binding=choices("loopback", "network", "unverified"), client_allowlist=boolean,
                       hostname_resolution=choices("loopback", "non_loopback", "unavailable")),
        "FPM002": dict(socket_mode=lambda value: type(value) is str and re.fullmatch(r"0[0-7]{3}", value) is not None,
                       source=choices("configured", "observed", "acl"), named_acl=boolean),
        "FPM003": dict(unrestricted=boolean, allowed_known_extensions=names(".php", ".phar"), other_extension_count=count),
        "FPM004": dict(clear_env=boolean),
        "FPM005": dict(pool_count=count),
        "FS001": dict(writable_files=count),
        "FS002": dict(writable_directories=count),
        "FS004": dict(runtime_directories=count),
        "HTTP001": dict(http_status=lambda value: type(value) is int and 100 <= value <= 599),
        "SYS001": dict(ptrace_scope=lambda value: type(value) is int and 0 <= value <= 3),
        "WS001": dict(indicators=names(*WEBSHELL_INDICATORS), line=count),
        "WS002": dict(indicators=names("startup-reference"), line=count),
        "WS003": dict(examined_files=count, attempted_files=count, incomplete_files=count, indicator_count=count,
                      baseline_accepted_count=count, omitted_coverage_paths=count, coverage_reasons=names(*WEBSHELL_REASONS),
                      coverage_counts=lambda value: type(value) is dict and len(value) <= len(WEBSHELL_REASONS) and
                          all(type(k) is str and k in WEBSHELL_REASONS and count(v) for k,v in value.items())),
        "WS004": dict(indicators=names("prefixed-include", "registry-callable"), line=count, review_required=boolean),
        "WS005": dict(baseline_entries=count),
    }.get(rule_id[4:], {})
    return {name: value for name, value in evidence.items() if name in fields and fields[name](value)}


RULE_NAMES = {"PHP001": "Shell function restrictions", "PHP002": "URL includes", "PHP003": "Filesystem restriction",
              "PHP004": "PHP FFI", "FPM001": "FPM TCP listener", "FPM002": "FPM Unix socket",
              "FPM003": "FPM script extensions", "FPM004": "FPM environment clearing", "FPM005": "Shared FPM account",
              "FS001": "Writable PHP files", "FS002": "Writable directories", "FS004": "Declared runtime storage",
              "HTTP001": "Sensitive HTTP path", "SYS001": "ptrace_scope",
              "WS001": "PHP webshell indicator", "WS002": "PHP startup reference", "WS003": "Webshell scan coverage",
              "WS004": "PHP code review", "WS005": "Webshell baseline"}


def evidence_summary(rule_id, evidence, lang="en"):
    facts = safe_evidence(rule_id, evidence)
    say = lambda value: _EVIDENCE_GERMAN.get(value, value) if lang == "de" else {"non_loopback":"outside loopback", "acl":"ACL"}.get(value, value)
    labels = dict(missing_functions="Missing", allow_url_include="URL includes", unrestricted="Unrestricted",
                  ffi_policy="ffi.enable", binding="TCP binding", client_allowlist="Client allowlist",
                  hostname_resolution="Name resolution", socket_mode="Socket mode", source="Source",
                  named_acl="Named ACL", allowed_known_extensions="Known script extensions",
                  other_extension_count="Other script extensions", clear_env="clear_env", pool_count="Pools",
                  writable_files="Writable PHP files", writable_directories="Writable directories",
                  runtime_directories="Runtime directories", http_status="HTTP status", ptrace_scope="ptrace_scope",
                  indicators="Indicators", line="Line", examined_files="Examined files",
                  indicator_count="Indicator count", coverage_reasons="Coverage reasons", attempted_files="Attempted files",
                  incomplete_files="Incomplete files", baseline_accepted_count="Baseline accepted", baseline_entries="Baseline entries",
                  omitted_coverage_paths="Omitted coverage paths", coverage_counts="Coverage counts", review_required="Review required")
    parts = []
    for key, value in facts.items():
        if key == "affected_pool_count":
            continue
        if isinstance(value, list):
            value = ", ".join(localize(WEBSHELL_INDICATORS[item], lang) if key == "indicators" else say(item) for item in value) or say("none")
        elif isinstance(value, dict):
            value = ", ".join(say(reason) + ": " + str(number) for reason, number in sorted(value.items())) or say("none")
        elif type(value) is bool:
            value = say("yes" if value else "no")
        elif type(value) is str and key != "socket_mode":
            value = say(value)
        parts.append(localize(labels[key], lang) + ": " + str(value))
    result = "; ".join(parts) or localize("Host details omitted; rerun locally without --redact", lang)
    if "affected_pool_count" in facts:
        count = facts["affected_pool_count"]
        result += " (" + str(count) + " " + say("pool" if count == 1 else "pools") + ")"
    return result


class Report:
    def __init__(self):
        self.rows = []
        self.discovery = {}

    def add(self, status, title, detail, *, rule_id="P2S-CUSTOM", resource=None, evidence=None):
        key = rule_id[4:]
        severity, remediation = RULES[key]
        resource = title if resource is None else resource
        identity = json.dumps([rule_id, resource], ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        finding_id = rule_id + "-" + digest(identity.encode())[:16]
        self.rows.append(dict(id=finding_id, rule_id=rule_id, resource=resource,
                              status=status, title=title, detail=detail,
                              severity=severity if status == "OPEN" else "unknown" if status == "UNKNOWN" else "info",
                              remediation=remediation, suppressed=False, evidence=safe_evidence(rule_id, evidence)))
        return self.rows[-1]

    def configure(self, fail_on="complete", ignore=()):
        self.fail_on = fail_on
        for row in self.rows:
            row["suppressed"] = row["status"] == "OPEN" and (row.get("baseline_accepted") is True or row["id"] in ignore or row["rule_id"] in ignore)

    def has(self, status):
        return any(r["status"] == status and not r["suppressed"] for r in self.rows)

    def exit_code(self):
        if getattr(self, "fail_on", "complete") == "open" and self.has("OPEN"):
            return 1
        if self.has("UNKNOWN"):
            return 2
        return int(self.has("OPEN"))

    def show(self, as_json=False, verbose=False, lang="en", redact=False):
        rows = [dict(row, title=localize(row["title"], lang), detail=localize(row["detail"], lang),
                     remediation=localize(row["remediation"], lang)) for row in self.rows]
        discovery = localized_discovery(self.discovery, lang)
        if redact:
            # Allowlist projection, not regex replacement: even exception text,
            # arbitrary discovery metadata and future resource shapes are omitted.
            nonce = uuid.uuid4().hex
            def project(index, row):
                evidence = safe_evidence(row["rule_id"], row.get("evidence"))
                if as_json:
                    detail = json.dumps(evidence, sort_keys=True) if evidence else localize("Host details omitted; rerun locally without --redact", lang)
                else:
                    detail = evidence_summary(row["rule_id"], evidence, lang)
                return dict(id=row["rule_id"] + "-" + digest((nonce + str(index)).encode())[:16],
                            rule_id=row["rule_id"], resource=None, status=row["status"],
                            title=localize(RULE_NAMES.get(row["rule_id"][4:], row["rule_id"]), lang),
                            detail=detail,
                            severity=row["severity"], remediation=localize(RULES[row["rule_id"][4:]][1], lang),
                            evidence=evidence, suppressed=row["suppressed"],
                            **({"baseline_accepted":row["baseline_accepted"] is True} if "baseline_accepted" in row else {}))
            rows = [project(index, row) for index, row in enumerate(self.rows)]
            discovery = dict(redacted=True, doctor=bool(self.discovery.get("doctor")),
                             inventory_only=bool(self.discovery.get("inventory_only")))
        if as_json:
            print(json.dumps(dict(schema_version=2, version=VERSION, language=lang, redacted=redact, findings=rows,
                                  has_open=self.has("OPEN"), has_unknown=self.has("UNKNOWN"),
                                  counts={state: sum(r["status"] == state for r in rows) for state in ("OK", "OPEN", "UNKNOWN", "INFO")},
                                  suppressed_open=sum(r["suppressed"] for r in rows),
                                  fail_on=getattr(self, "fail_on", "complete"),
                                  discovery=discovery, plan=None if redact else getattr(self, "plan", None),
                                  transaction=None if redact else getattr(self, "transaction", None),
                                  exit_code=self.exit_code()), ensure_ascii=False, indent=2))
            return
        def emit(line):
            # Configured names/paths must not inject terminal escape sequences.
            print("".join(c if c.isprintable() else "?" for c in line))
        label = "Prerequisites" if discovery.get("doctor") else "Discovered inventory" if discovery.get("inventory_only") else "PHP webshell indicator scan" if self.discovery.get("webshell_scan") else "Configuration audit"
        emit(f"p2s-harden {VERSION} – {localize(label, lang)}")
        cap = discovery.get("capabilities", {})
        missing_tools = [name for name, present in cap.get("tools", {}).items() if not present and name != "curl"]
        if missing_tools:
            emit(("Fehlende Helfer: " if lang == "de" else "Missing helpers: ") + ", ".join(missing_tools) +
                 ("; --doctor zeigt Zweck und nächste Schritte." if lang == "de" else "; --doctor explains their purpose and next steps."))
        if self.discovery and not self.discovery.get("doctor") and not redact:
            pools = sum(len(i["pools"]) for i in self.discovery.get("fpm_instances", []))
            instance_count, site_count = len(self.discovery.get('fpm_instances', [])), len(self.discovery.get('selected_sites', []))
            if not self.discovery.get("webshell_scan"):
                emit(f"Erkannt: {instance_count} Host-FPM-Instanzen, {pools} Pools, {site_count} HTTP-Zuordnungen" if lang == "de" else
                     f"Discovered: {instance_count} host FPM instances, {pools} pools, {site_count} HTTP mappings")
            roots = self.discovery.get("scan_roots", [])
            emit(("Prüfpfade: " if lang == "de" else "Audit paths: ") + ", ".join(roots[:8]))
            if len(roots) > 8:
                emit(f"Weitere {len(roots) - 8} Pfade im vollständigen --json-Inventar." if lang == "de" else
                     f"{len(roots) - 8} more paths in the complete --json inventory.")
            if self.discovery.get("inventory_only"):
                for instance in discovery.get("fpm_instances", []):
                    for pool in instance["pools"]:
                        emit(f"POOL    {pool['name']} | " + ("Benutzer" if lang == "de" else "User") +
                             f": {pool['user']} | Listener: {pool['listen']}")
                for site in self.discovery.get("selected_sites", []):
                    emit("SITE    " + site)
        if not redact:
            coverage_paths = [item for root in self.discovery.get("webshell_coverage", []) for item in root["paths"]]
            for item in coverage_paths if verbose else coverage_paths[:20]:
                reason = _EVIDENCE_GERMAN.get(item["reason"], item["reason"]) if lang == "de" else item["reason"]
                emit(localize("Incomplete path ({reason}): {path}", lang).format(reason=reason, path=item["path"]))
            if not verbose and len(coverage_paths) > 20:
                emit(localize("More incomplete paths: use --verbose or --json", lang))
            if any(root["omitted_paths"] for root in self.discovery.get("webshell_coverage", [])):
                emit(localize("Coverage path list truncated at 1000 entries per root; narrow --root to resolve remaining paths", lang))
        shown = rows if verbose or self.discovery.get("doctor") else [r for r in rows if r["status"] != "OK" and not r.get("baseline_accepted")]
        if self.discovery.get("webshell_scan"):
            # Coverage remains visible even when a noisy tree hits the human
            # output limit. Full finding details stay in --verbose/--json.
            shown.sort(key=lambda row: row["rule_id"] != "P2S-WS003")
        for row in shown if verbose else shown[:40]:
            emit(f"{row['status']:7} {row['title']}: {row['detail']}")
            if row["status"] in ("OPEN", "UNKNOWN") or row["rule_id"] == "P2S-WS004":
                marker = " [baseline]" if row.get("baseline_accepted") else " [ignored OPEN]" if row["suppressed"] else ""
                emit("        " + row["id"] + marker)
                if row.get("affected_pools"):
                    count = len(row["affected_pools"])
                    emit(f"        Unverändert für {count} Pools; --json nennt die zugehörigen Pools." if lang == "de" else
                         f"        Applies unchanged to {count} pools; --json lists the related pools.")
                emit("        " + row["remediation"])
        if not verbose and len(shown) > 40:
            emit(f"Weitere {len(shown) - 40} Befunde: --verbose oder --json zeigt alle Details." if lang == "de" else
                 f"{len(shown) - 40} more findings: --verbose or --json shows all details.")
        counts = {s: sum(r["status"] == s for r in self.rows) for s in ("OK", "OPEN", "UNKNOWN", "INFO", "N/A")}
        print("\n" + "   ".join(f"{s}: {n}" for s, n in counts.items()))
        accepted = sum(r.get("baseline_accepted") is True for r in self.rows)
        if accepted:
            emit(localize("Baseline accepted: {count} unchanged indicator rows; --verbose or --json retains them", lang).format(count=accepted))
        emit("Nur die ausgewiesenen Host-Pfade/Instanzen wurden geprüft; keine Sicherheitszertifizierung." if lang == "de" else
             "Only the reported host paths and instances were checked; this is not a security certification.")
        if self.discovery.get("assessment"):
            emit("Datenträger-Konfiguration geprüft; bestehende Worker, Netzwerk-Erreichbarkeit und Anwendungsschwachstellen bleiben ungeprüft." if lang == "de" else
                 "Disk configuration inspected; existing workers, network reachability and application vulnerabilities remain unverified.")
