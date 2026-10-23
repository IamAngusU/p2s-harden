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
    "CUSTOM": ("info", "Review this diagnostic in its reported context."),
}


class Report:
    def __init__(self):
        self.rows = []
        self.discovery = {}

    def add(self, status, title, detail, *, rule_id="P2S-CUSTOM", resource=None):
        key = rule_id[4:]
        severity, remediation = RULES[key]
        resource = title if resource is None else resource
        identity = json.dumps([rule_id, resource], ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        finding_id = rule_id + "-" + digest(identity.encode())[:16]
        self.rows.append(dict(id=finding_id, rule_id=rule_id, resource=resource,
                              status=status, title=title, detail=detail,
                              severity=severity if status == "OPEN" else "unknown" if status == "UNKNOWN" else "info",
                              remediation=remediation, suppressed=False))

    def configure(self, fail_on="complete", ignore=()):
        self.fail_on = fail_on
        for row in self.rows:
            row["suppressed"] = row["status"] == "OPEN" and (row["id"] in ignore or row["rule_id"] in ignore)

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
            rows = [dict(id=row["rule_id"] + "-" + digest((nonce + str(index)).encode())[:16],
                         rule_id=row["rule_id"], resource=None, status=row["status"],
                         title=row["rule_id"], detail=localize("Host details omitted; rerun locally without --redact", lang),
                         severity=row["severity"], remediation=localize(RULES[row["rule_id"][4:]][1], lang),
                         suppressed=row["suppressed"]) for index, row in enumerate(self.rows)]
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
        label = "Prerequisites" if discovery.get("doctor") else "Discovered inventory" if discovery.get("inventory_only") else "Configuration audit"
        emit(f"p2s-harden {VERSION} – {localize(label, lang)}")
        cap = discovery.get("capabilities", {})
        missing_tools = [name for name, present in cap.get("tools", {}).items() if not present and name != "curl"]
        if missing_tools:
            emit(("Fehlende Helfer: " if lang == "de" else "Missing helpers: ") + ", ".join(missing_tools) +
                 ("; --doctor zeigt Zweck und nächste Schritte." if lang == "de" else "; --doctor explains their purpose and next steps."))
        if self.discovery and not self.discovery.get("doctor") and not redact:
            pools = sum(len(i["pools"]) for i in self.discovery.get("fpm_instances", []))
            instance_count, site_count = len(self.discovery.get('fpm_instances', [])), len(self.discovery.get('selected_sites', []))
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
        shown = rows if verbose or self.discovery.get("doctor") else [r for r in rows if r["status"] != "OK"]
        for row in shown if verbose else shown[:40]:
            emit(f"{row['status']:7} {row['title']}: {row['detail']}")
            if row["status"] in ("OPEN", "UNKNOWN"):
                emit("        " + row["id"] + (" [ignored OPEN]" if row["suppressed"] else ""))
                emit("        " + row["remediation"])
        if not verbose and len(shown) > 40:
            emit(f"Weitere {len(shown) - 40} Befunde: --verbose oder --json zeigt alle Details." if lang == "de" else
                 f"{len(shown) - 40} more findings: --verbose or --json shows all details.")
        counts = {s: sum(r["status"] == s for r in self.rows) for s in ("OK", "OPEN", "UNKNOWN", "INFO", "N/A")}
        print("\n" + "   ".join(f"{s}: {n}" for s, n in counts.items()))
        emit("Nur die ausgewiesenen Host-Pfade/Instanzen wurden geprüft; keine Sicherheitszertifizierung." if lang == "de" else
             "Only the reported host paths and instances were checked; this is not a security certification.")
        if self.discovery.get("assessment"):
            emit("Datenträger-Konfiguration geprüft; bestehende Worker, Netzwerk-Erreichbarkeit und Anwendungsschwachstellen bleiben ungeprüft." if lang == "de" else
                 "Disk configuration inspected; existing workers, network reachability and application vulnerabilities remain unverified.")
