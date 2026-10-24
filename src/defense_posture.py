"""Read-only policy observations, never a sandbox or exploitability verdict."""

RESIDUAL_FUNCTIONS = ("putenv", "mail", "error_log", "dl", "pcntl_fork", "symlink", "link", "file_put_contents")


def residual_php_policy(report, instance):
    groups = {}
    for name, settings in instance["pools"].items():
        disabled = functions(instance["values"].get("disable_functions", ""))
        for prefix in ("php_value", "php_admin_value"):
            disabled |= functions(settings.get(prefix + "[disable_functions]", ""))
        remaining = tuple(value for value in RESIDUAL_FUNCTIONS if value not in disabled)
        dl = pool_effective(instance["values"], settings, "enable_dl")
        dl = "unknown" if dl is None else "off" if dl.lower() in ("", "off", "0", "no", "false") else "on"
        mail = pool_effective(instance["values"], settings, "sendmail_path")
        mail = "unknown" if mail is None else "empty" if mail.strip().lower() in ("", "no value", "none") else "configured"
        groups.setdefault((remaining, dl, mail), []).append(name)
    for (remaining, dl, mail), pools in sorted(groups.items()):
        row = report.add("INFO", "Residual PHP capabilities " + instance["config"],
            "Function restrictions are not a sandbox. Function availability and indirect execution are not tested; dl is unavailable in FPM. Mail, environment and file APIs may be required by the application. No extra functions or settings are changed.",
            rule_id="P2S-PHP005", resource=dict(config=instance["config"], pools=sorted(pools)),
            evidence=dict(not_disabled_functions=list(remaining), enable_dl=dl, sendmail_path=mail,
                          affected_pool_count=len(pools), policy_only=True))
        row["affected_pools"] = sorted(pools)


def fpm_service_posture(report, instance, cap):
    service = instance.get("service")
    resource = dict(config=instance["config"], service=service)
    title = "FPM systemd hardening " + instance["config"]
    if not service or not cap.get("systemd") or not cap.get("tools", {}).get("systemctl"):
        report.add("INFO", title, "No verified active systemd context; service hardening is not assessed. Audit the actual service/container boundary separately.",
                   rule_id="P2S-SYS002", resource=resource, evidence=dict(assessment="not_assessed", worker_attestation=False))
        return
    try:
        if re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", service) is None or service.startswith("-"):
            raise CheckError("Invalid FPM service identity")
        helper = shutil.which("systemctl")
        if helper is None:
            raise CheckError("systemctl is unavailable")
        helper = str(trusted(Path(helper).resolve(strict=True)))
        props = ("Id", "LoadState", "ActiveState", "MainPID", "NoNewPrivileges", "ProtectSystem", "PrivateTmp")
        output, _ = command([helper, "show", "--no-pager", "--property=" + ",".join(props), "--", service], timeout=5)
        values = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in props and key not in values:
                values[key] = value
            else:
                raise CheckError("Ambiguous systemd property output")
        if (set(values) != set(props) or values["Id"] != service or values["LoadState"] != "loaded" or
                values["ActiveState"] != "active" or values["MainPID"] != str(instance["pid"])):
            raise CheckError("systemd properties do not match the active FPM master")
        if (values["NoNewPrivileges"] not in ("yes", "no") or values["ProtectSystem"] not in ("no", "yes", "full", "strict") or
                values["PrivateTmp"] not in ("no", "yes", "disconnected")):
            raise CheckError("Unknown systemd hardening property value")
        report.add("INFO", title,
            "Manager-reported policy only; existing workers, exceptions and kernel enforcement are not attested. Review application writes, mail and shared temporary-file requirements before changing a service. No unit is changed.",
            rule_id="P2S-SYS002", resource=resource,
            evidence=dict(assessment="manager_policy", no_new_privileges=values["NoNewPrivileges"],
                          protect_system=values["ProtectSystem"], private_tmp=values["PrivateTmp"], worker_attestation=False))
    except (OSError, ValueError, CheckError):
        report.add("UNKNOWN", title, "Active FPM service properties could not be verified; inspect systemctl show and the running worker boundary separately. No unit is changed.",
                   rule_id="P2S-SYS002", resource=resource, evidence=dict(assessment="unavailable", worker_attestation=False))
