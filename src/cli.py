def main(argv=None):
    language = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    language.add_argument("--lang", choices=("en", "de"), default="en")
    selected, _ = language.parse_known_args(argv)
    def text(message):
        return localize(message, selected.lang)
    def emit(message):
        print("".join(c if c.isprintable() else "?" for c in text(message)))
    parser = argparse.ArgumentParser(parents=[language], allow_abbrev=False,
        description=text("Bounded PHP/FPM checks; UNKNOWN means an incomplete check."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  sudo bash p2s-harden.sh --dry-run\n  sudo bash p2s-harden.sh --fix --yes\n  bash p2s-harden.sh --ssh root@SERVER --json --fail-on open\n  sudo bash p2s-harden.sh --rollback --backup-id ID")
    mode = parser.add_mutually_exclusive_group()
    for name, help_text in (("check", "Audit selected settings, permissions and HTTP paths (default)"),
                            ("doctor", "Explain prerequisites and missing capabilities"),
                            ("discover", "Show detected FPM pools and web mappings"),
                            ("dry-run", "Show proposed values and a unified diff without changes"),
                            ("fix", "Apply the displayed supported plan after confirmation"),
                            ("rollback", "Restore only the latest transaction, or one explicit backup ID")):
        mode.add_argument("--" + name, dest="mode", action="store_const", const=name, help=text(help_text))
    parser.set_defaults(mode="check")
    parser.add_argument("--root", help=text('Audit scope (default: discovered document roots)'))
    parser.add_argument("--web-user", action="append", default=[], help=text("Additional PHP user for permission checks; repeatable"))
    parser.add_argument("--site", action="append", default=[], metavar="URL=ROOT", help=text("Explicit virtual host and document root; repeatable"))
    parser.add_argument("--nginx-config", help=text('Custom Nginx main configuration'))
    parser.add_argument("--no-auto", action="store_true", help=text('Disable automatic document-root/domain discovery'))
    parser.add_argument("--max-sites", type=int, default=32, help=text('Maximum automatic HTTP mappings (default 32)'))
    parser.add_argument("--max-paths", type=int, default=250000, help=text("Maximum entries per filesystem walk (default 250000)"))
    parser.add_argument("--walk-seconds", type=float, default=10, help=text("Seconds per filesystem walk (default 10)"))
    parser.add_argument("--max-http-probes", type=int, default=128, help=text("Total HTTP request budget (default 128)"))
    parser.add_argument("--runtime-dir", action="append", default=[], help=text("Declare writable runtime storage inside selected roots; repeatable"))
    parser.add_argument("--protect-dir", action="append", default=[], help=text('Transfer explicit directory ownership to root; non-recursive'))
    parser.add_argument("--backup-root", default="/root/p2s-harden-backup-v2", help=text("Protected transaction directory (default /root/p2s-harden-backup-v2)"))
    parser.add_argument("--backup-id", help=text("Choose one transaction explicitly for rollback"))
    parser.add_argument("--yes", "-y", action="store_true", help=text("Approve the displayed fix plan without an interactive prompt"))
    parser.add_argument("--fail-on", choices=("complete", "open"), default="complete", help=text("Exit precedence: complete (UNKNOWN first) or open (OPEN first); unknowns never pass"))
    parser.add_argument("--ignore", action="append", default=[], metavar="ID", help=text("Suppress one finding/rule's OPEN exit impact; keep it visible; repeatable"))
    parser.add_argument("--json", action="store_true", help=text("Structured findings, stable IDs, remediation, preview and transaction state"))
    parser.add_argument("--redact", action="store_true", help=text("Shareable read-only report: omit host details, inventory and original finding IDs"))
    parser.add_argument("--verbose", action="store_true", help=text('Show all findings, including OK'))
    parser.add_argument("--no-progress", action="store_true", help=text('Hide interactive progress messages'))
    parser.add_argument("--progress", action="store_true", help=text('Write progress to stderr even without a TTY'))
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    report, tx = None, None
    def show_report():
        report.configure(args.fail_on, args.ignore)
        report.show(args.json, verbose=args.verbose, lang=args.lang, redact=args.redact)
    def summarize(transaction):
        import shlex
        undo = ("sudo bash p2s-harden.sh --rollback --backup-id " + shlex.quote(transaction.path.name) +
                " --backup-root " + shlex.quote(str(transaction.root))) if transaction.path else None
        return dict(id=transaction.path.name if transaction.path else None,
                    backup_path=str(transaction.path) if transaction.path else None,
                    status=transaction.data["status"], noop=transaction.noop,
                    files=len(transaction.data["files"]), directories=len(transaction.data["directories"]),
                    undo_command=undo)
    def transaction_output(action):
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                return action()
        finally:
            if not args.json:
                for line in output.getvalue().splitlines():
                    emit(line)
    try:
        if args.redact and args.mode not in ("check", "doctor", "discover"):
            raise CheckError("--redact supports --check, --doctor and --discover; review change previews locally without redaction")
        if any(not re.fullmatch(r"P2S-(?:[A-Z]+\d{3}|CUSTOM)(?:-[a-f0-9]{16})?", value) for value in args.ignore):
            raise CheckError("--ignore requires a finding id or rule_id from --json")
        if args.mode == "doctor":
            report = doctor()
            show_report()
            return report.exit_code()
        if sys.platform != "linux" or not Path("/proc/self/stat").is_file():
            raise CheckError('A Linux target with /proc is required; use --ssh root@SERVER from Windows/macOS')
        if sys.version_info < (3, 8):
            raise CheckError(f"Python 3.8 or later required; {install_hint('python3')}")
        if args.root is not None and not Path(args.root).is_absolute():
            raise CheckError('--root must be absolute')
        if args.root is not None:
            args.root = os.path.normpath(args.root)
        if not 1 <= args.max_sites <= 512:
            raise CheckError('--max-sites must be between 1 and 512')
        if not 1 <= args.max_paths <= 1000000:
            raise CheckError("--max-paths must be between 1 and 1000000")
        if not 0.05 <= args.walk_seconds <= 120:
            raise CheckError("--walk-seconds must be between 0.05 and 120")
        if not 1 <= args.max_http_probes <= 4096:
            raise CheckError("--max-http-probes must be between 1 and 4096")
        if args.mode == "rollback" and os.geteuid() != 0:
            raise CheckError('Changes require root: sudo bash p2s-harden.sh --fix or --ssh root@SERVER')
        if args.mode == "rollback":
            tx = transaction_output(lambda: Transaction.rollback(args.backup_root, args.backup_id))
            report = Report()
            report.transaction = summarize(tx)
            report.add("INFO", "Rollback", "Latest transaction already restored; no changes made" if tx.noop else "Selected transaction restored", rule_id='P2S-TX001', resource="rollback")
            show_report()
            return 0
        stage(args, 'Discovering Nginx mappings and audit paths')
        prepare_scope(args)
        prepare_runtime_dirs(args)
        report, updates, instances, users = scan(args, inventory_only=True) if args.mode == "discover" else scan(args)
        if args.mode in ("dry-run", "fix"):
            blockers = fix_blockers(updates, args.protect_dir, instances, users)
            plan = change_plan(updates, args.protect_dir, [text(reason) for reason in blockers])
            report.plan = plan
            for reason in blockers:
                report.add("UNKNOWN", 'Fix blocked', reason, rule_id='P2S-FIX001', resource=reason)
            if not args.json:
                for path, values in updates.items():
                    emit(f"PLANNED INI {path}: {','.join(values)}")
                for entry in plan["ini"]:
                    for line in entry["diff"].splitlines():
                        emit(line)
                for path in args.protect_dir:
                    emit(f'PLANNED DIRECTORY {path}: owner root, no g+w/o+w, non-recursive')
                emit('HTTP, ImageMagick, runtime and writable-storage findings require individual review; they are not changed automatically.')
            if args.mode == "fix" and not blockers and (updates or args.protect_dir):
                if not confirm_fix(args):
                    report.add("INFO", "Fix cancelled", "No changes made; rerun --dry-run to review the plan", rule_id="P2S-TX001", resource="cancelled")
                    show_report()
                    return report.exit_code()
                tx = Transaction(args.backup_root)
                def apply():
                    tx.prepare(updates, args.protect_dir, instances,
                               expected={entry["path"]: entry["before_sha256"] for entry in plan["ini"]})
                    tx.apply(instances, users)
                transaction_output(apply)
                report, _, _, _ = scan(args)
                report.plan, report.transaction = plan, summarize(tx)
                if not args.json:
                    emit("Undo this transaction: " + report.transaction["undo_command"])
        show_report()
        return report.exit_code()
    except (OSError, ValueError, KeyError, CheckError) as exc:
        report = report or Report()
        report.add("UNKNOWN", 'Execution', str(exc), rule_id='P2S-EXEC001', resource="execution")
        if tx is None:
            tx = getattr(exc, "p2s_transaction", None)
        if tx is not None:
            report.transaction = summarize(tx)
        show_report()
        return report.exit_code()


if __name__ == "__main__":
    sys.exit(main())
