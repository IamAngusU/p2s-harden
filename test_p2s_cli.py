"""CLI contracts using disposable files, including real fix/rollback JSON."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import p2s_harden as p


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "Linux root fixtures")
class CliContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd(), prefix="p2s-cli-")
        self.root = Path(self.temporary.name)
        self.ini = self.root / "php.ini"
        self.original = b"allow_url_include=On\n"
        self.ini.write_bytes(self.original)
        self.backups = self.root / "backups with ' quote"

    def tearDown(self):
        self.temporary.cleanup()

    def report(self):
        report = p.Report()
        report.add("OPEN" if b"=On" in self.ini.read_bytes() else "OK", "fixture", "retained finding")
        report.add("INFO", "manual scope", "not an automated check")
        return report

    def invoke(self, *options, scan_error=None, approve=True, as_json=True):
        def scope(args):
            args.roots, args.discovery = [str(self.root)], {}
        def scan(args):
            if scan_error:
                raise scan_error
            updates = {str(self.ini): {"allow_url_include": "Off"}} if b"=On" in self.ini.read_bytes() else {}
            return self.report(), updates, [], []
        out = io.StringIO()
        with patch.object(p, "prepare_scope", side_effect=scope), patch.object(p, "scan", side_effect=scan), patch.object(p, "fix_blockers", return_value=[]), contextlib.redirect_stdout(out):
            code = p.main(["--root", str(self.root), "--backup-root", str(self.backups), "--no-progress", *(["--json"] if as_json else []), *options,
                           *(["--yes"] if "--fix" in options and approve else [])])
        if not as_json:
            return code, out.getvalue()
        result = json.loads(out.getvalue())  # Rejects preceding/trailing transaction text.
        self.assertEqual(code, result["exit_code"])
        return code, result

    def test_dry_run_json_contains_plan_and_does_not_create_backup(self):
        code, result = self.invoke("--dry-run")
        self.assertEqual(code, 1)
        self.assertEqual(result["language"], "en")
        entry = result["plan"]["ini"][0]
        self.assertEqual(entry["path"], str(self.ini))
        self.assertEqual(entry["values"], {"allow_url_include": "Off"})
        self.assertIn("-allow_url_include=On", entry["diff"])
        self.assertIn("+allow_url_include = Off", entry["diff"])
        self.assertIsNone(result["transaction"])
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.ini.read_bytes(), self.original)

    def test_human_ini_preview_and_approved_fix_show_upgrade_notice_once(self):
        code,preview=self.invoke("--dry-run",as_json=False)
        self.assertEqual(code,1)
        self.assertEqual(preview.count(p.INI_UPGRADE_NOTICE),1)
        code,fixed=self.invoke("--fix",as_json=False)
        self.assertEqual(code,0)
        self.assertEqual(fixed.count(p.INI_UPGRADE_NOTICE),1)
        code,unchanged=self.invoke("--dry-run",as_json=False)
        self.assertEqual(code,0)
        self.assertNotIn(p.INI_UPGRADE_NOTICE,unchanged)

    def test_json_fix_requires_explicit_approval_and_keeps_preview(self):
        code, result = self.invoke("--fix", approve=False)
        self.assertEqual(code, 2)
        self.assertTrue(any("requires --yes" in r["detail"] for r in result["findings"]))
        self.assertIsNotNone(result["plan"])
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.ini.read_bytes(), self.original)

    def test_preview_contains_only_changed_directives_and_detects_concurrent_edit(self):
        self.ini.write_text("extension_secret=DO_NOT_PRINT_THIS\nallow_url_include=On\n")
        plan = p.change_plan({str(self.ini): {"allow_url_include": "Off"}}, [], [])
        self.assertNotIn("DO_NOT_PRINT_THIS", plan["ini"][0]["diff"])
        self.ini.write_text("extension_secret=DO_NOT_PRINT_THIS")
        appended = p.change_plan({str(self.ini): {"allow_url_include": "Off"}}, [], [])
        self.assertNotIn("DO_NOT_PRINT_THIS", appended["ini"][0]["diff"])
        self.assertIn("+allow_url_include = Off", appended["ini"][0]["diff"])
        self.ini.write_text("allow_url_include=On")
        no_newline = p.change_plan({str(self.ini): {"allow_url_include": "Off"}}, [], [])
        self.assertIn("-allow_url_include=On\n+allow_url_include = Off\n", no_newline["ini"][0]["diff"])
        self.ini.write_text("allow_url_include=Off\n")
        tx = p.Transaction(self.backups)
        with self.assertRaisesRegex(p.CheckError, "changed after"):
            tx.prepare({str(self.ini): {"allow_url_include": "Off"}}, [], [],
                       expected={str(self.ini): plan["ini"][0]["before_sha256"]})
        self.assertEqual(self.ini.read_text(), "allow_url_include=Off\n")

    def test_fix_and_repeated_rollback_are_single_json_documents(self):
        code, fixed = self.invoke("--fix")
        self.assertEqual(code, 0)
        self.assertEqual(fixed["transaction"]["status"], "applied")
        import shlex
        undo = shlex.split(fixed["transaction"]["undo_command"])
        self.assertEqual(undo[undo.index("--backup-root") + 1], str(self.backups))
        self.assertEqual(undo[undo.index("--backup-id") + 1], fixed["transaction"]["id"])
        self.assertEqual(self.ini.read_bytes(), b"allow_url_include = Off\n")
        code, restored = self.invoke("--rollback")
        self.assertEqual(code, 0)
        self.assertEqual(restored["transaction"]["status"], "rolled_back")
        self.assertFalse(restored["transaction"]["noop"])
        self.assertEqual(self.ini.read_bytes(), self.original)
        code, repeated = self.invoke("--rollback", "--lang", "de")
        self.assertEqual(code, 0)
        self.assertTrue(repeated["transaction"]["noop"])
        self.assertEqual(repeated["transaction"]["id"], fixed["transaction"]["id"])

    def test_failed_fix_retains_findings_plan_and_recovery_status(self):
        original = p.atomic_bytes
        def fail_target(path, *args, **kwargs):
            if Path(path) == self.ini:
                raise p.CheckError("fixture failure")
            return original(path, *args, **kwargs)
        with patch.object(p, "atomic_bytes", side_effect=fail_target):
            code, result = self.invoke("--fix")
        self.assertEqual(code, 2)
        self.assertTrue(any(r["title"] == "fixture" for r in result["findings"]))
        self.assertTrue(any(r["status"] == "UNKNOWN" for r in result["findings"]))
        self.assertEqual(result["transaction"]["status"], "rolled_back")
        self.assertIsNotNone(result["plan"])
        self.assertEqual(self.ini.read_bytes(), self.original)

    def test_invalid_limits_fail_before_scanning(self):
        for flag, value in (("--max-paths", "0"), ("--walk-seconds", "nan"), ("--max-http-probes", "4097")):
            with self.subTest(flag=flag):
                code, result = self.invoke(flag, value, scan_error=AssertionError("scan should not run"))
                self.assertEqual(code, 2)
                self.assertIn(flag, result["findings"][0]["detail"])

    def test_rollback_failure_keeps_the_reached_recovery_state_in_json(self):
        self.invoke("--fix")
        backup = next(self.backups.iterdir())
        manifest = backup / "manifest.json"
        data = json.loads(manifest.read_text())
        binary = self.root / "fake-fpm"
        binary.write_text("fixture")
        binary.chmod(0o755)
        data["instances"] = [dict(binary=str(binary), config=str(self.ini), service="fixture.service")]
        manifest.write_text(json.dumps(data))
        with patch.object(p, "command", side_effect=p.CheckError("service recovery unavailable")):
            code, result = self.invoke("--rollback")
        self.assertEqual(code, 2)
        self.assertEqual(self.ini.read_bytes(), self.original)
        self.assertEqual(result["transaction"]["status"], "rolling_back")
        self.assertEqual(result["transaction"]["id"], backup.name)

    def test_writable_git_directory_and_php_are_not_excluded(self):
        git = self.root / ".git"
        git.mkdir()
        (git / "evil.php").write_text("<?php /* disposable fixture */")
        result = subprocess.run([sys.executable, "-B", "-c", p.PERMISSION_SCAN, str(self.root)],
                                check=True, capture_output=True, text=True)
        data = json.loads(result.stdout)
        self.assertEqual(data["files"], 1)
        self.assertEqual(data["directories"], 2)
        self.assertEqual(data["errors"], [])

    def test_invalid_manifest_types_return_json_without_mutation(self):
        self.invoke("--fix")
        manifest = next(self.backups.iterdir()) / "manifest.json"
        original = json.loads(manifest.read_text())
        broken = [[], None, dict(original, files=None), dict(original, directories=[None]),
                  dict(original, instances=[{}]), dict(original, created_ns="broken"),
                  dict(original, files=[dict(original["files"][0], meta={})])]
        before = self.ini.read_bytes()
        for value in broken:
            with self.subTest(value=value):
                manifest.write_text(json.dumps(value))
                code, result = self.invoke("--rollback")
                self.assertEqual(code, 2)
                self.assertIn("Invalid backup manifest", result["findings"][0]["detail"])
                self.assertEqual(self.ini.read_bytes(), before)

    def test_git_time_budget_also_checks_empty_directories(self):
        root = self.root / "empty-tree"
        (root / "child").mkdir(parents=True)
        with patch.object(p.time, "monotonic", side_effect=[0, 0, 0, 2]):
            _, issues = p.git_endpoints(root, max_seconds=1)
        self.assertTrue(any("budget" in issue for issue in issues))

    def test_explicit_runtime_storage_does_not_exclude_php_files(self):
        runtime = self.root / "uploads"
        runtime.mkdir()
        (runtime / "payload.php").write_text("<?php echo 'fixture';")
        # The child is exercised directly as this fixture's UID. Classification
        # and traversal are independent of runuser and production ownership.
        result = subprocess.run([sys.executable, "-B", "-c", p.PERMISSION_SCAN, str(self.root),
                                 json.dumps(dict(runtime_dirs=[str(runtime)], max_paths=100, max_seconds=5))],
                                check=True, capture_output=True, text=True)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["runtime_directories"], 1)
        self.assertEqual(observed["files"], 1)
        self.assertIn(str(runtime / "payload.php"), observed["file_sample"])
        self.assertEqual(observed["error_count"], 0)

    def test_runtime_cannot_neutralize_entire_root_or_symlink(self):
        import argparse
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        args = argparse.Namespace(runtime_dir=[str(self.root), str(alias)], roots=[str(self.root)], root=str(self.root))
        p.prepare_runtime_dirs(args)
        self.assertEqual(args.runtime_dirs, [])
        self.assertEqual(len(args.discovery["issues"]), 2)

    def test_permission_and_git_walks_report_incomplete_budgets(self):
        for number in range(5):
            (self.root / str(number)).mkdir()
        result = subprocess.run([sys.executable, "-B", "-c", p.PERMISSION_SCAN, str(self.root),
                                 json.dumps(dict(max_paths=1, max_seconds=5))], check=True, capture_output=True, text=True)
        self.assertGreater(json.loads(result.stdout)["error_count"], 0)
        _, issues = p.git_endpoints(self.root, max_paths=1)
        self.assertTrue(any("budget" in issue for issue in issues))


class FunctionNames(unittest.TestCase):
    def test_zend_case_and_delimiters_are_preserved(self):
        self.assertEqual(p.functions("exec system,,shell_exec"), {"exec", "system", "shell_exec"})
        self.assertNotIn("exec", p.functions("EXEC"))
        self.assertEqual(p.functions("exec\tsystem"), {"exec\tsystem"})


if __name__ == "__main__":
    unittest.main()
