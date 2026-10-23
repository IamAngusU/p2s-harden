"""Stable automation contracts, complete diagnostics and realistic traversal."""
import argparse
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import mock_open, patch

import p2s_harden as p


class FindingContracts(unittest.TestCase):
    def render(self, report, lang="en"):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            report.show(True, lang=lang)
        return json.loads(out.getvalue())

    def test_identity_is_independent_of_status_language_and_prose(self):
        first, second = p.Report(), p.Report()
        resource=dict(config="/etc/php/8.3/fpm/php-fpm.conf", pool="app")
        first.add("OPEN", "Old title", "Missing exec", rule_id="P2S-PHP001", resource=resource)
        second.add("OK", "A reworded title", "No missing functions", rule_id="P2S-PHP001", resource=dict(reversed(list(resource.items()))))
        self.assertEqual(self.render(first,"de")["findings"][0]["id"], self.render(second)["findings"][0]["id"])
        self.assertEqual(first.rows[0]["resource"], resource)
        self.assertEqual(first.rows[0]["severity"], "high")
        self.assertTrue(first.rows[0]["remediation"])

    def test_open_first_does_not_make_unknowns_pass(self):
        report=p.Report()
        report.add("OPEN", "functions", "missing popen", rule_id="P2S-PHP001", resource="one")
        report.add("UNKNOWN", "coverage", "partial", rule_id="P2S-FS003", resource="two")
        self.assertEqual(report.exit_code(),2)
        report.configure("open")
        self.assertEqual(report.exit_code(),1)
        result=self.render(report)
        self.assertTrue(result["has_open"])
        self.assertTrue(result["has_unknown"])
        self.assertEqual(result["schema_version"],2)
        report.configure("open", [report.rows[0]["id"]])
        self.assertEqual(report.exit_code(),2)
        self.assertTrue(self.render(report)["has_unknown"])

    def test_suppression_is_visible_specific_and_never_suppresses_unknown(self):
        report=p.Report()
        for pool in ("a","b"):
            report.add("OPEN","functions",pool,rule_id="P2S-PHP001",resource=pool)
        report.configure(ignore=[report.rows[0]["id"]])
        result=self.render(report)
        self.assertEqual(result["suppressed_open"],1)
        self.assertEqual(result["exit_code"],1)
        self.assertEqual(len(result["findings"]),2)
        report.configure(ignore=["P2S-PHP001"])
        self.assertEqual(report.exit_code(),0)
        report.add("UNKNOWN","coverage","missing",rule_id="P2S-PHP001",resource="c")
        report.configure(ignore=["P2S-PHP001"])
        self.assertEqual(report.exit_code(),2)

    def test_fix_confirmation_uses_controlling_terminal_and_defaults_to_no(self):
        args=argparse.Namespace(yes=False,json=False,lang="en")
        # A separate controlling tty is required: engine stdin contains source
        # code during SSH execution and must never be consumed for answers.
        with patch("builtins.open",mock_open(read_data="\n")) as opened:
            self.assertFalse(p.confirm_fix(args))
            opened.assert_called_once_with("/dev/tty","r+",encoding="utf-8")
        with patch("builtins.open",mock_open(read_data="yes\n")):
            self.assertTrue(p.confirm_fix(args))
        with patch("builtins.open",side_effect=OSError("no tty")), self.assertRaisesRegex(p.CheckError,"--fix --yes"):
            p.confirm_fix(args)
        args.yes=True
        with patch("builtins.open",side_effect=AssertionError("must not prompt")):
            self.assertTrue(p.confirm_fix(args))

    def test_english_source_guard_covers_all_error_and_finding_literals(self):
        german=re.compile(r"\b(?:fehlt|erforderlich|verfuegbar|Pruefung|geaendert|Benutzer|Verzeichnis|unbekannt|haengender|schreibbare|Aenderungen)\b")
        violations=[]
        for path in (Path(__file__).parent/"src").glob("*.py"):
            if path.name=="messages.py": continue
            tree=ast.parse(path.read_text(encoding="utf-8"))
            # Also catch messages assigned to variables/tuples before add(),
            # not just inline strings. Report.show deliberately has DE branches.
            if path.name!="report.py":
                for node in ast.walk(tree):
                    if isinstance(node,ast.Constant) and isinstance(node.value,str) and german.search(node.value):
                        violations.append((path.name,node.lineno,node.value))
            for call in ast.walk(tree):
                if not isinstance(call,ast.Call): continue
                error=isinstance(call.func,ast.Name) and call.func.id=="CheckError"
                finding=isinstance(call.func,ast.Attribute) and call.func.attr=="add" and isinstance(call.func.value,ast.Name) and call.func.value.id=="report"
                if not (error or finding): continue
                for node in ast.walk(call):
                    if isinstance(node,ast.Constant) and isinstance(node.value,str) and german.search(node.value):
                        violations.append((path.name,call.lineno,node.value))
                if finding:
                    self.assertTrue({"rule_id","resource"} <= {k.arg for k in call.keywords}, (path.name,call.lineno))
        self.assertEqual(violations,[])

    def test_help_documents_every_option_and_examples(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            p.main(["--help"])
        self.assertIn("Examples:",out.getvalue())
        for option in ("--yes", "--fail-on", "--ignore", "--backup-id", "--json", "--discover"):
            self.assertIn(option,out.getvalue())


@unittest.skipUnless(sys.platform=="linux", "real Linux filesystem traversal")
class LargeTree(unittest.TestCase):
    def test_36000_php_files_fit_default_budget_and_remain_in_permission_scope(self):
        with tempfile.TemporaryDirectory(prefix="p2s-large-") as temporary:
            root=Path(temporary)
            vendor=root/"vendor"
            vendor.mkdir()
            # One realistic large tree checks both walkers against actual files.
            for number in range(36000):
                (vendor/(str(number)+".php")).touch()
            hidden=vendor/"dependency"/".git"
            hidden.mkdir(parents=True)
            (vendor/".env.local").touch()
            (root/"backup.sql").touch()
            (root/"phpinfo.php").touch()
            endpoints,issues=p.git_endpoints(root)
            self.assertEqual(issues,[])
            self.assertTrue({"vendor/dependency/.git/config","vendor/.env.local","backup.sql","phpinfo.php"} <= endpoints)
            run=subprocess.run([sys.executable,"-B","-c",p.PERMISSION_SCAN,str(root)],capture_output=True,text=True,check=True)
            data=json.loads(run.stdout)
            self.assertEqual(data["error_count"],0,data)
            self.assertEqual(data["files"],36001)


if __name__=="__main__": unittest.main()
