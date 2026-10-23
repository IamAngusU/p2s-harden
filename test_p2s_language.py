"""Display-language contracts; no Linux configuration or privileges needed."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import string
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import p2s_harden as p


class LanguageTests(unittest.TestCase):
    def render(self, report, lang="en", as_json=False, verbose=True):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            report.show(as_json, verbose=verbose, lang=lang)
        return output.getvalue()

    def test_english_is_the_default_and_rows_stay_canonical(self):
        report = p.Report()
        report.add("UNKNOWN", "File permissions", "No verified FPM user; specify --web-user")
        original = copy.deepcopy(report.rows)
        text = self.render(report)
        self.assertIn("Configuration audit", text)
        self.assertIn("File permissions: No verified FPM user; specify --web-user", text)
        self.assertNotIn("Dateirechte", text)
        self.assertEqual(report.rows, original)

    def test_german_uses_real_umlauts_without_changing_technical_values(self):
        report = p.Report()
        path = "/srv/Pruefung/Aenderungen ü/URL?x=fehlt"
        report.add("UNKNOWN", "FPM configuration " + path,
                   "Untrusted path or ancestor: " + path)
        text = self.render(report, "de")
        self.assertIn("Konfigurationsprüfung", text)
        self.assertIn("Nicht vertrauenswürdiger Root-Pfad: " + path, text)
        self.assertEqual(text.count(path), 2)

    def test_json_localizes_only_known_prose_and_keeps_structured_data_opaque(self):
        report = p.Report()
        path = "/srv/Pruefung/fehlt: exec"
        url = "https://unbekannt.example/Dateirechte?q=pruefen"
        report.add("UNKNOWN", "Automatic discovery", "Nginx include missing: " + path)
        report.discovery = dict(issues=["Nginx include missing: " + path], config=path,
            scan_roots=[path], selected_sites=[url + "=" + path],
            automatic_changes="No permission-change targets inferred from discovery",
            fpm_instances=[dict(config=path, pools=[dict(name="unbekannt", user="unbekannt", listen="unbekannt")])])
        original = copy.deepcopy(report.discovery)
        report.plan = {"paths": [path], "site": url}
        report.transaction = {"path": path, "status": "prepared"}
        data = json.loads(self.render(report, as_json=True))
        self.assertEqual(data["language"], "en")
        self.assertEqual(data["findings"][0]["detail"], "Nginx include missing: " + path)
        self.assertEqual(data["discovery"]["config"], path)
        self.assertEqual(data["discovery"]["scan_roots"], [path])
        self.assertEqual(data["discovery"]["selected_sites"], [url + "=" + path])
        self.assertEqual(data["discovery"]["fpm_instances"][0]["pools"][0],
                         dict(name="unbekannt", user="unbekannt", listen="unbekannt"))
        self.assertEqual(data["plan"], report.plan)
        self.assertEqual(data["transaction"], report.transaction)
        self.assertEqual(report.discovery, original)

    def test_nested_diagnostics_translate_without_touching_their_path(self):
        path = "/etc/Pruefung/haengender.ini"
        source = "Automatic Nginx discovery incomplete: Nginx include missing: " + path
        self.assertEqual(p.localize(source), "Automatic Nginx discovery incomplete: Nginx include missing: " + path)
        self.assertEqual(p.localize(source, "de"), "Automatische Nginx-Erkennung unvollständig: Nginx-Include fehlt: " + path)

    def test_english_canonical_messages_support_german_too(self):
        path = "/srv/Pruefung/unchanged"
        self.assertEqual(p.localize("Absolute path required: " + path, "de"), "Absoluter Pfad erforderlich: " + path)
        self.assertEqual(p.localize("Changes and rollback require root", "de"), "Änderungen und Rollback erfordern root")
        self.assertEqual(p.localize("Absolute path required: " + path), "Absolute path required: " + path)

    def test_engine_help_localizes_descriptions_and_language_can_follow_help(self):
        for lang, fragment in (("en", "Audit scope"), ("de", "Prüfbereich")):
            with self.subTest(lang=lang):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as ended:
                    p.main(["--help", "--lang", lang])
                self.assertEqual(ended.exception.code, 0)
                self.assertIn(fragment, output.getvalue())
                self.assertNotIn("Pruefbereich", output.getvalue())
                self.assertNotIn("root-uebertragen", output.getvalue())

    def test_all_owned_templates_preserve_their_technical_placeholders(self):
        for source, english, german in p._MESSAGE_TEMPLATES:
            names = [name for _, name, _, _ in string.Formatter().parse(source) if name is not None]
            values = {name: "Value missing" if name == "message" else "/Pruefung/" + name + " ü:'?foo=exec" for name in names}
            canonical = source.format(**values)
            for lang, expected in (("en", english), ("de", german)):
                with self.subTest(source=source, lang=lang):
                    translated = dict(values)
                    if "message" in translated:
                        translated["message"] = "Value missing" if lang == "en" else "Wert fehlt"
                    self.assertEqual(p.localize(canonical, lang), expected.format(**translated))

    def test_english_doctor_has_no_owned_german_messages(self):
        cap = dict(platform="linux", proc=True, root=False, python="3.12.0", systemd=False,
                   tools={key: False for key in ("ps", "curl", "runuser", "systemctl")})
        with patch.object(p, "capabilities", return_value=cap):
            report = p.doctor()
        text = self.render(report)
        for fragment in ("Pruefung", "Prüfung", "verfuegbar", "erforderlich", "fehlt", "Berechtigungen", "Benutzer"):
            self.assertNotIn(fragment, text)
        self.assertIn("Prerequisites", text)

    def test_external_messages_are_verbatim_and_escape_sequences_are_sanitized(self):
        external = "[Errno 13] Permission denied: '/srv/Dateirechte'"
        self.assertEqual(p.localize(external), external)
        report = p.Report()
        report.add("OPEN", "\x1b[31mhost", "/srv/name\nFORGED OK")
        report.discovery = dict(scan_roots=["/srv/\x1b[31mhost\nFORGED"], fpm_instances=[], selected_sites=[])
        text = self.render(report)
        self.assertNotIn("\x1b", text)
        self.assertIn("name?FORGED OK", text)
        self.assertIn("host?FORGED", text)

    def test_info_is_counted_without_affecting_the_exit_code(self):
        report = p.Report()
        report.add("INFO", "ImageMagick policy", "No known policy; extension/container coverage unknown")
        self.assertEqual(report.exit_code(), 0)
        self.assertIn("INFO: 1", self.render(report))

    def test_invalid_language_fails_explicitly(self):
        with self.assertRaisesRegex(ValueError, "choose en or de"):
            p.localize("Wert fehlt", "fr")


@unittest.skipUnless(sys.platform == "linux", "Linux Bash/bootstrap checks")
class LauncherLanguageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p2s-language-")
        self.directory = Path(self.temporary.name)
        base = Path(__file__).parent
        self.launcher = self.directory / "p2s-harden.sh"
        # Exercise the current template without mutating generated release files.
        self.launcher.write_text((base / "p2s-launcher.sh.in").read_text(encoding="utf-8") +
            (base / "p2s_harden.py").read_text(encoding="utf-8") + "\n__P2S_ENGINE_EOF__\n", encoding="utf-8")
        self.empty = self.directory / "empty"
        self.empty.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def run_launcher(self, *args, env=None):
        return subprocess.run(["/bin/bash", str(self.launcher), *args], capture_output=True,
                              text=True, encoding="utf-8", env=env)

    def test_help_defaults_to_english_and_language_may_follow_help(self):
        english = self.run_launcher("--help")
        german = self.run_launcher("--help", "--lang", "de")
        self.assertEqual((english.returncode, german.returncode), (0, 0))
        self.assertIn("Discover and audit locally", english.stdout)
        self.assertIn("Lokal erkennen und prüfen", german.stdout)
        self.assertNotIn("pruefen", german.stdout)
        self.assertIn("--runtime-dir", english.stdout)
        self.assertIn("--max-http-probes", german.stdout)

    def test_missing_python_bootstrap_localizes_json_without_other_programs(self):
        for lang, title, fragment in (("en", "Prerequisites", "is missing"), ("de", "Voraussetzungen", "fehlt")):
            with self.subTest(lang=lang):
                run = self.run_launcher("--doctor", "--json", "--lang=" + lang,
                                        env=dict(os.environ, PATH=str(self.empty)))
                self.assertEqual(run.returncode, 2, run.stderr)
                report = json.loads(run.stdout)
                self.assertEqual(report["language"], lang)
                self.assertEqual(report["findings"][0]["title"], title)
                self.assertEqual(report["schema_version"], 2)
                self.assertRegex(report["findings"][0]["id"], r"^P2S-EXEC001-[a-f0-9]{16}$")
                self.assertTrue(report["has_unknown"])
                self.assertFalse(report["has_open"])
                self.assertIn(fragment, report["findings"][0]["detail"])
                self.assertTrue(report["discovery"]["bootstrap"])
                self.assertFalse(any(report["discovery"]["capabilities"]["tools"].values()))

    def test_remote_posix_bootstrap_gets_the_selected_language(self):
        ssh = self.directory / "ssh"
        ssh.write_text('#!/bin/bash\nfor argument; do last="$argument"; done\nexec /bin/sh -c "$last"\n')
        ssh.chmod(0o700)
        for lang, title in (("en", "Prerequisites"), ("de", "Voraussetzungen")):
            with self.subTest(lang=lang):
                run = self.run_launcher("--ssh", "example.test", "--json", "--lang", lang,
                    env=dict(os.environ, PATH=str(self.empty), SSH_BIN=str(ssh)))
                self.assertEqual(run.returncode, 2, run.stderr)
                report = json.loads(run.stdout)
                self.assertEqual(report["language"], lang)
                self.assertEqual(report["findings"][0]["title"], title)

    def test_missing_ssh_is_reported_in_the_selected_language(self):
        for lang, fragment in (("en", "client is missing"), ("de", "Client fehlt")):
            with self.subTest(lang=lang):
                run = self.run_launcher("--ssh", "example.test", "--json", "--lang", lang,
                    env=dict(os.environ, SSH_BIN="/nonexistent/p2s-ssh"))
                self.assertEqual(run.returncode, 2)
                report = json.loads(run.stdout)
                self.assertEqual(report["language"], lang)
                self.assertIn(fragment, report["findings"][0]["detail"])

    def test_invalid_or_missing_language_is_an_actionable_usage_error(self):
        for args in (("--lang",), ("--lang", "fr"), ("--lang=fr", "--help")):
            with self.subTest(args=args):
                run = self.run_launcher(*args)
                self.assertEqual(run.returncode, 2)
                self.assertIn("--lang requires en or de", run.stderr)
                self.assertNotIn("Traceback", run.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
