"""Fault injection for incomplete hosts; no production configuration changes."""
import argparse
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


class ResilienceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='p2s-resilience-', dir=Path.cwd())
        self.root = Path(self.tmp.name)
        self.ini = self.root / 'php.ini'
        self.ini.write_text('allow_url_include=Off\n')
        self.cap = dict(platform='linux', python='3.11.0', proc=True, root=True, systemd=True,
                        tools=dict(ps=True, curl=True, runuser=True, systemctl=True))
        self.args = argparse.Namespace(root=str(self.root), roots=[str(self.root)], site=['http://example.test=' + str(self.root)],
                                       web_user=['www-data'], no_progress=True)
        self.instance = dict(pid=42, config='/fake/fpm.conf', service=None, inis=[str(self.ini)],
                             values={'disable_functions': ','.join(p.REQUIRED), 'allow_url_include': 'Off'},
                             pools={'www': {'user': 'www-data'}})
        self.permissions = json.dumps(dict(files=0, directories=0, file_sample=[], directory_sample=[], errors=[]))

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, instances=None, discovery_error=None):
        discover = patch.object(p, 'discover', side_effect=discovery_error) if discovery_error else patch.object(p, 'discover', return_value=(instances or [self.instance], []))
        with patch.object(p, 'capabilities', return_value=self.cap), discover, patch.object(p, 'as_user', return_value=self.permissions) as permissions, patch.object(p, 'http_observation', return_value=dict(status=403, bytes=0, sha256=p.digest(b''))) as http:
            result = p.scan(self.args)
        return result, permissions, http

    def test_missing_curl_does_not_prevent_http_or_permission_checks(self):
        self.cap['tools']['curl'] = False
        self.args.site *= 10
        (report, _, _, _), permissions, http = self.scan()
        self.assertFalse(any('curl fehlt' in r['detail'] for r in report.rows))
        self.assertTrue(permissions.called)
        self.assertTrue(http.called)
        self.assertTrue(any(r['status'] == 'OK' and 'Pool ' in r['title'] for r in report.rows))
        self.assertTrue(all(r['status'] == 'OK' for r in report.rows if r['title'].startswith('HTTP http')))

    def test_missing_runuser_is_reported_once_per_user_not_per_root(self):
        self.cap['tools']['runuser'] = False
        self.args.roots *= 15
        (report, _, _, _), permissions, http = self.scan()
        self.assertEqual(len([r for r in report.rows if 'runuser fehlt' in r['detail']]), 1)
        permissions.assert_not_called()
        self.assertTrue(http.called)

    def test_no_root_keeps_http_and_ini_checks_running(self):
        self.cap['root'] = False
        (report, _, _, _), permissions, http = self.scan()
        self.assertTrue(any('Fremde UID' in r['detail'] for r in report.rows))
        permissions.assert_not_called()
        self.assertTrue(http.called)

    def test_unknown_user_does_not_stop_other_modules(self):
        self.args.web_user = ['p2s-user-that-does-not-exist']
        self.instance['pools'] = {}
        (report, _, _, _), permissions, http = self.scan()
        self.assertTrue(any('Benutzer existiert nicht' in r['detail'] for r in report.rows))
        self.assertTrue(http.called)

    def test_fpm_discovery_failure_keeps_permissions_http_and_kernel_checks(self):
        (report, _, _, _), permissions, http = self.scan(discovery_error=p.CheckError('procfs denied'))
        self.assertTrue(any(r['title'] == 'FPM-Abdeckung' for r in report.rows))
        self.assertTrue(any(r['title'] == 'ptrace_scope' for r in report.rows))
        self.assertTrue(permissions.called)
        self.assertTrue(http.called)

    def test_one_unreadable_ini_does_not_discard_another_instance(self):
        bad = dict(self.instance, config='/bad/fpm.conf', inis=['/nonexistent/p2s/php.ini'],
                   values=dict(self.instance['values'], disable_functions='exec'))
        (report, updates, _, _), _, http = self.scan([bad, self.instance])
        self.assertTrue(any(r['title'] == 'FPM-Konfiguration /bad/fpm.conf' for r in report.rows))
        self.assertTrue(any(r['title'] == 'disable_functions /fake/fpm.conf' for r in report.rows))
        self.assertFalse(updates)
        self.assertTrue(http.called)

    def test_audit_without_systemd_still_checks_ini(self):
        self.cap['tools']['systemctl'] = False
        self.cap['systemd'] = False
        (report, _, _, _), _, _ = self.scan()
        self.assertTrue(any(r['title'].startswith('disable_functions') and r['status'] == 'OK' for r in report.rows))

    def test_missing_reload_blocks_fix_before_backup_creation(self):
        with patch.object(p, 'capabilities', return_value=self.cap):
            reasons = p.fix_blockers({str(self.ini): {'allow_url_include': 'Off'}}, [], [self.instance], {'www-data'})
        self.assertTrue(any('Reload' in r for r in reasons))
        with patch.object(p.Transaction, 'begin', side_effect=AssertionError('must not create backup')):
            with self.assertRaises(p.CheckError):
                p.Transaction(self.root / 'backup').prepare({str(self.ini): {'allow_url_include': 'Off'}}, [], [self.instance])

    def test_permission_plan_requires_a_real_user_and_runuser(self):
        self.cap['tools']['runuser'] = False
        with patch.object(p, 'capabilities', return_value=self.cap):
            self.assertTrue(p.fix_blockers({}, [str(self.root)], [], []))
            reasons = p.fix_blockers({}, [str(self.root)], [], ['www-data'])
            self.assertTrue(any('runuser' in r for r in reasons))

    def test_missing_optional_http_client_does_not_block_permission_plan(self):
        self.cap['tools']['curl'] = False
        with patch.object(p, 'capabilities', return_value=self.cap):
            self.assertEqual(p.fix_blockers({}, [str(self.root)], [], ['www-data']), [])

    def test_blocked_fix_keeps_the_audit_report_and_never_starts_transaction(self):
        report = p.Report()
        report.add('OK', 'HTTP fixture', '403')
        output = io.StringIO()
        with patch.object(p, 'prepare_scope'), patch.object(p, 'prepare_runtime_dirs'), patch.object(p, 'scan', return_value=(report, {str(self.ini): {'allow_url_include': 'Off'}}, [self.instance], {'www-data'})), patch.object(p, 'capabilities', return_value=self.cap), patch.object(p.Transaction, 'begin', side_effect=AssertionError('must not mutate')), contextlib.redirect_stdout(output):
            result = p.main(['--fix', '--verbose', '--lang', 'de'])
        self.assertEqual(result, 2)
        self.assertIn('HTTP fixture', output.getvalue())
        self.assertIn('Fix gesperrt', output.getvalue())
        self.assertEqual(self.ini.read_text(), 'allow_url_include=Off\n')

    def test_missing_ssh_client_returns_json_without_traceback(self):
        run = subprocess.run(['/bin/bash', str(Path('p2s-harden.sh').absolute()), '--ssh', 'example.test', '--json', '--lang', 'de'],
                             env=dict(os.environ, SSH_BIN='/nonexistent/p2s-ssh'), capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn('OpenSSH-Client fehlt', json.loads(run.stdout)['findings'][0]['detail'])
        self.assertNotIn('Traceback', run.stderr)

    def test_doctor_does_not_read_web_or_fpm_configuration(self):
        self.cap['tools'] = {key: False for key in self.cap['tools']}
        with patch.object(p, 'capabilities', return_value=self.cap), patch.object(p, 'discover', side_effect=AssertionError), patch.object(p, 'read_nginx', side_effect=AssertionError):
            report = p.doctor()
        self.assertTrue(any('/proc-Fallback' in r['detail'] and r['status'] == 'OK' for r in report.rows))
        self.assertEqual(report.exit_code(), 2)

    def test_procfs_is_used_when_ps_missing_or_broken(self):
        with patch.object(p.shutil, 'which', return_value=None):
            listing, issues = p.process_listing()
        self.assertIsInstance(listing, str)
        self.assertIsInstance(issues, list)
        with patch.object(p, 'command', side_effect=p.CheckError('ps broken')), patch.object(p.shutil, 'which', return_value='/fake/ps'):
            listing, issues = p.process_listing()
        self.assertIsInstance(listing, str)

    def test_remote_bootstrap_works_in_posix_shell_without_python(self):
        fake = self.root / 'ssh'
        fake.write_text('#!/bin/bash\nfor argument; do last="$argument"; done\nexec /bin/sh -c "$last"\n')
        fake.chmod(0o700)
        empty = self.root / 'empty'
        empty.mkdir()
        run = subprocess.run(['/bin/bash', str(Path('p2s-harden.sh').absolute()), '--ssh', 'example.test', '--doctor', '--json'],
                             env=dict(os.environ, PATH=str(empty), SSH_BIN=str(fake)), capture_output=True, text=True)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertTrue(json.loads(run.stdout)['discovery']['bootstrap'])

    def test_unreachable_ssh_is_unknown_with_actionable_json(self):
        fake = self.root / 'ssh'
        fake.write_text('#!/bin/bash\nexit 255\n')
        fake.chmod(0o700)
        run = subprocess.run(['/bin/bash', str(Path('p2s-harden.sh').absolute()), '--ssh', 'example.test', '--json'],
                             env=dict(os.environ, SSH_BIN=str(fake)), capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        result = json.loads(run.stdout)
        self.assertEqual(result['findings'][0]['title'], 'SSH')
        self.assertEqual(result['findings'][0]['status'], 'UNKNOWN')

    def test_python_missing_bootstrap_is_structured_and_lists_all_missing_tools(self):
        empty = self.root / 'empty-path'
        empty.mkdir()
        run = subprocess.run(['/bin/bash', str(Path('p2s-harden.sh').absolute()), '--doctor', '--json', '--lang', 'de'],
                             env=dict(os.environ, PATH=str(empty)), capture_output=True, text=True)
        self.assertEqual(run.returncode, 2, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result['schema_version'], 1)
        self.assertTrue(result['discovery']['bootstrap'])
        self.assertFalse(any(result['discovery']['capabilities']['tools'].values()))
        self.assertIn('Python', result['findings'][0]['detail'])
        self.assertNotIn('Traceback', run.stderr)

    def test_minimal_path_runs_python_doctor_without_optional_tools(self):
        minimal = self.root / 'minimal-path'
        minimal.mkdir()
        (minimal / 'python3').symlink_to(sys.executable)
        run = subprocess.run(['/bin/bash', str(Path('p2s-harden.sh').absolute()), '--doctor', '--json', '--lang', 'de'],
                             env=dict(os.environ, PATH=str(minimal)), capture_output=True, text=True)
        result = json.loads(run.stdout)
        self.assertEqual(run.returncode, result['exit_code'])
        self.assertFalse(result['discovery'].get('bootstrap', False))
        self.assertEqual(len(result['findings']), 7)
        self.assertTrue(any('/proc-Fallback' in r['detail'] for r in result['findings']))

    def test_json_has_schema_and_does_not_mix_terminal_progress(self):
        report = p.Report()
        report.add('UNKNOWN', 'missing', 'curl')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            report.show(True)
        self.assertEqual(json.loads(output.getvalue())['schema_version'], 1)

    def test_human_output_cannot_inject_terminal_escape_codes(self):
        report = p.Report()
        report.add('OPEN', '\x1b[31mhost', '/srv/name\nFORGED OK')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            report.show()
        self.assertNotIn('\x1b', output.getvalue())
        self.assertIn('name?FORGED OK', output.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
