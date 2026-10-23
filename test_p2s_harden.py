import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest
import subprocess
from unittest.mock import patch

import p2s_harden as p


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="p2s-test-", dir=Path.cwd())
        self.root = Path(self.tmp.name)
        self.ini = self.root / "php.ini"
        self.ini.write_text("; disable_functions = exec,system\nallow_url_include = On\n")
        self.ini.chmod(0o640)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, **kwargs):
        values = dict(root=str(self.root), site=[], web_user=["www-data"])
        values.update(kwargs)
        return argparse.Namespace(**values)

    def instance(self, disabled=None, pool=None):
        return dict(pid=123, start="identity", binary="/fake/fpm", config="/fake/fpm.conf", service="fake-fpm.service",
                    env={}, inis=[str(self.ini)],
                    values={"disable_functions": ",".join(p.REQUIRED) if disabled is None else disabled,
                            "allow_url_include": "Off", "open_basedir": "/srv/site"},
                    pools={"www": dict(user="www-data", **(pool or {}))})

    def scan(self, instance=None, probe=None, permission_error=False, **kwargs):
        data = dict(files=0, directories=0, file_sample=[], directory_sample=[], errors=[])
        as_user = patch.object(p, "as_user", side_effect=p.CheckError("runuser failed")) if permission_error else patch.object(p, "as_user", return_value=json.dumps(data))
        def observation(url, connect_ip="127.0.0.1"):
            code = 403 if "/.p2s-missing-" in url or probe is None else probe(url)
            return dict(status=code, bytes=0, sha256=p.digest(b""))
        with patch.object(p, "discover", return_value=([instance or self.instance()], [])), as_user, patch.object(p, "http_observation", side_effect=observation):
            return p.scan(self.args(**kwargs))

    def test_commented_ini_is_not_active(self):
        self.assertEqual(p.active_ini_lines(";disable_functions = exec\n#disable_functions=system\n", "disable_functions"), [])

    def test_absent_directive_is_added_and_comment_preserved(self):
        new = p.set_ini(self.ini.read_text(), {"disable_functions": "exec,system"})
        self.assertIn("; disable_functions = exec,system", new)
        self.assertEqual(len(p.active_ini_lines(new, "disable_functions")), 1)

    def test_last_real_assignment_is_updated(self):
        old = "allow_url_include = On\n;allow_url_include = On\nallow_url_include=Yes\n"
        self.assertTrue(p.set_ini(old, {"allow_url_include": "Off"}).endswith("allow_url_include = Off\n"))

    def test_conditional_ini_is_refused(self):
        with self.assertRaises(p.CheckError):
            p.set_ini("[PATH=/srv]\n", {"allow_url_include": "Off"})

    def test_multiple_pool_sections_are_kept(self):
        data = p.pool_values("NOTICE: [global]\nNOTICE: [one]\nNOTICE: \tuser = www-data\nNOTICE: [two]\nNOTICE: \tuser = nobody\n")
        self.assertEqual(set(data), {"one", "two"})
        self.assertEqual(data["two"]["user"], "nobody")

    def test_short_pool_cannot_remove_global_disable_functions(self):
        report, updates, _, _ = self.scan(self.instance(pool={"php_admin_value[disable_functions]": "exec"}))
        self.assertEqual(next(r["status"] for r in report.rows if r["title"].startswith("Pool ")), "OK")
        self.assertEqual(updates, {})

    def test_incomplete_inherited_global_is_open(self):
        report, updates, _, _ = self.scan(self.instance(disabled="exec"))
        self.assertEqual(next(r["status"] for r in report.rows if r["title"].startswith("Pool ")), "OPEN")
        self.assertEqual(p.functions(updates[str(self.ini)]["disable_functions"]), p.REQUIRED)
        self.assertNotIn("putenv", updates[str(self.ini)]["disable_functions"])

    def test_root_open_basedir_is_open(self):
        instance = self.instance(pool={"php_admin_value[open_basedir]": "/srv:/"})
        report, _, _, _ = self.scan(instance)
        self.assertEqual(next(r["status"] for r in report.rows if r["title"].startswith("open_basedir")), "OPEN")

    def test_shared_cli_module_ini_is_not_automatically_modified(self):
        directory = self.root / 'fpm'
        directory.mkdir()
        main = directory / 'php.ini'
        main.write_text('allow_url_include=Off\n')
        shared = self.root / 'shared-module.ini'
        shared.write_text('disable_functions=exec\n')
        instance = self.instance(disabled='exec')
        instance['inis'] = [str(main), str(shared)]
        report, updates, _, _ = self.scan(instance)
        self.assertEqual(updates, {})
        self.assertTrue(any(r['title'] == 'Automatischer INI-Fix ausgespart' for r in report.rows))

    def test_permission_command_failure_is_unknown(self):
        report, _, _, _ = self.scan(permission_error=True)
        self.assertEqual(next(r["status"] for r in report.rows if r["title"].startswith("Dateirechte")), "UNKNOWN")
        self.assertEqual(report.exit_code(), 2)

    def test_http_status_classes_and_nested_git(self):
        (self.root / "nested" / ".git").mkdir(parents=True)
        for code, expected in ((200, "OPEN"), (206, "OPEN"), (301, "UNKNOWN"), (403, "OK"), (404, "OK"), (503, "UNKNOWN")):
            with self.subTest(code=code):
                report, _, _, _ = self.scan(site=["https://example.test=" + str(self.root)], probe=lambda _: code)
                rows = [r for r in report.rows if r["title"].startswith("HTTP https")]
                self.assertEqual(len(rows), 3)
                self.assertTrue(all(r["status"] == expected for r in rows))
                self.assertTrue(any("nested/.git/config" in r["title"] for r in rows))

    def test_http_failure_is_unknown(self):
        def fail(_):
            raise p.CheckError("HTTP request failed: TimeoutError")
        report, _, _, _ = self.scan(site=["https://example.test=" + str(self.root)], probe=fail)
        self.assertTrue(all(r["status"] == "UNKNOWN" for r in report.rows if r["title"].startswith("HTTP https")))

    def test_status_000_is_not_a_success(self):
        status, _ = p.classify_http(dict(status=0, bytes=0, sha256=p.digest(b"")), [])
        self.assertEqual(status, "UNKNOWN")

    def test_unknown_never_prints_all_passed(self):
        report = p.Report()
        report.add("UNKNOWN", "FPM", "unreadable")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            report.show()
        self.assertEqual(report.exit_code(), 2)
        self.assertNotIn("Alle Pruefpunkte bestanden", out.getvalue())

    def test_check_and_dry_run_never_start_transaction(self):
        report = p.Report()
        report.add("OPEN", "fixture", "fixture")
        before = self.ini.read_bytes()
        for mode in ("--check", "--dry-run"):
            with patch.object(p, "scan", return_value=(report, {str(self.ini): {"allow_url_include": "Off"}}, [], [])), patch.object(p, "fix_blockers", return_value=[]), patch.object(p.Transaction, "begin", side_effect=AssertionError("mutation in read-only mode")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(p.main([mode, "--protect-dir", str(self.root)]), 1)
        self.assertEqual(self.ini.read_bytes(), before)
        self.assertEqual(sorted(x.name for x in self.root.iterdir()), ["php.ini"])

    def test_transaction_roundtrip_preserves_contents_mode_owner_xattr(self):
        os.setxattr(self.ini, "user.p2s-test", b"original")
        original, meta = self.ini.read_bytes(), p.metadata(self.ini)
        tx = p.Transaction(self.root / "backups")
        tx.prepare({str(self.ini): {"disable_functions": "exec,system", "allow_url_include": "Off"}}, [], [])
        self.assertEqual(len(tx.data["files"]), 1)
        tx.apply([], [])
        self.assertIn("allow_url_include = Off", self.ini.read_text())
        p.Transaction.rollback(tx.root)
        self.assertEqual(self.ini.read_bytes(), original)
        after = p.metadata(self.ini)
        self.assertTrue(all(meta[k] == after[k] for k in ("uid", "gid", "mode", "mtime_ns", "xattrs")))

    def test_parallel_edit_is_not_overwritten_on_rollback(self):
        tx = p.Transaction(self.root / "backups")
        tx.prepare({str(self.ini): {"allow_url_include": "Off"}}, [], [])
        tx.apply([], [])
        self.ini.write_text("unrelated change\n")
        with self.assertRaises(p.CheckError):
            p.Transaction.rollback(tx.root)
        self.assertEqual(self.ini.read_text(), "unrelated change\n")

    def test_partial_failure_restores_only_started_files(self):
        second = self.root / "z.ini"
        second.write_text("allow_url_include=On\n")
        original = self.ini.read_bytes()
        tx = p.Transaction(self.root / "backups")
        tx.prepare({str(self.ini): {"allow_url_include": "Off"}, str(second): {"allow_url_include": "Off"}}, [], [])
        second.write_text("external edit\n")
        with self.assertRaises(p.CheckError):
            tx.apply([], [])
        self.assertEqual(self.ini.read_bytes(), original)
        self.assertEqual(second.read_text(), "external edit\n")

    def test_syntax_failure_restores_file(self):
        inst = self.instance()
        original = self.ini.read_bytes()
        tx = p.Transaction(self.root / "backups")
        tx.prepare({str(self.ini): {"allow_url_include": "Off"}}, [], [inst])
        def fail(*args, **kwargs):
            raise p.CheckError("invalid configuration")
        with patch.object(p, "command", side_effect=fail), self.assertRaises((p.CheckError, OSError)):
            tx.apply([inst], [])
        self.assertEqual(self.ini.read_bytes(), original)

    def test_reload_failure_restores_even_when_master_disappears(self):
        inst = self.instance()
        original = self.ini.read_bytes()
        tx = p.Transaction(self.root / "backups")
        tx.prepare({str(self.ini): {"allow_url_include": "Off"}}, [], [inst])
        calls = []
        def command(argv, **kwargs):
            calls.append(argv)
            if "-i" in argv:
                return "disable_functions => " + ",".join(p.REQUIRED) + "\nallow_url_include => Off\n", ""
            if "show" in argv:
                return "0\n", ""
            return "", ""
        with patch.object(p, "command", side_effect=command), patch.object(p, "reload_instances", side_effect=p.CheckError("reload failed")), patch.object(p, "trusted", side_effect=lambda path: Path(path)), self.assertRaises(p.CheckError):
            tx.apply([inst], [])
        self.assertEqual(self.ini.read_bytes(), original)
        self.assertIn(["systemctl", "start", "fake-fpm.service"], calls)

    def test_pool_allow_url_include_override_is_open(self):
        instance = self.instance(pool={"php_admin_flag[allow_url_include]": "on"})
        report, _, _, _ = self.scan(instance)
        rows = [r for r in report.rows if r["title"].startswith("allow_url_include [")]
        self.assertEqual(rows[0]["status"], "OPEN")

    def test_http_queries_and_fragments_are_rejected(self):
        for url in ("https://example.test/#preview", "https://example.test/?preview=1"):
            with self.subTest(url=url):
                report, _, _, _ = self.scan(site=[url + "=" + str(self.root)], probe=lambda _: 403)
                self.assertFalse(any(r["title"].startswith("HTTP https") for r in report.rows))
                self.assertTrue(any(r["title"] == "HTTP-Konfiguration" and r["status"] == "UNKNOWN" for r in report.rows))

    def test_status_only_probe_preserves_its_public_interface(self):
        with patch.object(p, "http_observation", return_value=dict(status=403, bytes=0, sha256=p.digest(b""))) as mock:
            self.assertEqual(p.probe("https://example.test/.env"), 403)
        mock.assert_called_once_with("https://example.test/.env", "127.0.0.1")

    def test_master_environment_is_used_without_caller_leaks(self):
        with patch.object(Path, "read_bytes", return_value=b"FPM_DISABLED_FUNCTIONS=exec,system\0PATH=/usr/bin\0"), patch.dict(os.environ, {"UNRELATED_CALLER_SECRET": "must-not-leak"}):
            env = p.selected_environment(123)
        self.assertEqual(env["FPM_DISABLED_FUNCTIONS"], "exec,system")
        self.assertNotIn("UNRELATED_CALLER_SECRET", env)

    def test_metadata_change_between_prepare_apply_is_not_overwritten(self):
        tx = p.Transaction(self.root / "backups")
        tx.prepare({str(self.ini): {"allow_url_include": "Off"}}, [], [])
        self.ini.chmod(0o600)
        with self.assertRaises(p.CheckError):
            tx.apply([], [])
        self.assertEqual(self.ini.stat().st_mode & 0o777, 0o600)

    def test_metadata_change_after_fix_blocks_rollback(self):
        tx = p.Transaction(self.root / "backups")
        tx.prepare({str(self.ini): {"allow_url_include": "Off"}}, [], [])
        tx.apply([], [])
        self.ini.chmod(0o600)
        with self.assertRaises(p.CheckError):
            p.Transaction.rollback(tx.root)
        self.assertEqual(self.ini.stat().st_mode & 0o777, 0o600)

    def test_interrupted_prepared_transaction_can_be_rolled_back(self):
        tx = p.Transaction(self.root / "backups")
        original = self.ini.read_bytes()
        tx.prepare({str(self.ini): {"allow_url_include": "Off"}}, [], [])
        item = tx.data["files"][0]
        item["started"] = True
        tx.save()
        p.atomic_bytes(self.ini, p.set_ini(original.decode(), item["values"]).encode(), item["meta"])
        p.Transaction.rollback(tx.root, tx.path.name)
        self.assertEqual(self.ini.read_bytes(), original)

    def test_default_acl_is_not_silently_inherited_by_atomic_replacement(self):
        import struct
        acl = struct.pack('<I', 2)
        for tag, perms, uid in ((1, 7, 0xffffffff), (2, 4, pwd.getpwnam('www-data').pw_uid), (4, 5, 0xffffffff), (16, 5, 0xffffffff), (32, 0, 0xffffffff)):
            acl += struct.pack('<HHI', tag, perms, uid)
        os.setxattr(self.root, 'system.posix_acl_default', acl)
        original = p.metadata(self.ini)
        p.atomic_bytes(self.ini, b'new contents\n', original)
        self.assertEqual(p.metadata(self.ini)['xattrs'], original['xattrs'])
        self.assertEqual(self.ini.stat().st_mode & 0o777, 0o640)

    def test_protect_directory_is_nonrecursive_and_reversible(self):
        directory = self.root / "code"
        directory.mkdir()
        owner = pwd.getpwnam("www-data")
        child = directory / "child"
        child.write_text("runtime data")
        os.chown(directory, owner.pw_uid, owner.pw_gid)
        os.chown(child, owner.pw_uid, owner.pw_gid)
        directory.chmod(0o775)
        tx = p.Transaction(self.root / "backups")
        tx.prepare({}, [str(directory)], [])
        tx.apply([], [])
        self.assertEqual(directory.stat().st_uid, 0)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        self.assertEqual(child.stat().st_uid, owner.pw_uid)
        p.Transaction.rollback(tx.root)
        self.assertEqual(directory.stat().st_uid, owner.pw_uid)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o775)

    def test_symlink_target_refused(self):
        link = self.root / "link.ini"
        link.symlink_to(self.ini)
        with self.assertRaises(p.CheckError):
            p.trusted(link)

    def test_shell_metacharacters_in_path_are_data(self):
        path = self.root / "name ' $(touch NEVER) & |.ini"
        path.write_text("allow_url_include=On\n")
        tx = p.Transaction(self.root / "backups")
        tx.prepare({str(path): {"allow_url_include": "Off"}}, [], [])
        tx.apply([], [])
        self.assertIn("Off", path.read_text())
        self.assertFalse((self.root / "NEVER").exists())


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='p2s-discovery-', dir=Path.cwd())
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def inventory(self, text):
        with patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'is_file', return_value=False), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'resolve', side_effect=lambda *a, **kw: a[0], autospec=True):
            return p.nginx_inventory(p.parse_nginx(text))

    def test_quotes_comments_and_variables_do_not_change_structure(self):
        tree = p.parse_nginx('http { # comment\n server { root "/srv/site with spaces"; server_name "{literal}"; set $path ${SITE_ROOT}; } }')
        server = tree[0]['children'][0]
        self.assertEqual(server['children'][0]['args'], ['/srv/site with spaces'])
        self.assertEqual(server['children'][1]['args'], ['{literal}'])
        self.assertEqual(server['children'][2]['args'], ['$path', '${SITE_ROOT}'])

    def test_relative_includes_are_relative_to_main_config(self):
        (self.base / 'parts').mkdir()
        (self.base / 'shared').mkdir()
        (self.base / 'nginx.conf').write_text('http { include parts/*.conf; }')
        (self.base / 'parts/site.conf').write_text('server { include shared/root.conf; }')
        (self.base / 'shared/root.conf').write_text('root /srv/example;')
        tree = p.read_nginx(self.base / 'nginx.conf')
        self.assertEqual(tree[0]['children'][0]['children'][0]['args'], ['/srv/example'])

    def test_root_owned_sites_enabled_symlink_is_supported(self):
        (self.base / 'nginx.conf').write_text('include enabled.conf;')
        (self.base / 'available.conf').write_text('http {}')
        (self.base / 'enabled.conf').symlink_to(self.base / 'available.conf')
        self.assertEqual(p.read_nginx(self.base / 'nginx.conf')[0]['name'], 'http')

    def test_include_cycle_is_refused(self):
        file = self.base / 'nginx.conf'
        file.write_text('include nginx.conf;')
        with self.assertRaises(p.CheckError):
            p.read_nginx(file)

    def test_empty_glob_is_valid_but_missing_literal_is_not(self):
        file = self.base / 'nginx.conf'
        file.write_text('include empty/*.conf; http {}')
        self.assertEqual(len(p.read_nginx(file)), 1)
        file.write_text('include missing.conf;')
        with self.assertRaises(p.CheckError):
            p.read_nginx(file)

    def test_untrusted_config_is_not_used_for_discovery(self):
        file = self.base / 'nginx.conf'
        file.write_text('http {}')
        file.chmod(0o666)
        with self.assertRaises(p.CheckError):
            p.read_nginx(file)

    def test_partial_include_failure_keeps_other_sites_without_certifying_bad_site(self):
        config = self.base / 'nginx.conf'
        config.write_text('http { server { server_name good.example; root /srv/good; } server { server_name bad.example; root /srv/bad; include missing.conf; } }')
        tree = p.read_nginx(config, partial=True)
        with patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'resolve', side_effect=lambda *a, **kw: a[0], autospec=True):
            inventory = p.nginx_inventory(tree)
        self.assertEqual([s['url'] for s in inventory['sites']], ['http://good.example'])
        self.assertTrue(any('unvollstaendigen Includes' in s for s in inventory['issues']))

    def test_domains_tls_ports_and_ipv4_ipv6_deduplication(self):
        inventory = self.inventory('http { server { listen 8443 ssl; listen [::]:8443 ssl; server_name example.org www.example.org; root /srv/site; } }')
        self.assertEqual({s['url'] for s in inventory['sites']}, {'https://example.org:8443', 'https://www.example.org:8443'})
        self.assertTrue(all(s['connect_ip'] == '127.0.0.1' for s in inventory['sites']))
        self.assertEqual(inventory['issues'], [])

    def test_ipv6_only_is_represented_and_passed_to_http_backend(self):
        inventory = self.inventory('http { server { listen [::]:443 ssl; server_name example.org; root /srv/site; } }')
        self.assertEqual(inventory['sites'][0]['connect_ip'], '::1')
        with patch.object(p, 'http_observation', return_value=dict(status=403, bytes=0, sha256=p.digest(b''))) as observation:
            self.assertEqual(p.probe('https://example.org/.env', connect_ip='::1'), 403)
        observation.assert_called_once_with('https://example.org/.env', '::1')

    def test_http_root_inheritance_and_static_location_alias(self):
        inventory = self.inventory('http { root /srv/site; server { listen 80; server_name example.org; location /assets/ { alias /opt/assets/; } location /files/ { root /srv/files; } } }')
        sites = {s['url']: s['root'] for s in inventory['sites']}
        self.assertEqual(sites['http://example.org'], '/srv/site')
        self.assertEqual(sites['http://example.org/assets'], '/opt/assets')
        self.assertEqual(sites['http://example.org/files'], '/srv/files/files')

    def test_dynamic_wildcard_regex_and_proxy_contexts_are_unknown(self):
        inventory = self.inventory('http { server { server_name *.example.org; root /srv/$domain; } server { server_name proxy.example; location / { proxy_pass http://backend; } } }')
        self.assertFalse(inventory['sites'])
        self.assertGreaterEqual(len(inventory['issues']), 3)

    def test_duplicate_conflicting_domain_roots_are_not_guessed(self):
        inventory = self.inventory('http { server { server_name example.org; root /srv/one; } server { server_name example.org; root /srv/two; } }')
        self.assertEqual(inventory['sites'], [])
        self.assertTrue(any('Mehrdeutig' in s for s in inventory['issues']))

    def test_system_root_is_not_automatically_scanned(self):
        inventory = self.inventory('http { server { server_name example.org; root /; } }')
        self.assertFalse(inventory['roots'])
        self.assertTrue(any('Systempfad' in s for s in inventory['issues']))

    def test_malformed_configuration_is_not_partially_accepted(self):
        for text in ('http {', 'root "/srv/unterminated;', 'http {} }', 'root /srv/missing-semicolon'):
            with self.subTest(text=text), self.assertRaises(p.CheckError):
                p.parse_nginx(text)

    def test_redundant_scan_roots_are_removed(self):
        self.assertEqual(p.minimal_roots(['/srv/a', '/srv/a/sub', '/srv/another']), ['/srv/a', '/srv/another'])

    def test_manual_sites_override_auto_config_and_derive_roots(self):
        args = argparse.Namespace(root=None, site=['https://example.org=/srv/site'], no_auto=False,
                                  nginx_config=None, max_sites=32)
        with patch.object(p, 'read_nginx', side_effect=AssertionError('should not read auto config')):
            p.prepare_scope(args)
        self.assertEqual(args.roots, ['/srv/site'])
        self.assertEqual(args.site, ['https://example.org=/srv/site'])

    def test_automatic_site_budget_is_visible_and_not_a_pass(self):
        inventory = dict(server='nginx', roots=['/srv/site'], issues=[], sites=[
            dict(url='https://a.example', root='/srv/site', connect_ip='127.0.0.1'),
            dict(url='https://b.example', root='/srv/site', connect_ip='127.0.0.1')])
        args = argparse.Namespace(root=None, site=[], no_auto=False, nginx_config='/fake/nginx.conf', max_sites=1)
        with patch.object(p, 'read_nginx', return_value=[]), patch.object(p, 'nginx_inventory', return_value=inventory):
            p.prepare_scope(args)
        self.assertEqual(len(args.site), 1)
        self.assertTrue(any('HTTP-Limit' in s for s in args.discovery['issues']))

    def test_detection_never_infers_permission_changes(self):
        inventory = dict(server='nginx', roots=['/srv/site'], issues=[], sites=[])
        args = argparse.Namespace(root=None, site=[], no_auto=False, nginx_config='/fake/nginx.conf', max_sites=32, protect_dir=[])
        with patch.object(p, 'read_nginx', return_value=[]), patch.object(p, 'nginx_inventory', return_value=inventory):
            p.prepare_scope(args)
        self.assertEqual(args.protect_dir, [])

    def test_self_contained_launcher_contains_the_exact_tested_engine(self):
        launcher = Path('p2s-harden.sh').read_text()
        embedded = launcher.split('# __P2S_PYTHON__\n', 1)[1].rsplit('\n__P2S_ENGINE_EOF__', 1)[0]
        self.assertEqual(embedded, Path('p2s_harden.py').read_text())
        result = subprocess.run(['bash', '-n', 'p2s-harden.sh'], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_single_ssh_call_preserves_arguments_payload_and_failure_exit(self):
        import shlex
        fake = self.base / 'fake ssh'
        arguments, payload = self.base / 'arguments', self.base / 'payload.py'
        fake.write_text('#!/usr/bin/env bash\nprintf "%s\\0" "$@" > "$P2S_ARGUMENTS"\ncat > "$P2S_PAYLOAD"\nexit 17\n')
        fake.chmod(0o700)
        path = "/srv/a space/it's a $(literal) path"
        env = dict(os.environ, SSH_BIN=str(fake), P2S_ARGUMENTS=str(arguments), P2S_PAYLOAD=str(payload))
        result = subprocess.run(['bash', 'p2s-harden.sh', '--ssh', 'tester@example.test', '--root', path], env=env, capture_output=True)
        self.assertEqual(result.returncode, 17)
        argv = arguments.read_bytes().rstrip(b'\0').decode().split('\0')
        self.assertEqual(argv[-2], 'tester@example.test')
        self.assertEqual(shlex.split(argv[-1].rsplit('exec python3 -B -', 1)[1]), ['--root', path])
        received = payload.read_text()
        self.assertEqual(received.rstrip('\n'), Path('p2s_harden.py').read_text().rstrip('\n'))
        compile(received, '<payload>', 'exec')
        ipv6 = subprocess.run(['bash', 'p2s-harden.sh', '--ssh', 'tester@[::1]', '--discover'], env=env, capture_output=True)
        self.assertEqual(ipv6.returncode, 17, ipv6.stderr)
        self.assertEqual(arguments.read_bytes().rstrip(b'\0').decode().split('\0')[-2], 'tester@[::1]')


if __name__ == "__main__":
    unittest.main(verbosity=2)
