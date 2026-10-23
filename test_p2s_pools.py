"""FPM trust boundaries and privacy contracts, using disposable fixtures only."""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import p2s_harden as p


class PoolBoundaries(unittest.TestCase):
    def test_empty_dump_values_are_not_silently_replaced_by_defaults(self):
        pools=p.pool_values("NOTICE: [app]\nNOTICE: security.limit_extensions = \nNOTICE: php_admin_value[allow_url_include] = \n")
        self.assertEqual(pools["app"]["security.limit_extensions"], "")
        self.assertEqual(pools["app"]["php_admin_value[allow_url_include]"], "")

    def report(self, settings=None, values=None):
        report = p.Report()
        pool = dict(user="app", listen="127.0.0.1:9000")
        pool.update(settings or {})
        instance = dict(config="/etc/php/8.3/fpm/php-fpm.conf", values=values or {}, pools={"app": pool})
        p.pool_security(report, instance)
        return report

    def states(self, rule, **settings):
        return [row["status"] for row in self.report(settings).rows if row["rule_id"] == rule]

    def test_network_listeners_require_an_allowlist_even_on_private_addresses(self):
        for listen in ("9000", "0.0.0.0:9000", "*:9000", ":9000", "[::]:9000", "10.0.0.1:9000", "[2001:db8::1]:9000"):
            with self.subTest(listen=listen):
                self.assertEqual(self.states("P2S-FPM001", listen=listen), ["OPEN"])

    def test_loopback_ipv4_ipv6_and_mapped_ipv4(self):
        for listen in ("127.0.0.1:9000", "127.2.3.4:9000", "[::1]:9000", "[::ffff:127.0.0.1]:9000"):
            self.assertEqual(self.states("P2S-FPM001", listen=listen), ["OK"])

    def test_literal_client_allowlist_and_no_dns_or_network_probe(self):
        with patch.object(p.socket, "getaddrinfo", side_effect=AssertionError("no DNS")):
            self.assertEqual(self.states("P2S-FPM001", listen="0.0.0.0:9000", **{"listen.allowed_clients":"127.0.0.1, ::1"}), ["OK"])
            for value in ("proxy.local", "0.0.0.0/0", "127.0.0.1,", "*"):
                self.assertEqual(self.states("P2S-FPM001", listen="0.0.0.0:9000", **{"listen.allowed_clients":value}), ["UNKNOWN"])

    def test_unsupported_listener_is_unknown(self):
        for listen in ("", "proxy.local:9000", "relative/socket", "[::1]:0", "127.0.0.1:65536", "@abstract", "::1:9000"):
            self.assertEqual(self.states("P2S-FPM001", listen=listen), ["UNKNOWN"])

    @unittest.skipUnless(os.name == "posix", "Unix sockets")
    def test_socket_configuration_and_actual_modes_are_independent(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as stream:
            path = str(Path(directory)/"fpm.sock")
            stream.bind(path)
            os.chmod(path, 0o666)
            self.assertEqual(self.states("P2S-FPM002", listen=path, **{"listen.mode":"0600"}), ["OK","OPEN"])
            os.chmod(path, 0o600)
            self.assertEqual(self.states("P2S-FPM002", listen=path, **{"listen.mode":"0666"}), ["OPEN","OK"])
            self.assertEqual(self.states("P2S-FPM002", listen=path, **{"listen.mode":"undefined", "listen.acl_users":"nginx"}), ["OK","OK","INFO"])

    @unittest.skipUnless(os.name == "posix", "Unix socket paths")
    def test_socket_missing_or_invalid_mode_does_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/"missing.sock")
            self.assertEqual(self.states("P2S-FPM002", listen=path, **{"listen.mode":"bogus"}), ["UNKNOWN","UNKNOWN"])

    def test_extensions_and_environment_policy(self):
        for value, state in (("", "OPEN"),("undefined","OPEN"),(".php .jpg","OPEN"),(".php","OK"),(".php .phar","INFO")):
            self.assertEqual(self.states("P2S-FPM003", **{"security.limit_extensions":value}), [state])
        for value, state in (("yes","OK"),("no","OPEN"),("garbage","UNKNOWN")):
            self.assertEqual(self.states("P2S-FPM004", clear_env=value), [state])

    def test_ffi_requires_loaded_directive_and_respects_admin_override(self):
        for value,state in (("Off","OK"),("preload","INFO"),("On","OPEN"),("invalid","UNKNOWN")):
            rows=self.report(values={"ffi.enable":value}).rows
            self.assertEqual([r["status"] for r in rows if r["rule_id"]=="P2S-PHP004"],[state])
        rows=self.report({"php_value[ffi.enable]":"On","php_admin_value[ffi.enable]":"Off"},{"ffi.enable":"On"}).rows
        self.assertEqual([r["status"] for r in rows if r["rule_id"]=="P2S-PHP004"],["OK"])
        self.assertFalse(any(r["rule_id"]=="P2S-PHP004" for r in self.report({"php_admin_value[ffi.enable]":"On"}).rows))

    def test_alias_accounts_share_a_numeric_uid_but_are_only_context(self):
        report=p.Report()
        instances=[dict(config="/a",pools={"one":{"user":"alias1"},"two":{"user":"alias2"}})]
        with patch.object(p,"pwd",SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=33))):
            p.shared_pool_users(report,instances)
        self.assertEqual([r["status"] for r in report.rows],["INFO"])
        self.assertEqual(report.exit_code(),0)


class PrivateReports(unittest.TestCase):
    def test_allowlist_projection_omits_all_host_strings_and_mutation_metadata(self):
        report=p.Report()
        secret="PRIVATE-canary-user@example.test:/srv/private"
        for rule in p.RULES:
            report.add("UNKNOWN",secret,secret,rule_id="P2S-"+rule,resource={secret:[secret]})
        report.discovery={secret:secret,"scan_roots":[secret],"capabilities":{"tools":{secret:False}}}
        report.plan={secret:secret}
        report.transaction={secret:secret}
        report.configure("open")
        for lang in ("en","de"):
            for as_json in (True,False):
                output=io.StringIO()
                with contextlib.redirect_stdout(output): report.show(as_json,verbose=True,lang=lang,redact=True)
                self.assertNotIn(secret,output.getvalue())
                if as_json:
                    data=json.loads(output.getvalue())
                    self.assertTrue(data["redacted"])
                    self.assertIsNone(data["plan"])
                    self.assertIsNone(data["transaction"])
                    self.assertTrue(all(r["resource"] is None for r in data["findings"]))
                    self.assertTrue(set(r["id"] for r in data["findings"]).isdisjoint(r["id"] for r in report.rows))
                    self.assertEqual(data["exit_code"],2)

    def test_redaction_cannot_hide_a_change_preview_during_approval(self):
        for mode in ("--fix","--dry-run","--rollback"):
            output=io.StringIO()
            with contextlib.redirect_stdout(output): code=p.main([mode,"--redact","--json"])
            self.assertEqual(code,2)
            data=json.loads(output.getvalue())
            self.assertTrue(data["redacted"])
            self.assertIsNone(data["transaction"])


class IncludeBudgets(unittest.TestCase):
    def test_deep_include_chain_is_controlled_without_python_recursion(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for number in range(67):
                (root/str(number)).write_text("include="+str(root/str(number+1))+"\n" if number<66 else "[www]\n")
            with patch.object(p,"trusted",side_effect=Path), self.assertRaisesRegex(p.CheckError,"coverage limit"):
                p.validate_fpm_files(root/"0")

    def test_cycles_terminate_and_oversized_files_are_controlled(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"fpm.conf"
            path.write_text("include="+str(path)+"\n")
            with patch.object(p,"trusted",side_effect=Path): p.validate_fpm_files(path)
            path.write_bytes(b";"*(2*1024*1024+1))
            with patch.object(p,"trusted",side_effect=Path), self.assertRaisesRegex(p.CheckError,"byte budget"):
                p.validate_fpm_files(path)


if __name__ == "__main__": unittest.main()
