"""Real loopback HTTP fixtures plus complete audit exit-code contracts.

No PHP/FPM process or production web server is involved in these fixtures.
"""
import argparse
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import p2s_harden as p


class HttpFixture:
    def __init__(self, fallback="missing", family=socket.AF_INET):
        self.requests = []
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            # HTTP/1.0 intentionally closes each response, as many real servers
            # and reverse proxies do. This exercises response/socket lifetime.
            protocol_version = "HTTP/1.0"

            def log_message(self, *_):
                pass

            def do_GET(self):
                fixture.requests.append((self.path, self.headers.get("Host")))
                code, body, headers = 404, b"not found", {}
                if self.path == "/protected/.env":
                    code, body = 403, b"forbidden"
                elif self.path == "/open/.env":
                    code, body = 200, b"DATABASE_PASSWORD=do-not-print-this-fixture"
                elif self.path == "/empty":
                    code, body = 204, b""
                elif self.path == "/redirect":
                    code, body, headers = 302, b"redirect", {"Location": "/open/.env"}
                elif self.path == "/large":
                    code, body = 200, b"x" * 8192
                elif self.path == "/slow":
                    self.send_response(200)
                    self.send_header("Content-Length", "4")
                    self.end_headers()
                    try:
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.25)
                        self.wfile.write(b"bcd")
                    except OSError:
                        pass
                    return
                elif self.path == "/truncated":
                    self.send_response(200)
                    self.send_header("Content-Length", "20")
                    self.end_headers()
                    self.wfile.write(b"abc")
                    return
                elif self.path in ("/chunk-drip", "/header-drip"):
                    try:
                        if self.path == "/chunk-drip":
                            self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                        else:
                            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Drip: ")
                        for _ in range(20):
                            self.wfile.write(b"1\r\na\r\n" if self.path == "/chunk-drip" else b"a")
                            self.wfile.flush()
                            time.sleep(0.03)
                        self.wfile.write(b"0\r\n\r\n" if self.path == "/chunk-drip" else b"\r\n\r\n")
                    except OSError:
                        pass
                    return
                elif self.path == "/drip":
                    self.send_response(200)
                    self.send_header("Content-Length", "20")
                    self.end_headers()
                    try:
                        for _ in range(20):
                            self.wfile.write(b"a")
                            self.wfile.flush()
                            time.sleep(0.03)
                    except OSError:
                        pass
                    return
                elif fallback != "missing":
                    code, body = 200, b"application fallback"
                    if fallback == "dynamic":
                        body += self.path.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass
        class Server(ThreadingHTTPServer):
            address_family = family
            daemon_threads = True
        self.server = Server(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.url = "http://unresolvable.invalid:" + str(self.port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class HttpTests(unittest.TestCase):
    def fixture(self, *args, **kwargs):
        fixture = HttpFixture(*args, **kwargs)
        self.addCleanup(fixture.close)
        return fixture

    def observe(self, fixture, path, **kwargs):
        return p.http_observation(fixture.url + path, **kwargs)

    def test_forbidden_file_is_ok_and_status_only_interface_remains_integer(self):
        fixture = self.fixture()
        observation = self.observe(fixture, "/protected/.env")
        self.assertEqual(p.classify_http(observation, [])[0], "OK")
        self.assertEqual(p.probe(fixture.url + "/protected/.env"), 403)

    def test_open_file_is_open_when_missing_paths_are_rejected(self):
        fixture = self.fixture()
        observation = self.observe(fixture, "/open/.env")
        baselines = [self.observe(fixture, path) for path in ("/.p2s-missing-a", "/.p2s-missing-b")]
        status, detail = p.classify_http(observation, baselines)
        self.assertEqual(status, "OPEN")
        self.assertIn("missing paths were rejected", detail)

    def test_static_soft404_cannot_be_reported_as_file_exposure(self):
        fixture = self.fixture("static")
        observation = self.observe(fixture, "/pretend/.git/config")
        baselines = [self.observe(fixture, path) for path in ("/.p2s-missing-a", "/.p2s-missing-b")]
        status, detail = p.classify_http(observation, baselines)
        self.assertEqual(status, "UNKNOWN")
        self.assertIn("matches soft-404", detail)

    def test_dynamic_soft404_is_ambiguous_even_with_a_different_target(self):
        fixture = self.fixture("dynamic")
        observation = self.observe(fixture, "/open/.env")
        baselines = [self.observe(fixture, path) for path in ("/.p2s-missing-a", "/.p2s-missing-b")]
        self.assertEqual(p.classify_http(observation, baselines)[0], "UNKNOWN")

    def test_distinct_response_from_static_fallback_stays_open(self):
        fixture = self.fixture("static")
        observation = self.observe(fixture, "/open/.env")
        baselines = [self.observe(fixture, path) for path in ("/.p2s-missing-a", "/.p2s-missing-b")]
        self.assertEqual(p.classify_http(observation, baselines)[0], "OPEN")

    def test_redirect_is_unknown_and_is_never_followed(self):
        fixture = self.fixture()
        observation = self.observe(fixture, "/redirect")
        self.assertEqual(observation["status"], 302)
        self.assertEqual(p.classify_http(observation, [])[0], "UNKNOWN")
        self.assertEqual([request[0] for request in fixture.requests], ["/redirect"])

    def test_hashes_response_without_returning_or_printing_body(self):
        fixture = self.fixture()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            observation = self.observe(fixture, "/open/.env")
        body = b"DATABASE_PASSWORD=do-not-print-this-fixture"
        self.assertEqual(observation, dict(status=200, bytes=len(body), sha256=hashlib.sha256(body).hexdigest()))
        self.assertNotIn("DATABASE_PASSWORD", output.getvalue())

    def test_response_byte_limit_is_enforced(self):
        fixture = self.fixture()
        with self.assertRaisesRegex(p.CheckError, "byte budget exceeded"):
            self.observe(fixture, "/large", max_bytes=1024)

    def test_exact_byte_limit_and_empty_response_do_not_use_a_closed_socket(self):
        fixture = self.fixture()
        self.assertEqual(self.observe(fixture, "/large", max_bytes=8192)["bytes"], 8192)
        self.assertEqual(self.observe(fixture, "/empty")["bytes"], 0)

    def test_slow_body_is_bounded_and_only_exception_type_is_exposed(self):
        fixture = self.fixture()
        start = time.monotonic()
        with self.assertRaises(p.CheckError) as caught:
            self.observe(fixture, "/slow", timeout=0.05)
        self.assertLess(time.monotonic() - start, 1)
        self.assertNotIn("do-not-print", str(caught.exception))

    def test_drip_feed_cannot_reset_the_absolute_response_deadline(self):
        fixture = self.fixture()
        start = time.monotonic()
        # Each byte arrives sooner than the socket timeout, but the whole body
        # takes 0.6s. A per-read timeout alone cannot enforce this deadline.
        with self.assertRaises(p.CheckError):
            self.observe(fixture, "/drip", timeout=0.08)
        self.assertLess(time.monotonic() - start, 0.35)

    def test_chunked_body_drip_is_bounded_by_the_absolute_deadline(self):
        fixture = self.fixture()
        start = time.monotonic()
        with self.assertRaises(p.CheckError):
            self.observe(fixture, "/chunk-drip", timeout=0.08)
        self.assertLess(time.monotonic() - start, 0.35)

    def test_header_drip_is_bounded_by_the_absolute_deadline(self):
        fixture = self.fixture()
        start = time.monotonic()
        with self.assertRaises(p.CheckError):
            self.observe(fixture, "/header-drip", timeout=0.08)
        self.assertLess(time.monotonic() - start, 0.35)

    def test_truncated_content_length_response_is_not_a_complete_observation(self):
        fixture = self.fixture()
        with self.assertRaises(p.CheckError):
            self.observe(fixture, "/truncated")

    def test_explicit_connect_ip_preserves_host_header_and_ignores_proxies(self):
        fixture = self.fixture()
        proxies = {name: "http://127.0.0.1:1" for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")}
        with patch.dict(os.environ, proxies), patch.object(p, "command", side_effect=AssertionError("no curl or other subprocess")):
            observation = self.observe(fixture, "/protected/.env", connect_ip="127.0.0.1")
        self.assertEqual(observation["status"], 403)
        self.assertEqual(fixture.requests[-1][1], "unresolvable.invalid:" + str(fixture.port))

    def test_explicit_ipv6_connect_ip_preserves_the_dns_host(self):
        try:
            fixture = self.fixture(family=socket.AF_INET6)
        except OSError as exc:
            self.skipTest("IPv6 loopback unavailable: " + type(exc).__name__)
        self.assertEqual(self.observe(fixture, "/protected/.env", connect_ip="::1")["status"], 403)
        self.assertEqual(fixture.requests[-1][1], "unresolvable.invalid:" + str(fixture.port))

    def test_credentials_queries_and_fragments_are_rejected_before_connecting(self):
        fixture = self.fixture()
        for url in (fixture.url + "/.env?secret=yes", fixture.url + "/.env#fragment", fixture.url.replace("http://", "http://user:secret@")):
            with self.subTest(url=url), self.assertRaises(p.CheckError):
                p.http_observation(url)
        self.assertEqual(fixture.requests, [])


class FullAuditExitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p2s-audit-exit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ini = self.root / "php.ini"
        self.ini.write_text("disable_functions=" + ",".join(p.REQUIRED) + "\nallow_url_include=Off\n")

    def audit(self, http_status=403, missing_functions=False, permission_error=False, http_limit=128, imagick=True):
        args = argparse.Namespace(root=str(self.root), roots=[str(self.root)], site=["http://example.test=" + str(self.root)],
            web_user=["fixture-user"], no_progress=True, max_http_probes=http_limit)
        instance = dict(pid=1, config="/fake/fpm.conf", service=None, inis=[str(self.ini)],
            values=dict(disable_functions="exec" if missing_functions else ",".join(p.REQUIRED), allow_url_include="Off", open_basedir="/srv/site"),
            pools={"www": {"user": "fixture-user", "listen": "127.0.0.1:9000"}})
        cap = dict(root=True, tools=dict(ps=True, curl=False, runuser=True, systemctl=False), systemd=False)
        if imagick:
            instance["values"]["imagick module"] = "enabled"
        permissions = json.dumps(dict(files=0, directories=0, file_sample=[], directory_sample=[], errors=[]))
        original_read = Path.read_text
        def read(path, *values, **kwargs):
            return "1" if path.as_posix() == "/proc/sys/kernel/yama/ptrace_scope" else original_read(path, *values, **kwargs)
        def observe(url, connect_ip="127.0.0.1"):
            return dict(status=404 if "/.p2s-missing-" in url else http_status, bytes=0, sha256=p.digest(b""))
        permissions_patch = patch.object(p, "as_user", side_effect=p.CheckError("fixture permissions unavailable")) if permission_error else patch.object(p, "as_user", return_value=permissions)
        with patch.object(p, "discover", return_value=([instance], [])), patch.object(p, "capabilities", return_value=cap), \
             patch.object(p, "pwd", SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=1000))), \
             patch.object(p.os, "geteuid", return_value=1000, create=True), patch.object(Path, "read_text", read), \
             permissions_patch, patch.object(p, "http_observation", side_effect=observe) as http:
            report, updates, _, _ = p.scan(args)
        return report, updates, http

    def test_complete_clean_audit_returns_zero_with_manual_policy_info(self):
        report, updates, _ = self.audit()
        self.assertEqual(report.exit_code(), 0, report.rows)
        self.assertEqual(updates, {})
        policy = next(row for row in report.rows if row["title"] == "ImageMagick policy")
        self.assertEqual(policy["status"], "INFO")

    def test_complete_audit_with_an_open_finding_returns_one(self):
        report, _, _ = self.audit(http_status=200)
        self.assertEqual(report.exit_code(), 1, report.rows)
        self.assertTrue(any(row["status"] == "OPEN" for row in report.rows))

    def test_absent_imagick_and_policy_do_not_add_a_manual_warning(self):
        exists = Path.exists
        def available(path):
            return False if str(path).replace("\\", "/").endswith(("ImageMagick-6/policy.xml", "ImageMagick-7/policy.xml")) else exists(path)
        with patch.object(Path, "exists", available):
            report, _, _ = self.audit(imagick=False)
        self.assertEqual(report.discovery["manual_checks"], [])

    def test_incomplete_audit_returns_two_even_with_an_open_finding(self):
        report, _, _ = self.audit(http_status=200, permission_error=True)
        self.assertEqual(report.exit_code(), 2)
        self.assertTrue(any(row["status"] == "OPEN" for row in report.rows))
        self.assertTrue(any(row["status"] == "UNKNOWN" for row in report.rows))

    def test_http_budget_exhaustion_is_visible_and_bounds_request_count(self):
        report, _, http = self.audit(http_status=200, http_limit=1)
        self.assertEqual(report.exit_code(), 2)
        self.assertEqual(http.call_count, 1)
        self.assertEqual(report.discovery["http_budget"], dict(requests=1, limit=1, exhausted=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
