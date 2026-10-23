"""Bounded client regression tests; no Docker, SSH, PHP or real sockets needed."""
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_fpm_runtime as runtime


class Peer:
    def __init__(self, response):
        self.response = response
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        pass

    def settimeout(self, value):
        pass

    def connect(self, address):
        pass

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        # Exercise fragmented TCP/Unix stream reads, including header fragments.
        chunk = self.response[:min(size, 3)]
        self.response = self.response[len(chunk):]
        return chunk


class ClientTests(unittest.TestCase):
    def request(self, response):
        peer = Peer(response)
        with patch.object(runtime.socket, "AF_UNIX", 1, create=True), patch.object(runtime.socket, "socket", return_value=peer):
            value = runtime.fastcgi_request("/fixture/fpm.sock")
        self.assertTrue(peer.sent.startswith(runtime.record(1, struct.pack("!HB5x", 1, 0))))
        return value

    def response(self, status=None, app_status=0, protocol_status=0):
        header = "Content-Type: application/json\r\n"
        if status:
            header += "Status: " + status + "\r\n"
        body = json.dumps(dict(sapi="fpm-fcgi", functions={})).encode()
        return (runtime.record(6, header.encode() + b"\r\n" + body[:8]) +
                runtime.record(6, body[8:]) + runtime.record(6) +
                runtime.record(3, struct.pack("!IB3x", app_status, protocol_status)))

    def test_fragmented_complete_real_sapi_response(self):
        self.assertEqual(self.request(self.response())["sapi"], "fpm-fcgi")

    def test_explicit_200_status_is_accepted(self):
        self.assertEqual(self.request(self.response("200 OK"))["sapi"], "fpm-fcgi")

    def test_500_is_unknown_not_success(self):
        with self.assertRaises(runtime.EvidenceError):
            self.request(self.response("500 Internal Server Error"))

    def test_premature_eof_is_unknown(self):
        with self.assertRaises(runtime.EvidenceError):
            self.request(self.response()[:-3])

    def test_nonzero_application_status_is_unknown(self):
        with self.assertRaises(runtime.EvidenceError):
            self.request(self.response(app_status=1))

    def test_protocol_overload_is_unknown(self):
        with self.assertRaises(runtime.EvidenceError):
            self.request(self.response(protocol_status=2))

    def test_wrong_request_identity_is_unknown(self):
        with self.assertRaises(runtime.EvidenceError):
            self.request(runtime.record(6, b"x", request_id=2))

    def test_wrong_sapi_is_unknown(self):
        with self.assertRaises(runtime.EvidenceError):
            self.request(self.response().replace(b"fpm-fcgi", b"cli-----"))

    def test_invalid_json_is_unknown(self):
        with self.assertRaises(runtime.EvidenceError):
            self.request(self.response().replace(b'"sapi"', b'!sapi!'))

    def test_name_value_lengths_have_fastcgi_encoding(self):
        self.assertEqual(runtime.encoded_length(127), b"\x7f")
        self.assertEqual(runtime.encoded_length(128), b"\x80\x00\x00\x80")


if __name__ == "__main__":
    unittest.main(verbosity=2)
