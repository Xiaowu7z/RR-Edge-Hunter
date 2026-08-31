from __future__ import annotations

import base64
import hashlib
import re
import ssl
import time
import unittest
from unittest.mock import patch

from cfopt.probe import probe_argo_compatibility


class _FakeRawSocket:
    def __init__(self) -> None:
        self.connected = None
        self.closed = False

    def settimeout(self, _value: float) -> None:
        return None

    def connect(self, address) -> None:
        self.connected = address

    def close(self) -> None:
        self.closed = True


class _FakeTlsStream:
    def __init__(self, remote: str = "104.16.0.9") -> None:
        self.remote = remote
        self.sent = b""
        self.handshakes = 0
        self.closed = False

    def settimeout(self, _value: float) -> None:
        return None

    def do_handshake(self) -> None:
        self.handshakes += 1

    def getpeername(self):
        return (self.remote, 443)

    def sendall(self, payload: bytes) -> None:
        self.sent += payload

    def close(self) -> None:
        self.closed = True


class _FakeContext:
    def __init__(self, stream: _FakeTlsStream, error: Exception | None = None) -> None:
        self.stream = stream
        self.error = error
        self.server_hostname = ""

    def wrap_socket(self, _raw, *, server_hostname: str, do_handshake_on_connect: bool):
        self.server_hostname = server_hostname
        if do_handshake_on_connect:
            raise AssertionError("握手必须显式执行以测量 TLS 耗时")
        if self.error:
            raise self.error
        return self.stream


class ArgoProbeTest(unittest.TestCase):
    def test_trace_gate_pins_ip_but_keeps_sni_host_and_certificate_validation(self) -> None:
        raw = _FakeRawSocket()
        stream = _FakeTlsStream()
        context = _FakeContext(stream)

        def headers(_stream, _cancel, _deadline):
            body = b"colo=HKG\nloc=HK\n"
            return f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}".encode("ascii"), body, time.perf_counter()

        with (
            patch("cfopt.probe.socket.socket", return_value=raw),
            patch("cfopt.probe.ssl.create_default_context", return_value=context) as default_context,
            patch("cfopt.probe._read_headers", side_effect=headers),
        ):
            result = probe_argo_compatibility(
                "104.16.0.9", hostname="argo.example.com", port=8443
            )

        request = stream.sent.decode("ascii")
        self.assertTrue(result.ok)
        self.assertTrue(result.cert_verified)
        self.assertEqual(result.colo, "HKG")
        self.assertEqual(context.server_hostname, "argo.example.com")
        self.assertEqual(raw.connected, ("104.16.0.9", 8443))
        self.assertIn("GET /cdn-cgi/trace HTTP/1.1\r\n", request)
        self.assertIn("Host: argo.example.com\r\n", request)
        self.assertEqual(request.lower().count("connection:"), 1)
        self.assertIn("Connection: close\r\n", request)
        default_context.assert_called_once_with()

    def test_ws_gate_requires_real_upgrade_accept_and_one_connection_header(self) -> None:
        raw = _FakeRawSocket()
        stream = _FakeTlsStream()
        context = _FakeContext(stream)

        def websocket_headers(_stream, _cancel, _deadline):
            request = stream.sent.decode("ascii")
            key = re.search(r"Sec-WebSocket-Key: ([^\r]+)", request).group(1)
            self.assertEqual(len(base64.b64decode(key, validate=True)), 16)
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
            ).decode("ascii")
            head = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: keep-alive, Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}"
            ).encode("ascii")
            return head, b"", time.perf_counter()

        with (
            patch("cfopt.probe.socket.socket", return_value=raw),
            patch("cfopt.probe.ssl.create_default_context", return_value=context),
            patch("cfopt.probe._read_headers", side_effect=websocket_headers),
        ):
            result = probe_argo_compatibility(
                "104.16.0.9", hostname="argo.example.com", ws_path="/vless?ed=2048"
            )

        request = stream.sent.decode("ascii")
        self.assertTrue(result.ok)
        self.assertIn("GET /vless?ed=2048 HTTP/1.1", request)
        self.assertEqual(request.lower().count("connection:"), 1)
        self.assertIn("Connection: Upgrade\r\n", request)

    def test_ws_gate_rejects_missing_connection_upgrade_token(self) -> None:
        raw = _FakeRawSocket()
        stream = _FakeTlsStream()
        context = _FakeContext(stream)

        def incomplete_headers(_stream, _cancel, _deadline):
            key = re.search(r"Sec-WebSocket-Key: ([^\r]+)", stream.sent.decode("ascii")).group(1)
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
            ).decode("ascii")
            return (
                f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Accept: {accept}".encode("ascii"),
                b"",
                time.perf_counter(),
            )

        with (
            patch("cfopt.probe.socket.socket", return_value=raw),
            patch("cfopt.probe.ssl.create_default_context", return_value=context),
            patch("cfopt.probe._read_headers", side_effect=incomplete_headers),
        ):
            result = probe_argo_compatibility(
                "104.16.0.9", hostname="argo.example.com", ws_path="/vless"
            )
        self.assertFalse(result.ok)

    def test_certificate_failure_and_unsafe_path_are_never_bypassed(self) -> None:
        raw = _FakeRawSocket()
        context = _FakeContext(_FakeTlsStream(), ssl.SSLCertVerificationError("bad certificate"))
        with (
            patch("cfopt.probe.socket.socket", return_value=raw),
            patch("cfopt.probe.ssl.create_default_context", return_value=context),
        ):
            result = probe_argo_compatibility("104.16.0.9", hostname="argo.example.com")
        self.assertFalse(result.ok)
        self.assertFalse(result.cert_verified)

        with patch("cfopt.probe.socket.socket") as socket_factory:
            unsafe = probe_argo_compatibility(
                "104.16.0.9", hostname="argo.example.com", ws_path="/ws%zz"
            )
        self.assertFalse(unsafe.ok)
        socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
