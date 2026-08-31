from __future__ import annotations

import base64
import hashlib
import re
import ssl
import time
import unittest
from unittest.mock import patch

from cfopt.probe import (
    _speed_sample_has_sufficient_window,
    probe_argo_compatibility,
    probe_speed_window,
    speed_request_bytes,
)


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

    def recv(self, _size: int) -> bytes:
        return b""

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

    def test_argo_gate_shares_one_absolute_deadline_across_all_phases(self) -> None:
        raw = _FakeRawSocket()
        stream = _FakeTlsStream()
        context = _FakeContext(stream)
        deadlines: list[float] = []

        def headers(_stream, _cancel, deadline):
            deadlines.append(deadline)
            return b"HTTP/1.1 200 OK\r\nContent-Length: 21", b"", time.perf_counter()

        def body(_stream, _initial, _headers, _cancel, _idle, deadline, _limit):
            deadlines.append(deadline)
            return b"colo=HKG\nloc=HK\n"

        with (
            patch("cfopt.probe.socket.socket", return_value=raw),
            patch("cfopt.probe.ssl.create_default_context", return_value=context),
            patch("cfopt.probe._read_headers", side_effect=headers),
            patch("cfopt.probe._read_body", side_effect=body),
            patch("cfopt.probe.time.monotonic", side_effect=[100.0, 101.0, 102.0, 103.0, 104.0, 105.0, 106.0, 107.0, 108.0]),
        ):
            result = probe_argo_compatibility(
                "104.16.0.9", timeout_sec=10, hostname="argo.example.com"
            )

        self.assertTrue(result.ok)
        self.assertEqual(deadlines, [110.0, 110.0])

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

    def test_one_second_speed_probe_keeps_tls_peer_and_cf_identity_checks(self) -> None:
        raw = _FakeRawSocket()
        stream = _FakeTlsStream()
        context = _FakeContext(stream)
        requested = speed_request_bytes(100)

        def headers(_stream, _cancel, _deadline):
            return (
                f"HTTP/1.1 200 OK\r\nCF-RAY: 0123456789abcdef-LAX\r\nContent-Length: {requested}".encode("ascii"),
                b"x" * requested,
                time.perf_counter(),
            )

        with (
            patch("cfopt.probe.socket.socket", return_value=raw),
            patch("cfopt.probe.ssl.create_default_context", return_value=context) as default_context,
            patch("cfopt.probe._read_headers", side_effect=headers),
        ):
            result = probe_speed_window("104.16.0.9", 100, sample_seconds=0.25)

        self.assertTrue(result.ok)
        self.assertTrue(result.cert_verified)
        self.assertTrue(result.target_matches_remote)
        self.assertEqual(result.colo, "LAX")
        self.assertEqual(context.server_hostname, "speed.cloudflare.com")
        self.assertIn(f"/__down?bytes={requested}", stream.sent.decode("ascii"))
        default_context.assert_called_once_with()

    def test_speed_probe_rejects_response_without_cf_ray(self) -> None:
        raw = _FakeRawSocket()
        stream = _FakeTlsStream()
        context = _FakeContext(stream)
        with (
            patch("cfopt.probe.socket.socket", return_value=raw),
            patch("cfopt.probe.ssl.create_default_context", return_value=context),
            patch(
                "cfopt.probe._read_headers",
                return_value=(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4000000",
                    b"x" * 32_768,
                    time.perf_counter(),
                ),
            ),
        ):
            result = probe_speed_window("104.16.0.9", 100, sample_seconds=0.25)
        self.assertFalse(result.ok)
        self.assertIn("CF-RAY", result.error)

    def test_speed_window_rejects_short_partial_body_but_accepts_full_response(self) -> None:
        requested = speed_request_bytes(100)
        self.assertFalse(_speed_sample_has_sufficient_window(32_768, requested, 0.01, 1.0))
        self.assertFalse(_speed_sample_has_sufficient_window(requested - 1, requested, 0.79, 1.0))
        self.assertTrue(_speed_sample_has_sufficient_window(requested - 1, requested, 0.81, 1.0))
        self.assertTrue(_speed_sample_has_sufficient_window(requested, requested, 0.01, 1.0))

    def test_complete_speed_includes_connection_tls_and_ttfb_overhead(self) -> None:
        raw = _FakeRawSocket()
        stream = _FakeTlsStream()
        context = _FakeContext(stream)
        requested = speed_request_bytes(100)

        with (
            patch("cfopt.probe.socket.socket", return_value=raw),
            patch("cfopt.probe.ssl.create_default_context", return_value=context),
            patch(
                "cfopt.probe._read_headers",
                return_value=(
                    f"HTTP/1.1 200 OK\r\nCF-RAY: abcdef-LAX\r\nContent-Length: {requested}".encode("ascii"),
                    b"x" * requested,
                    0.25,
                ),
            ),
            patch("cfopt.probe.time.perf_counter", side_effect=[0.0, 0.1, 0.2, 0.3, 1.3]),
        ):
            result = probe_speed_window("104.16.0.9", 100, sample_seconds=1.0)

        self.assertTrue(result.ok)
        self.assertAlmostEqual(result.body_ms, 1000.0)
        self.assertAlmostEqual(result.total_ms, 1300.0)
        self.assertGreater(result.payload_mbps, result.complete_mbps)

    def test_speed_probe_rejects_redirect_and_early_partial_eof(self) -> None:
        for status in (200, 302):
            with self.subTest(status=status):
                raw = _FakeRawSocket()
                stream = _FakeTlsStream()
                context = _FakeContext(stream)
                with (
                    patch("cfopt.probe.socket.socket", return_value=raw),
                    patch("cfopt.probe.ssl.create_default_context", return_value=context),
                    patch(
                        "cfopt.probe._read_headers",
                        return_value=(
                            f"HTTP/1.1 {status} Test\r\nCF-RAY: abcdef-LAX\r\nContent-Length: 4000000".encode("ascii"),
                            b"x" * 32_768,
                            time.perf_counter(),
                        ),
                    ),
                ):
                    result = probe_speed_window("104.16.0.9", 100, sample_seconds=0.25)
                self.assertFalse(result.ok)
                self.assertIn("HTTP 302" if status == 302 else "测速窗口过短", result.error)

    def test_speed_request_is_bounded_and_max_mode_uses_longer_sample(self) -> None:
        self.assertEqual(speed_request_bytes(100), 18_750_000)
        self.assertEqual(speed_request_bytes(100, maximum=True), 64_000_000)
        self.assertLessEqual(speed_request_bytes(10_000, maximum=True), 256_000_000)

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
