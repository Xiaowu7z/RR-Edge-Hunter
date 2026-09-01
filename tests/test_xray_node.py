from __future__ import annotations

import json
from pathlib import Path
import threading
import time
import unittest
from unittest import mock

from cfopt.node_template import parse_node_profile
from cfopt.xray_node import (
    NODE_GATE_TIMEOUT_SECONDS,
    XrayRuntimeError,
    _http_status_through_node,
    build_xray_config,
    validate_xray_runtime,
    verify_node_candidate,
)


LINK = (
    "vless://12345678-abcd-abcd-abcd-123456789abc@origin.example:2053"
    "?type=ws&security=tls&sni=route.example.com&host=route.example.com&path=%2Fargo%3Fed%3D2048&fp=chrome"
)


class _CaptureInput:
    def __init__(self) -> None:
        self.payload = b""

    def write(self, value: bytes) -> int:
        self.payload += value
        return len(value)

    def close(self) -> None:
        return None


class _FakeProcess:
    def __init__(self, command: list[str], **_: object) -> None:
        self.command = command
        self.input_capture = _CaptureInput()
        self.stdin = self.input_capture
        self.running = True

    def poll(self) -> int | None:
        return None if self.running else 0

    def terminate(self) -> None:
        self.running = False

    def kill(self) -> None:
        self.running = False

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.running = False
        return 0


class _FakeTlsSocket:
    def __init__(self, response: bytes) -> None:
        self.response = bytearray(response)
        self.sent = b""

    def settimeout(self, _value: float) -> None:
        return None

    def sendall(self, value: bytes) -> None:
        self.sent += value

    def recv(self, size: int) -> bytes:
        if not self.response:
            return b""
        output = bytes(self.response[:size])
        del self.response[:size]
        return output

    def close(self) -> None:
        return None


class XrayNodeTest(unittest.TestCase):
    def test_runtime_is_executed_before_scanning(self) -> None:
        completed = mock.Mock(returncode=0, stdout=b"Xray 26.7.28\n")
        path = Path("C:/portable/xray/xray.exe")
        with (
            mock.patch("cfopt.xray_node.find_xray_executable", return_value=path),
            mock.patch("cfopt.xray_node.subprocess.run", return_value=completed) as run,
        ):
            self.assertEqual(validate_xray_runtime(), path)
        self.assertEqual(run.call_args.args[0], [str(path), "version"])

    def test_profile_is_syntax_checked_before_bandwidth_scan(self) -> None:
        profile = parse_node_profile(LINK)
        path = Path("C:/portable/xray/xray.exe")
        responses = [
            mock.Mock(returncode=0, stdout=b"Xray 26.7.28\n"),
            mock.Mock(returncode=0, stdout=b"Configuration OK.\n"),
        ]
        with (
            mock.patch("cfopt.xray_node.find_xray_executable", return_value=path),
            mock.patch("cfopt.xray_node.subprocess.run", side_effect=responses) as run,
        ):
            self.assertEqual(validate_xray_runtime(profile=profile), path)
        self.assertEqual(run.call_args_list[1].args[0], [str(path), "run", "-test", "-c", "stdin:"])
        checked = json.loads(run.call_args_list[1].kwargs["input"].decode("utf-8"))
        self.assertEqual(checked["outbounds"][0]["settings"]["vnext"][0]["address"], "104.16.0.1")

    def test_invalid_profile_stops_before_bandwidth_scan(self) -> None:
        profile = parse_node_profile(LINK)
        responses = [
            mock.Mock(returncode=0, stdout=b"Xray 26.7.28\n"),
            mock.Mock(returncode=23, stdout=b"failed\n"),
        ]
        with (
            mock.patch("cfopt.xray_node.find_xray_executable", return_value=Path("xray.exe")),
            mock.patch("cfopt.xray_node.subprocess.run", side_effect=responses),
        ):
            with self.assertRaises(XrayRuntimeError):
                validate_xray_runtime(profile=profile)

    def test_unstartable_runtime_is_fatal_not_an_ip_rejection(self) -> None:
        profile = parse_node_profile(LINK)
        with (
            mock.patch("cfopt.xray_node.find_xray_executable", return_value=Path("C:/portable/xray/xray.exe")),
            mock.patch("cfopt.xray_node.subprocess.Popen", side_effect=OSError("bad executable")),
        ):
            with self.assertRaises(XrayRuntimeError):
                verify_node_candidate("104.18.1.2", 7, threading.Event(), profile=profile)

    def test_config_preserves_node_and_changes_only_server(self) -> None:
        profile = parse_node_profile(LINK)
        config = json.loads(build_xray_config(profile, "104.18.1.2", 32123))
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        endpoint = config["outbounds"][0]["settings"]["vnext"][0]
        self.assertEqual(endpoint["address"], "104.18.1.2")
        self.assertEqual(endpoint["port"], 2053)
        self.assertEqual(endpoint["users"][0]["id"], "12345678-abcd-abcd-abcd-123456789abc")
        stream = config["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["tlsSettings"]["serverName"], "route.example.com")
        self.assertEqual(stream["wsSettings"]["host"], "route.example.com")

    def test_delay_probe_matches_v2rayng_head_request(self) -> None:
        raw = mock.Mock()
        wrapped = _FakeTlsSocket(b"HTTP/1.1 204 No Content\r\n")
        context = mock.Mock()
        context.wrap_socket.return_value = wrapped
        cancel = threading.Event()
        with (
            mock.patch("cfopt.xray_node._socks_connect", return_value=raw),
            mock.patch("cfopt.xray_node.ssl.create_default_context", return_value=context),
        ):
            status, _delay = _http_status_through_node(
                32123,
                time.monotonic() + NODE_GATE_TIMEOUT_SECONDS,
                cancel,
            )
        self.assertEqual(status, 204)
        self.assertTrue(wrapped.sent.startswith(b"HEAD /generate_204 HTTP/1.1\r\n"))

    def test_verifier_sends_config_via_stdin_and_returns_node_delay(self) -> None:
        profile = parse_node_profile(LINK)
        created: list[_FakeProcess] = []

        def spawn(command: list[str], **kwargs: object) -> _FakeProcess:
            process = _FakeProcess(command, **kwargs)
            created.append(process)
            return process

        with (
            mock.patch("cfopt.xray_node.find_xray_executable", return_value=Path("C:/portable/xray/xray.exe")),
            mock.patch("cfopt.xray_node._free_loopback_port", return_value=32123),
            mock.patch("cfopt.xray_node._wait_for_socks"),
            mock.patch("cfopt.xray_node._http_status_through_node", return_value=(204, 188.4)),
            mock.patch("cfopt.xray_node.subprocess.Popen", side_effect=spawn),
        ):
            result = verify_node_candidate("104.18.1.2", 7, threading.Event(), profile=profile)

        self.assertTrue(result.ok)
        self.assertEqual(result.http_code, 204)
        self.assertEqual(result.ttfb_ms, 188.4)
        self.assertEqual(created[0].command[-2:], ["-c", "stdin:"])
        config = json.loads(created[0].input_capture.payload.decode("utf-8"))
        self.assertEqual(config["outbounds"][0]["settings"]["vnext"][0]["address"], "104.18.1.2")

    def test_cancel_after_node_response_never_returns_success(self) -> None:
        profile = parse_node_profile(LINK)
        cancel = threading.Event()

        def response(*_args: object) -> tuple[int, float]:
            cancel.set()
            return 204, 188.4

        with (
            mock.patch("cfopt.xray_node.find_xray_executable", return_value=Path("C:/portable/xray/xray.exe")),
            mock.patch("cfopt.xray_node._free_loopback_port", return_value=32123),
            mock.patch("cfopt.xray_node._wait_for_socks"),
            mock.patch("cfopt.xray_node._http_status_through_node", side_effect=response),
            mock.patch("cfopt.xray_node.subprocess.Popen", side_effect=_FakeProcess),
        ):
            result = verify_node_candidate("104.18.1.2", NODE_GATE_TIMEOUT_SECONDS, cancel, profile=profile)
        self.assertFalse(result.ok)
        self.assertIn("取消", result.error)


if __name__ == "__main__":
    unittest.main()
