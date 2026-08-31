from __future__ import annotations

import ipaddress
import base64
import hashlib
import os
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .models import ProbeResult, SPEED_HOST
from .ranges import family_of, normalized_ip


class ProbeCancelled(RuntimeError):
    pass


@dataclass
class _HttpResult:
    status: int
    version: str
    headers: dict[str, str]
    body: bytes
    remote_ip: str
    tcp_ms: float
    tls_ms: float
    ttfb_ms: float
    body_ms: float
    total_ms: float


class _SocketReader:
    def __init__(
        self,
        stream: ssl.SSLSocket,
        initial: bytes,
        cancel_event: threading.Event,
        idle_timeout: float,
        absolute_deadline: float,
    ) -> None:
        self.stream = stream
        self.buffer = bytearray(initial)
        self.cancel_event = cancel_event
        self.idle_timeout = idle_timeout
        self.absolute_deadline = absolute_deadline
        self.last_activity = time.monotonic()

    def _recv(self) -> bytes:
        while True:
            if self.cancel_event.is_set():
                raise ProbeCancelled("已取消")
            now = time.monotonic()
            if now >= self.absolute_deadline or now - self.last_activity >= self.idle_timeout:
                raise TimeoutError("读取超时")
            self.stream.settimeout(min(1.0, self.absolute_deadline - now, self.idle_timeout))
            try:
                chunk = self.stream.recv(256 * 1024)
            except socket.timeout:
                continue
            if chunk:
                self.last_activity = time.monotonic()
            return chunk

    def read_line(self, max_bytes: int = 65_536) -> bytes:
        while True:
            index = self.buffer.find(b"\r\n")
            if index >= 0:
                line = bytes(self.buffer[:index])
                del self.buffer[: index + 2]
                return line
            if len(self.buffer) > max_bytes:
                raise ValueError("HTTP 行过长")
            chunk = self._recv()
            if not chunk:
                raise EOFError("响应提前结束")
            self.buffer.extend(chunk)

    def read_exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            chunk = self._recv()
            if not chunk:
                raise EOFError("响应体提前结束")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def read_to_eof(self, max_bytes: int) -> bytes:
        output = bytearray(self.buffer)
        self.buffer.clear()
        while len(output) <= max_bytes:
            chunk = self._recv()
            if not chunk:
                break
            output.extend(chunk)
        if len(output) > max_bytes:
            raise ValueError("响应体超过限制")
        return bytes(output)


def _socket_address(target_ip: str, port: int = 443) -> tuple[int, tuple[object, ...]]:
    address = ipaddress.ip_address(target_ip)
    if address.version == 6:
        return socket.AF_INET6, (str(address), port, 0, 0)
    return socket.AF_INET, (str(address), port)


def _read_headers(stream: ssl.SSLSocket, cancel_event: threading.Event, deadline: float) -> tuple[bytes, bytes, float]:
    buffer = bytearray()
    first_byte_at = -1.0
    while b"\r\n\r\n" not in buffer:
        if cancel_event.is_set():
            raise ProbeCancelled("已取消")
        now = time.monotonic()
        if now >= deadline:
            raise TimeoutError("响应头超时")
        stream.settimeout(min(1.0, deadline - now))
        try:
            chunk = stream.recv(64 * 1024)
        except socket.timeout:
            continue
        if not chunk:
            raise EOFError("未收到完整 HTTP 响应头")
        if first_byte_at < 0.0:
            first_byte_at = time.perf_counter()
        buffer.extend(chunk)
        if len(buffer) > 128 * 1024:
            raise ValueError("HTTP 响应头过大")
    head, body = bytes(buffer).split(b"\r\n\r\n", 1)
    return head, body, first_byte_at


def _parse_head(head: bytes) -> tuple[int, str, dict[str, str]]:
    lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError("无效 HTTP 状态行")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return int(parts[1]), parts[0], headers


def _read_body(
    stream: ssl.SSLSocket,
    initial: bytes,
    headers: dict[str, str],
    cancel_event: threading.Event,
    timeout_sec: int,
    absolute_deadline: float,
    max_body: int,
) -> bytes:
    reader = _SocketReader(stream, initial, cancel_event, float(timeout_sec), absolute_deadline)
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        output = bytearray()
        while True:
            size_line = reader.read_line().split(b";", 1)[0].strip()
            size = int(size_line, 16)
            if size == 0:
                while reader.read_line():
                    pass
                break
            if len(output) + size > max_body:
                raise ValueError("响应体超过限制")
            output.extend(reader.read_exact(size))
            if reader.read_exact(2) != b"\r\n":
                raise ValueError("无效 chunked 响应")
        return bytes(output)
    if "content-length" in headers:
        size = int(headers["content-length"].split(",", 1)[0])
        if size > max_body:
            raise ValueError("响应体超过限制")
        return reader.read_exact(size)
    return reader.read_to_eof(max_body)


def _http_get_pinned(
    target_ip: str,
    path: str,
    timeout_sec: int,
    cancel_event: threading.Event,
    max_body: int,
    hostname: str = SPEED_HOST,
    port: int = 443,
) -> _HttpResult:
    if cancel_event.is_set():
        raise ProbeCancelled("已取消")
    family, address = _socket_address(target_ip, port)
    connect_started = time.perf_counter()
    absolute_deadline = time.monotonic() + timeout_sec + 10.0
    raw = socket.socket(family, socket.SOCK_STREAM)
    stream: ssl.SSLSocket | None = None
    try:
        raw.settimeout(float(timeout_sec))
        raw.connect(address)
        connected = time.perf_counter()
        context = ssl.create_default_context()
        stream = context.wrap_socket(raw, server_hostname=hostname, do_handshake_on_connect=False)
        stream.settimeout(float(timeout_sec))
        stream.do_handshake()
        tls_done = time.perf_counter()
        remote = stream.getpeername()[0]
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            "User-Agent: RR-Edge-Hunter/0.1\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        stream.sendall(request)
        head, initial, first_byte_at = _read_headers(stream, cancel_event, absolute_deadline)
        status, version, headers = _parse_head(head)
        body_started = time.perf_counter()
        body = _read_body(
            stream,
            initial,
            headers,
            cancel_event,
            timeout_sec,
            absolute_deadline,
            max_body,
        )
        body_done = time.perf_counter()
        return _HttpResult(
            status=status,
            version=version,
            headers=headers,
            body=body,
            remote_ip=normalized_ip(remote),
            tcp_ms=(connected - connect_started) * 1000.0,
            tls_ms=(tls_done - connected) * 1000.0,
            ttfb_ms=(first_byte_at - connect_started) * 1000.0,
            body_ms=(body_done - body_started) * 1000.0,
            total_ms=(body_done - connect_started) * 1000.0,
        )
    finally:
        try:
            if stream is not None:
                stream.close()
            else:
                raw.close()
        except OSError:
            pass


def probe_trace(
    target_ip: str,
    timeout_sec: int = 5,
    cancel_event: threading.Event | None = None,
    hostname: str = SPEED_HOST,
    port: int = 443,
) -> tuple[str, str]:
    cancel = cancel_event or threading.Event()
    try:
        result = _http_get_pinned(target_ip, "/cdn-cgi/trace", timeout_sec, cancel, 64 * 1024, hostname, port)
        if not 200 <= result.status <= 399:
            return "", ""
        values: dict[str, str] = {}
        for line in result.body.decode("utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        return values.get("colo", "").upper(), values.get("loc", "").upper()
    except (OSError, ValueError, TimeoutError, EOFError, ssl.SSLError, ProbeCancelled):
        return "", ""


def probe_download(
    target_ip: str,
    bytes_target: int,
    timeout_sec: int,
    include_trace: bool = True,
    cancel_event: threading.Event | None = None,
    log: Callable[[str], None] | None = None,
    hostname: str = SPEED_HOST,
    port: int = 443,
) -> ProbeResult:
    cancel = cancel_event or threading.Event()
    logger = log or (lambda _message: None)
    try:
        target_ip = normalized_ip(target_ip)
        result = _http_get_pinned(
            target_ip,
            f"/__down?bytes={int(bytes_target)}",
            timeout_sec,
            cancel,
            max(int(bytes_target * 1.2), 1_000_000),
            hostname,
            port,
        )
        downloaded = len(result.body)
        complete = bytes_target <= 0 or downloaded >= int(bytes_target * 0.8)
        target_matches = ipaddress.ip_address(target_ip) == ipaddress.ip_address(result.remote_ip)
        ok = 200 <= result.status <= 399 and complete and target_matches
        error = ""
        if not target_matches:
            error = f"实际连接地址不一致：{result.remote_ip}"
        elif not 200 <= result.status <= 399:
            error = f"HTTP {result.status}"
        elif not complete:
            error = f"下载不完整：{downloaded}/{bytes_target}（<80%）"
        payload_mbps = downloaded * 8.0 / result.body_ms / 1000.0 if ok and result.body_ms > 0.0 else 0.0
        complete_mbps = downloaded * 8.0 / result.total_ms / 1000.0 if ok and result.total_ms > 0.0 else 0.0
        colo = ""
        loc = ""
        if ok and include_trace and not cancel.is_set():
            colo, loc = probe_trace(target_ip, timeout_sec, cancel, hostname, port)
        return ProbeResult(
            ok=ok,
            error=error,
            family=family_of(result.remote_ip) or "未知",
            target_ip=target_ip,
            actual_remote_address=result.remote_ip,
            target_matches_remote=target_matches,
            remote_is_ipv6=":" in result.remote_ip,
            sni=hostname,
            cert_verified=True,
            http_code=result.status,
            http_version=result.version,
            tcp_ms=result.tcp_ms,
            tls_ms=result.tls_ms,
            ttfb_ms=result.ttfb_ms,
            body_ms=result.body_ms,
            total_ms=result.total_ms,
            bytes_downloaded=downloaded,
            bytes_target=bytes_target,
            payload_mbps=payload_mbps,
            complete_mbps=complete_mbps,
            colo=colo,
            loc=loc,
        )
    except ProbeCancelled:
        return ProbeResult(ok=False, error="已取消", target_ip=target_ip, bytes_target=bytes_target)
    except (OSError, ValueError, TimeoutError, EOFError, ssl.SSLError) as exc:
        message = f"{type(exc).__name__}: {str(exc)[:100]}"
        logger(f"{target_ip} 测试失败：{message}")
        return ProbeResult(ok=False, error=message, target_ip=target_ip, bytes_target=bytes_target)


def probe_argo_compatibility(
    target_ip: str,
    timeout_sec: int = 7,
    cancel_event: threading.Event | None = None,
    *,
    hostname: str,
    ws_path: str = "",
    port: int = 443,
) -> ProbeResult:
    """Verify that a pinned CF address can serve the user's Argo hostname.

    Throughput remains measured against ``speed.cloudflare.com`` because an
    ordinary Argo tunnel does not expose Cloudflare's ``/__down`` endpoint.
    This separate gate keeps certificate verification enabled and, when a WS
    path is supplied, requires a genuine WebSocket upgrade response.
    """
    cancel = cancel_event or threading.Event()
    target_ip = normalized_ip(target_ip)
    if ws_path:
        if (
            len(ws_path) > 512
            or not ws_path.startswith("/")
            or ws_path.startswith("//")
            or "://" in ws_path
            or "\\" in ws_path
            or "#" in ws_path
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in ws_path)
            or re.search(r"%(?![0-9A-Fa-f]{2})", ws_path)
        ):
            return ProbeResult(ok=False, error="WS 路径格式无效", target_ip=target_ip, sni=hostname)
    family, address = _socket_address(target_ip, port)
    started = time.perf_counter()
    raw = socket.socket(family, socket.SOCK_STREAM)
    stream: ssl.SSLSocket | None = None
    try:
        if cancel.is_set():
            raise ProbeCancelled("已取消")
        raw.settimeout(float(timeout_sec))
        raw.connect(address)
        connected = time.perf_counter()
        context = ssl.create_default_context()
        stream = context.wrap_socket(raw, server_hostname=hostname, do_handshake_on_connect=False)
        stream.settimeout(float(timeout_sec))
        stream.do_handshake()
        tls_done = time.perf_counter()
        remote = normalized_ip(stream.getpeername()[0])
        target_matches = ipaddress.ip_address(target_ip) == ipaddress.ip_address(remote)
        path = ws_path or "/cdn-cgi/trace"
        websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
        upgrade = ""
        connection_header = "Connection: close\r\n"
        if ws_path:
            upgrade = (
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Key: {websocket_key}\r\n"
            )
            connection_header = "Connection: Upgrade\r\n"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            "User-Agent: RR-Edge-Hunter/0.1\r\n"
            f"{upgrade}"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            f"{connection_header}\r\n"
        ).encode("ascii")
        stream.sendall(request)
        deadline = time.monotonic() + timeout_sec
        head, initial, first_byte_at = _read_headers(stream, cancel, deadline)
        status, version, headers = _parse_head(head)
        colo = ""
        loc = ""
        bytes_downloaded = 0
        if ws_path:
            expected_accept = base64.b64encode(
                hashlib.sha1((websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
            ).decode("ascii")
            connection_tokens = {token.strip().lower() for token in headers.get("connection", "").split(",")}
            ok_status = (
                status == 101
                and headers.get("upgrade", "").lower() == "websocket"
                and "upgrade" in connection_tokens
                and expected_accept == headers.get("sec-websocket-accept", "")
            )
            error = "" if ok_status else f"WebSocket 握手未通过（HTTP {status}）"
        else:
            body = _read_body(stream, initial, headers, cancel, timeout_sec, deadline, 64 * 1024)
            bytes_downloaded = len(body)
            trace_values: dict[str, str] = {}
            for line in body.decode("utf-8", errors="replace").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    trace_values[key.strip()] = value.strip()
            colo = trace_values.get("colo", "").upper()
            loc = trace_values.get("loc", "").upper()
            ok_status = 200 <= status <= 399 and bool(colo)
            error = "" if ok_status else (f"Argo 主机返回 HTTP {status}" if not 200 <= status <= 399 else "未获得 Cloudflare Trace")
        ok = bool(target_matches and ok_status)
        if not target_matches:
            error = f"实际连接地址不一致：{remote}"
        ended = time.perf_counter()
        return ProbeResult(
            ok=ok,
            error=error,
            family=family_of(remote) or "未知",
            target_ip=target_ip,
            actual_remote_address=remote,
            target_matches_remote=target_matches,
            remote_is_ipv6=":" in remote,
            sni=hostname,
            cert_verified=True,
            http_code=status,
            http_version=version,
            tcp_ms=(connected - started) * 1000.0,
            tls_ms=(tls_done - connected) * 1000.0,
            ttfb_ms=(first_byte_at - started) * 1000.0,
            total_ms=(ended - started) * 1000.0,
            bytes_downloaded=bytes_downloaded,
            colo=colo,
            loc=loc,
        )
    except ProbeCancelled:
        return ProbeResult(ok=False, error="已取消", target_ip=target_ip, sni=hostname)
    except (OSError, ValueError, TimeoutError, EOFError, ssl.SSLError) as exc:
        return ProbeResult(ok=False, error=f"{type(exc).__name__}: {str(exc)[:100]}", target_ip=target_ip, sni=hostname)
    finally:
        try:
            if stream is not None:
                stream.close()
            else:
                raw.close()
        except OSError:
            pass
