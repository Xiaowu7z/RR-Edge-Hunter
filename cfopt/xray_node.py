from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

from .models import ProbeResult
from .node_template import NodeProfile


DELAY_TEST_HOST = "www.gstatic.com"
DELAY_TEST_PATH = "/generate_204"
DELAY_TEST_PORT = 443


class XrayNodeError(RuntimeError):
    pass


class XrayRuntimeError(XrayNodeError):
    """The local Xray program is missing or cannot be executed at all."""


def find_xray_executable(explicit: str | os.PathLike[str] | None = None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    configured = os.environ.get("RR_EDGE_HUNTER_XRAY", "").strip()
    if configured:
        candidates.append(Path(configured))
    candidates.extend([
        Path(sys.executable).resolve().parent / "xray" / "xray.exe",
        Path(__file__).resolve().parents[1] / "runtime" / "xray.exe",
    ])
    located = shutil.which("xray") or shutil.which("xray.exe")
    if located:
        candidates.append(Path(located))
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_file():
            return resolved
    raise XrayNodeError("未找到内置 Xray 核心；请重新下载完整便携版并保持 xray 文件夹不变")


def validate_xray_runtime(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Resolve and launch Xray once before any bandwidth-consuming scan starts."""

    xray = find_xray_executable(explicit)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        checked = subprocess.run(
            [str(xray), "version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            creationflags=flags,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise XrayRuntimeError("内置 Xray 核心无法启动；请重新下载完整便携版") from exc
    banner = checked.stdout.decode("utf-8", "replace")[:512]
    if checked.returncode != 0 or "xray" not in banner.lower():
        raise XrayRuntimeError("内置 Xray 核心自检失败；请重新下载完整便携版")
    return xray


def build_xray_config(profile: NodeProfile, candidate_ip: str, socks_port: int) -> str:
    if isinstance(socks_port, bool) or not 1 <= int(socks_port) <= 65535:
        raise ValueError("本地测试端口无效")
    outbound = profile.outbound_for(candidate_ip)
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "rr-local-socks",
            "listen": "127.0.0.1",
            "port": int(socks_port),
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound],
    }
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.bind(("127.0.0.1", 0))
        return int(stream.getsockname()[1])


def _remaining(deadline: float, cancel: threading.Event) -> float:
    if cancel.is_set():
        raise XrayNodeError("已取消")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("V2rayNG 同口径节点测试超时")
    return remaining


def _receive_exact(stream: socket.socket, size: int, deadline: float, cancel: threading.Event) -> bytes:
    output = bytearray()
    while len(output) < size:
        stream.settimeout(min(0.5, _remaining(deadline, cancel)))
        try:
            chunk = stream.recv(size - len(output))
        except socket.timeout:
            continue
        if not chunk:
            raise XrayNodeError("本地 Xray SOCKS 响应提前结束")
        output.extend(chunk)
    return bytes(output)


def _socks_connect(port: int, deadline: float, cancel: threading.Event) -> socket.socket:
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        stream.settimeout(min(0.5, _remaining(deadline, cancel)))
        stream.connect(("127.0.0.1", port))
        stream.sendall(b"\x05\x01\x00")
        if _receive_exact(stream, 2, deadline, cancel) != b"\x05\x00":
            raise XrayNodeError("本地 Xray SOCKS 协商失败")
        domain = DELAY_TEST_HOST.encode("ascii")
        request = b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + DELAY_TEST_PORT.to_bytes(2, "big")
        stream.sendall(request)
        head = _receive_exact(stream, 4, deadline, cancel)
        if head[:2] != b"\x05\x00":
            raise XrayNodeError(f"完整节点无法建立代理连接（SOCKS {head[1]}）")
        if head[3] == 1:
            _receive_exact(stream, 4, deadline, cancel)
        elif head[3] == 3:
            length = _receive_exact(stream, 1, deadline, cancel)[0]
            _receive_exact(stream, length, deadline, cancel)
        elif head[3] == 4:
            _receive_exact(stream, 16, deadline, cancel)
        else:
            raise XrayNodeError("本地 Xray SOCKS 地址类型无效")
        _receive_exact(stream, 2, deadline, cancel)
        return stream
    except Exception:
        stream.close()
        raise


def _wait_for_socks(process: subprocess.Popen[bytes], port: int, deadline: float, cancel: threading.Event) -> None:
    while True:
        _remaining(deadline, cancel)
        if process.poll() is not None:
            raise XrayNodeError("Xray 核心未能启动完整节点")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.03)


def _http_status_through_node(port: int, deadline: float, cancel: threading.Event) -> tuple[int, float]:
    started = time.perf_counter()
    raw = _socks_connect(port, deadline, cancel)
    wrapped: ssl.SSLSocket | None = None
    try:
        context = ssl.create_default_context()
        raw.settimeout(_remaining(deadline, cancel))
        wrapped = context.wrap_socket(raw, server_hostname=DELAY_TEST_HOST)
        request = (
            f"GET {DELAY_TEST_PATH} HTTP/1.1\r\n"
            f"Host: {DELAY_TEST_HOST}\r\n"
            "User-Agent: RR-Edge-Hunter/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        wrapped.sendall(request)
        line = bytearray()
        while b"\r\n" not in line:
            wrapped.settimeout(min(0.5, _remaining(deadline, cancel)))
            try:
                chunk = wrapped.recv(1)
            except socket.timeout:
                continue
            if not chunk or len(line) > 4096:
                raise XrayNodeError("generate_204 响应无效")
            line.extend(chunk)
        parts = bytes(line).decode("ascii", "replace").strip().split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise XrayNodeError("generate_204 HTTP 状态无效")
        return int(parts[1]), (time.perf_counter() - started) * 1000.0
    finally:
        try:
            (wrapped or raw).close()
        except OSError:
            pass


def verify_node_candidate(
    target_ip: str,
    timeout_sec: int = 7,
    cancel_event: threading.Event | None = None,
    *,
    profile: NodeProfile,
    xray_executable: str | os.PathLike[str] | None = None,
) -> ProbeResult:
    cancel = cancel_event or threading.Event()
    try:
        normalized_ip = str(ipaddress.ip_address(target_ip))
    except ValueError:
        return ProbeResult(ok=False, error="候选不是有效 IP", target_ip=str(target_ip))
    xray = find_xray_executable(xray_executable)
    process: subprocess.Popen[bytes] | None = None
    deadline = time.monotonic() + max(5.0, min(float(timeout_sec), 15.0))
    try:
        port = _free_loopback_port()
        config = build_xray_config(profile, normalized_ip, port).encode("utf-8")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            process = subprocess.Popen(
                [str(xray), "run", "-c", "stdin:"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=flags,
            )
        except OSError as exc:
            raise XrayRuntimeError("内置 Xray 核心无法启动；本轮已停止以避免继续消耗流量") from exc
        if process.stdin is None:
            raise XrayNodeError("无法把节点配置交给 Xray")
        process.stdin.write(config)
        process.stdin.close()
        process.stdin = None
        _wait_for_socks(process, port, deadline, cancel)
        status, delay_ms = _http_status_through_node(port, deadline, cancel)
        if status not in {200, 204}:
            raise XrayNodeError(f"generate_204 返回 HTTP {status}")
        return ProbeResult(
            ok=True,
            family="IPv6" if ":" in normalized_ip else "IPv4",
            target_ip=normalized_ip,
            actual_remote_address=normalized_ip,
            target_matches_remote=True,
            remote_is_ipv6=":" in normalized_ip,
            sni=profile.route.sni,
            cert_verified=True,
            http_code=status,
            ttfb_ms=delay_ms,
            total_ms=delay_ms,
        )
    except XrayRuntimeError:
        raise
    except (OSError, ValueError, TimeoutError, XrayNodeError, ssl.SSLError) as exc:
        return ProbeResult(ok=False, error=f"{type(exc).__name__}: {str(exc)[:140]}", target_ip=normalized_ip, sni=profile.route.sni)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)


__all__ = [
    "DELAY_TEST_HOST",
    "DELAY_TEST_PATH",
    "NodeProfile",
    "XrayNodeError",
    "XrayRuntimeError",
    "build_xray_config",
    "find_xray_executable",
    "validate_xray_runtime",
    "verify_node_candidate",
]
