"""Reference-compatible Cloudflare IP selection engine.

This is an independent implementation of the public behaviour documented by
``better-cloudflare-ip``.  No upstream source code is vendored: the module
implements the same observable pipeline (maintained subnet feed -> 100 random
candidates -> three CF-RAY RTT checks -> ten lowest-latency download tests ->
first target hit) using Python's standard library.
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import http.client
import ipaddress
import json
import os
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .history import data_dir
from .models import FamilyRunResult, IpMetric, OptimizerResult, ProbeResult
from .ranges import FALLBACK_V4, FALLBACK_V6


POOL_V4_URL = "https://www.baipiao.eu.org/cloudflare/ips-v4"
POOL_V6_URL = "https://www.baipiao.eu.org/cloudflare/ips-v6"
SPEED_TARGET_URL = "https://www.baipiao.eu.org/cloudflare/url"
LOCATIONS_URL = "https://www.baipiao.eu.org/cloudflare/locations"

CACHE_MAX_AGE_SECONDS = 6 * 60 * 60
MAX_FEED_BYTES = 4 * 1024 * 1024
ROUND_SIZE = 100
RTT_ATTEMPTS = 3
RTT_CONCURRENCY = 50
RTT_DEADLINE_SECONDS = 1.0
SPEED_DEADLINE_SECONDS = 5.0
SPEED_SHORTLIST = 10
CUSTOM_PER_ROUND = 20
FALLBACK_SPEED_TARGET = "speed.cloudflare.com/__down?bytes=250000000"

StageCallback = Callable[[str, int, int, str], None]
LogCallback = Callable[[str], None]
CompatibilityFunction = Callable[..., ProbeResult]
NetworkFingerprintFunction = Callable[[], tuple[str, str]]


class ReferenceCancelled(RuntimeError):
    pass


class ReferenceNetworkChanged(RuntimeError):
    pass


@dataclass(frozen=True)
class MaintainedData:
    ipv4_ranges: tuple[str, ...]
    ipv6_ranges: tuple[str, ...]
    speed_host: str
    speed_path: str
    locations: dict[str, str]
    source: str


@dataclass(frozen=True)
class RoundCandidate:
    ip: str
    source: str


@dataclass(frozen=True)
class RttResult:
    candidate: RoundCandidate
    latency_ms: int


@dataclass(frozen=True)
class SpeedResult:
    ok: bool
    peak_kbps: int = 0
    tcp_ms: int = 0
    colo: str = ""
    bytes_downloaded: int = 0
    error: str = ""


def _cancelled(cancel_event: threading.Event) -> None:
    if cancel_event.is_set():
        raise ReferenceCancelled("已停止")


def _safe_public_ip(value: str, family: str | None = None) -> str | None:
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return None
    expected = 6 if family == "IPv6" else 4 if family == "IPv4" else None
    if expected and address.version != expected:
        return None
    if not address.is_global or address.is_multicast or address.is_unspecified:
        return None
    return str(address)


def _feed_lines(text: str, family: str) -> tuple[str, ...]:
    output: list[str] = []
    seen: set[str] = set()
    version = 6 if family == "IPv6" else 4
    for raw in text.splitlines():
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.version != version or not network.network_address.is_global:
            continue
        normalized = network.with_prefixlen
        if normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return tuple(output)


def _parse_speed_target(value: str) -> tuple[str, str]:
    raw = value.strip()
    if not raw:
        raise ValueError("测速地址为空")
    parsed = urllib.parse.urlsplit(raw if "://" in raw else "//" + raw)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("测速地址端口无效") from exc
    if not host or port not in {None, 80, 443}:
        raise ValueError("测速地址必须是普通 HTTP/HTTPS 域名")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("测速地址必须使用域名")
    if any(character.isspace() for character in host) or len(host) > 253:
        raise ValueError("测速域名无效")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if not path.startswith("/") or len(path) > 2_048:
        raise ValueError("测速路径无效")
    return host, path


def _fetch_text(url: str, max_bytes: int = MAX_FEED_BYTES) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "RR-Edge-Hunter/1.0", "Accept": "text/plain, application/json"},
        method="GET",
    )
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=20, context=context) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme.lower() != "https" or final.hostname != "www.baipiao.eu.org":
            raise ValueError("维护数据发生了不受信任的跳转")
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > max_bytes:
            raise ValueError("维护数据超过大小上限")
        payload = response.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError("维护数据超过大小上限")
    return payload.decode("utf-8-sig")


def _parse_locations(text: str) -> dict[str, str]:
    value = json.loads(text)
    if not isinstance(value, list):
        raise ValueError("数据中心列表格式无效")
    output: dict[str, str] = {}
    for item in value[:2_000]:
        if not isinstance(item, dict):
            continue
        code = str(item.get("iata", "")).strip().upper()
        city = str(item.get("city", "")).strip()
        if len(code) == 3 and code.isalpha():
            output[code] = city or code
    return output


def _cache_path() -> Path:
    return data_dir() / "reference-pool-v1.json"


def _decode_cached(value: object, *, source: str) -> MaintainedData:
    if not isinstance(value, dict):
        raise ValueError("缓存格式无效")
    v4 = _feed_lines("\n".join(map(str, value.get("ipv4_ranges", []))), "IPv4")
    v6 = _feed_lines("\n".join(map(str, value.get("ipv6_ranges", []))), "IPv6")
    host, path = _parse_speed_target(str(value.get("speed_target", "")))
    locations_raw = value.get("locations", {})
    locations = {
        str(code).upper(): str(city)
        for code, city in locations_raw.items()
        if isinstance(locations_raw, dict) and len(str(code)) == 3
    }
    if not v4 or not v6:
        raise ValueError("缓存 IP 池为空")
    return MaintainedData(v4, v6, host, path, locations, source)


def load_maintained_data(force_refresh: bool = False, log: LogCallback | None = None) -> MaintainedData:
    logger = log or (lambda _message: None)
    path = _cache_path()
    cached_value: object | None = None
    cached_fresh = False
    try:
        stat = path.stat()
        cached_value = json.loads(path.read_text(encoding="utf-8"))
        cached_fresh = time.time() - stat.st_mtime <= CACHE_MAX_AGE_SECONDS
    except (OSError, json.JSONDecodeError):
        cached_value = None
    if cached_value is not None and cached_fresh and not force_refresh:
        try:
            return _decode_cached(cached_value, source="维护池缓存")
        except ValueError:
            cached_value = None

    try:
        speed_text = _fetch_text(SPEED_TARGET_URL, 16 * 1024)
        speed_host, speed_path = _parse_speed_target(speed_text)
        v4 = _feed_lines(_fetch_text(POOL_V4_URL), "IPv4")
        v6 = _feed_lines(_fetch_text(POOL_V6_URL), "IPv6")
        locations = _parse_locations(_fetch_text(LOCATIONS_URL))
        if not v4 or not v6:
            raise ValueError("在线维护池为空")
        payload = {
            "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "ipv4_ranges": list(v4),
            "ipv6_ranges": list(v6),
            "speed_target": speed_host + speed_path,
            "locations": locations,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, path)
        logger(f"维护数据已更新：IPv4 {len(v4)} 段 / IPv6 {len(v6)} 段")
        return MaintainedData(v4, v6, speed_host, speed_path, locations, "baipiao.eu.org 维护池")
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, urllib.error.URLError) as exc:
        if cached_value is not None:
            logger(f"在线维护数据不可用，使用上次缓存：{type(exc).__name__}")
            return _decode_cached(cached_value, source="维护池离线缓存")
        logger(f"在线维护数据不可用，使用 Cloudflare 官方备用网段：{type(exc).__name__}")
        host, speed_path = _parse_speed_target(FALLBACK_SPEED_TARGET)
        return MaintainedData(tuple(FALLBACK_V4), tuple(FALLBACK_V6), host, speed_path, {}, "Cloudflare 官方备用池")


def _random_from_prefix(value: str, family: str, rng: random.Random) -> str | None:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if family == "IPv4" and network.version == 4:
        # Observable reference behaviour: retain the first three octets and
        # randomise the last octet, independent of the textual prefix length.
        octets = str(network.network_address).split(".")
        candidate = ".".join([*octets[:3], str(rng.randrange(256))])
        return _safe_public_ip(candidate, family)
    if family == "IPv6" and network.version == 6:
        base = int(network.network_address)
        candidate = (base >> 80 << 80) | rng.getrandbits(80)
        return _safe_public_ip(str(ipaddress.IPv6Address(candidate)), family)
    return None


def build_round_candidates(
    ranges: Iterable[str],
    custom_ips: Iterable[str],
    family: str,
    rng: random.Random,
    limit: int = ROUND_SIZE,
) -> list[RoundCandidate]:
    if limit <= 0:
        return []
    custom = list(dict.fromkeys(filter(None, (_safe_public_ip(item, family) for item in custom_ips))))
    rng.shuffle(custom)
    custom = custom[: min(CUSTOM_PER_ROUND, limit)]
    range_values = list(dict.fromkeys(str(item).strip() for item in ranges if str(item).strip()))
    rng.shuffle(range_values)
    maintained_limit = max(0, limit - len(custom))
    output: list[RoundCandidate] = [RoundCandidate(ip, "我的 IP 名单") for ip in custom]
    seen = set(custom)
    for prefix in range_values:
        candidate = _random_from_prefix(prefix, family, rng)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        output.append(RoundCandidate(candidate, "维护 IP 池"))
        if len(output) >= limit:
            break
    rng.shuffle(output)
    return output


def _socket_address(target_ip: str, port: int) -> tuple[int, tuple[object, ...]]:
    address = ipaddress.ip_address(target_ip)
    if address.version == 6:
        return socket.AF_INET6, (str(address), port, 0, 0)
    return socket.AF_INET, (str(address), port)


def _remaining(deadline: float, cancel_event: threading.Event) -> float:
    _cancelled(cancel_event)
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("截止时间已到")
    return seconds


def _read_headers(stream: socket.socket, deadline: float, cancel_event: threading.Event) -> tuple[int, dict[str, str]]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        if len(data) > 64 * 1024:
            raise ValueError("HTTP 响应头过大")
        stream.settimeout(_remaining(deadline, cancel_event))
        chunk = stream.recv(4_096)
        if not chunk:
            raise EOFError("HTTP 响应提前结束")
        data.extend(chunk)
    head, _initial = bytes(data).split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError("HTTP 状态行无效")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return int(parts[1]), headers


def _rtt_once(candidate: RoundCandidate, use_tls: bool, cancel_event: threading.Event) -> int:
    port = 443 if use_tls else 80
    family, address = _socket_address(candidate.ip, port)
    deadline = time.monotonic() + RTT_DEADLINE_SECONDS
    raw = socket.socket(family, socket.SOCK_STREAM)
    stream: socket.socket = raw
    started = time.perf_counter()
    try:
        raw.settimeout(_remaining(deadline, cancel_event))
        raw.connect(address)
        connected = time.perf_counter()
        remote = str(ipaddress.ip_address(raw.getpeername()[0]))
        if ipaddress.ip_address(remote) != ipaddress.ip_address(candidate.ip):
            raise ValueError("实际远端不一致")
        if use_tls:
            context = ssl.create_default_context()
            stream = context.wrap_socket(raw, server_hostname="cloudflare.com", do_handshake_on_connect=False)
            stream.settimeout(_remaining(deadline, cancel_event))
            stream.do_handshake()
        request = (
            "GET / HTTP/1.1\r\n"
            "Host: cloudflare.com\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        stream.settimeout(_remaining(deadline, cancel_event))
        stream.sendall(request)
        _status, headers = _read_headers(stream, deadline, cancel_event)
        if not headers.get("cf-ray"):
            raise ValueError("缺少 CF-RAY")
        return max(1, int((connected - started) * 1_000))
    finally:
        try:
            stream.close()
        except OSError:
            pass
        if stream is not raw:
            try:
                raw.close()
            except OSError:
                pass


def _rtt_candidate(candidate: RoundCandidate, use_tls: bool, cancel_event: threading.Event) -> RttResult | None:
    values: list[int] = []
    try:
        for _ in range(RTT_ATTEMPTS):
            values.append(_rtt_once(candidate, use_tls, cancel_event))
    except ReferenceCancelled:
        raise
    except (OSError, ssl.SSLError, TimeoutError, EOFError, ValueError):
        return None
    return RttResult(candidate, sum(values) // RTT_ATTEMPTS)


def run_rtt_round(
    candidates: list[RoundCandidate],
    use_tls: bool,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    round_number: int,
) -> list[RttResult]:
    if not candidates:
        return []
    total = len(candidates)
    done = 0
    stage = f"第 {round_number} 轮 · 3 次 RTT / CF-RAY 验证"
    on_stage(stage, 0, total, f"并发 {min(RTT_CONCURRENCY, total)}")
    results: list[RttResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(RTT_CONCURRENCY, total)) as executor:
        futures = {executor.submit(_rtt_candidate, item, use_tls, cancel_event): item for item in candidates}
        try:
            for future in concurrent.futures.as_completed(futures):
                _cancelled(cancel_event)
                done += 1
                item = futures[future]
                try:
                    result = future.result()
                except ReferenceCancelled:
                    raise
                except Exception:
                    result = None
                if result is not None:
                    results.append(result)
                on_stage(stage, done, total, item.ip)
        except ReferenceCancelled:
            for future in futures:
                future.cancel()
            raise
    results.sort(key=lambda item: (item.latency_ms, item.candidate.ip))
    return results[:SPEED_SHORTLIST]


def _colo_from_ray(value: str) -> str:
    suffix = value.rsplit("-", 1)[-1].strip().upper() if "-" in value else ""
    return suffix if len(suffix) == 3 and suffix.isalpha() else ""


def probe_speed(
    candidate: RoundCandidate,
    data: MaintainedData,
    use_tls: bool,
    cancel_event: threading.Event,
) -> SpeedResult:
    port = 443 if use_tls else 80
    family, address = _socket_address(candidate.ip, port)
    deadline = time.monotonic() + SPEED_DEADLINE_SECONDS
    raw = socket.socket(family, socket.SOCK_STREAM)
    stream: socket.socket = raw
    response: http.client.HTTPResponse | None = None
    total_bytes = 0
    max_kbps = 0
    tcp_ms = 0
    colo = ""
    try:
        started = time.perf_counter()
        raw.settimeout(_remaining(deadline, cancel_event))
        raw.connect(address)
        tcp_ms = max(1, int((time.perf_counter() - started) * 1_000))
        remote = str(ipaddress.ip_address(raw.getpeername()[0]))
        if ipaddress.ip_address(remote) != ipaddress.ip_address(candidate.ip):
            raise ValueError("实际远端不一致")
        if use_tls:
            context = ssl.create_default_context()
            stream = context.wrap_socket(raw, server_hostname=data.speed_host, do_handshake_on_connect=False)
            stream.settimeout(_remaining(deadline, cancel_event))
            stream.do_handshake()
        request = (
            f"GET {data.speed_path} HTTP/1.1\r\n"
            f"Host: {data.speed_host}\r\n"
            "User-Agent: RR-Edge-Hunter/1.0\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        stream.settimeout(_remaining(deadline, cancel_event))
        stream.sendall(request)
        response = http.client.HTTPResponse(stream)
        response.begin()
        if not 200 <= response.status <= 299:
            return SpeedResult(False, tcp_ms=tcp_ms, error=f"HTTP {response.status}")
        ray = response.getheader("CF-RAY", "")
        if not ray:
            return SpeedResult(False, tcp_ms=tcp_ms, error="缺少 CF-RAY")
        colo = _colo_from_ray(ray)
        window_bytes = 0
        window_started = time.monotonic()
        while True:
            _cancelled(cancel_event)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            stream.settimeout(remaining)
            try:
                chunk = response.read(32 * 1024)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            amount = len(chunk)
            total_bytes += amount
            window_bytes += amount
            elapsed = time.monotonic() - window_started
            if elapsed >= 1.0:
                max_kbps = max(max_kbps, int(window_bytes / 1024.0 / elapsed))
                window_bytes = 0
                window_started = time.monotonic()
        # Deliberately ignore the last incomplete (<1 second) window. This is
        # the important compatibility rule that prevents tiny bodies from
        # creating an impossible peak value.
        return SpeedResult(max_kbps > 0, max_kbps, tcp_ms, colo, total_bytes, "" if max_kbps > 0 else "没有完整 1 秒下载窗口")
    except ReferenceCancelled:
        raise
    except (OSError, ssl.SSLError, TimeoutError, EOFError, ValueError, http.client.HTTPException) as exc:
        return SpeedResult(False, tcp_ms=tcp_ms, colo=colo, bytes_downloaded=total_bytes, error=f"{type(exc).__name__}: {str(exc)[:100]}")
    finally:
        try:
            if response is not None:
                response.close()
        except OSError:
            pass
        try:
            stream.close()
        except OSError:
            pass
        if stream is not raw:
            try:
                raw.close()
            except OSError:
                pass


def _network_changed(
    family: str,
    initial: tuple[str, str],
    fingerprint: NetworkFingerprintFunction | None,
) -> bool:
    if fingerprint is None:
        return False
    current = fingerprint()
    index = 1 if family == "IPv6" else 0
    return bool(initial[index] and current[index] and initial[index] != current[index])


def run_reference_family(
    *,
    family: str,
    data: MaintainedData,
    custom_ips: Iterable[str],
    target_mbps: int,
    use_tls: bool,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    log: LogCallback,
    source_label: str,
    compatibility_fn: CompatibilityFunction | None = None,
    compatibility_host: str = "",
    compatibility_port: int = 443,
    ws_path: str = "",
    network_fingerprint_fn: NetworkFingerprintFunction | None = None,
    initial_fingerprint: tuple[str, str] = ("", ""),
    seed: object | None = None,
) -> FamilyRunResult:
    started = time.perf_counter()
    ranges = data.ipv6_ranges if family == "IPv6" else data.ipv4_ranges
    rng = random.Random(f"rr-reference:{seed}:{family}:{time.time_ns()}")
    threshold_kbps = target_mbps * 128
    round_number = 0
    traffic_bytes = 0
    last_candidate_count = 0
    while True:
        _cancelled(cancel_event)
        if _network_changed(family, initial_fingerprint, network_fingerprint_fn):
            raise ReferenceNetworkChanged("测试期间网络出口发生变化")
        round_number += 1
        candidates = build_round_candidates(ranges, custom_ips, family, rng)
        last_candidate_count = len(candidates)
        if not candidates:
            raise ValueError(f"{family} 维护池没有可用候选")
        log(f"{family} 第 {round_number} 轮：随机生成 {len(candidates)} 个候选")
        rtt_rows = run_rtt_round(candidates, use_tls, cancel_event, on_stage, round_number)
        if not rtt_rows:
            log(f"{family} 第 {round_number} 轮 RTT 全部失败，自动换一批")
            continue
        log(
            f"{family} RTT 有效，保留延迟最低 {len(rtt_rows)} 个：" +
            " / ".join(f"{row.candidate.ip} {row.latency_ms}ms" for row in rtt_rows)
        )
        stage = f"第 {round_number} 轮 · 最低延迟 IP 逐个下载测速"
        on_stage(stage, 0, len(rtt_rows), f"目标 {target_mbps} Mbps")
        for index, rtt in enumerate(rtt_rows, 1):
            _cancelled(cancel_event)
            result = probe_speed(rtt.candidate, data, use_tls, cancel_event)
            traffic_bytes += result.bytes_downloaded
            on_stage(stage, index, len(rtt_rows), rtt.candidate.ip)
            if result.ok:
                log(
                    f"{rtt.candidate.ip} 峰值 {result.peak_kbps} kB/s "
                    f"({result.peak_kbps // 128} Mbps) · TCP {result.tcp_ms}ms · {result.colo or '未知 POP'}"
                )
            else:
                log(f"{rtt.candidate.ip} 下载测速失败：{result.error}")
            if not result.ok or result.peak_kbps < threshold_kbps:
                continue
            route: ProbeResult | None = None
            if compatibility_fn is not None and compatibility_host:
                on_stage("Argo 域名兼容复核", 0, 1, rtt.candidate.ip)
                route = compatibility_fn(rtt.candidate.ip, 7, cancel_event)
                on_stage("Argo 域名兼容复核", 1, 1, rtt.candidate.ip)
                if not (route.ok and route.cert_verified and route.target_matches_remote):
                    log(f"{rtt.candidate.ip} 达到带宽，但未通过 Argo 兼容复核，继续下一个")
                    continue
            if _network_changed(family, initial_fingerprint, network_fingerprint_fn):
                raise ReferenceNetworkChanged("测试期间网络出口发生变化")
            real_mbps = result.peak_kbps / 128.0
            location = data.locations.get(result.colo, result.colo)
            probe = ProbeResult(
                ok=True,
                family=family,
                target_ip=rtt.candidate.ip,
                actual_remote_address=rtt.candidate.ip,
                target_matches_remote=True,
                remote_is_ipv6=family == "IPv6",
                sni=data.speed_host,
                cert_verified=use_tls,
                http_code=200,
                tcp_ms=float(result.tcp_ms),
                ttfb_ms=float(rtt.latency_ms),
                bytes_downloaded=result.bytes_downloaded,
                payload_mbps=real_mbps,
                complete_mbps=real_mbps,
                colo=result.colo,
                loc=location,
            )
            metric = IpMetric(
                ip=rtt.candidate.ip,
                family=family,
                min_complete_mbps=real_mbps,
                avg_complete_mbps=real_mbps,
                max_complete_mbps=real_mbps,
                min_payload_mbps=real_mbps,
                avg_payload_mbps=real_mbps,
                success_rate_pct=100.0,
                variation_pct=0.0,
                median_ttfb_ms=float(rtt.latency_ms),
                round_floor_mbps=real_mbps,
                rounds_tested=1,
                source_tags=[rtt.candidate.source, source_label],
                pop=result.colo,
                loc=location,
                stability="达标",
                peak_kbps=result.peak_kbps,
                latency_ms=result.tcp_ms,
                data_center=location,
                scan_round=round_number,
                use_tls=use_tls,
            )
            log(f"{family} 已找到首个达标 IP：{metric.ip}")
            return FamilyRunResult(
                family=family,
                ranked=[metric],
                asia_ranked=[metric],
                estimated_traffic_mb=traffic_bytes / 1_000_000.0,
                elapsed_seconds=time.perf_counter() - started,
                candidate_count=last_candidate_count,
                compatible_count=1 if route is not None else last_candidate_count,
            )
        log(f"{family} 第 {round_number} 轮没有 IP 达到 {target_mbps} Mbps，自动开始下一轮")


def run_reference_optimizer(
    *,
    family: str,
    operator: str,
    target_host: str,
    custom_ips: Iterable[str] | None,
    source_kind: str,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    log: LogCallback,
    purpose: str,
    node_port: int,
    ws_path: str,
    target_mbps: int,
    use_tls: bool,
    compatibility_fn: CompatibilityFunction | None,
    network_fingerprint_fn: NetworkFingerprintFunction | None,
    seed: object | None = None,
) -> OptimizerResult:
    started = time.perf_counter()
    data = load_maintained_data(log=log)
    log(
        f"数据来源：{data.source} · 测速 {data.speed_host}{data.speed_path} · "
        f"{'TLS 443' if use_tls else '非 TLS 80'}"
    )
    requested = ["IPv4", "IPv6"] if family == "dual" else ["IPv6" if family == "ipv6" else "IPv4"]
    initial = network_fingerprint_fn() if network_fingerprint_fn else ("", "")
    results: list[FamilyRunResult] = []
    cancelled = False
    try:
        for family_name in requested:
            _cancelled(cancel_event)
            results.append(
                run_reference_family(
                    family=family_name,
                    data=data,
                    custom_ips=custom_ips or (),
                    target_mbps=target_mbps,
                    use_tls=use_tls,
                    cancel_event=cancel_event,
                    on_stage=on_stage,
                    log=log,
                    source_label=data.source,
                    compatibility_fn=compatibility_fn if purpose == "argo" else None,
                    compatibility_host=target_host if purpose == "argo" else "",
                    compatibility_port=node_port,
                    ws_path=ws_path,
                    network_fingerprint_fn=network_fingerprint_fn,
                    initial_fingerprint=initial,
                    seed=seed,
                )
            )
    except ReferenceCancelled:
        cancelled = True
        log("优选已停止")
    except ReferenceNetworkChanged:
        log("网络出口已变化，本轮结果作废")
        if requested:
            results.append(FamilyRunResult(requested[min(len(results), len(requested) - 1)], [], [], invalid=True))
    return OptimizerResult(
        created_at=dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        mode="reference",
        operator=operator,
        requested_family=family,
        ip_count=sum(item.candidate_count for item in results),
        target_host=target_host,
        source_kind=source_kind,
        families=results,
        elapsed_seconds=time.perf_counter() - started,
        cancelled=cancelled,
        purpose=purpose,
        target_mbps=target_mbps,
        node_port=node_port,
        ws_path=ws_path,
        measurement_host=data.speed_host,
        measurement_port=443 if use_tls else 80,
        use_tls=use_tls,
        network_fingerprints={"IPv4": initial[0], "IPv6": initial[1]},
    )


__all__ = [
    "MaintainedData",
    "ReferenceCancelled",
    "RoundCandidate",
    "SpeedResult",
    "build_round_candidates",
    "load_maintained_data",
    "probe_speed",
    "run_reference_optimizer",
    "run_rtt_round",
]
