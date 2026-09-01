from __future__ import annotations

import datetime as dt
import functools
import hashlib
import ipaddress
import socket
import stat
import statistics
import threading
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Iterable

from .hostnames import HostnameError, normalize_hostname
from .ip_sources import MAX_SOURCE_BYTES, IpSourceError, decode_ip_source_bytes, normalize_ip_values, parse_ip_source
from .models import ASIA_HUNT, BALANCED, MODES, FamilyRunResult, IpMetric, ModeParams, OptimizerResult, PopDiscovery, ProbeResult, Snapshot, SPEED_HOST
from .probe import probe_argo_compatibility, probe_download, probe_speed_window, probe_tcp_rtt, probe_trace, speed_request_bytes
from .ranges import family_of, is_cloudflare_ip, normalized_ip, prefix_of, sample_official_cloudflare_ips
from .ranking import address_floor, median_ttfb, rank, rank_asia, rank_maximum, stability_label, success_rate, variation


StageCallback = Callable[[str, int, int, str], None]
LogCallback = Callable[[str], None]
ProbeFunction = Callable[..., ProbeResult]
SpeedProbeFunction = Callable[..., ProbeResult]
RttProbeFunction = Callable[..., ProbeResult]
TraceFunction = Callable[..., tuple[str, str]]
CompatibilityFunction = Callable[..., ProbeResult]
CandidateGateFunction = Callable[[str], bool]
ResolveFunction = Callable[[str], list[str]]

ASIA_POP_ORDER = ("HKG", "NRT", "SIN", "ICN", "TPE")
POP_PRIORITY = {"HKG": 5, "NRT": 4, "SIN": 3, "ICN": 2, "TPE": 1}
MAX_CANDIDATES_PER_FAMILY = 100
PURPOSE_DIRECT = "direct"
PURPOSE_ARGO = "argo"
PURPOSE_DNS = "dns"
SUPPORTED_TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
MIN_TARGET_MBPS = 1
MAX_TARGET_MBPS = 10_000
RESTRICTED_PUBLIC_SOURCE = "我的 IP 名单（受限公网候选）"


class OptimizerCancelled(RuntimeError):
    pass


class NetworkChanged(RuntimeError):
    pass


def _is_safe_public_ip(value: str) -> bool:
    """Accept routable unicast addresses, never local/reserved destinations."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def _normalize_restricted_candidates(candidates: Iterable[str]) -> tuple[list[str], int]:
    """Parse user input while preserving a count of unsafe/invalid entries."""
    parsed = parse_ip_source("\n".join(str(value) for value in candidates), "values.txt")
    safe = [value for value in parsed.ips if _is_safe_public_ip(value)]
    return safe, parsed.ignored + len(parsed.ips) - len(safe)


def pop_priority(pop: str) -> int:
    return POP_PRIORITY.get(pop.upper(), 0)


def _normalize_target_host(value: object) -> str:
    try:
        return normalize_hostname(value)
    except HostnameError as exc:
        raise ValueError(f"测试主机无效：{exc}") from exc


def normalize_ws_path(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if (
        len(raw) > 512
        or not raw.startswith("/")
        or raw.startswith("//")
        or "://" in raw
        or "\\" in raw
        or "#" in raw
        or any(raw[index] == "%" and (index + 2 >= len(raw) or any(character not in "0123456789abcdefABCDEF" for character in raw[index + 1:index + 3])) for index in range(len(raw)))
    ):
        raise ValueError("WS 路径必须是以 / 开头的相对路径，且不能包含 URL 或片段")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in raw):
        raise ValueError("WS 路径只能包含可见 ASCII 字符；请先进行 URL 编码")
    return raw


def resolve_target_ips(hostname: str) -> list[str]:
    try:
        rows = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("测试主机 DNS 解析失败") from exc
    output: list[str] = []
    seen: set[str] = set()
    for row in rows:
        try:
            ip = normalized_ip(row[4][0])
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            output.append(ip)
    if not output:
        raise ValueError("测试主机没有可用 A/AAAA 记录")
    return output


def _cancelled(cancel_event: threading.Event) -> None:
    if cancel_event.is_set():
        raise OptimizerCancelled("已取消")


def _filter_candidates(
    candidates: Iterable[str] | None,
    resolved_ips: Iterable[str],
    log: LogCallback,
) -> tuple[list[str], int, str]:
    resolved = list(dict.fromkeys(normalized_ip(value) for value in resolved_ips))
    cf_resolved = [value for value in resolved if is_cloudflare_ip(value)]
    if not cf_resolved:
        raise ValueError("测试主机当前解析结果不在 Cloudflare 公共边缘地址范围内")
    if candidates is None:
        log(f"当前主机已验证 Cloudflare 地址：{len(cf_resolved)} 个")
        return cf_resolved, 0, "当前 DNS"
    try:
        supplied = normalize_ip_values(candidates)
    except IpSourceError as exc:
        raise ValueError(str(exc)) from exc
    supplied_set = set(supplied)
    eligible = [item for item in cf_resolved if item in supplied_set]
    rejected = len(supplied_set - set(eligible))
    if not eligible:
        raise ValueError("导入名单与测试主机当前获分配的 Cloudflare IP 没有交集；为避免把流量导向未分配地址，本轮未开始")
    log(f"导入名单 {len(supplied)} 个 → 已验证可测 {len(eligible)} 个 · 不匹配/不适用 {rejected} 个")
    return eligible, rejected, "导入交集"


def _build_argo_candidates(
    candidates: Iterable[str] | None,
    resolved_ips: Iterable[str],
    log: LogCallback,
    sample_seed: object | None = None,
) -> tuple[list[str], int, str, dict[str, list[str]]]:
    resolved = list(dict.fromkeys(normalized_ip(value) for value in resolved_ips))
    cf_resolved = [value for value in resolved if is_cloudflare_ip(value)]
    if not cf_resolved:
        raise ValueError("Argo 域名当前 DNS 未返回 Cloudflare 公共边缘地址；请确认域名已启用 Cloudflare 代理")

    official = sample_official_cloudflare_ips("IPv4", seed=sample_seed) + sample_official_cloudflare_ips("IPv6", seed=sample_seed)
    supplied_public: list[str] = []
    rejected = 0
    if candidates is not None:
        try:
            supplied_public, rejected = _normalize_restricted_candidates(candidates)
        except IpSourceError as exc:
            raise ValueError(str(exc)) from exc
        if rejected:
            log(f"导入名单中 {rejected} 个无效、私网、本地或保留地址已拒绝")

    merged = list(dict.fromkeys([*cf_resolved, *official, *supplied_public]))
    sources: dict[str, list[str]] = {
        "当前 DNS": cf_resolved,
        "内置 Cloudflare 官方 CIDR 快照抽样": official,
    }
    if candidates is not None:
        sources[RESTRICTED_PUBLIC_SOURCE] = supplied_public
    label = "智能候选池" if candidates is None else "智能候选池 + 我的 IP 名单"
    log(
        f"Argo 智能候选：当前 DNS {len(cf_resolved)} + 内置官方 CIDR 快照抽样 {len(official)}"
        + (f" + 导入受限公网候选 {len(supplied_public)}（须通过严格 CF 身份复测和 Argo 门禁）" if candidates is not None else "")
    )
    return merged, rejected, label, sources


def _build_direct_candidates(
    candidates: Iterable[str] | None,
    resolved_ips: Iterable[str],
    log: LogCallback,
    sample_seed: object | None = None,
) -> tuple[list[str], int, str, dict[str, list[str]]]:
    """Build the normal IP-hunting pool without requiring a user's Argo host.

    The public speed host contributes live DNS seeds, while deterministic,
    bounded samples from every published Cloudflare CIDR provide broad
    coverage.  User input can extend that pool with any safe public unicast
    address.  Such external addresses remain restricted candidates until two
    strict speed.cloudflare.com identity-checked downloads succeed.
    """
    resolved = list(dict.fromkeys(normalized_ip(value) for value in resolved_ips))
    cf_resolved = [value for value in resolved if is_cloudflare_ip(value)]
    if not cf_resolved:
        raise ValueError("Cloudflare 公共测速端点当前 DNS 未返回官方边缘地址")

    official = sample_official_cloudflare_ips("IPv4", seed=sample_seed) + sample_official_cloudflare_ips("IPv6", seed=sample_seed)
    supplied_public: list[str] = []
    rejected = 0
    if candidates is not None:
        try:
            supplied_public, rejected = _normalize_restricted_candidates(candidates)
        except IpSourceError as exc:
            raise ValueError(str(exc)) from exc
        if rejected:
            log(f"导入名单中 {rejected} 个无效、私网、本地或保留地址已拒绝")

    merged = list(dict.fromkeys([*cf_resolved, *official, *supplied_public]))
    sources: dict[str, list[str]] = {
        "Cloudflare 测速端点 DNS 种子": cf_resolved,
        "Cloudflare 官方 CIDR 分散抽样": official,
    }
    if candidates is not None:
        sources[RESTRICTED_PUBLIC_SOURCE] = supplied_public
    label = "Cloudflare 官方 IP 池" if candidates is None else "Cloudflare 官方 IP 池 + 我的名单"
    log(
        f"独立优选池：测速端点 DNS 种子 {len(cf_resolved)} + 官方 CIDR 分散抽样 {len(official)}"
        + (f" + 导入受限公网候选 {len(supplied_public)}（须通过两次严格 CF 身份复测）" if candidates is not None else "")
    )
    return merged, rejected, label, sources


def build_snapshot(
    ips: Iterable[str],
    family: str,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    log: LogCallback,
    source_tag: str = "当前 DNS",
    sources: dict[str, list[str]] | None = None,
) -> Snapshot:
    normalized: list[str] = []
    seen: set[str] = set()
    original = list(ips)
    on_stage(f"候选校验 {family}", 0, len(original), "校验公网单播地址与协议族")
    for index, raw in enumerate(original, 1):
        _cancelled(cancel_event)
        try:
            value = normalized_ip(raw)
        except ValueError:
            on_stage(f"候选校验 {family}", index, len(original), str(raw))
            continue
        if value not in seen and family_of(value) == family and _is_safe_public_ip(value):
            seen.add(value)
            normalized.append(value)
        on_stage(f"候选校验 {family}", index, len(original), value)
    source_values = sources or {source_tag: original}
    normalized_set = set(normalized)
    filtered_sources: dict[str, list[str]] = {}
    for tag, values in source_values.items():
        tagged: list[str] = []
        for raw in values:
            try:
                value = normalized_ip(raw)
            except ValueError:
                continue
            if value in normalized_set and family_of(value) == family and value not in tagged:
                tagged.append(value)
        filtered_sources[tag] = tagged
    if len(normalized) > MAX_CANDIDATES_PER_FAMILY:
        priority_tags = [tag for tag in filtered_sources if "DNS" in tag]
        priority_tags.extend(
            tag for tag in filtered_sources
            if tag not in priority_tags and ("我的 IP" in tag or "我的名单" in tag)
        )
        selected: list[str] = []
        for tag in priority_tags:
            for value in filtered_sources[tag]:
                if value not in selected:
                    selected.append(value)
                    if len(selected) >= MAX_CANDIDATES_PER_FAMILY:
                        break
            if len(selected) >= MAX_CANDIDATES_PER_FAMILY:
                break
        seen_selected = set(selected)
        buckets = [values for tag, values in filtered_sources.items() if tag not in priority_tags and values]
        positions = [0 for _ in buckets]
        while len(selected) < MAX_CANDIDATES_PER_FAMILY and buckets:
            progressed = False
            for bucket_index, bucket in enumerate(buckets):
                while positions[bucket_index] < len(bucket) and bucket[positions[bucket_index]] in seen_selected:
                    positions[bucket_index] += 1
                if positions[bucket_index] < len(bucket):
                    value = bucket[positions[bucket_index]]
                    positions[bucket_index] += 1
                    selected.append(value)
                    seen_selected.add(value)
                    progressed = True
                    if len(selected) >= MAX_CANDIDATES_PER_FAMILY:
                        break
            if not progressed:
                break
        if len(selected) < MAX_CANDIDATES_PER_FAMILY:
            selected.extend(value for value in normalized if value not in seen_selected)
            selected = selected[:MAX_CANDIDATES_PER_FAMILY]
        log(f"{family} 已验证候选 {len(normalized)} 个；按来源均衡保留 {MAX_CANDIDATES_PER_FAMILY} 个")
        normalized = selected
        normalized_set = set(normalized)
        filtered_sources = {tag: [value for value in values if value in normalized_set] for tag, values in filtered_sources.items()}
    snapshot = Snapshot(family, normalized, filtered_sources)
    log(f"候选快照({family})：已验证地址 {len(snapshot.ips)}")
    return snapshot


def validate_argo_snapshot(
    snapshot: Snapshot,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    log: LogCallback,
    compatibility_fn: CompatibilityFunction,
) -> tuple[Snapshot, int]:
    stage = f"Argo SNI/Host 兼容验证 {snapshot.family}"
    on_stage(stage, 0, len(snapshot.ips), "固定候选 IP，保持域名证书校验")
    passed: list[str] = []
    if snapshot.ips:
        with ThreadPoolExecutor(max_workers=12, thread_name_prefix="rr-argo-gate") as pool:
            futures = {pool.submit(compatibility_fn, ip, 7, cancel_event): ip for ip in snapshot.ips}
            completed = 0
            for future in as_completed(futures):
                _cancelled(cancel_event)
                ip = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = ProbeResult(ok=False, error=f"{type(exc).__name__}: {exc}", target_ip=ip)
                if result.ok and result.cert_verified and result.target_matches_remote:
                    passed.append(ip)
                completed += 1
                on_stage(stage, completed, len(snapshot.ips), ip)
    passed_set = set(passed)
    ordered = [ip for ip in snapshot.ips if ip in passed_set]
    rejected = len(snapshot.ips) - len(ordered)
    log(f"{snapshot.family} Argo 兼容验证：{len(ordered)}/{len(snapshot.ips)} 个候选通过 TLS SNI/Host 与证书校验")
    sources = {tag: [ip for ip in values if ip in passed_set] for tag, values in snapshot.sources.items()}
    return Snapshot(snapshot.family, ordered, sources), rejected


def full_schedule(ips: list[str], full_rounds: int) -> list[str]:
    return [ip for ip in ips for _ in range(max(1, full_rounds))]


def estimate_traffic_upper_bound_mb(
    snapshot: Snapshot,
    params: ModeParams,
    target_mbps: int = 100,
) -> float:
    gate = len(snapshot.ips) * params.pre_bytes
    shortlist = min(len(snapshot.ips), params.micro_candidates)
    per_sample = speed_request_bytes(target_mbps, maximum=not params.early_stop)
    # Every shortlisted address can consume one first sample and at most one
    # confirmation sample.  In target modes several first samples may hit the
    # threshold and then fail confirmation; maximum mode may need to walk past
    # failed finalists.  Two samples per address is therefore the real bound.
    return (gate + shortlist * 2 * per_sample) / 1_000_000.0


def network_fingerprint() -> tuple[str, str]:
    def source_for(family: int, address: tuple[object, ...]) -> str:
        probe = socket.socket(family, socket.SOCK_DGRAM)
        try:
            probe.connect(address)
            return normalized_ip(probe.getsockname()[0])
        except OSError:
            return ""
        finally:
            probe.close()

    return (
        source_for(socket.AF_INET, ("1.1.1.1", 53)),
        source_for(socket.AF_INET6, ("2606:4700:4700::1111", 53, 0, 0)),
    )


def network_fingerprint_token(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    return hashlib.sha256(f"rr-edge-hunter:network:v1:{normalized}".encode("utf-8")).hexdigest()


def _run_parallel_probes(
    ips: list[str],
    bytes_target: int,
    timeout_sec: int,
    concurrency: int,
    stage_name: str,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    probe_fn: ProbeFunction,
    include_trace: bool = False,
) -> dict[str, ProbeResult]:
    results: dict[str, ProbeResult] = {}
    on_stage(stage_name, 0, len(ips), "")
    if not ips:
        return results
    with ThreadPoolExecutor(max_workers=max(1, concurrency), thread_name_prefix="rr-probe") as pool:
        futures: dict[Future[ProbeResult], str] = {
            pool.submit(probe_fn, ip, bytes_target, timeout_sec, include_trace, cancel_event): ip
            for ip in ips
        }
        completed = 0
        for future in as_completed(futures):
            _cancelled(cancel_event)
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception as exc:
                results[ip] = ProbeResult(ok=False, error=f"{type(exc).__name__}: {exc}", target_ip=ip)
            completed += 1
            on_stage(stage_name, completed, len(ips), ip)
    return {ip: results.get(ip, ProbeResult(ok=False, target_ip=ip)) for ip in ips}


def _run_parallel_rtt_rounds(
    ips: list[str],
    rounds: int,
    timeout_sec: float,
    concurrency: int,
    stage_name: str,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    rtt_probe_fn: RttProbeFunction,
) -> dict[str, ProbeResult]:
    """Require every candidate to pass every bounded TCP-connect RTT round."""
    required = max(1, int(rounds))
    total = len(ips) * required
    on_stage(stage_name, 0, total, "")
    samples: dict[str, list[float]] = {ip: [] for ip in ips}
    eligible = list(ips)
    completed = 0
    for _round in range(required):
        if not eligible:
            break
        current = list(eligible)
        passed: list[str] = []
        with ThreadPoolExecutor(max_workers=max(1, concurrency), thread_name_prefix="rr-rtt") as pool:
            futures = {
                pool.submit(rtt_probe_fn, ip, timeout_sec, cancel_event): ip
                for ip in current
            }
            for future in as_completed(futures):
                _cancelled(cancel_event)
                ip = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = ProbeResult(ok=False, error=f"{type(exc).__name__}: {exc}", target_ip=ip)
                if result.ok and result.tcp_ms >= 0.0:
                    samples[ip].append(result.tcp_ms)
                    passed.append(ip)
                completed += 1
                on_stage(stage_name, completed, total, ip)
        passed_set = set(passed)
        eligible = [ip for ip in current if ip in passed_set]

    eligible_set = set(eligible)
    return {
        ip: ProbeResult(
            ok=ip in eligible_set and len(samples[ip]) == required,
            target_ip=ip,
            actual_remote_address=ip if ip in eligible_set else "",
            target_matches_remote=ip in eligible_set,
            tcp_ms=statistics.fmean(samples[ip]) if len(samples[ip]) == required else -1.0,
            ttfb_ms=statistics.fmean(samples[ip]) if len(samples[ip]) == required else -1.0,
        )
        for ip in ips
    }


def _discover_pops(
    snapshot: Snapshot,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    log: LogCallback,
    trace_fn: TraceFunction,
) -> PopDiscovery:
    stage = f"POP 发现 {snapshot.family}"
    on_stage(stage, 0, len(snapshot.ips), "")
    rows: dict[str, tuple[str, str]] = {}
    if snapshot.ips:
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="rr-trace") as pool:
            futures = {pool.submit(trace_fn, ip, 5, cancel_event): ip for ip in snapshot.ips}
            completed = 0
            for future in as_completed(futures):
                _cancelled(cancel_event)
                ip = futures[future]
                try:
                    colo, loc = future.result()
                except Exception:
                    colo, loc = "", ""
                rows[ip] = (colo.upper(), loc.upper())
                completed += 1
                on_stage(stage, completed, len(snapshot.ips), ip)
    ip_to_pop = {ip: rows.get(ip, ("", ""))[0] for ip in snapshot.ips}
    ip_to_loc = {ip: rows.get(ip, ("", ""))[1] for ip in snapshot.ips}
    candidates = [
        {
            "ip": ip,
            "pop": ip_to_pop[ip] or "UNKNOWN",
            "loc": ip_to_loc[ip],
            "prefix": prefix_of(ip),
            "priority": pop_priority(ip_to_pop[ip]),
        }
        for ip in snapshot.ips
    ]
    candidates.sort(key=lambda row: (-int(row["priority"]), str(row["pop"]), str(row["ip"])))
    counts = dict(sorted(Counter(str(row["pop"]) for row in candidates).items()))
    summary = " · ".join(f"{pop}={counts.get(pop, 0)}" for pop in ASIA_POP_ORDER)
    log(f"{snapshot.family} POP 发现：{summary} · 未知={counts.get('UNKNOWN', 0)}")
    return PopDiscovery(counts, candidates, ip_to_pop, ip_to_loc)


def _pre_rank(ips: list[str], cache: dict[str, ProbeResult], pops: dict[str, str], asia_hunt: bool) -> list[str]:
    def key(ip: str) -> tuple[object, ...]:
        result = cache.get(ip, ProbeResult(False, target_ip=ip))
        pop = pop_priority(pops.get(ip, ""))
        performance: tuple[object, ...] = (
            0 if result.ok else 1,
            result.ttfb_ms if result.ttfb_ms >= 0.0 else float("inf"),
            result.tcp_ms if result.tcp_ms >= 0.0 else float("inf"),
            -result.complete_mbps if result.ok else 0.0,
        )
        # Asian POP is a same-performance preference, never a reason to keep a
        # much slower address ahead of a stable high-throughput candidate.
        return (*performance, -pop, ip) if asia_hunt else (*performance, ip)

    return sorted(ips, key=key)


def _select_speed_candidates(
    ranked: list[str],
    limit: int,
    maximum: bool = False,
    preferred: Iterable[str] = (),
) -> list[str]:
    """Choose the real-download shortlist without making it latency-only.

    Normal target modes retain strict latency order for fast early stopping.
    Maximum-bandwidth mode keeps most of the fastest addresses and reserves a
    small, evenly spaced tail for different /24 or /48 paths that a pure RTT
    top-N would otherwise discard.
    """
    bounded = max(0, int(limit))
    if bounded <= 0 or not ranked:
        return []
    preferred_set = set(preferred)
    if not maximum or len(ranked) <= bounded:
        selected = ranked[:bounded]
    else:
        reserve = min(max(2, bounded // 5), bounded - 1)
        primary_count = bounded - reserve
        selected = list(ranked[:primary_count])
        selected_set = set(selected)
        prefixes = {prefix_of(ip) for ip in selected}
        tail = ranked[primary_count:]

        # Pick one address from each evenly spaced latency band where possible.
        for band in range(reserve):
            start = len(tail) * band // reserve
            end = max(start + 1, len(tail) * (band + 1) // reserve)
            bucket = tail[start:end]
            chosen = next((ip for ip in bucket if prefix_of(ip) not in prefixes), None)
            chosen = chosen or next((ip for ip in bucket if ip not in selected_set), None)
            if chosen is None:
                continue
            selected.append(chosen)
            selected_set.add(chosen)
            prefixes.add(prefix_of(chosen))

        if len(selected) < bounded:
            selected.extend(ip for ip in ranked if ip not in selected_set)
        selected = selected[:bounded]

    selected_set = set(selected)
    for ip in (item for item in ranked if item in preferred_set and item not in selected_set):
        replace_at = next(
            (index for index in range(len(selected) - 1, -1, -1) if selected[index] not in preferred_set),
            None,
        )
        if replace_at is None:
            break
        selected_set.remove(selected[replace_at])
        selected[replace_at] = ip
        selected_set.add(ip)
    order = {ip: index for index, ip in enumerate(ranked)}
    return sorted(selected, key=order.__getitem__)


def _run_full_rounds(
    ips: list[str],
    params: ModeParams,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    probe_fn: ProbeFunction,
    family: str,
) -> dict[str, list[ProbeResult]]:
    schedule = full_schedule(ips, params.full_rounds)
    output = {ip: [] for ip in ips}
    stage = f"完整复核 {family}"
    on_stage(stage, 0, len(schedule), "")
    if not schedule:
        return output
    with ThreadPoolExecutor(max_workers=max(1, params.full_concurrency), thread_name_prefix="rr-full") as pool:
        futures = {
            pool.submit(probe_fn, ip, params.full_bytes, 20, True, cancel_event): ip
            for ip in schedule
        }
        completed = 0
        for future in as_completed(futures):
            _cancelled(cancel_event)
            ip = futures[future]
            try:
                output[ip].append(future.result())
            except Exception as exc:
                output[ip].append(ProbeResult(ok=False, error=f"{type(exc).__name__}: {exc}", target_ip=ip))
            completed += 1
            on_stage(stage, completed, len(schedule), ip)
    return output


def _run_fast_speed_stage(
    ips: list[str],
    params: ModeParams,
    target_mbps: int,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    log: LogCallback,
    speed_probe_fn: SpeedProbeFunction,
    family: str,
    candidate_gate: CandidateGateFunction | None = None,
    gate_passed: set[str] | None = None,
    gate_rejected: set[str] | None = None,
    confirmed_output: set[str] | None = None,
) -> dict[str, list[ProbeResult]]:
    """Run one-second samples sequentially and stop once a result is confirmed."""
    output: dict[str, list[ProbeResult]] = {}
    confirmed: set[str] = set()
    completed = 0
    maximum = not params.early_stop
    # This is a hard upper bound: no address is sampled more than twice.
    total = len(ips) * 2
    stage = f"1 秒吞吐测速 {family}"
    on_stage(stage, 0, total, "全部测速" if maximum else f"达到 {target_mbps} Mbps 后复测并早停")

    def accepted(ip: str) -> bool:
        if candidate_gate is None:
            return True
        if gate_passed is not None and ip in gate_passed:
            return True
        if gate_rejected is not None and ip in gate_rejected:
            return False
        try:
            allowed = bool(candidate_gate(ip))
        except Exception:
            allowed = False
        if allowed:
            if gate_passed is not None:
                gate_passed.add(ip)
        elif gate_rejected is not None:
            gate_rejected.add(ip)
        return allowed

    def once(ip: str) -> ProbeResult:
        nonlocal completed
        _cancelled(cancel_event)
        try:
            result = speed_probe_fn(ip, target_mbps, 1.0, 5, cancel_event)
        except Exception as exc:
            result = ProbeResult(ok=False, error=f"{type(exc).__name__}: {exc}", target_ip=ip)
        completed += 1
        on_stage(stage, completed, total, ip)
        return result

    early_winner = ""
    tested: list[str] = []
    for ip in ips:
        first = once(ip)
        output[ip] = [first]
        tested.append(ip)
        if params.early_stop and first.ok and first.complete_mbps >= target_mbps:
            second = once(ip)
            output[ip].append(second)
            if second.ok and accepted(ip):
                confirmed.add(ip)
            if ip in confirmed and min(first.complete_mbps, second.complete_mbps) >= target_mbps:
                early_winner = ip
                log(f"{family} {ip} 两次 1 秒实测均达到 {target_mbps} Mbps，提前结束")
                break

    if not early_winner:
        ranked_first = sorted(
            (ip for ip in tested if output[ip][0].ok),
            key=lambda ip: (
                -output[ip][0].complete_mbps,
                -output[ip][0].payload_mbps,
                output[ip][0].ttfb_ms if output[ip][0].ttfb_ms >= 0 else float("inf"),
                ip,
            ),
        )
        needed = max(0, params.final_candidates - len(confirmed))
        for ip in ranked_first:
            if needed <= 0:
                break
            if ip in confirmed:
                continue
            # An address that already failed its one allowed confirmation is
            # not silently rehabilitated by a third try; move to the next one.
            if len(output[ip]) >= 2:
                continue
            second = once(ip)
            output[ip].append(second)
            if second.ok and accepted(ip):
                confirmed.add(ip)
                needed -= 1

    if confirmed_output is not None:
        confirmed_output.update(confirmed)
    return output


def _metric(
    ip: str,
    family: str,
    full_results: list[ProbeResult],
    micro: ProbeResult | None,
    discovery_pops: dict[str, str],
    discovery_locs: dict[str, str],
    source_tags: list[str],
) -> IpMetric:
    speeds = [item.complete_mbps if item.ok else 0.0 for item in full_results]
    payloads = [item.payload_mbps if item.ok else 0.0 for item in full_results]
    successes = sum(1 for item in full_results if item.ok)
    chosen = next((item for item in reversed(full_results) if item.ok), None) or micro
    pop = (chosen.colo if chosen and chosen.colo else discovery_pops.get(ip, "")).upper()
    loc = (chosen.loc if chosen and chosen.loc else discovery_locs.get(ip, "")).upper()
    metric = IpMetric(
        ip=ip,
        family=family,
        min_complete_mbps=min(speeds) if speeds else 0.0,
        avg_complete_mbps=statistics.fmean(speeds) if speeds else 0.0,
        max_complete_mbps=max(speeds) if speeds else 0.0,
        min_payload_mbps=min(payloads) if payloads else 0.0,
        avg_payload_mbps=statistics.fmean(payloads) if payloads else 0.0,
        success_rate_pct=success_rate(successes, len(full_results)),
        variation_pct=variation(speeds),
        median_ttfb_ms=median_ttfb([item.ttfb_ms for item in full_results]),
        round_floor_mbps=address_floor(speeds, len(full_results) - successes),
        rounds_tested=len(full_results),
        source_tags=source_tags,
        pop=pop,
        loc=loc,
        edge_score=pop_priority(pop),
        pop_drift=bool(discovery_pops.get(ip) and pop and discovery_pops[ip].upper() != pop),
    )
    metric.stability = stability_label(metric.variation_pct, metric.success_rate_pct)
    return metric


def run_family(
    snapshot: Snapshot,
    params: ModeParams,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    log: LogCallback,
    network_changed: Callable[[], bool] | None = None,
    probe_fn: ProbeFunction = probe_download,
    trace_fn: TraceFunction = probe_trace,
    target_mbps: int = 100,
    speed_probe_fn: SpeedProbeFunction | None = None,
    rtt_probe_fn: RttProbeFunction | None = None,
    candidate_gate: CandidateGateFunction | None = None,
) -> FamilyRunResult:
    started = time.perf_counter()
    if not snapshot.ips:
        return FamilyRunResult(snapshot.family, [], [], elapsed_seconds=time.perf_counter() - started)
    guard = network_changed or (lambda: False)

    def check() -> None:
        _cancelled(cancel_event)
        if guard():
            raise NetworkChanged("测试期间网络出口发生变化")

    check()
    if rtt_probe_fn is not None:
        pre_cache = _run_parallel_rtt_rounds(
            snapshot.ips,
            3,
            1.0,
            params.pre_concurrency,
            f"3 轮 TCP RTT 快筛 {snapshot.family}",
            cancel_event,
            on_stage,
            rtt_probe_fn,
        )
    else:
        # Test/embedding compatibility for callers that inject the historical
        # HTTP probe but do not yet provide a TCP RTT function.
        pre_cache = _run_parallel_probes(
            snapshot.ips,
            params.pre_bytes,
            3,
            params.pre_concurrency,
            f"并发连通快筛 {snapshot.family}",
            cancel_event,
            on_stage,
            probe_fn,
            include_trace=False,
        )
    pre_ranked = [
        ip for ip in _pre_rank(snapshot.ips, pre_cache, {}, False)
        if pre_cache.get(ip, ProbeResult(False)).ok
    ]
    preferred = {
        ip
        for tag, values in snapshot.sources.items()
        if "DNS" in tag or "我的 IP" in tag or "我的名单" in tag
        for ip in values
    }
    speed_ips = _select_speed_candidates(
        pre_ranked,
        params.micro_candidates,
        maximum=not params.early_stop,
        preferred=preferred,
    )
    log(
        f"{snapshot.family} 快筛完成：{len(pre_ranked)}/{len(snapshot.ips)} IP 可用；"
        f"按 TTFB/TCP 取前 {len(speed_ips)} 个做 1 秒吞吐"
    )
    if not speed_ips:
        return FamilyRunResult(
            snapshot.family,
            [],
            [],
            elapsed_seconds=time.perf_counter() - started,
            candidate_count=len(snapshot.ips),
            compatible_count=len(snapshot.ips),
        )

    if speed_probe_fn is None:
        def speed_worker(
            ip: str,
            expected: int,
            _window: float,
            timeout: int,
            cancel: threading.Event,
        ) -> ProbeResult:
            return probe_fn(
                ip,
                speed_request_bytes(expected, maximum=not params.early_stop),
                timeout,
                True,
                cancel,
            )
    else:
        speed_worker = speed_probe_fn

    check()
    gate_passed: set[str] = set()
    gate_rejected: set[str] = set()
    confirmed_ips: set[str] = set()
    full = _run_fast_speed_stage(
        speed_ips,
        params,
        target_mbps,
        cancel_event,
        on_stage,
        log,
        speed_worker,
        snapshot.family,
        candidate_gate=candidate_gate,
        gate_passed=gate_passed,
        gate_rejected=gate_rejected,
        confirmed_output=confirmed_ips,
    )
    # Do not publish a ranking measured across a changed client network.
    check()
    pops: dict[str, str] = {}
    locs: dict[str, str] = {}
    for ip, samples in full.items():
        chosen = next((item for item in reversed(samples) if item.ok), None)
        if chosen is not None:
            pops[ip] = chosen.colo
            locs[ip] = chosen.loc

    metric_ips = [
        ip
        for ip in full
        if ip in confirmed_ips
        if (candidate_gate is None or ip in gate_passed)
    ]
    metrics = [
        _metric(
            ip,
            snapshot.family,
            full.get(ip, []),
            pre_cache.get(ip),
            pops,
            locs,
            [tag for tag, values in snapshot.sources.items() if ip in values],
        )
        for ip in metric_ips
    ]
    ranked = rank(metrics) if params.early_stop else rank_maximum(metrics)
    asia_ranked = rank_asia(metrics) if params.asia_hunt else ranked
    actual_bytes = sum(item.bytes_downloaded for item in pre_cache.values())
    actual_bytes += sum(item.bytes_downloaded for samples in full.values() for item in samples)
    actual_mb = actual_bytes / 1_000_000.0
    log(f"{snapshot.family} 测速完成：实测 {len(metrics)} 个 IP；实际下载约 {actual_mb:.1f} MB")
    return FamilyRunResult(
        family=snapshot.family,
        ranked=ranked,
        asia_ranked=asia_ranked,
        discovery=None,
        estimated_traffic_mb=actual_mb,
        elapsed_seconds=time.perf_counter() - started,
        candidate_count=len(snapshot.ips),
        compatible_count=len(snapshot.ips) if candidate_gate is None else len(gate_passed),
    )


def load_ips(path: Path) -> list[str]:
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise IpSourceError("IP 列表必须是普通文件")
        if metadata.st_size > MAX_SOURCE_BYTES:
            raise IpSourceError("IP 列表不能超过 1 MiB")
        with path.open("rb") as source:
            payload = source.read(MAX_SOURCE_BYTES + 1)
        return parse_ip_source(decode_ip_source_bytes(payload), path.name).ips
    except (OSError, IpSourceError) as exc:
        raise ValueError(f"无法读取 IP 列表：{exc}") from exc


def run_optimizer(
    mode: str = "balanced",
    family: str = "dual",
    operator: str = "自动",
    target_host: str = SPEED_HOST,
    ips_path: Path | None = None,
    ips: Iterable[str] | None = None,
    source_kind: str = "当前 DNS",
    cancel_event: threading.Event | None = None,
    on_stage: StageCallback | None = None,
    log: LogCallback | None = None,
    resolver: ResolveFunction = resolve_target_ips,
    resolved_ips: Iterable[str] | None = None,
    probe_fn: ProbeFunction | None = None,
    trace_fn: TraceFunction | None = None,
    purpose: str = PURPOSE_DIRECT,
    node_port: int = 443,
    ws_path: str = "",
    target_mbps: int = 100,
    compatibility_fn: CompatibilityFunction | None = None,
    speed_probe_fn: SpeedProbeFunction | None = None,
    candidate_seed: object | None = None,
    rtt_probe_fn: RttProbeFunction | None = None,
    use_tls: bool = True,
) -> OptimizerResult:
    if mode not in MODES:
        raise ValueError(f"未知模式：{mode}")
    if family not in {"ipv4", "ipv6", "dual"}:
        raise ValueError(f"未知协议族：{family}")
    if purpose not in {PURPOSE_DIRECT, PURPOSE_ARGO, PURPOSE_DNS}:
        raise ValueError(f"未知用途：{purpose}")
    if purpose == PURPOSE_ARGO:
        if isinstance(node_port, bool) or node_port not in SUPPORTED_TLS_PORTS:
            raise ValueError("节点端口仅支持 Cloudflare HTTPS 端口：443、2053、2083、2087、2096、8443")
    else:
        node_port = 443
    if isinstance(target_mbps, bool) or not isinstance(target_mbps, int) or not MIN_TARGET_MBPS <= target_mbps <= MAX_TARGET_MBPS:
        raise ValueError(f"目标带宽必须在 {MIN_TARGET_MBPS}–{MAX_TARGET_MBPS} Mbps 之间")
    target = SPEED_HOST if purpose == PURPOSE_DIRECT else _normalize_target_host(target_host)
    normalized_ws_path = normalize_ws_path(ws_path) if purpose == PURPOSE_ARGO else ""
    cancel = cancel_event or threading.Event()
    stage_callback = on_stage or (lambda _name, _current, _total, _detail: None)
    logger = log or (lambda _message: None)
    supplied = load_ips(ips_path) if ips_path is not None else ips
    run_seed = candidate_seed if candidate_seed is not None else f"{time.time_ns()}:{threading.get_ident()}"
    if mode == "reference" and purpose != PURPOSE_DNS:
        from .reference_engine import run_reference_optimizer

        worker_compatibility = compatibility_fn or functools.partial(
            probe_argo_compatibility,
            hostname=target,
            ws_path=normalized_ws_path,
            port=node_port,
        )
        result = run_reference_optimizer(
            family=family,
            operator=operator,
            target_host=target,
            custom_ips=list(supplied or ()),
            source_kind=source_kind,
            cancel_event=cancel,
            on_stage=stage_callback,
            log=logger,
            purpose=purpose,
            node_port=node_port,
            ws_path=normalized_ws_path,
            target_mbps=target_mbps,
            use_tls=bool(use_tls),
            compatibility_fn=worker_compatibility,
            network_fingerprint_fn=network_fingerprint,
            seed=run_seed,
        )
        result.network_fingerprints = {
            family_name: network_fingerprint_token(value)
            for family_name, value in result.network_fingerprints.items()
        }
        return result
    current_ips = list(resolved_ips) if resolved_ips is not None else resolver(target)
    if purpose == PURPOSE_ARGO:
        candidates, rejected_count, actual_source, candidate_sources = _build_argo_candidates(
            supplied, current_ips, logger, run_seed
        )
    elif purpose == PURPOSE_DIRECT:
        candidates, rejected_count, actual_source, candidate_sources = _build_direct_candidates(
            supplied, current_ips, logger, run_seed
        )
    else:
        candidates, rejected_count, verified_source = _filter_candidates(supplied, current_ips, logger)
        actual_source = source_kind if supplied is not None else verified_source
        if supplied is not None:
            actual_source = f"{source_kind}（与当前 DNS 交集）"
        candidate_sources = {actual_source: candidates}
    params = MODES[mode]
    requested = ["IPv4", "IPv6"] if family == "dual" else ["IPv6" if family == "ipv6" else "IPv4"]
    started = time.perf_counter()
    initial_fingerprint = network_fingerprint()
    measurement_host = SPEED_HOST if purpose in {PURPOSE_DIRECT, PURPOSE_ARGO} else target
    # Comparable throughput and POP discovery always use Cloudflare's public
    # speed endpoint on 443.  In advanced Argo mode the user's node port is
    # used only by the separate SNI/Host/certificate compatibility gate.
    measurement_port = 443
    worker_probe = probe_fn or functools.partial(
        probe_download, hostname=measurement_host, port=measurement_port
    )
    worker_trace = trace_fn or functools.partial(
        probe_trace, hostname=measurement_host, port=measurement_port
    )
    worker_speed = speed_probe_fn
    worker_rtt = rtt_probe_fn
    if worker_rtt is None and probe_fn is None:
        worker_rtt = functools.partial(probe_tcp_rtt, port=measurement_port)
    if worker_speed is None and probe_fn is None:
        worker_speed = functools.partial(
            probe_speed_window,
            hostname=measurement_host,
            port=measurement_port,
            maximum=not params.early_stop,
        )
    worker_compatibility = compatibility_fn or functools.partial(
        probe_argo_compatibility,
        hostname=target,
        ws_path=normalized_ws_path,
        port=node_port,
    )
    family_results: list[FamilyRunResult] = []
    cancelled = False
    try:
        for family_name in requested:
            _cancelled(cancel)
            snapshot = build_snapshot(candidates, family_name, cancel, stage_callback, logger, actual_source, candidate_sources)
            if not snapshot.ips:
                logger(f"{family_name} 没有可用候选地址，已跳过")
                continue
            original_candidate_count = len(snapshot.ips)
            logger(f"{family_name} 安全预计流量上限 ≈ {estimate_traffic_upper_bound_mb(snapshot, params, target_mbps):.1f} MB")

            def changed() -> bool:
                current = network_fingerprint()
                before = initial_fingerprint[1 if family_name == "IPv6" else 0]
                after = current[1 if family_name == "IPv6" else 0]
                return bool(before and after and before != after)

            try:
                compatibility_cache: dict[str, bool] = {}

                def candidate_gate(ip: str) -> bool:
                    if ip in compatibility_cache:
                        return compatibility_cache[ip]
                    stage = f"Argo SNI/Host 兼容验证 {family_name}"
                    stage_callback(stage, len(compatibility_cache), params.micro_candidates, ip)
                    try:
                        result = worker_compatibility(ip, 7, cancel)
                    except Exception as exc:
                        result = ProbeResult(ok=False, error=f"{type(exc).__name__}: {exc}", target_ip=ip)
                    allowed = bool(result.ok and result.cert_verified and result.target_matches_remote)
                    compatibility_cache[ip] = allowed
                    stage_callback(stage, len(compatibility_cache), params.micro_candidates, ip)
                    return allowed

                family_result = run_family(
                    snapshot,
                    params,
                    cancel,
                    stage_callback,
                    logger,
                    network_changed=changed,
                    probe_fn=worker_probe,
                    trace_fn=worker_trace,
                    target_mbps=target_mbps,
                    speed_probe_fn=worker_speed,
                    rtt_probe_fn=worker_rtt,
                    candidate_gate=candidate_gate if purpose == PURPOSE_ARGO else None,
                )
                family_result.candidate_count = original_candidate_count
                if purpose == PURPOSE_ARGO:
                    passed = sum(1 for allowed in compatibility_cache.values() if allowed)
                    failed = len(compatibility_cache) - passed
                    rejected_count += failed
                    family_result.compatible_count = passed
                    logger(
                        f"{family_name} Argo 延后兼容验证：{passed}/{len(compatibility_cache)} 个复核候选通过"
                    )
                    if not passed:
                        logger(f"{family_name} 入围地址均未通过 Argo 域名兼容验证")
                else:
                    family_result.compatible_count = len(snapshot.ips)
                family_results.append(family_result)
            except NetworkChanged:
                logger("!! 网络出口已变化，本轮结果作废")
                family_results.append(FamilyRunResult(family_name, [], [], invalid=True))
                break
    except OptimizerCancelled:
        cancelled = True
        logger("优选已停止")
    return OptimizerResult(
        created_at=dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        mode=mode,
        operator=operator,
        requested_family=family,
        ip_count=len(candidates),
        target_host=target,
        source_kind=actual_source,
        families=family_results,
        elapsed_seconds=time.perf_counter() - started,
        cancelled=cancelled,
        rejected_ip_count=rejected_count,
        purpose=purpose,
        target_mbps=target_mbps,
        node_port=node_port,
        ws_path=normalized_ws_path,
        measurement_host=measurement_host,
        measurement_port=measurement_port,
        network_fingerprints={
            "IPv4": network_fingerprint_token(initial_fingerprint[0]),
            "IPv6": network_fingerprint_token(initial_fingerprint[1]),
        },
    )


__all__ = [
    "ASIA_HUNT",
    "BALANCED",
    "MAX_CANDIDATES_PER_FAMILY",
    "MAX_TARGET_MBPS",
    "MIN_TARGET_MBPS",
    "PURPOSE_ARGO",
    "PURPOSE_DIRECT",
    "PURPOSE_DNS",
    "build_snapshot",
    "estimate_traffic_upper_bound_mb",
    "full_schedule",
    "load_ips",
    "network_fingerprint",
    "network_fingerprint_token",
    "normalize_ws_path",
    "resolve_target_ips",
    "run_family",
    "run_optimizer",
    "validate_argo_snapshot",
]
