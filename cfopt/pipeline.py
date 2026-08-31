from __future__ import annotations

import datetime as dt
import functools
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
from .probe import probe_download, probe_trace
from .ranges import family_of, is_cloudflare_ip, normalized_ip, prefix_of
from .ranking import address_floor, median_ttfb, rank, rank_asia, stability_label, success_rate, variation


StageCallback = Callable[[str, int, int, str], None]
LogCallback = Callable[[str], None]
ProbeFunction = Callable[..., ProbeResult]
TraceFunction = Callable[..., tuple[str, str]]
ResolveFunction = Callable[[str], list[str]]

ASIA_POP_ORDER = ("HKG", "NRT", "SIN", "ICN", "TPE")
POP_PRIORITY = {"HKG": 5, "NRT": 4, "SIN": 3, "ICN": 2, "TPE": 1}
MAX_CANDIDATES_PER_FAMILY = 128


class OptimizerCancelled(RuntimeError):
    pass


class NetworkChanged(RuntimeError):
    pass


def pop_priority(pop: str) -> int:
    return POP_PRIORITY.get(pop.upper(), 0)


def _normalize_target_host(value: object) -> str:
    try:
        return normalize_hostname(value)
    except HostnameError as exc:
        raise ValueError(f"测试主机无效：{exc}") from exc


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


def build_snapshot(
    ips: Iterable[str],
    family: str,
    cancel_event: threading.Event,
    on_stage: StageCallback,
    log: LogCallback,
    source_tag: str = "当前 DNS",
) -> Snapshot:
    normalized: list[str] = []
    seen: set[str] = set()
    original = list(ips)
    on_stage(f"候选校验 {family}", 0, len(original), "校验 Cloudflare 地址与协议族")
    for index, raw in enumerate(original, 1):
        _cancelled(cancel_event)
        try:
            value = normalized_ip(raw)
        except ValueError:
            on_stage(f"候选校验 {family}", index, len(original), str(raw))
            continue
        if value not in seen and family_of(value) == family and is_cloudflare_ip(value):
            seen.add(value)
            normalized.append(value)
        on_stage(f"候选校验 {family}", index, len(original), value)
    if len(normalized) > MAX_CANDIDATES_PER_FAMILY:
        log(f"{family} 已验证候选 {len(normalized)} 个；为控制本轮真实下载与亚洲 POP 探测，按 DNS 顺序保留前 {MAX_CANDIDATES_PER_FAMILY} 个")
        normalized = normalized[:MAX_CANDIDATES_PER_FAMILY]
    snapshot = Snapshot(family, normalized, {source_tag: normalized})
    log(f"候选快照({family})：已验证地址 {len(snapshot.ips)}")
    return snapshot


def full_schedule(ips: list[str], full_rounds: int) -> list[str]:
    return [ip for ip in ips for _ in range(max(1, full_rounds))]


def estimate_traffic_upper_bound_mb(snapshot: Snapshot, params: ModeParams) -> float:
    pre = len(snapshot.ips) * params.pre_bytes
    micro = min(len(snapshot.ips), params.micro_candidates) * params.micro_bytes
    full = min(len(snapshot.ips), params.final_candidates) * params.full_rounds * params.full_bytes
    return (pre + micro + full) / 1_000_000.0


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
        tail: tuple[object, ...] = (
            0 if result.ok else 1,
            -result.complete_mbps if result.ok else 0.0,
            result.ttfb_ms if result.ttfb_ms >= 0.0 else float("inf"),
            ip,
        )
        return (-pop, *tail) if asia_hunt else tail

    return sorted(ips, key=key)


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
) -> FamilyRunResult:
    started = time.perf_counter()
    if not snapshot.ips:
        return FamilyRunResult(snapshot.family, [], [], elapsed_seconds=time.perf_counter() - started)
    guard = network_changed or (lambda: False)

    def check() -> None:
        _cancelled(cancel_event)
        if guard():
            raise NetworkChanged("测试期间网络出口发生变化")

    discovery: PopDiscovery | None = None
    pops: dict[str, str] = {}
    locs: dict[str, str] = {}
    if params.asia_hunt:
        check()
        discovery = _discover_pops(snapshot, cancel_event, on_stage, log, trace_fn)
        pops, locs = discovery.ip_to_pop, discovery.ip_to_loc

    check()
    pre_cache = _run_parallel_probes(snapshot.ips, params.pre_bytes, 8, params.pre_concurrency, f"初筛 {snapshot.family}", cancel_event, on_stage, probe_fn)
    for ip, result in pre_cache.items():
        result.colo = result.colo or pops.get(ip, "")
        result.loc = result.loc or locs.get(ip, "")
    pre_ranked = _pre_rank(snapshot.ips, pre_cache, pops, params.asia_hunt)
    micro_ips = pre_ranked[: params.micro_candidates]
    log(f"{snapshot.family} 初筛完成：{sum(1 for item in pre_cache.values() if item.ok)}/{len(snapshot.ips)} IP 可用；进入小流量复核 {len(micro_ips)} 个")

    check()
    micro_cache = _run_parallel_probes(micro_ips, params.micro_bytes, 12, params.micro_concurrency, f"小流量复核 {snapshot.family}", cancel_event, on_stage, probe_fn)
    for ip, result in micro_cache.items():
        result.colo = result.colo or pops.get(ip, "")
        result.loc = result.loc or locs.get(ip, "")
    final_ranked = _pre_rank(micro_ips, micro_cache, pops, params.asia_hunt)[: params.final_candidates]
    log(f"{snapshot.family} 小流量复核完成：进入完整复核 {len(final_ranked)} 个")

    check()
    full = _run_full_rounds(final_ranked, params, cancel_event, on_stage, probe_fn, snapshot.family)
    metrics = [
        _metric(ip, snapshot.family, full.get(ip, []), micro_cache.get(ip), pops, locs, list(snapshot.sources))
        for ip in final_ranked
    ]
    ranked = rank(metrics)
    asia_ranked = rank_asia(metrics) if params.asia_hunt else ranked
    estimated = (
        len(snapshot.ips) * params.pre_bytes
        + len(micro_ips) * params.micro_bytes
        + len(final_ranked) * params.full_rounds * params.full_bytes
    ) / 1_000_000.0
    log(f"{snapshot.family} 完整复核完成：{len(metrics)} 个 IP；实际计划流量约 {estimated:.1f} MB")
    return FamilyRunResult(
        family=snapshot.family,
        ranked=ranked,
        asia_ranked=asia_ranked,
        discovery=discovery,
        estimated_traffic_mb=estimated,
        elapsed_seconds=time.perf_counter() - started,
        candidate_count=len(snapshot.ips),
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
) -> OptimizerResult:
    if mode not in MODES:
        raise ValueError(f"未知模式：{mode}")
    if family not in {"ipv4", "ipv6", "dual"}:
        raise ValueError(f"未知协议族：{family}")
    target = _normalize_target_host(target_host)
    cancel = cancel_event or threading.Event()
    stage_callback = on_stage or (lambda _name, _current, _total, _detail: None)
    logger = log or (lambda _message: None)
    supplied = load_ips(ips_path) if ips_path is not None else ips
    current_ips = list(resolved_ips) if resolved_ips is not None else resolver(target)
    candidates, rejected_count, verified_source = _filter_candidates(supplied, current_ips, logger)
    actual_source = source_kind if supplied is not None else verified_source
    if supplied is not None:
        actual_source = f"{source_kind}（与当前 DNS 交集）"
    params = MODES[mode]
    requested = ["IPv4", "IPv6"] if family == "dual" else ["IPv6" if family == "ipv6" else "IPv4"]
    started = time.perf_counter()
    initial_fingerprint = network_fingerprint()
    worker_probe = probe_fn or functools.partial(probe_download, hostname=target)
    worker_trace = trace_fn or functools.partial(probe_trace, hostname=target)
    family_results: list[FamilyRunResult] = []
    cancelled = False
    try:
        for family_name in requested:
            _cancelled(cancel)
            snapshot = build_snapshot(candidates, family_name, cancel, stage_callback, logger, actual_source)
            if not snapshot.ips:
                logger(f"{family_name} 没有当前 DNS 分配的候选地址，已跳过")
                continue
            logger(f"{family_name} 安全预计流量上限 ≈ {estimate_traffic_upper_bound_mb(snapshot, params):.1f} MB")

            def changed() -> bool:
                current = network_fingerprint()
                before = initial_fingerprint[1 if family_name == "IPv6" else 0]
                after = current[1 if family_name == "IPv6" else 0]
                return bool(before and after and before != after)

            try:
                family_results.append(run_family(snapshot, params, cancel, stage_callback, logger, changed, worker_probe, worker_trace))
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
    )


__all__ = [
    "ASIA_HUNT",
    "BALANCED",
    "MAX_CANDIDATES_PER_FAMILY",
    "build_snapshot",
    "estimate_traffic_upper_bound_mb",
    "full_schedule",
    "load_ips",
    "network_fingerprint",
    "resolve_target_ips",
    "run_family",
    "run_optimizer",
]
