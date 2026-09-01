from __future__ import annotations

import datetime as dt
import csv
import functools
import io
import ipaddress
import json
import secrets
import socket
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .cloudflare_dns import (
    CloudflareDnsClient,
    CloudflareDnsError,
    DnsSyncPlan,
    DnsSyncResult,
    normalize_champion_ip,
    normalize_record_name,
    normalize_zone_id,
)
from .history import load_history, save_history
from .ip_sources import IpSourceError, MAX_IPS, MAX_SOURCE_BYTES, fetch_ip_subscription, normalize_ip_values, parse_ip_source
from .models import MODES, OptimizerResult, SPEED_HOST
from .node_template import NodeProfile, parse_node_profile
from .pipeline import (
    MAX_CANDIDATES_PER_FAMILY,
    MAX_TARGET_MBPS,
    MIN_TARGET_MBPS,
    PURPOSE_ARGO,
    PURPOSE_DIRECT,
    PURPOSE_DNS,
    SUPPORTED_TLS_PORTS,
    network_fingerprint,
    network_fingerprint_token,
    normalize_ws_path,
    run_optimizer,
)
from .hostnames import HostnameError, normalize_hostname
from .resources import package_root
from .version import VERSION
from .xray_node import XrayNodeError, validate_xray_runtime, verify_node_candidate


WEB_DIR = package_root() / "web"
MAX_REQUEST_BYTES = MAX_SOURCE_BYTES + 64 * 1024
MIN_AUTOMATION_INTERVAL_MINUTES = 5
MAX_AUTOMATION_INTERVAL_MINUTES = 1_440
DNS_PLAN_TTL_SECONDS = 300
MAX_PENDING_DNS_PLANS = 8
_DNS_AUTOMATION_GLOBAL_STOP_CODES = frozenset({
    "auth_failed",
    "rate_limited",
    "timeout",
    "network",
    "transport",
    "server_error",
    "response_too_large",
    "protocol",
    "api_rejected",
    "verification_failed",
})


def _result_champions(result: OptimizerResult) -> dict[str, str]:
    if result.cancelled:
        return {}
    champions: dict[str, str] = {}
    for family in result.families:
        if family.invalid:
            continue
        rows = family.asia_ranked if result.mode == "asia" else family.ranked
        if not rows:
            continue
        champion = rows[0]
        required_rounds = MODES.get(result.mode, MODES["balanced"]).full_rounds
        if (
            champion.rounds_tested >= required_rounds
            and champion.round_floor_mbps > 0
            and champion.success_rate_pct >= 66.0
        ):
            champions[family.family] = champion.ip
    return champions


def _network_matches_result(result: OptimizerResult, family: str) -> bool:
    expected = str(result.network_fingerprints.get(family, ""))
    if not expected:
        return False
    current = network_fingerprint()
    address = current[1 if family == "IPv6" else 0]
    return bool(address and secrets.compare_digest(expected, network_fingerprint_token(address)))


def _normalize_dns_sync_config(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or value.get("enabled") is not True:
        raise IpSourceError("Cloudflare DNS 自动同步配置无效")
    token = str(value.get("api_token", ""))
    if not token or token != token.strip() or len(token) > 4_096 or "\r" in token or "\n" in token:
        raise IpSourceError("Cloudflare API Token 无效")
    try:
        zone_id = normalize_zone_id(value.get("zone_id"))
        record_name = normalize_record_name(value.get("record_name"))
    except CloudflareDnsError as exc:
        raise IpSourceError(str(exc)) from exc
    return {"api_token": token, "zone_id": zone_id, "record_name": record_name}


def _inspect_dns_sync(config: dict[str, Any], champion_ip: str) -> DnsSyncPlan:
    client = CloudflareDnsClient(str(config.get("api_token", "")))
    return client.inspect_sync(
        zone_id=str(config.get("zone_id", "")),
        record_name=str(config.get("record_name", "")),
        champion_ip=champion_ip,
    )


def _apply_dns_plan(config: dict[str, Any], champion_ip: str, fingerprint: str) -> DnsSyncResult:
    client = CloudflareDnsClient(str(config.get("api_token", "")))
    return client.apply_sync(
        zone_id=str(config.get("zone_id", "")),
        record_name=str(config.get("record_name", "")),
        champion_ip=champion_ip,
        expected_fingerprint=fingerprint,
        confirm_create=True,
    )


def _apply_dns_sync(config: dict[str, Any], champion_ip: str) -> DnsSyncResult:
    plan = _inspect_dns_sync(config, champion_ip)
    if plan.action == "create":
        raise CloudflareDnsError(
            "定时 DNS 同步不会静默创建新记录；请先用手动同步查看预览并确认创建",
            code="automatic_create_forbidden",
        )
    return _apply_dns_plan(config, plan.champion_ip, plan.fingerprint)


@dataclass
class RuntimeState:
    lock: threading.RLock = field(default_factory=threading.RLock)
    status: str = "idle"
    stage: str = "等待开始"
    current: int = 0
    total: int = 0
    detail: str = ""
    logs: list[str] = field(default_factory=list)
    result: OptimizerResult | None = None
    error: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    worker: threading.Thread | None = None
    automation_enabled: bool = False
    automation_interval_minutes: int = 30
    automation_next_run_at: float | None = None
    automation_runs_started: int = 0
    automation_config: dict[str, Any] | None = None
    automation_stop_event: threading.Event = field(default_factory=threading.Event)
    automation_worker: threading.Thread | None = None
    automation_generation: int = 0
    automation_stop_in_progress: bool = False
    dns_automation_paused: bool = False
    dns_write_lock: threading.Lock = field(default_factory=threading.Lock)
    dns_write_in_progress: bool = False
    dns_manual_plans: dict[str, dict[str, Any]] = field(default_factory=dict)

    @staticmethod
    def _public_config(config: dict[str, Any]) -> dict[str, Any]:
        visible = {
            "mode", "family", "operator", "target_host", "source", "source_ip_count",
            "automation_enabled", "automation_interval_minutes", "traffic_upper_bound_mb",
            "purpose", "node_port", "ws_path",
            "target_mbps", "use_tls", "node_protocol",
        }
        return {key: value for key, value in config.items() if key in visible}

    @staticmethod
    def _format_timestamp(value: float | None) -> str | None:
        if value is None:
            return None
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).astimezone().isoformat(timespec="seconds")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "status": self.status,
                "stage": self.stage,
                "current": self.current,
                "total": self.total,
                "detail": self.detail,
                "logs": self.logs[-220:],
                "result": self.result.to_dict() if self.result else None,
                "error": self.error,
                "config": dict(self.config),
                "automation": {
                    "enabled": self.automation_enabled,
                    "interval_minutes": self.automation_interval_minutes if self.automation_enabled else None,
                    "next_run_at": self._format_timestamp(self.automation_next_run_at),
                    "runs_started": self.automation_runs_started,
                    "dns_sync_enabled": bool(self.automation_enabled and self.automation_config and self.automation_config.get("_dns_sync")),
                    "dns_sync_paused": self.dns_automation_paused,
                },
            }

    def on_stage(self, name: str, current: int, total: int, detail: str) -> None:
        with self.lock:
            self.stage = name
            self.current = current
            self.total = total
            self.detail = detail

    def log(self, message: str) -> None:
        with self.lock:
            self.logs.append(message)
            if len(self.logs) > 500:
                del self.logs[:-400]

    def start(self, config: dict[str, Any], *, scheduled: bool = False) -> tuple[bool, str]:
        prepared = dict(config)
        node_profile = prepared.get("_node_profile")
        if isinstance(node_profile, NodeProfile):
            try:
                prepared["_xray_executable"] = str(
                    validate_xray_runtime(
                        prepared.get("_xray_executable"),
                        profile=node_profile,
                    )
                )
            except XrayNodeError as exc:
                return False, f"无法开始：{exc}"
        config = prepared
        with self.lock:
            if scheduled and (
                not self.automation_enabled
                or config.get("_automation_generation") != self.automation_generation
                or self.automation_config is None
            ):
                return False, "该定时任务已停止或已被新配置替代"
            if self.status in {"running", "stopping"}:
                return False, "已有任务正在运行"
            if self.dns_write_in_progress:
                return False, "Cloudflare DNS 正在同步，请稍候再开始优选"
            if self.automation_enabled and not scheduled:
                return False, "定时自动优选已启用；请先停止自动任务，再开始临时优选"
            self.status = "running"
            self.stage = "准备优选"
            self.current = 0
            self.total = 0
            self.detail = ""
            self.logs = []
            self.result = None
            self.error = ""
            self.dns_manual_plans.clear()
            self.config = self._public_config(config)
            self.cancel_event = threading.Event()
            self.worker = threading.Thread(target=self._work, args=(config,), name="rr-edge-hunter", daemon=True)
            self.worker.start()
        return True, "定时优选已开始" if scheduled else "优选已开始"

    def _work(self, config: dict[str, Any]) -> None:
        try:
            run_config = dict(config)
            subscription_url = str(run_config.get("_subscription_url", ""))
            if subscription_url and run_config.get("automation_enabled"):
                try:
                    refreshed, final_url = fetch_ip_subscription(subscription_url)
                    run_config["_ips"] = refreshed.ips
                    run_config["_subscription_url"] = final_url
                    self.log(f"定时任务已安全刷新 IP 订阅：{len(refreshed.ips)} 个地址")
                except IpSourceError as exc:
                    self.log(f"IP 订阅刷新失败，继续使用上次已载入快照：{exc}")
            node_profile = run_config.get("_node_profile")
            compatibility_fn = (
                functools.partial(
                    verify_node_candidate,
                    profile=node_profile,
                    xray_executable=run_config.get("_xray_executable"),
                )
                if isinstance(node_profile, NodeProfile)
                else None
            )
            result = run_optimizer(
                mode=str(run_config.get("mode", "reference")),
                family=str(run_config.get("family", "ipv4")),
                operator=str(run_config.get("operator", "自动")),
                target_host=str(run_config.get("target_host", SPEED_HOST)),
                ips=run_config.get("_ips"),
                source_kind=str(run_config.get("source", "当前 DNS")),
                purpose=str(run_config.get("purpose", PURPOSE_DIRECT)),
                node_port=int(run_config.get("node_port", 443)),
                ws_path=str(run_config.get("ws_path", "")),
                target_mbps=int(run_config.get("target_mbps", 100)),
                use_tls=bool(run_config.get("use_tls", True)),
                cancel_event=self.cancel_event,
                on_stage=self.on_stage,
                log=self.log,
                compatibility_fn=compatibility_fn,
            )
            if isinstance(node_profile, NodeProfile):
                result.node_sni = node_profile.route.sni
                result.node_host = node_profile.route.host_header
            with self.lock:
                self.result = result
                self.status = "cancelled" if result.cancelled else "completed"
                self.stage = "已停止" if result.cancelled else "优选完成"
                self.detail = ""
            if not result.cancelled and result.families:
                try:
                    save_history(result.to_dict())
                except OSError as exc:
                    self.log(f"历史记录保存失败：{exc}")
                dns_sync = run_config.get("_dns_sync")
                if run_config.get("automation_enabled") and isinstance(dns_sync, dict):
                    generation = run_config.get("_automation_generation")
                    if isinstance(generation, int):
                        self._sync_automatic_champions(result, dns_sync, generation=generation)
        except Exception as exc:
            with self.lock:
                self.status = "error"
                self.stage = "发生错误"
                self.error = f"{type(exc).__name__}: {exc}"
            self.log(self.error)

    def start_automation(self, config: dict[str, Any], interval_minutes: int) -> tuple[bool, str]:
        if not MIN_AUTOMATION_INTERVAL_MINUTES <= interval_minutes <= MAX_AUTOMATION_INTERVAL_MINUTES:
            return False, f"自动运行间隔必须在 {MIN_AUTOMATION_INTERVAL_MINUTES}–{MAX_AUTOMATION_INTERVAL_MINUTES} 分钟之间"
        prepared = dict(config)
        node_profile = prepared.get("_node_profile")
        if isinstance(node_profile, NodeProfile):
            try:
                prepared["_xray_executable"] = str(
                    validate_xray_runtime(
                        prepared.get("_xray_executable"),
                        profile=node_profile,
                    )
                )
            except XrayNodeError as exc:
                return False, f"无法开启定时优选：{exc}"
        config = prepared
        with self.lock:
            if self.automation_enabled:
                return False, "定时自动优选已在运行"
            if self.automation_stop_in_progress:
                return False, "正在安全停止上一项定时任务，请稍候"
            if self.status in {"running", "stopping"}:
                return False, "请等待当前优选结束后再开启定时自动优选"
            if self.dns_write_in_progress:
                return False, "Cloudflare DNS 正在同步，请稍候再开启定时自动优选"
            self.automation_generation += 1
            self.automation_enabled = True
            self.automation_interval_minutes = interval_minutes
            self.automation_next_run_at = time.time()
            self.automation_config = dict(config)
            self.dns_automation_paused = False
            self.automation_stop_event = threading.Event()
            stop_event = self.automation_stop_event
            self.automation_worker = threading.Thread(target=self._automation_loop, args=(stop_event,), name="rr-edge-hunter-scheduler", daemon=True)
            self.automation_worker.start()
        return True, f"已开启定时自动优选：每 {interval_minutes} 分钟运行一次"

    def _automatic_sync_is_current(
        self,
        result: OptimizerResult,
        dns_sync: dict[str, Any],
        generation: int,
    ) -> bool:
        return bool(
            self.automation_enabled
            and self.automation_generation == generation
            and self.status == "completed"
            and self.result is result
            and self.automation_config
            and self.automation_config.get("_dns_sync") == dns_sync
        )

    def _sync_automatic_champions(
        self,
        result: OptimizerResult,
        dns_sync: dict[str, Any],
        *,
        generation: int,
    ) -> None:
        with self.dns_write_lock:
            with self.lock:
                if not self._automatic_sync_is_current(result, dns_sync, generation):
                    self.log("定时任务已停止或结果已过期，跳过旧任务的 DNS 写入")
                    return
                if self.dns_automation_paused:
                    self.log("Cloudflare DNS 自动同步已暂停；测速定时任务继续运行")
                    return
                self.dns_write_in_progress = True
            try:
                champions = _result_champions(result)
                if not champions:
                    self.log("本轮没有有效冠军 IP，未执行 Cloudflare DNS 同步")
                    return
                for family, ip in champions.items():
                    with self.lock:
                        if not self._automatic_sync_is_current(result, dns_sync, generation):
                            self.log("定时任务已停止或结果已变化，停止旧任务的 DNS 写入")
                            return
                    if not _network_matches_result(result, family):
                        self.log(f"{family} 网络出口已变化或无法复核，未执行 Cloudflare DNS 自动同步")
                        continue
                    try:
                        changed = _apply_dns_sync(dns_sync, ip)
                    except CloudflareDnsError as exc:
                        self.log(f"{family} Cloudflare DNS 自动同步失败：{exc}")
                        if exc.pause_dns_automation:
                            with self.lock:
                                self.dns_automation_paused = True
                            self.log("鉴权失败：仅暂停 DNS 自动写入，后续定时测速仍会继续")
                        if exc.pause_dns_automation or exc.code in _DNS_AUTOMATION_GLOBAL_STOP_CODES:
                            break
                        continue
                    except Exception:
                        self.log("Cloudflare DNS 自动同步发生未预期错误；本轮已安全停止写入")
                        break
                    operation = {"created": "已创建", "updated": "已更新", "unchanged": "无需变更"}.get(changed.action, changed.action)
                    self.log(f"Cloudflare DNS {operation}：{changed.record_type} {changed.record_name} → {ip}（DNS-only）")
            finally:
                with self.lock:
                    self.dns_write_in_progress = False

    def _automation_loop(self, stop_event: threading.Event) -> None:
        first_run = True
        while not stop_event.is_set():
            if not first_run:
                with self.lock:
                    if not self.automation_enabled or stop_event is not self.automation_stop_event:
                        break
                    self.automation_next_run_at = time.time() + self.automation_interval_minutes * 60
                    interval_seconds = self.automation_interval_minutes * 60
                if stop_event.wait(interval_seconds):
                    break
            with self.lock:
                if not self.automation_enabled or stop_event is not self.automation_stop_event or not self.automation_config:
                    break
                config = dict(self.automation_config)
                config["_automation_generation"] = self.automation_generation
                self.automation_next_run_at = None
            started, message = self.start(config, scheduled=True)
            if not started:
                self.log(f"自动优选未启动：{message}")
            else:
                with self.lock:
                    self.automation_runs_started += 1
                    worker = self.worker
                if worker is not None:
                    worker.join()
            first_run = False
        with self.lock:
            if stop_event is self.automation_stop_event:
                self.automation_next_run_at = None

    def stop_automation(self) -> bool:
        # Invalidate the generation before waiting for a DNS request already in
        # flight. The writer checks this state between IPv4/IPv6, so no second
        # family can be written after stop begins. Never wait for dns_write_lock
        # while holding state.lock: the writer needs state.lock to observe this.
        with self.lock:
            if not self.automation_enabled:
                return False
            self.automation_enabled = False
            self.automation_generation += 1
            self.automation_next_run_at = None
            self.automation_config = None
            self.dns_automation_paused = False
            self.automation_stop_in_progress = True
            self.automation_stop_event.set()
        try:
            with self.dns_write_lock:
                pass
        finally:
            with self.lock:
                self.automation_stop_in_progress = False
        return True

    def stop(self) -> tuple[bool, str]:
        stopped_automation = self.stop_automation()
        with self.lock:
            if self.status in {"running", "stopping"}:
                self.status = "stopping"
                self.stage = "正在停止"
                self.cancel_event.set()
                return True, "已停止后续自动优选，当前任务正在停止"
            if stopped_automation:
                self.stage = "定时自动优选已停止"
                return True, "定时自动优选已停止"
            return False, "当前没有运行中的任务或定时自动优选"


def _csv_bytes(result: OptimizerResult) -> bytes:
    argo = result.purpose == PURPOSE_ARGO
    node_output = result.purpose in {PURPOSE_DIRECT, PURPOSE_ARGO}
    node_sni = result.node_sni or result.target_host
    node_host = result.node_host or node_sni
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "family", "rank", "ip", "server", "target_mbps", "meets_target", "port", "sni", "host", "ws_path",
        "peak_kbps", "tcp_latency_ms", "scan_round", "data_center", "transport", "measurement_host", "measurement_port",
        "round_floor_mbps", "avg_complete_mbps", "min_complete_mbps", "success_rate_pct", "variation_pct", "median_ttfb_ms", "v2rayng_delay_ms", "pop", "loc", "rounds_tested", "source_tags",
    ])
    for family in result.families:
        rows = family.asia_ranked if result.mode == "asia" else family.ranked
        for index, item in enumerate(rows, 1):
            writer.writerow([
                family.family, index, item.ip, item.ip if node_output else "", result.target_mbps,
                "yes" if item.round_floor_mbps >= result.target_mbps else "no", result.node_port if argo else "",
                node_sni if argo else "", node_host if argo else "", result.ws_path if argo else "",
                item.peak_kbps, item.latency_ms, item.scan_round, item.data_center,
                "TLS" if item.use_tls else "plain HTTP", result.measurement_host, result.measurement_port,
                f"{item.round_floor_mbps:.3f}", f"{item.avg_complete_mbps:.3f}",
                f"{item.min_complete_mbps:.3f}", f"{item.success_rate_pct:.1f}", f"{item.variation_pct:.1f}",
                f"{item.median_ttfb_ms:.1f}", f"{item.node_delay_ms:.1f}", item.pop, item.loc, item.rounds_tested, " | ".join(item.source_tags),
            ])
    return output.getvalue().encode("utf-8-sig")


def _traffic_upper_bound_mb(mode: str, family: str, target_mbps: int = 100) -> float:
    if mode == "reference":
        # Reference mode repeats fresh rounds until a hit.  A true hard upper
        # bound therefore does not exist; expose the useful first-speed-test
        # estimate instead of pretending all ten candidates always download
        # for five seconds.
        first_hit = max(1, target_mbps) * 125_000 * 5 / 1_000_000.0
        return round(first_hit * (2 if family == "dual" else 1), 1)
    params = MODES[mode]
    shortlist = min(MAX_CANDIDATES_PER_FAMILY, params.micro_candidates)
    request_floor = 64_000_000 if not params.early_stop else 4_000_000
    request_bytes = min(
        256_000_000,
        max(request_floor, int(max(1, target_mbps) * 125_000 * 1.5)),
    )
    per_family = (
        MAX_CANDIDATES_PER_FAMILY * params.pre_bytes
        + shortlist * 2 * request_bytes
    ) / 1_000_000.0
    return round(per_family * (2 if family == "dual" else 1), 1)


def make_handler(state: RuntimeState, request_token: str, allowed_hosts: set[str] | None = None) -> type[BaseHTTPRequestHandler]:
    safe_hosts = {item.lower() for item in (allowed_hosts or {"127.0.0.1", "localhost", "::1"})}

    class Handler(BaseHTTPRequestHandler):
        server_version = f"RR-Edge-Hunter/{VERSION}"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _send(self, body: bytes, content_type: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, value: object, status: int = 200) -> None:
            self._send(json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

        def _local_host(self) -> bool:
            try:
                if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                    return False
                hostname = urllib.parse.urlsplit("//" + self.headers.get("Host", "")).hostname or ""
            except ValueError:
                return False
            return hostname.lower() in safe_hosts

        def _authorized_post(self) -> bool:
            supplied = self.headers.get("X-RR-Request-Token", "")
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            return content_type == "application/json" and secrets.compare_digest(supplied, request_token)

        def _body_json(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise IpSourceError("请求长度无效") from exc
            if length <= 0:
                raise IpSourceError("请求内容为空")
            if length > MAX_REQUEST_BYTES:
                raise IpSourceError("请求内容不能超过 1 MiB")
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise IpSourceError("JSON 请求格式无效") from exc
            if not isinstance(value, dict):
                raise IpSourceError("JSON 请求必须是对象")
            return value

        def _run_config(self, body: dict[str, Any]) -> dict[str, Any]:
            if body.get("confirmed") is not True:
                raise IpSourceError("请确认本轮会产生真实 HTTPS 下载流量")
            mode = str(body.get("mode", "reference"))
            family = str(body.get("family", "ipv4"))
            operator = str(body.get("operator", "自动"))[:30]
            purpose = str(body.get("purpose", PURPOSE_DIRECT))
            if purpose not in {PURPOSE_DIRECT, PURPOSE_ARGO, PURPOSE_DNS}:
                raise IpSourceError("用途参数无效")
            node_profile: NodeProfile | None = None
            if purpose == PURPOSE_DIRECT:
                target_host = SPEED_HOST
            elif purpose == PURPOSE_ARGO:
                raw_node_link = str(body.get("node_link", "")).strip()
                if not raw_node_link:
                    raise IpSourceError("请粘贴一个当前在 V2rayNG 可用的 VMess/VLESS Argo 节点")
                if len(raw_node_link.encode("utf-8")) > 32 * 1024:
                    raise IpSourceError("节点分享链接过长")
                try:
                    node_profile = parse_node_profile(raw_node_link)
                except ValueError as exc:
                    raise IpSourceError(str(exc)) from exc
                target_host = node_profile.route.sni
            else:
                raw_target = str(body.get("target_host", SPEED_HOST)).strip()[:255]
                if any(marker in raw_target for marker in ("://", "/", "?", "#", "@")) or ":" in raw_target:
                    raise IpSourceError("请只填写域名，不要填写 IP、URL、端口或路径")
                try:
                    target_host = normalize_hostname(raw_target)
                except HostnameError as exc:
                    raise IpSourceError(f"测试主机无效：{exc}") from exc
            if purpose == PURPOSE_ARGO:
                assert node_profile is not None
                node_port = node_profile.route.port
            else:
                node_port = 443
            if purpose == PURPOSE_ARGO:
                assert node_profile is not None
                ws_path = node_profile.route.ws_path
            else:
                ws_path = ""
            raw_target_mbps = body.get("target_mbps", 100)
            if isinstance(raw_target_mbps, bool):
                raise IpSourceError("目标带宽无效")
            try:
                target_mbps = int(raw_target_mbps)
            except (TypeError, ValueError) as exc:
                raise IpSourceError("目标带宽无效") from exc
            if not MIN_TARGET_MBPS <= target_mbps <= MAX_TARGET_MBPS:
                raise IpSourceError(f"目标带宽必须在 {MIN_TARGET_MBPS}–{MAX_TARGET_MBPS} Mbps 之间")
            source = "custom" if body.get("source") == "custom" else "dns"
            if mode != "reference" or family not in {"ipv4", "ipv6", "dual"}:
                raise IpSourceError("参数无效")
            raw_use_tls = body.get("use_tls", True)
            if not isinstance(raw_use_tls, bool):
                raise IpSourceError("TLS 模式参数无效")
            config: dict[str, Any] = {
                "mode": mode,
                "family": family,
                "operator": operator,
                "target_host": target_host,
                "source": (
                    "在线维护 IP 池 + 我的名单" if source == "custom" and purpose == PURPOSE_ARGO
                    else "在线维护 IP 池" if purpose == PURPOSE_ARGO
                    else "在线维护 IP 池 + 我的名单" if source == "custom" and purpose == PURPOSE_DIRECT
                    else "在线维护 IP 池" if purpose == PURPOSE_DIRECT
                    else "我的 IP 名单" if source == "custom"
                    else "当前 DNS"
                ),
                "purpose": purpose,
                "node_port": node_port,
                "ws_path": ws_path,
                "target_mbps": target_mbps,
                "use_tls": raw_use_tls,
                "traffic_upper_bound_mb": _traffic_upper_bound_mb(mode, family, target_mbps),
            }
            if node_profile is not None:
                config["_node_profile"] = node_profile
                config["node_protocol"] = node_profile.route.protocol
            if source == "custom":
                values = body.get("ips")
                if not isinstance(values, list):
                    raise IpSourceError("请先识别并载入自定义 IP")
                custom_ips = normalize_ip_values(values)
                config["_ips"] = custom_ips
                config["source_ip_count"] = len(custom_ips)
                subscription_url = str(body.get("subscription_url", "")).strip()
                if subscription_url:
                    if len(subscription_url) > 2_048:
                        raise IpSourceError("订阅链接过长")
                    parsed_subscription = urllib.parse.urlsplit(subscription_url)
                    try:
                        subscription_port = parsed_subscription.port
                    except ValueError as exc:
                        raise IpSourceError("订阅链接端口无效") from exc
                    if (
                        parsed_subscription.scheme.lower() != "https"
                        or not parsed_subscription.hostname
                        or parsed_subscription.username
                        or parsed_subscription.password
                        or subscription_port not in {None, 443}
                        or parsed_subscription.fragment
                    ):
                        raise IpSourceError("订阅链接只支持 HTTPS")
                    config["_subscription_url"] = subscription_url
            return config

        @staticmethod
        def _interval_minutes(body: dict[str, Any]) -> int:
            raw = body.get("interval_minutes")
            if isinstance(raw, bool):
                raise IpSourceError("自动运行间隔无效")
            try:
                interval = int(raw)
            except (TypeError, ValueError) as exc:
                raise IpSourceError("自动运行间隔无效") from exc
            if not MIN_AUTOMATION_INTERVAL_MINUTES <= interval <= MAX_AUTOMATION_INTERVAL_MINUTES:
                raise IpSourceError(f"自动运行间隔必须在 {MIN_AUTOMATION_INTERVAL_MINUTES}–{MAX_AUTOMATION_INTERVAL_MINUTES} 分钟之间")
            return interval

        def do_GET(self) -> None:  # noqa: N802
            if not self._local_host():
                self._json({"error": "仅允许从本机地址访问"}, HTTPStatus.MISDIRECTED_REQUEST)
                return
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/config":
                self._json({
                    "version": VERSION,
                    "request_token": request_token,
                    "default_purpose": PURPOSE_ARGO,
                    "default_target_host": SPEED_HOST,
                    "diagnostic_default_target_host": SPEED_HOST,
                    "default_node_port": 443,
                    "supported_tls_ports": sorted(SUPPORTED_TLS_PORTS),
                    "max_custom_ips": MAX_IPS,
                    "max_source_bytes": MAX_SOURCE_BYTES,
                    "candidate_cap_per_family": MAX_CANDIDATES_PER_FAMILY,
                    "target_mbps": {
                        "default": 100,
                        "min": MIN_TARGET_MBPS,
                        "max": MAX_TARGET_MBPS,
                    },
                    "automation": {
                        "min_interval_minutes": MIN_AUTOMATION_INTERVAL_MINUTES,
                        "max_interval_minutes": MAX_AUTOMATION_INTERVAL_MINUTES,
                    },
                    "modes": {
                        name: {
                            "label": mode.label,
                            "micro_candidates": mode.micro_candidates,
                            "final_candidates": mode.final_candidates,
                            "pre_concurrency": mode.pre_concurrency,
                            "pre_bytes": mode.pre_bytes,
                            "micro_bytes": mode.micro_bytes,
                            "full_bytes": mode.full_bytes,
                            "full_rounds": mode.full_rounds,
                            "early_stop": mode.early_stop,
                        }
                        for name, mode in MODES.items()
                        if name == "reference"
                    },
                })
                return
            if parsed.path == "/api/status":
                self._json(state.snapshot())
                return
            if parsed.path == "/api/history":
                self._json(load_history())
                return
            if parsed.path == "/api/export":
                if not state.result:
                    self._json({"error": "暂无可导出的结果"}, HTTPStatus.NOT_FOUND)
                    return
                query = urllib.parse.parse_qs(parsed.query)
                export_format = query.get("format", ["json"])[0]
                if export_format == "csv":
                    self._send(_csv_bytes(state.result), "text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="rr-edge-hunter-result.csv"'})
                else:
                    self._send(json.dumps(state.result.to_dict(), ensure_ascii=False, indent=2).encode("utf-8"), "application/json; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="rr-edge-hunter-result.json"'})
                return
            name = "index.html" if parsed.path == "/" else parsed.path.lstrip("/")
            candidate = (WEB_DIR / name).resolve()
            try:
                candidate.relative_to(WEB_DIR.resolve())
            except ValueError:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if not candidate.is_file():
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            content_types = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".svg": "image/svg+xml"}
            self._send(candidate.read_bytes(), content_types.get(candidate.suffix, "application/octet-stream"))

        def do_POST(self) -> None:  # noqa: N802
            if not self._local_host():
                self._json({"ok": False, "message": "仅允许从本机地址访问"}, HTTPStatus.MISDIRECTED_REQUEST)
                return
            if not self._authorized_post():
                self._json({"ok": False, "message": "本机请求校验失败，请刷新页面重试"}, HTTPStatus.FORBIDDEN)
                return
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/stop":
                ok, message = state.stop()
                self._json({"ok": ok, "message": message}, 200 if ok else HTTPStatus.CONFLICT)
                return
            try:
                body = self._body_json()
            except IpSourceError as exc:
                self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            if parsed.path == "/api/start":
                try:
                    config = self._run_config(body)
                except IpSourceError as exc:
                    self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return
                ok, message = state.start(config)
                self._json({"ok": ok, "message": message, "traffic_upper_bound_mb": config["traffic_upper_bound_mb"]}, 200 if ok else HTTPStatus.CONFLICT)
                return
            if parsed.path == "/api/dns/inspect":
                try:
                    dns_config = _normalize_dns_sync_config({**body, "enabled": True})
                    normalized_ip, expected_type = normalize_champion_ip(body.get("ip"))
                except (IpSourceError, CloudflareDnsError) as exc:
                    self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return
                expected_family = "IPv6" if expected_type == "AAAA" else "IPv4"
                if str(body.get("family", "")) != expected_family:
                    self._json({"ok": False, "message": "冠军 IP 与协议族不一致"}, HTTPStatus.BAD_REQUEST)
                    return
                with state.dns_write_lock:
                    with state.lock:
                        current_result = state.result
                        champions = _result_champions(current_result) if current_result is not None else {}
                        if state.status != "completed" or champions.get(expected_family) != normalized_ip:
                            self._json({"ok": False, "message": "该 IP 不是当前稳定有效冠军，请重新优选"}, HTTPStatus.CONFLICT)
                            return
                        if not _network_matches_result(current_result, expected_family):
                            self._json({"ok": False, "message": "当前网络出口与优选时不一致或无法复核，请重新优选"}, HTTPStatus.CONFLICT)
                            return
                        result_created_at = current_result.created_at
                        state.dns_write_in_progress = True
                    try:
                        plan = _inspect_dns_sync(dns_config, normalized_ip)
                    except CloudflareDnsError as exc:
                        self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_GATEWAY)
                        return
                    except Exception:
                        self._json({"ok": False, "message": "Cloudflare DNS 检查发生未预期错误，未执行写入"}, HTTPStatus.BAD_GATEWAY)
                        return
                    finally:
                        with state.lock:
                            state.dns_write_in_progress = False
                    with state.lock:
                        current_result = state.result
                        champions = _result_champions(current_result) if current_result is not None else {}
                        if state.status != "completed" or not current_result or current_result.created_at != result_created_at or champions.get(expected_family) != normalized_ip:
                            self._json({"ok": False, "message": "优选结果在检查期间已变化，请重新操作"}, HTTPStatus.CONFLICT)
                            return
                        if not _network_matches_result(current_result, expected_family):
                            self._json({"ok": False, "message": "网络出口在检查期间发生变化，请重新优选"}, HTTPStatus.CONFLICT)
                            return
                        now = time.monotonic()
                        state.dns_manual_plans = {
                            key: value for key, value in state.dns_manual_plans.items()
                            if float(value.get("expires_at", 0)) > now
                        }
                        while len(state.dns_manual_plans) >= MAX_PENDING_DNS_PLANS:
                            state.dns_manual_plans.pop(next(iter(state.dns_manual_plans)))
                        state.dns_manual_plans[plan.fingerprint] = {
                            "expires_at": now + DNS_PLAN_TTL_SECONDS,
                            "result_created_at": result_created_at,
                            "family": expected_family,
                            "ip": normalized_ip,
                            "zone_id": dns_config["zone_id"],
                            "record_name": dns_config["record_name"],
                        }
                self._json({"ok": True, "plan": plan.to_dict()})
                return
            if parsed.path == "/api/dns/apply":
                if body.get("dns_write_confirmed") is not True:
                    self._json({"ok": False, "message": "请在查看 DNS 变更预览后二次确认"}, HTTPStatus.BAD_REQUEST)
                    return
                try:
                    dns_config = _normalize_dns_sync_config({**body, "enabled": True})
                    normalized_ip, expected_type = normalize_champion_ip(body.get("ip"))
                except (IpSourceError, CloudflareDnsError) as exc:
                    self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return
                fingerprint = str(body.get("fingerprint", ""))
                expected_family = "IPv6" if expected_type == "AAAA" else "IPv4"
                if str(body.get("family", "")) != expected_family:
                    self._json({"ok": False, "message": "冠军 IP 与协议族不一致"}, HTTPStatus.BAD_REQUEST)
                    return
                with state.dns_write_lock:
                    with state.lock:
                        pending = state.dns_manual_plans.pop(fingerprint, None)
                        current_result = state.result
                        champions = _result_champions(current_result) if current_result is not None else {}
                        valid_plan = bool(
                            pending
                            and float(pending.get("expires_at", 0)) > time.monotonic()
                            and pending.get("result_created_at") == (current_result.created_at if current_result else "")
                            and pending.get("family") == expected_family
                            and pending.get("ip") == normalized_ip
                            and pending.get("zone_id") == dns_config["zone_id"]
                            and pending.get("record_name") == dns_config["record_name"]
                        )
                        if state.status != "completed" or not valid_plan or champions.get(expected_family) != normalized_ip:
                            self._json({"ok": False, "message": "DNS 预览已过期、已使用或不再匹配当前冠军，请重新检查"}, HTTPStatus.CONFLICT)
                            return
                        if not current_result or not _network_matches_result(current_result, expected_family):
                            self._json({"ok": False, "message": "当前网络出口与优选时不一致，请重新优选"}, HTTPStatus.CONFLICT)
                            return
                        state.dns_write_in_progress = True
                    try:
                        changed = _apply_dns_plan(dns_config, normalized_ip, fingerprint)
                    except CloudflareDnsError as exc:
                        self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_GATEWAY)
                        return
                    except Exception:
                        self._json({"ok": False, "message": "Cloudflare DNS 同步发生未预期错误，未继续写入"}, HTTPStatus.BAD_GATEWAY)
                        return
                    finally:
                        with state.lock:
                            state.dns_write_in_progress = False
                operation = {"created": "已创建", "updated": "已更新", "unchanged": "无需变更"}.get(changed.action, changed.action)
                self._json({"ok": True, "message": f"{operation} {changed.record_type} 记录（DNS-only）", "result": changed.to_dict()})
                return
            if parsed.path == "/api/automation/start":
                try:
                    config = self._run_config(body)
                    interval = self._interval_minutes(body)
                    if body.get("dns_sync") is not None:
                        if body.get("dns_write_confirmed") is not True:
                            raise IpSourceError("请二次确认定时 Cloudflare DNS 自动写入")
                        config["_dns_sync"] = _normalize_dns_sync_config(body.get("dns_sync"))
                except IpSourceError as exc:
                    self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return
                config["automation_enabled"] = True
                config["automation_interval_minutes"] = interval
                ok, message = state.start_automation(config, interval)
                self._json({"ok": ok, "message": message, "traffic_upper_bound_mb": config["traffic_upper_bound_mb"]}, 200 if ok else HTTPStatus.CONFLICT)
                return
            if parsed.path == "/api/ips/parse":
                try:
                    result = parse_ip_source(body.get("text"), str(body.get("filename", ""))[:255])
                except IpSourceError as exc:
                    self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return
                self._json({"ok": True, **result.to_dict()})
                return
            if parsed.path == "/api/ips/fetch":
                try:
                    result, final_url = fetch_ip_subscription(str(body.get("url", "")))
                except IpSourceError as exc:
                    self._json({"ok": False, "message": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return
                self._json({"ok": True, "final_url": final_url, **result.to_dict()})
                return
            self.send_error(HTTPStatus.NOT_FOUND)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 0, open_browser: bool = True) -> None:
    normalized_host = host.strip().lower()
    try:
        parsed_host = None if normalized_host == "localhost" else ipaddress.ip_address(normalized_host)
        loopback = normalized_host == "localhost" or bool(parsed_host and parsed_host.is_loopback)
    except ValueError:
        loopback = False
        parsed_host = None
    if not loopback:
        raise ValueError("网页界面只允许绑定本机回环地址或 localhost")

    server_type: type[ThreadingHTTPServer] = ThreadingHTTPServer
    if parsed_host is not None and parsed_host.version == 6:
        class IPv6ThreadingHTTPServer(ThreadingHTTPServer):
            address_family = socket.AF_INET6

        server_type = IPv6ThreadingHTTPServer
    state = RuntimeState()
    request_token = secrets.token_urlsafe(32)
    server = server_type((host, port), make_handler(state, request_token, {normalized_host, "127.0.0.1", "localhost", "::1"}))
    actual_port = server.server_address[1]
    url_host = f"[{host}]" if parsed_host is not None and parsed_host.version == 6 else host
    url = f"http://{url_host}:{actual_port}/"
    print(f"RR Edge Hunter 已启动：{url}", flush=True)
    print("保持此窗口运行；按 Ctrl+C 退出。", flush=True)
    if open_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
