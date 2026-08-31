from __future__ import annotations

import datetime as dt
import csv
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

from .history import load_history, save_history
from .ip_sources import IpSourceError, MAX_IPS, MAX_SOURCE_BYTES, fetch_ip_subscription, normalize_ip_values, parse_ip_source
from .models import MODES, OptimizerResult, SPEED_HOST
from .pipeline import (
    MAX_CANDIDATES_PER_FAMILY,
    PURPOSE_ARGO,
    PURPOSE_DNS,
    SUPPORTED_TLS_PORTS,
    normalize_ws_path,
    run_optimizer,
)
from .hostnames import HostnameError, normalize_hostname
from .resources import package_root
from .version import VERSION


WEB_DIR = package_root() / "web"
MAX_REQUEST_BYTES = MAX_SOURCE_BYTES + 64 * 1024
MIN_AUTOMATION_INTERVAL_MINUTES = 5
MAX_AUTOMATION_INTERVAL_MINUTES = 1_440


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

    @staticmethod
    def _public_config(config: dict[str, Any]) -> dict[str, Any]:
        visible = {
            "mode", "family", "operator", "target_host", "source", "source_ip_count",
            "automation_enabled", "automation_interval_minutes", "traffic_upper_bound_mb",
            "purpose", "node_port", "ws_path",
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
        with self.lock:
            if self.status in {"running", "stopping"}:
                return False, "已有任务正在运行"
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
            result = run_optimizer(
                mode=str(run_config.get("mode", "balanced")),
                family=str(run_config.get("family", "dual")),
                operator=str(run_config.get("operator", "自动")),
                target_host=str(run_config.get("target_host", SPEED_HOST)),
                ips=run_config.get("_ips"),
                source_kind=str(run_config.get("source", "当前 DNS")),
                purpose=str(run_config.get("purpose", PURPOSE_DNS)),
                node_port=int(run_config.get("node_port", 443)),
                ws_path=str(run_config.get("ws_path", "")),
                cancel_event=self.cancel_event,
                on_stage=self.on_stage,
                log=self.log,
            )
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
        except Exception as exc:
            with self.lock:
                self.status = "error"
                self.stage = "发生错误"
                self.error = f"{type(exc).__name__}: {exc}"
            self.log(self.error)

    def start_automation(self, config: dict[str, Any], interval_minutes: int) -> tuple[bool, str]:
        if not MIN_AUTOMATION_INTERVAL_MINUTES <= interval_minutes <= MAX_AUTOMATION_INTERVAL_MINUTES:
            return False, f"自动运行间隔必须在 {MIN_AUTOMATION_INTERVAL_MINUTES}–{MAX_AUTOMATION_INTERVAL_MINUTES} 分钟之间"
        with self.lock:
            if self.automation_enabled:
                return False, "定时自动优选已在运行"
            if self.status in {"running", "stopping"}:
                return False, "请等待当前优选结束后再开启定时自动优选"
            self.automation_enabled = True
            self.automation_interval_minutes = interval_minutes
            self.automation_next_run_at = time.time()
            self.automation_config = dict(config)
            self.automation_stop_event = threading.Event()
            stop_event = self.automation_stop_event
            self.automation_worker = threading.Thread(target=self._automation_loop, args=(stop_event,), name="rr-edge-hunter-scheduler", daemon=True)
            self.automation_worker.start()
        return True, f"已开启定时自动优选：每 {interval_minutes} 分钟运行一次"

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
        if not self.automation_enabled:
            return False
        self.automation_enabled = False
        self.automation_next_run_at = None
        self.automation_config = None
        self.automation_stop_event.set()
        return True

    def stop(self) -> tuple[bool, str]:
        with self.lock:
            stopped_automation = self.stop_automation()
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
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "family", "rank", "ip", "server", "port", "sni", "host", "ws_path", "round_floor_mbps", "avg_complete_mbps", "min_complete_mbps",
        "success_rate_pct", "variation_pct", "median_ttfb_ms", "pop", "loc", "rounds_tested", "source_tags",
    ])
    for family in result.families:
        rows = family.asia_ranked if result.mode == "asia" else family.ranked
        for index, item in enumerate(rows, 1):
            writer.writerow([
                family.family, index, item.ip, item.ip if argo else "", result.node_port if argo else "",
                result.target_host if argo else "", result.target_host if argo else "", result.ws_path if argo else "",
                f"{item.round_floor_mbps:.3f}", f"{item.avg_complete_mbps:.3f}",
                f"{item.min_complete_mbps:.3f}", f"{item.success_rate_pct:.1f}", f"{item.variation_pct:.1f}",
                f"{item.median_ttfb_ms:.1f}", item.pop, item.loc, item.rounds_tested, " | ".join(item.source_tags),
            ])
    return output.getvalue().encode("utf-8-sig")


def _traffic_upper_bound_mb(mode: str, family: str) -> float:
    params = MODES[mode]
    per_family = (
        MAX_CANDIDATES_PER_FAMILY * params.pre_bytes
        + min(MAX_CANDIDATES_PER_FAMILY, params.micro_candidates) * params.micro_bytes
        + min(MAX_CANDIDATES_PER_FAMILY, params.final_candidates) * params.full_rounds * params.full_bytes
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
            mode = str(body.get("mode", "balanced"))
            family = str(body.get("family", "dual"))
            operator = str(body.get("operator", "自动"))[:30]
            purpose = str(body.get("purpose", PURPOSE_ARGO))
            if purpose not in {PURPOSE_ARGO, PURPOSE_DNS}:
                raise IpSourceError("用途参数无效")
            raw_target = str(body.get("target_host", "" if purpose == PURPOSE_ARGO else SPEED_HOST)).strip()[:255]
            if any(marker in raw_target for marker in ("://", "/", "?", "#", "@")) or ":" in raw_target:
                raise IpSourceError("请只填写域名，不要填写 IP、URL、端口或路径")
            try:
                target_host = normalize_hostname(raw_target)
            except HostnameError as exc:
                label = "Argo 节点域名" if purpose == PURPOSE_ARGO else "测试主机"
                raise IpSourceError(f"{label}无效：{exc}") from exc
            raw_port = body.get("node_port", 443)
            if isinstance(raw_port, bool):
                raise IpSourceError("节点端口无效")
            try:
                node_port = int(raw_port)
            except (TypeError, ValueError) as exc:
                raise IpSourceError("节点端口无效") from exc
            if node_port not in SUPPORTED_TLS_PORTS:
                raise IpSourceError("节点端口仅支持 443、2053、2083、2087、2096、8443")
            try:
                ws_path = normalize_ws_path(body.get("ws_path", ""))
            except ValueError as exc:
                raise IpSourceError(str(exc)) from exc
            source = "custom" if body.get("source") == "custom" else "dns"
            if mode not in MODES or family not in {"ipv4", "ipv6", "dual"}:
                raise IpSourceError("参数无效")
            config: dict[str, Any] = {
                "mode": mode,
                "family": family,
                "operator": operator,
                "target_host": target_host,
                "source": (
                    "智能候选池 + 我的 IP 名单" if source == "custom" and purpose == PURPOSE_ARGO
                    else "智能候选池" if purpose == PURPOSE_ARGO
                    else "我的 IP 名单" if source == "custom"
                    else "当前 DNS"
                ),
                "purpose": purpose,
                "node_port": node_port,
                "ws_path": ws_path,
                "traffic_upper_bound_mb": _traffic_upper_bound_mb(mode, family),
            }
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
                    "default_target_host": "",
                    "diagnostic_default_target_host": SPEED_HOST,
                    "default_node_port": 443,
                    "supported_tls_ports": sorted(SUPPORTED_TLS_PORTS),
                    "max_custom_ips": MAX_IPS,
                    "max_source_bytes": MAX_SOURCE_BYTES,
                    "candidate_cap_per_family": MAX_CANDIDATES_PER_FAMILY,
                    "automation": {
                        "min_interval_minutes": MIN_AUTOMATION_INTERVAL_MINUTES,
                        "max_interval_minutes": MAX_AUTOMATION_INTERVAL_MINUTES,
                    },
                    "modes": {
                        name: {
                            "label": mode.label,
                            "micro_candidates": mode.micro_candidates,
                            "final_candidates": mode.final_candidates,
                            "pre_bytes": mode.pre_bytes,
                            "micro_bytes": mode.micro_bytes,
                            "full_bytes": mode.full_bytes,
                            "full_rounds": mode.full_rounds,
                        }
                        for name, mode in MODES.items()
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
            if parsed.path == "/api/automation/start":
                try:
                    config = self._run_config(body)
                    interval = self._interval_minutes(body)
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
