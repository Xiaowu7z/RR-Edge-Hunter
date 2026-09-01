"""Local desktop UI for the unmodified better-cloudflare-ip engine."""

from __future__ import annotations

import datetime as dt
import json
import mimetypes
import secrets
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
    normalize_record_name,
    normalize_zone_id,
)
from .reference_process import (
    ReferenceEngineCancelled,
    ReferenceResult,
    run_reference_scan,
    update_reference_data,
)
from .resources import package_root
from .version import VERSION


WEB_DIR = package_root() / "web"
MAX_REQUEST_BYTES = 64 * 1024
DNS_PLAN_TTL_SECONDS = 300
AUTOMATION_INTERVAL_HOURS = (1, 2, 4, 6, 12, 24)
_DNS_AUTOMATION_PAUSE_CODES = frozenset({
    "auth_failed",
    "invalid_zone_id",
    "invalid_record_name",
    "cname_conflict",
    "ns_conflict",
    "multiple_records",
})


def _normalize_automatic_dns(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"api_token", "zone_id", "record_name"}:
        raise CloudflareDnsError("Cloudflare DNS 自动解析配置无效", code="invalid_config")
    token = str(value.get("api_token", ""))
    if not token or token != token.strip() or len(token) > 4096 or any(ch in token for ch in "\r\n"):
        raise CloudflareDnsError("Cloudflare API Token 无效", code="invalid_token")
    return {
        "api_token": token,
        "zone_id": normalize_zone_id(value.get("zone_id")),
        "record_name": normalize_record_name(value.get("record_name")),
    }


@dataclass
class RuntimeState:
    lock: threading.RLock = field(default_factory=threading.RLock)
    status: str = "idle"
    stage: str = "等待开始"
    detail: str = ""
    logs: list[str] = field(default_factory=list)
    result: ReferenceResult | None = None
    error: str = ""
    config: dict[str, object] = field(default_factory=dict)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    worker: threading.Thread | None = None
    pending_dns: dict[str, dict[str, object]] = field(default_factory=dict)
    automation_enabled: bool = False
    automation_interval_hours: int = 1
    automation_next_run_at: float | None = None
    automation_runs_started: int = 0
    automation_config: dict[str, object] | None = None
    automation_stop_event: threading.Event = field(default_factory=threading.Event)
    automation_worker: threading.Thread | None = None
    automation_generation: int = 0
    automation_stop_in_progress: bool = False
    dns_automation_paused: bool = False
    dns_write_lock: threading.Lock = field(default_factory=threading.Lock)
    dns_write_in_progress: bool = False

    @staticmethod
    def _format_timestamp(value: float | None) -> str | None:
        if value is None:
            return None
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).astimezone().isoformat(timespec="seconds")

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            return {
                "status": self.status,
                "stage": self.stage,
                "detail": self.detail,
                "logs": self.logs[-220:],
                "result": self.result.to_dict() if self.result else None,
                "error": self.error,
                "config": dict(self.config),
                "automation": {
                    "enabled": self.automation_enabled,
                    "interval_hours": self.automation_interval_hours if self.automation_enabled else None,
                    "next_run_at": self._format_timestamp(self.automation_next_run_at),
                    "runs_started": self.automation_runs_started,
                    "dns_sync_enabled": bool(
                        self.automation_enabled
                        and self.automation_config
                        and isinstance(self.automation_config.get("dns_sync"), dict)
                    ),
                    "dns_sync_paused": self.dns_automation_paused,
                },
            }

    def _log(self, line: str) -> None:
        with self.lock:
            self.detail = line
            self.logs.append(line)
            del self.logs[:-500]

    def _begin(
        self,
        *,
        stage: str,
        config: dict[str, object],
        target: Any,
        scheduled_generation: int | None = None,
    ) -> tuple[bool, str]:
        with self.lock:
            if scheduled_generation is None and self.automation_enabled:
                return False, "定时自动优选正在运行；请先停止自动任务"
            if scheduled_generation is not None and (
                not self.automation_enabled
                or scheduled_generation != self.automation_generation
                or self.automation_config is None
            ):
                return False, "该自动任务已停止或已被替换"
            if self.status in {"running", "stopping"}:
                return False, "已有任务正在运行"
            if self.dns_write_in_progress:
                return False, "Cloudflare DNS 正在写入，请稍候"
            self.status = "running"
            self.stage = stage
            self.detail = ""
            self.logs = []
            self.result = None
            self.error = ""
            self.config = dict(config)
            self.pending_dns.clear()
            self.cancel_event = threading.Event()
            self.worker = threading.Thread(
                target=target,
                args=(self.cancel_event,),
                name="rr-reference-engine",
                daemon=True,
            )
            self.worker.start()
        return True, "自动优选已开始" if scheduled_generation is not None else "任务已开始"

    def start_scan(
        self,
        *,
        family: str,
        use_tls: bool,
        bandwidth: int,
        _scheduled_generation: int | None = None,
    ) -> tuple[bool, str]:
        return self._begin(
            stage="正在优选",
            config={"family": family, "use_tls": use_tls, "bandwidth": bandwidth},
            target=lambda cancel: self._scan(
                family,
                use_tls,
                bandwidth,
                cancel,
                _scheduled_generation,
            ),
            scheduled_generation=_scheduled_generation,
        )

    def _scan(
        self,
        family: str,
        use_tls: bool,
        bandwidth: int,
        cancel_event: threading.Event,
        scheduled_generation: int | None,
    ) -> None:
        try:
            result = run_reference_scan(
                family=family,
                use_tls=use_tls,
                bandwidth=bandwidth,
                task_count=50,
                cancel_event=cancel_event,
                on_line=self._log,
            )
            with self.lock:
                if cancel_event.is_set():
                    self.status = "cancelled"
                    self.stage = "已停止"
                    self.result = None
                else:
                    self.result = result
                    self.status = "completed"
                    self.stage = "优选完成"
                    self.detail = ""
            if not cancel_event.is_set() and scheduled_generation is not None:
                self._sync_automatic_result(result, scheduled_generation)
        except ReferenceEngineCancelled:
            with self.lock:
                self.status = "cancelled"
                self.stage = "已停止"
                self.result = None
                self.detail = ""
        except Exception as exc:
            with self.lock:
                self.status = "error"
                self.stage = "任务失败"
                self.error = f"{type(exc).__name__}: {exc}"
                self.detail = ""

    def start_update(self) -> tuple[bool, str]:
        return self._begin(stage="正在更新参考数据", config={}, target=self._update)

    def _update(self, cancel_event: threading.Event) -> None:
        try:
            update_reference_data(cancel_event=cancel_event, on_line=self._log)
            with self.lock:
                self.status = "completed"
                self.stage = "参考数据已更新"
                self.detail = ""
        except ReferenceEngineCancelled:
            with self.lock:
                self.status = "cancelled"
                self.stage = "已停止"
                self.detail = ""
        except Exception as exc:
            with self.lock:
                self.status = "error"
                self.stage = "更新失败"
                self.error = f"{type(exc).__name__}: {exc}"
                self.detail = ""

    def stop(self) -> tuple[bool, str]:
        stopped_automation = self.stop_automation()
        with self.lock:
            if self.status not in {"running", "stopping"}:
                if stopped_automation:
                    self.stage = "自动任务已停止"
                    return True, "自动任务已停止"
                return False, "当前没有运行中的任务"
            self.status = "stopping"
            self.stage = "正在停止"
            self.cancel_event.set()
        return True, "已停止后续自动测试，当前任务正在停止"

    def start_automation(
        self,
        *,
        family: str,
        use_tls: bool,
        bandwidth: int,
        interval_hours: int,
        dns_sync: dict[str, str] | None,
    ) -> tuple[bool, str]:
        if interval_hours not in AUTOMATION_INTERVAL_HOURS:
            return False, "自动测试时长无效"
        config: dict[str, object] = {
            "family": family,
            "use_tls": use_tls,
            "bandwidth": bandwidth,
            "dns_sync": dict(dns_sync) if dns_sync else None,
        }
        with self.lock:
            if self.automation_enabled:
                return False, "定时自动优选已在运行"
            if self.automation_stop_in_progress:
                return False, "正在安全停止上一项自动任务，请稍候"
            if self.status in {"running", "stopping"}:
                return False, "请等待当前任务结束后再开启自动测试"
            if self.dns_write_in_progress:
                return False, "Cloudflare DNS 正在写入，请稍候"
            self.automation_generation += 1
            self.automation_enabled = True
            self.automation_interval_hours = interval_hours
            self.automation_next_run_at = time.time()
            self.automation_runs_started = 0
            self.automation_config = config
            self.dns_automation_paused = False
            self.automation_stop_event = threading.Event()
            stop_event = self.automation_stop_event
            self.automation_worker = threading.Thread(
                target=self._automation_loop,
                args=(stop_event,),
                name="rr-reference-scheduler",
                daemon=True,
            )
            self.automation_worker.start()
        label = "全天（24 小时）" if interval_hours == 24 else f"{interval_hours} 小时"
        return True, f"已开启自动测试：每 {label} 运行一轮，首轮立即开始"

    def _automation_is_current(self, result: ReferenceResult, generation: int) -> bool:
        return bool(
            self.automation_enabled
            and self.automation_generation == generation
            and self.status == "completed"
            and self.result is result
            and self.automation_config is not None
        )

    def _sync_automatic_result(self, result: ReferenceResult, generation: int) -> None:
        with self.lock:
            config = self.automation_config
            dns_sync = config.get("dns_sync") if config else None
        if not isinstance(dns_sync, dict):
            self._log("本轮保留 1 个优选 IP；自动解析未开启，可由用户手动添加")
            return
        with self.dns_write_lock:
            with self.lock:
                if not self._automation_is_current(result, generation):
                    self._log("自动任务已停止或结果已变化，跳过本轮 DNS 写入")
                    return
                if self.dns_automation_paused:
                    self._log("Cloudflare 自动解析已暂停；后续测速仍会继续")
                    return
                self.dns_write_in_progress = True
            try:
                client = CloudflareDnsClient(str(dns_sync.get("api_token", "")))
                plan = client.inspect_sync(
                    zone_id=str(dns_sync.get("zone_id", "")),
                    record_name=str(dns_sync.get("record_name", "")),
                    champion_ip=result.ip,
                )
                with self.lock:
                    if not self._automation_is_current(result, generation):
                        self._log("自动任务已停止或结果已变化，未执行本轮 DNS 写入")
                        return
                synced = client.apply_sync(
                    zone_id=plan.zone_id,
                    record_name=plan.record_name,
                    champion_ip=plan.champion_ip,
                    expected_fingerprint=plan.fingerprint,
                    confirm_create=True,
                )
                operation = {
                    "created": "已创建",
                    "updated": "已更新",
                    "unchanged": "无需变更",
                }.get(synced.action, synced.action)
                self._log(
                    f"Cloudflare DNS {operation}：{synced.record_type} "
                    f"{synced.record_name} → {synced.content}（本轮唯一 IP）"
                )
            except CloudflareDnsError as exc:
                self._log(f"本轮 Cloudflare 自动解析失败：{exc.message}")
                if exc.code in _DNS_AUTOMATION_PAUSE_CODES:
                    with self.lock:
                        self.dns_automation_paused = True
                    self._log("自动解析配置需要处理；仅暂停 DNS 写入，定时测速继续")
            except Exception:
                self._log("本轮 Cloudflare 自动解析发生未预期错误；未继续写入")
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
                    interval_seconds = self.automation_interval_hours * 60 * 60
                    self.automation_next_run_at = time.time() + interval_seconds
                if stop_event.wait(interval_seconds):
                    break
            with self.lock:
                config = self.automation_config
                if not self.automation_enabled or stop_event is not self.automation_stop_event or config is None:
                    break
                generation = self.automation_generation
                self.automation_next_run_at = None
                family = str(config["family"])
                use_tls = bool(config["use_tls"])
                bandwidth = int(config["bandwidth"])
            started, message = self.start_scan(
                family=family,
                use_tls=use_tls,
                bandwidth=bandwidth,
                _scheduled_generation=generation,
            )
            if not started:
                self._log(f"自动优选未启动：{message}")
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

    def inspect_dns(
        self,
        *,
        api_token: str,
        zone_id: str,
        record_name: str,
    ) -> dict[str, object]:
        token = api_token.strip()
        if not token or token != api_token or len(token) > 4096 or any(ch in token for ch in "\r\n"):
            raise CloudflareDnsError("Cloudflare API Token 无效", code="invalid_token")
        with self.dns_write_lock:
            with self.lock:
                if self.status != "completed" or self.result is None:
                    raise CloudflareDnsError("请先完成一次优选", code="result_unavailable")
                champion_ip = self.result.ip
                self.dns_write_in_progress = True
            try:
                client = CloudflareDnsClient(token)
                plan = client.inspect_sync(
                    zone_id=zone_id,
                    record_name=record_name,
                    champion_ip=champion_ip,
                )
            finally:
                with self.lock:
                    self.dns_write_in_progress = False
        plan_id = secrets.token_urlsafe(24)
        with self.lock:
            if self.result is None or self.result.ip != champion_ip:
                raise CloudflareDnsError("优选结果已变化，请重新预览", code="result_changed")
            now = time.monotonic()
            self.pending_dns = {
                key: value
                for key, value in self.pending_dns.items()
                if now - float(value.get("created_at", 0.0)) <= DNS_PLAN_TTL_SECONDS
            }
            self.pending_dns[plan_id] = {
                "created_at": now,
                "api_token": token,
                "zone_id": plan.zone_id,
                "record_name": plan.record_name,
                "champion_ip": plan.champion_ip,
                "fingerprint": plan.fingerprint,
            }
        value = plan.to_dict()
        value["plan_id"] = plan_id
        return value

    def apply_dns(self, plan_id: str) -> dict[str, object]:
        with self.dns_write_lock:
            with self.lock:
                pending = self.pending_dns.pop(plan_id, None)
                if pending is None:
                    raise CloudflareDnsError("DNS 预览已失效，请重新预览", code="invalid_plan")
                if time.monotonic() - float(pending["created_at"]) > DNS_PLAN_TTL_SECONDS:
                    raise CloudflareDnsError("DNS 预览已过期，请重新预览", code="expired_plan")
                if self.status != "completed" or self.result is None or self.result.ip != pending["champion_ip"]:
                    raise CloudflareDnsError("优选结果已变化，请重新预览", code="result_changed")
                self.dns_write_in_progress = True
            try:
                client = CloudflareDnsClient(str(pending["api_token"]))
                result = client.apply_sync(
                    zone_id=str(pending["zone_id"]),
                    record_name=str(pending["record_name"]),
                    champion_ip=str(pending["champion_ip"]),
                    expected_fingerprint=str(pending["fingerprint"]),
                    confirm_create=True,
                )
            finally:
                with self.lock:
                    self.dns_write_in_progress = False
        return result.to_dict()


def _loopback_host(value: str) -> bool:
    raw = value.strip().lower()
    if raw in {"::1", "[::1]"}:
        return True
    host = raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw
    host = host.strip("[]")
    return host in {"127.0.0.1", "localhost", "::1"}


def make_handler(
    state: RuntimeState,
    request_token: str,
    allowed_hosts: set[str],
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "RR-Edge-Hunter"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _host_allowed(self) -> bool:
            raw = self.headers.get("Host", "")
            host = raw
            if raw.startswith("["):
                host = raw[1:raw.find("]")] if "]" in raw else ""
            elif ":" in raw:
                host = raw.rsplit(":", 1)[0]
            return host.lower() in allowed_hosts

        def _json(self, value: object, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST, *, code: str = "invalid_request") -> None:
            self._json({"ok": False, "error": message, "code": code}, status)

        def _body(self) -> dict[str, object]:
            raw_length = self.headers.get("Content-Length", "")
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("请求长度无效") from exc
            if not 0 <= length <= MAX_REQUEST_BYTES:
                raise ValueError("请求内容过大")
            try:
                value = json.loads(self.rfile.read(length))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("请求 JSON 无效") from exc
            if not isinstance(value, dict):
                raise ValueError("请求必须是 JSON 对象")
            return value

        def _authorized_post(self) -> bool:
            if not self._host_allowed():
                self._error("Host 无效", HTTPStatus.FORBIDDEN, code="invalid_host")
                return False
            supplied = self.headers.get("X-RR-Request-Token", "")
            if not secrets.compare_digest(supplied, request_token):
                self._error("请求令牌无效", HTTPStatus.FORBIDDEN, code="invalid_token")
                return False
            return True

        def _static(self, name: str) -> None:
            path = WEB_DIR / name
            if not path.is_file() or path.parent != WEB_DIR:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            body = path.read_bytes()
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if not self._host_allowed():
                self._error("Host 无效", HTTPStatus.FORBIDDEN, code="invalid_host")
                return
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/config":
                self._json({
                    "version": VERSION,
                    "request_token": request_token,
                    "defaults": {"family": "ipv4", "use_tls": False, "bandwidth": 1},
                    "engine": "better-cloudflare-ip 原版程序",
                    "automation": {
                        "interval_hours": list(AUTOMATION_INTERVAL_HOURS),
                        "first_run_immediate": True,
                    },
                })
            elif path == "/api/status":
                self._json(state.snapshot())
            elif path in {"/", "/index.html"}:
                self._static("index.html")
            elif path == "/app.js":
                self._static("app.js")
            elif path == "/app.css":
                self._static("app.css")
            else:
                self.send_error(HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            if not self._authorized_post():
                return
            try:
                body = self._body()
                path = urllib.parse.urlsplit(self.path).path
                if path == "/api/start":
                    if set(body) != {"family", "use_tls", "bandwidth"}:
                        raise ValueError("只接受 IP 协议、连接方式和期望带宽")
                    family = body.get("family")
                    use_tls = body.get("use_tls")
                    bandwidth = body.get("bandwidth")
                    if family not in {"ipv4", "ipv6"}:
                        raise ValueError("IP 协议无效")
                    if not isinstance(use_tls, bool):
                        raise ValueError("连接方式无效")
                    if isinstance(bandwidth, bool) or not isinstance(bandwidth, int) or bandwidth <= 0:
                        raise ValueError("期望带宽必须是大于 0 的整数")
                    ok, message = state.start_scan(
                        family=str(family),
                        use_tls=use_tls,
                        bandwidth=bandwidth,
                    )
                    self._json({"ok": ok, "message": message}, HTTPStatus.OK if ok else HTTPStatus.CONFLICT)
                elif path == "/api/automation/start":
                    if set(body) != {
                        "family",
                        "use_tls",
                        "bandwidth",
                        "interval_hours",
                        "dns_sync",
                        "dns_write_confirmed",
                    }:
                        raise ValueError("自动测试参数无效")
                    family = body.get("family")
                    use_tls = body.get("use_tls")
                    bandwidth = body.get("bandwidth")
                    interval_hours = body.get("interval_hours")
                    if family not in {"ipv4", "ipv6"}:
                        raise ValueError("IP 协议无效")
                    if not isinstance(use_tls, bool):
                        raise ValueError("连接方式无效")
                    if isinstance(bandwidth, bool) or not isinstance(bandwidth, int) or bandwidth <= 0:
                        raise ValueError("期望带宽必须是大于 0 的整数")
                    if (
                        isinstance(interval_hours, bool)
                        or not isinstance(interval_hours, int)
                        or interval_hours not in AUTOMATION_INTERVAL_HOURS
                    ):
                        raise ValueError("请选择有效的自动测试时长")
                    raw_dns = body.get("dns_sync")
                    if raw_dns is None:
                        if body.get("dns_write_confirmed") is not False:
                            raise ValueError("未开启自动解析时不能授权 DNS 写入")
                        dns_sync = None
                    else:
                        if body.get("dns_write_confirmed") is not True:
                            raise ValueError("请确认每轮只自动解析本轮唯一 IP")
                        dns_sync = _normalize_automatic_dns(raw_dns)
                    ok, message = state.start_automation(
                        family=str(family),
                        use_tls=use_tls,
                        bandwidth=bandwidth,
                        interval_hours=interval_hours,
                        dns_sync=dns_sync,
                    )
                    self._json({"ok": ok, "message": message}, HTTPStatus.OK if ok else HTTPStatus.CONFLICT)
                elif path == "/api/stop":
                    if body:
                        raise ValueError("停止请求不接受额外参数")
                    ok, message = state.stop()
                    self._json({"ok": ok, "message": message}, HTTPStatus.OK if ok else HTTPStatus.CONFLICT)
                elif path == "/api/update":
                    if body:
                        raise ValueError("更新请求不接受额外参数")
                    ok, message = state.start_update()
                    self._json({"ok": ok, "message": message}, HTTPStatus.OK if ok else HTTPStatus.CONFLICT)
                elif path == "/api/dns/inspect":
                    if set(body) != {"api_token", "zone_id", "record_name"}:
                        raise ValueError("DNS 预览参数无效")
                    plan = state.inspect_dns(
                        api_token=str(body.get("api_token", "")),
                        zone_id=str(body.get("zone_id", "")),
                        record_name=str(body.get("record_name", "")),
                    )
                    self._json({"ok": True, "plan": plan})
                elif path == "/api/dns/apply":
                    if set(body) != {"plan_id"}:
                        raise ValueError("DNS 确认参数无效")
                    plan_id = str(body.get("plan_id", ""))
                    if not plan_id:
                        raise ValueError("DNS 预览凭据无效")
                    result = state.apply_dns(plan_id)
                    self._json({"ok": True, "result": result})
                else:
                    self.send_error(HTTPStatus.NOT_FOUND)
            except CloudflareDnsError as exc:
                self._error(exc.message, code=exc.code)
            except ValueError as exc:
                self._error(str(exc))
            except Exception as exc:
                self._error(f"{type(exc).__name__}: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR, code="internal")

    return Handler


def serve(host: str = "127.0.0.1", port: int = 0, *, open_browser: bool = True) -> None:
    if not _loopback_host(host):
        raise ValueError("桌面界面只能监听本机回环地址")
    request_token = secrets.token_urlsafe(32)
    state = RuntimeState()
    allowed_hosts = {"127.0.0.1", "localhost", "::1"}
    server = ThreadingHTTPServer((host, port), make_handler(state, request_token, allowed_hosts))
    address = server.server_address
    url = f"http://127.0.0.1:{address[1]}/"
    print(f"RR Edge Hunter 本机界面：{url}")
    if open_browser:
        threading.Timer(0.25, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        state.stop()
    finally:
        server.server_close()
