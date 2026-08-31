from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
DEFAULT_TIMEOUT_SECONDS = 12.0
DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024
MAX_LIST_PAGES = 10
MAX_ZONE_DISCOVERY_QUERIES = 20

_ZONE_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RECORD_ID_RE = _ZONE_ID_RE


class CloudflareDnsError(Exception):
    """A deliberately sanitized error safe to show in the local UI."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "cloudflare_dns_error",
        http_status: int | None = None,
        transient: bool = False,
        pause_dns_automation: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.http_status = http_status
        self.transient = transient
        self.pause_dns_automation = pause_dns_automation

    def to_dict(self) -> dict[str, Any]:
        # Never include request headers, response bodies, or the API token here.
        return {
            "code": self.code,
            "message": self.message,
            "http_status": self.http_status,
            "transient": self.transient,
            "pause_dns_automation": self.pause_dns_automation,
        }


class _TransportError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        # Authorization must never follow a Location header away from the
        # fixed Cloudflare API origin. Normal API calls do not require 3xx.
        return None


class UrlLibTransport:
    """Small bounded urllib transport used by the packaged desktop app."""

    def __init__(self) -> None:
        # Never expose the Bearer token to HTTP(S)_PROXY inherited from the
        # desktop environment. DNS writes only connect to Cloudflare directly.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
        )

    @staticmethod
    def _read_bounded(stream: Any, max_response_bytes: int) -> bytes:
        header_value = stream.headers.get("Content-Length") if stream.headers else None
        if header_value:
            try:
                if int(header_value) > max_response_bytes:
                    raise _TransportError("response_too_large")
            except ValueError:
                pass
        value = stream.read(max_response_bytes + 1)
        if len(value) > max_response_bytes:
            raise _TransportError("response_too_large")
        return value

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HttpResponse:
        request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                return HttpResponse(int(response.status), self._read_bounded(response, max_response_bytes))
        except urllib.error.HTTPError as exc:
            try:
                body_value = self._read_bounded(exc, max_response_bytes)
            finally:
                exc.close()
            return HttpResponse(int(exc.code), body_value)
        except _TransportError:
            raise
        except (TimeoutError, socket.timeout) as exc:
            raise _TransportError("timeout") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise _TransportError("network") from exc


@dataclass(frozen=True)
class DnsSyncPlan:
    zone_id: str
    zone_name: str
    record_name: str
    record_type: str
    champion_ip: str
    action: str
    fingerprint: str
    record_id: str = ""
    previous_content: str = ""
    previous_ttl: int | None = None
    previous_proxied: bool | None = None

    @property
    def requires_create_confirmation(self) -> bool:
        return self.action == "create"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["requires_create_confirmation"] = self.requires_create_confirmation
        return value


@dataclass(frozen=True)
class DnsSyncResult:
    action: str
    zone_id: str
    zone_name: str
    record_id: str
    record_name: str
    record_type: str
    content: str
    ttl: int = 1
    proxied: bool = False
    verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _RecordState:
    record_id: str
    content: str
    ttl: int | None
    proxied: bool | None

    def fingerprint_value(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "content": self.content,
            "ttl": self.ttl,
            "proxied": self.proxied,
        }


def normalize_zone_id(value: object) -> str:
    zone_id = str(value or "").strip().lower()
    if not _ZONE_ID_RE.fullmatch(zone_id):
        raise CloudflareDnsError("Zone ID 必须是 32 位十六进制字符串", code="invalid_zone_id")
    return zone_id


def normalize_record_name(value: object) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw or len(raw) > 253 or "://" in raw or any(mark in raw for mark in ("/", "?", "#", "@", "*")):
        raise CloudflareDnsError("记录名必须是完整域名，不能包含 URL、端口、路径或通配符", code="invalid_record_name")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise CloudflareDnsError("记录名必须是完整域名，不能填写 IP", code="invalid_record_name")
    try:
        normalized = raw.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise CloudflareDnsError("记录名不是有效域名", code="invalid_record_name") from None
    labels = normalized.split(".")
    if len(labels) < 2 or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise CloudflareDnsError("记录名不是有效的完整域名", code="invalid_record_name")
    return normalized


def normalize_champion_ip(value: object) -> tuple[str, str]:
    raw = str(value or "").strip()
    if not raw or "%" in raw:
        raise CloudflareDnsError("冠军 IP 无效", code="invalid_ip")
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        raise CloudflareDnsError("冠军 IP 无效", code="invalid_ip") from None
    if (
        not parsed.is_global
        or parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    ):
        raise CloudflareDnsError("冠军 IP 必须是公网单播地址", code="invalid_ip")
    normalized = str(parsed)
    return normalized, "A" if parsed.version == 4 else "AAAA"


class CloudflareDnsClient:
    """Inspect and safely apply a DNS-only A/AAAA record change.

    The two-step API is intentional: ``inspect_sync`` produces a preview and a
    fingerprint. ``apply_sync`` re-inspects the record and refuses to write if
    it changed between preview and confirmation. Cloudflare does not expose a
    conditional ETag/CAS for this endpoint, so the final recheck and mutation
    cannot be globally atomic against simultaneous Dashboard/API writers; an
    immediate readback detects that residual race instead of hiding it.
    """

    def __init__(
        self,
        api_token: str,
        *,
        transport: HttpTransport | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        token = str(api_token or "")
        if not token.strip() or token != token.strip() or "\r" in token or "\n" in token or len(token) > 4096:
            raise CloudflareDnsError("Cloudflare API Token 无效", code="invalid_token")
        if not 1.0 <= float(timeout_seconds) <= 60.0:
            raise CloudflareDnsError("Cloudflare API 超时时间无效", code="invalid_timeout")
        if not 1024 <= int(max_response_bytes) <= 2 * 1024 * 1024:
            raise CloudflareDnsError("Cloudflare API 响应大小上限无效", code="invalid_response_limit")
        self.__api_token = token
        self._transport = transport or UrlLibTransport()
        self._timeout_seconds = float(timeout_seconds)
        self._max_response_bytes = int(max_response_bytes)

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, object] | None = None,
        payload: Mapping[str, object] | None = None,
    ) -> dict[str, Any]:
        url = CLOUDFLARE_API_BASE + path
        if query:
            url += "?" + urllib.parse.urlencode({key: str(value) for key, value in query.items()})
        body = None if payload is None else json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.__api_token}",
            "User-Agent": "RR-Edge-Hunter/Cloudflare-DNS",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            response = self._transport.request(
                method,
                url,
                headers,
                body,
                timeout_seconds=self._timeout_seconds,
                max_response_bytes=self._max_response_bytes,
            )
        except _TransportError as exc:
            if exc.code == "response_too_large":
                raise CloudflareDnsError("Cloudflare API 响应超过安全大小上限", code="response_too_large") from None
            if exc.code == "timeout":
                raise CloudflareDnsError("Cloudflare API 连接超时；本轮不会重试写入", code="timeout", transient=True) from None
            raise CloudflareDnsError("无法连接 Cloudflare API；本轮不会重试写入", code="network", transient=True) from None
        except Exception:
            # A custom/injected transport must not be able to leak headers or
            # the token through its exception text.
            raise CloudflareDnsError("Cloudflare API 请求失败；本轮不会重试写入", code="transport", transient=True) from None

        if (
            not isinstance(response, HttpResponse)
            or isinstance(response.status, bool)
            or not isinstance(response.status, int)
            or not isinstance(response.body, bytes)
        ):
            raise CloudflareDnsError("Cloudflare API 传输层返回无效响应", code="protocol")
        if len(response.body) > self._max_response_bytes:
            raise CloudflareDnsError("Cloudflare API 响应超过安全大小上限", code="response_too_large")
        status = int(response.status)
        if status in {401, 403}:
            raise CloudflareDnsError(
                "Cloudflare API 鉴权失败；已请求暂停 DNS 自动写入",
                code="auth_failed",
                http_status=status,
                pause_dns_automation=True,
            )
        if status == 429:
            raise CloudflareDnsError(
                "Cloudflare API 请求频率受限；本轮不会重试写入",
                code="rate_limited",
                http_status=status,
                transient=True,
            )
        if status >= 500:
            raise CloudflareDnsError(
                "Cloudflare API 暂时不可用；本轮不会重试写入",
                code="server_error",
                http_status=status,
                transient=True,
            )
        if not 200 <= status < 300:
            raise CloudflareDnsError(
                f"Cloudflare API 拒绝了请求（HTTP {status}）",
                code="api_rejected",
                http_status=status,
            )
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CloudflareDnsError("Cloudflare API 返回了无效 JSON", code="protocol") from None
        if not isinstance(value, dict) or value.get("success") is not True:
            raise CloudflareDnsError("Cloudflare API 未确认请求成功", code="api_rejected", http_status=status)
        return value

    @staticmethod
    def _zone_candidates(record_name: str) -> list[str]:
        labels = record_name.split(".")
        return [".".join(labels[index:]) for index in range(len(labels) - 1)]

    def _resolve_zone(self, record_name: str, zone_id: object | None) -> tuple[str, str]:
        if str(zone_id or "").strip():
            return normalize_zone_id(zone_id), ""
        candidates = self._zone_candidates(record_name)
        if len(candidates) > MAX_ZONE_DISCOVERY_QUERIES:
            raise CloudflareDnsError("记录名层级过多，请手动填写 Zone ID", code="zone_discovery_limit")
        for candidate in candidates:
            response = self._request_json(
                "GET",
                "/zones",
                query={"name": candidate, "status": "active", "per_page": 50, "page": 1},
            )
            rows = response.get("result")
            if not isinstance(rows, list):
                raise CloudflareDnsError("Cloudflare API Zone 响应格式无效", code="protocol")
            exact: list[dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, dict):
                    raise CloudflareDnsError("Cloudflare API Zone 响应格式无效", code="protocol")
                try:
                    api_name = normalize_record_name(row.get("name", ""))
                except CloudflareDnsError:
                    continue
                if api_name == candidate and row.get("status") == "active":
                    exact.append(row)
            if len(exact) > 1:
                raise CloudflareDnsError("找到多个同名活动 Zone，请手动填写 Zone ID", code="ambiguous_zone")
            if exact:
                return normalize_zone_id(exact[0].get("id")), candidate
        raise CloudflareDnsError("无法从记录名找到唯一活动 Zone，请填写 Zone ID", code="zone_not_found")

    def _list_exact_records(self, zone_id: str, record_name: str, record_type: str) -> list[_RecordState]:
        exact: list[_RecordState] = []
        page = 1
        total_pages = 1
        while page <= total_pages:
            response = self._request_json(
                "GET",
                f"/zones/{zone_id}/dns_records",
                query={
                    "type": record_type,
                    "name.exact": record_name,
                    "match": "all",
                    "per_page": 100,
                    "page": page,
                },
            )
            rows = response.get("result")
            if not isinstance(rows, list):
                raise CloudflareDnsError("Cloudflare API DNS 记录响应格式无效", code="protocol")
            for row in rows:
                if not isinstance(row, dict):
                    raise CloudflareDnsError("Cloudflare API DNS 记录响应格式无效", code="protocol")
                try:
                    api_name = normalize_record_name(row.get("name", ""))
                except CloudflareDnsError:
                    continue
                if api_name != record_name or str(row.get("type", "")).upper() != record_type:
                    continue
                record_id = str(row.get("id", "")).lower()
                if not _RECORD_ID_RE.fullmatch(record_id):
                    raise CloudflareDnsError("Cloudflare API 返回了无效记录 ID", code="protocol")
                raw_ttl = row.get("ttl")
                ttl = raw_ttl if isinstance(raw_ttl, int) and not isinstance(raw_ttl, bool) else None
                raw_proxied = row.get("proxied")
                proxied = raw_proxied if isinstance(raw_proxied, bool) else None
                content = str(row.get("content", ""))
                if record_type in {"A", "AAAA"}:
                    try:
                        parsed_content = ipaddress.ip_address(content)
                        if (record_type == "A" and parsed_content.version == 4) or (
                            record_type == "AAAA" and parsed_content.version == 6
                        ):
                            content = str(parsed_content)
                    except ValueError:
                        pass
                exact.append(_RecordState(record_id, content, ttl, proxied))
                if len(exact) > 1:
                    return exact
            result_info = response.get("result_info", {})
            if isinstance(result_info, dict):
                raw_total_pages = result_info.get("total_pages", 1)
                if isinstance(raw_total_pages, int) and not isinstance(raw_total_pages, bool) and raw_total_pages > 0:
                    total_pages = raw_total_pages
            if total_pages > MAX_LIST_PAGES:
                raise CloudflareDnsError("DNS 记录分页过多，无法安全确认唯一记录", code="ambiguous_records")
            page += 1
        return exact

    @staticmethod
    def _fingerprint(
        zone_id: str,
        record_name: str,
        record_type: str,
        champion_ip: str,
        current: _RecordState | None,
    ) -> str:
        value = {
            "zone_id": zone_id,
            "record_name": record_name,
            "record_type": record_type,
            "champion_ip": champion_ip,
            "current": current.fingerprint_value() if current else None,
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def inspect_sync(
        self,
        *,
        record_name: object,
        champion_ip: object,
        zone_id: object | None = None,
    ) -> DnsSyncPlan:
        normalized_name = normalize_record_name(record_name)
        normalized_ip, record_type = normalize_champion_ip(champion_ip)
        normalized_zone_id, zone_name = self._resolve_zone(normalized_name, zone_id)

        cname_records = self._list_exact_records(normalized_zone_id, normalized_name, "CNAME")
        if cname_records:
            raise CloudflareDnsError(
                "该记录名已存在 CNAME；A/AAAA 不能与 CNAME 共存，请先人工处理，工具不会自动删除",
                code="cname_conflict",
            )
        ns_records = self._list_exact_records(normalized_zone_id, normalized_name, "NS")
        if ns_records:
            raise CloudflareDnsError(
                "该记录名已存在 NS；NS 不能与 A/AAAA 共存，请先人工处理，工具不会自动删除",
                code="ns_conflict",
            )
        records = self._list_exact_records(normalized_zone_id, normalized_name, record_type)
        if len(records) > 1:
            raise CloudflareDnsError(
                f"找到多个同名 {record_type} 记录；为避免破坏轮询，工具拒绝自动修改",
                code="multiple_records",
            )
        current = records[0] if records else None
        if current is None:
            action = "create"
        elif current.content == normalized_ip and current.ttl == 1 and current.proxied is False:
            action = "unchanged"
        else:
            action = "update"
        return DnsSyncPlan(
            zone_id=normalized_zone_id,
            zone_name=zone_name,
            record_name=normalized_name,
            record_type=record_type,
            champion_ip=normalized_ip,
            action=action,
            fingerprint=self._fingerprint(normalized_zone_id, normalized_name, record_type, normalized_ip, current),
            record_id=current.record_id if current else "",
            previous_content=current.content if current else "",
            previous_ttl=current.ttl if current else None,
            previous_proxied=current.proxied if current else None,
        )

    def apply_sync(
        self,
        *,
        record_name: object,
        champion_ip: object,
        expected_fingerprint: object,
        zone_id: object | None = None,
        confirm_create: bool = False,
    ) -> DnsSyncResult:
        expected = str(expected_fingerprint or "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise CloudflareDnsError("DNS 变更预览凭据无效，请重新检查", code="invalid_plan")
        current = self.inspect_sync(record_name=record_name, champion_ip=champion_ip, zone_id=zone_id)
        if not hmac.compare_digest(current.fingerprint, expected):
            raise CloudflareDnsError("DNS 记录在预览后发生变化，请重新检查并确认", code="plan_changed")
        if current.action == "create" and confirm_create is not True:
            raise CloudflareDnsError(
                f"将创建新的 {current.record_type} 记录，必须二次确认后才能执行",
                code="create_confirmation_required",
            )
        if current.action == "unchanged":
            return DnsSyncResult(
                action="unchanged",
                zone_id=current.zone_id,
                zone_name=current.zone_name,
                record_id=current.record_id,
                record_name=current.record_name,
                record_type=current.record_type,
                content=current.champion_ip,
            )

        if current.action == "create":
            response = self._request_json(
                "POST",
                f"/zones/{current.zone_id}/dns_records",
                payload={
                    "type": current.record_type,
                    "name": current.record_name,
                    "content": current.champion_ip,
                    "ttl": 1,
                    "proxied": False,
                },
            )
            response_record = response.get("result")
            if not isinstance(response_record, dict) or not _RECORD_ID_RE.fullmatch(str(response_record.get("id", "")).lower()):
                raise CloudflareDnsError("Cloudflare API 未返回有效的新记录 ID", code="protocol")
            expected_record_id = str(response_record["id"]).lower()
            applied_action = "created"
        else:
            # PATCH only the fields owned by this feature. Comments, tags and
            # any future Cloudflare record settings remain untouched.
            self._request_json(
                "PATCH",
                f"/zones/{current.zone_id}/dns_records/{current.record_id}",
                payload={"content": current.champion_ip, "ttl": 1, "proxied": False},
            )
            expected_record_id = current.record_id
            applied_action = "updated"

        verified = self.inspect_sync(
            record_name=current.record_name,
            champion_ip=current.champion_ip,
            zone_id=current.zone_id,
        )
        if verified.action != "unchanged" or verified.record_id != expected_record_id:
            raise CloudflareDnsError(
                "Cloudflare API 写入后回读校验失败，请在控制台检查记录",
                code="verification_failed",
            )
        return DnsSyncResult(
            action=applied_action,
            zone_id=verified.zone_id,
            zone_name=current.zone_name,
            record_id=verified.record_id,
            record_name=verified.record_name,
            record_type=verified.record_type,
            content=verified.champion_ip,
        )
