from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import http.client
import io
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from email.message import Message
from typing import Callable, Iterable


MAX_SOURCE_BYTES = 1_048_576
MAX_IPS = 2_000
MAX_CIDR_SAMPLES = 96
MAX_PARSED_VALUES = 20_000
MAX_CSV_ROW_CHARS = 65_536
SUBSCRIPTION_TIMEOUT_SECONDS = 12
MAX_REDIRECTS = 3
MAX_CONCURRENT_SUBSCRIPTIONS = 2
_JSON_IP_KEYS = ("ip", "ips", "ip_address", "ipaddress", "address", "addresses", "server", "servers", "host", "hosts")
_JSON_LIST_KEYS = ("ips", "addresses", "items", "data", "results", "entries", "servers", "nodes")
_CSV_IP_HEADERS = {"ip", "ips", "ip_address", "ipaddress", "address", "addresses", "server", "host", "ip地址", "地址"}
_IP_PORT = re.compile(r"^([^:\s]+):(\d{1,5})$")
_SUBSCRIPTION_GATE = threading.BoundedSemaphore(MAX_CONCURRENT_SUBSCRIPTIONS)


class IpSourceError(ValueError):
    """Raised when an IP source cannot be parsed safely."""


@dataclass
class IpParseResult:
    ips: list[str]
    source_format: str
    ignored: int = 0
    cidr_count: int = 0
    sampled_cidrs: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "ips": self.ips,
            "count": len(self.ips),
            "source_format": self.source_format,
            "ignored": self.ignored,
            "cidr_count": self.cidr_count,
            "sampled_cidrs": self.sampled_cidrs,
            "warnings": self.warnings,
        }


def decode_ip_source_bytes(payload: bytes) -> str:
    if len(payload) > MAX_SOURCE_BYTES:
        raise IpSourceError("来源内容不能超过 1 MiB")
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise IpSourceError("来源编码无效；仅支持 UTF-8 或 GB18030 文本")


def _strip_token(value: object) -> str:
    raw = str(value or "").replace("\ufeff", "").strip()
    if not raw:
        return ""
    raw = raw.split("#", 1)[0].strip()
    raw = raw.split(";", 1)[0].strip()
    if raw.startswith(("http://", "https://", "tcp://", "tls://")):
        parsed = urllib.parse.urlsplit(raw)
        if parsed.hostname:
            try:
                port = parsed.port
            except ValueError as exc:
                raise IpSourceError("IP 端口无效") from exc
            if port not in (None, 443):
                raise IpSourceError("测速仅支持 HTTPS 443 端口")
            return parsed.hostname
    if raw.startswith("[") and "]" in raw:
        closing = raw.index("]")
        suffix = raw[closing + 1 :]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                raise IpSourceError("IP 端口格式无效")
            if suffix[1:] != "443":
                raise IpSourceError("测速仅支持 HTTPS 443 端口")
        return raw[1:closing]
    match = _IP_PORT.fullmatch(raw)
    if match and "." in match.group(1):
        if match.group(2) != "443":
            raise IpSourceError("测速仅支持 HTTPS 443 端口")
        return match.group(1)
    return raw


def normalize_ip(value: object) -> str:
    raw = _strip_token(value)
    if not raw:
        raise IpSourceError("IP 为空")
    if "/" in raw:
        raise IpSourceError("CIDR 需要按列表解析")
    try:
        address = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError as exc:
        raise IpSourceError("不是有效 IP") from exc
    if not address.is_global:
        raise IpSourceError("仅允许公网 IP 地址")
    return str(address)


def _cidr_values(value: object) -> tuple[list[str], bool]:
    raw = _strip_token(value)
    if "/" not in raw:
        return [normalize_ip(raw)], False
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise IpSourceError("CIDR 格式无效") from exc
    if not network.network_address.is_global:
        raise IpSourceError("仅允许公网 CIDR")
    values = _sample_network(network)
    if not values:
        raise IpSourceError("CIDR 未产生可用公网 IP")
    return values, network.num_addresses > len(values)


def _sample_network(network: ipaddress._BaseNetwork) -> list[str]:
    """Bound CIDR expansion deterministically to prevent IPv6/prefix explosions."""
    if network.version == 4 and network.prefixlen <= 30:
        start = int(network.network_address) + 1
        span = max(0, network.num_addresses - 2)
    else:
        start = int(network.network_address)
        span = network.num_addresses
    if span <= 0:
        return []
    count = min(MAX_CIDR_SAMPLES, span)
    if count == span:
        return [str(ipaddress.ip_address(start + offset)) for offset in range(count)]
    offsets: set[int] = {0, span - 1}
    cursor = 0
    while len(offsets) < count:
        digest = hashlib.blake2b(f"rr-edge-hunter:{network.with_prefixlen}:{cursor}".encode("utf-8"), digest_size=16).digest()
        offsets.add(int.from_bytes(digest, "big") % span)
        cursor += 1
    return [str(ipaddress.ip_address(start + offset)) for offset in sorted(offsets)]


def _walk_json(value: object, output: list[object] | None = None, depth: int = 0) -> list[object]:
    if depth > 64:
        raise IpSourceError("JSON 层级过深")
    output = output if output is not None else []
    if isinstance(value, str):
        if len(output) >= MAX_PARSED_VALUES:
            raise IpSourceError(f"来源字段不能超过 {MAX_PARSED_VALUES} 个")
        output.append(value)
    elif isinstance(value, list):
        for item in value:
            _walk_json(item, output, depth + 1)
    elif isinstance(value, dict):
        lowered = {str(key).strip().lower(): item for key, item in value.items()}
        visited: set[str] = set()
        for key in (*_JSON_IP_KEYS, *_JSON_LIST_KEYS):
            if key in visited:
                continue
            visited.add(key)
            if key in lowered:
                _walk_json(lowered[key], output, depth + 1)
    return output


def _csv_values(text: str) -> tuple[list[object], str] | None:
    if any(len(line) > MAX_CSV_ROW_CHARS for line in io.StringIO(text)):
        raise IpSourceError(f"CSV 单行不能超过 {MAX_CSV_ROW_CHARS} 个字符")
    sample = text[:16_384]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;")
    except csv.Error:
        dialect = csv.excel_tab if "\t" in sample else csv.excel
    try:
        stream = io.StringIO(text)
        reader = csv.reader(stream, dialect)
        header_row = next((row for row in reader if any(cell.strip() for cell in row)), None)
        if header_row is None:
            return None
        headers = [cell.strip().lower() for cell in header_row]
        indexes = [index for index, header in enumerate(headers) if header in _CSV_IP_HEADERS]
        if not indexes:
            return None
        values: list[object] = []
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue
            for index in indexes:
                if index < len(row):
                    values.append(row[index])
                    if len(values) > MAX_PARSED_VALUES:
                        raise IpSourceError(f"来源字段不能超过 {MAX_PARSED_VALUES} 个")
    except csv.Error as exc:
        raise IpSourceError("CSV 格式无效") from exc
    return values, "TSV" if dialect.delimiter == "\t" else "CSV"


def _plain_values(text: str) -> list[str]:
    values: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.lower().startswith(("ip ", "address ")):
            line = line.split(None, 1)[1]
        parts = re.split(r"[\s,|]+", line)
        for part in parts:
            if not part:
                continue
            values.append(part)
            if len(values) > MAX_PARSED_VALUES:
                raise IpSourceError(f"来源字段不能超过 {MAX_PARSED_VALUES} 个")
    return values


def _try_base64(text: str) -> str | None:
    compact = "".join(text.split())
    if len(compact) < 16 or len(compact) % 4:
        return None
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return decode_ip_source_bytes(decoded)
    except IpSourceError:
        return None


def parse_ip_source(text: object, filename: str = "") -> IpParseResult:
    if not isinstance(text, str):
        raise IpSourceError("来源必须是文本")
    if len(text.encode("utf-8", errors="ignore")) > MAX_SOURCE_BYTES:
        raise IpSourceError("来源内容不能超过 1 MiB")
    stripped = text.replace("\ufeff", "").strip()
    if not stripped:
        raise IpSourceError("来源内容为空")
    values: list[object]
    source_format = "TXT"
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = None
    except RecursionError as exc:
        raise IpSourceError("JSON 层级过深") from exc
    if payload is not None:
        values = _walk_json(payload)
        source_format = "JSON"
        if not values:
            raise IpSourceError("JSON 中未找到 ip/address/ips 等受支持字段")
    else:
        decoded = _try_base64(stripped)
        if decoded is not None:
            inner = parse_ip_source(decoded, filename)
            inner.source_format = f"Base64 + {inner.source_format}"
            return inner
        csv_result = _csv_values(stripped)
        if csv_result:
            values, source_format = csv_result
        else:
            values = _plain_values(stripped)
            suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
            if suffix in {"csv", "tsv", "json"}:
                source_format = f"TXT（内容与 .{suffix} 扩展名不一致）"

    ips: list[str] = []
    seen: set[str] = set()
    ignored = 0
    cidr_count = 0
    sampled_cidrs = 0
    for value in values:
        try:
            raw = _strip_token(value)
            cidr_count += int("/" in raw)
            normalized, sampled = _cidr_values(raw)
        except IpSourceError:
            ignored += 1
            continue
        sampled_cidrs += int(sampled)
        for item in normalized:
            if item in seen:
                continue
            seen.add(item)
            ips.append(item)
            if len(ips) > MAX_IPS:
                raise IpSourceError(f"单次最多载入 {MAX_IPS} 个 IP；CIDR 会被安全抽样")
    if not ips:
        raise IpSourceError("没有识别到有效公网 IP；支持 TXT、CSV、TSV、JSON、Base64、IP:端口和 CIDR")
    warnings: list[str] = []
    if ignored:
        warnings.append(f"已忽略 {ignored} 个无效、私网或保留字段")
    if sampled_cidrs:
        warnings.append(f"{sampled_cidrs} 个 CIDR 已按每段最多 {MAX_CIDR_SAMPLES} 个地址安全抽样")
    return IpParseResult(ips, source_format, ignored, cidr_count, sampled_cidrs, warnings)


def normalize_ip_values(values: Iterable[object]) -> list[str]:
    return parse_ip_source("\n".join(str(value) for value in values), "values.txt").ips


def _safe_public_destination(value: object) -> str:
    """Normalize an address only when it is safe to dial for a subscription.

    ``is_global`` alone is not sufficient for every Python/IP-version
    combination: deprecated IPv6 site-local addresses may otherwise sneak
    through.  Keep the explicit checks here so URL validation and the pinned
    dial path cannot drift apart.
    """
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError as exc:
        raise IpSourceError("订阅域名返回无效地址") from exc
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or (isinstance(address, ipaddress.IPv6Address) and address.is_site_local)
    ):
        raise IpSourceError("订阅链接不能指向本机、内网、保留或非公网地址")
    return str(address)


def _public_subscription_url(url: str, resolver: Callable[..., list[tuple]] = socket.getaddrinfo) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(url).strip())
    except ValueError as exc:
        raise IpSourceError("订阅链接格式无效") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise IpSourceError("订阅链接只支持 HTTPS")
    if parsed.username or parsed.password:
        raise IpSourceError("订阅链接不能包含账号或密码")
    try:
        port = parsed.port
    except ValueError as exc:
        raise IpSourceError("订阅链接端口无效") from exc
    if port not in {None, 443}:
        raise IpSourceError("订阅链接只允许 HTTPS 默认 443 端口")
    try:
        rows = resolver(parsed.hostname, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise IpSourceError("订阅域名解析失败") from exc
    addresses = {row[4][0].split("%", 1)[0] for row in rows}
    if not addresses:
        raise IpSourceError("订阅域名没有可用地址")
    for address in addresses:
        _safe_public_destination(address)
    return urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path or "/", parsed.query, ""))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection with DNS rebinding resistance and normal hostname validation."""

    def __init__(self, hostname: str, address: str, timeout: float) -> None:
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()
        assert self._context is not None
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _resolve_public_addresses(hostname: str, resolver: Callable[..., list[tuple]]) -> list[str]:
    try:
        rows = resolver(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise IpSourceError("订阅域名解析失败") from exc
    output: list[str] = []
    seen: set[str] = set()
    for row in rows:
        try:
            value = _safe_public_destination(row[4][0])
        except (IndexError, TypeError) as exc:
            raise IpSourceError("订阅域名返回无效地址") from exc
        if value not in seen:
            seen.add(value)
            output.append(value)
    if not output:
        raise IpSourceError("订阅域名没有可用地址")
    return output


def _read_limited_response(
    response: http.client.HTTPResponse,
    connection: http.client.HTTPSConnection,
    deadline: float,
) -> bytes:
    payload = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IpSourceError("订阅下载超过 12 秒，请稍后重试")
        sock = getattr(connection, "sock", None)
        if sock is not None:
            sock.settimeout(max(0.1, remaining))
        chunk = response.read(min(65_536, MAX_SOURCE_BYTES + 1 - len(payload)))
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > MAX_SOURCE_BYTES:
            raise IpSourceError("订阅内容不能超过 1 MiB")


def fetch_ip_subscription(
    url: str,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> tuple[IpParseResult, str]:
    if not _SUBSCRIPTION_GATE.acquire(blocking=False):
        raise IpSourceError("当前订阅下载较多，请稍后重试")
    try:
        return _fetch_ip_subscription(url, resolver=resolver)
    finally:
        _SUBSCRIPTION_GATE.release()


def _fetch_ip_subscription(
    url: str,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> tuple[IpParseResult, str]:
    current_url = _public_subscription_url(url, resolver)
    payload = b""
    disposition = ""
    deadline = time.monotonic() + SUBSCRIPTION_TIMEOUT_SECONDS
    for redirect_count in range(MAX_REDIRECTS + 1):
        safe_url = _public_subscription_url(current_url, resolver)
        parsed = urllib.parse.urlsplit(safe_url)
        addresses = _resolve_public_addresses(parsed.hostname or "", resolver)
        request_path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IpSourceError("订阅下载超过 12 秒，请稍后重试")
        connection = _PinnedHTTPSConnection(parsed.hostname or "", addresses[0], min(SUBSCRIPTION_TIMEOUT_SECONDS, max(0.1, remaining)))
        try:
            connection.request("GET", request_path, headers={"Accept": "text/plain, application/json, text/csv, application/octet-stream", "User-Agent": "RR-Edge-Hunter/0.1", "Connection": "close"})
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if deadline - time.monotonic() <= 0:
                    raise IpSourceError("订阅下载超过 12 秒，请稍后重试")
                # The connection is closed in ``finally``.  Do not drain an
                # attacker-controlled redirect body just to follow Location.
                if not location:
                    raise IpSourceError("订阅重定向缺少目标地址")
                if redirect_count >= MAX_REDIRECTS:
                    raise IpSourceError("订阅重定向次数超过 3 次")
                current_url = urllib.parse.urljoin(safe_url, location)
                continue
            if not 200 <= response.status < 300:
                raise IpSourceError(f"订阅链接返回 HTTP {response.status}")
            content_type = str(response.headers.get_content_type()).lower()
            if content_type == "text/html":
                raise IpSourceError("订阅链接返回了网页，不是 IP 列表")
            length = response.getheader("Content-Length")
            if length and int(length) > MAX_SOURCE_BYTES:
                raise IpSourceError("订阅内容不能超过 1 MiB")
            payload = _read_limited_response(response, connection, deadline)
            disposition = response.getheader("Content-Disposition", "")
            current_url = safe_url
            break
        except IpSourceError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            raise IpSourceError(f"订阅下载失败：{exc}") from exc
        finally:
            connection.close()
    else:
        raise IpSourceError("订阅重定向次数超过 3 次")
    text = decode_ip_source_bytes(payload)
    filename = "subscription"
    if disposition:
        message = Message()
        message["content-disposition"] = disposition
        filename = message.get_filename() or filename
    return parse_ip_source(text, filename), current_url


__all__ = [
    "IpParseResult",
    "IpSourceError",
    "MAX_CIDR_SAMPLES",
    "MAX_IPS",
    "MAX_SOURCE_BYTES",
    "decode_ip_source_bytes",
    "fetch_ip_subscription",
    "normalize_ip",
    "normalize_ip_values",
    "parse_ip_source",
]
