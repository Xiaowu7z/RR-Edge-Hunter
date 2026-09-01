from __future__ import annotations

import base64
import copy
import dataclasses
import ipaddress
import json
import re
import urllib.parse
import uuid

from .hostnames import HostnameError, normalize_hostname


SUPPORTED_TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}


@dataclasses.dataclass(frozen=True)
class NodeRouteTemplate:
    protocol: str
    sni: str
    host_header: str
    port: int
    ws_path: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "sni": self.sni,
            "host_header": self.host_header,
            "port": self.port,
            "ws_path": self.ws_path,
            "safe_summary": f"{self.protocol} · {self.sni}:{self.port} · WS Path 已识别",
        }


@dataclasses.dataclass(frozen=True, repr=False)
class NodeProfile:
    """One full local Xray outbound. The credential-bearing JSON is never public."""

    route: NodeRouteTemplate
    outbound_json: str = dataclasses.field(repr=False)

    def __repr__(self) -> str:
        return f"NodeProfile(route={self.route!r}, outbound_json=<redacted>)"

    def outbound_for(self, candidate_ip: str) -> dict[str, object]:
        try:
            normalized = str(ipaddress.ip_address(candidate_ip))
        except ValueError as exc:
            raise ValueError("候选不是有效 IP") from exc
        outbound = json.loads(self.outbound_json)
        settings = outbound.get("settings") if isinstance(outbound, dict) else None
        vnext = settings.get("vnext") if isinstance(settings, dict) else None
        if not isinstance(vnext, list) or len(vnext) != 1 or not isinstance(vnext[0], dict):
            raise ValueError("节点地址结构无效")
        vnext[0]["address"] = normalized
        return copy.deepcopy(outbound)


def _path(value: object) -> str:
    raw = str(value or "").strip() or "/"
    if (
        len(raw) > 1024
        or not raw.startswith("/")
        or raw.startswith("//")
        or "\\" in raw
        or "#" in raw
        or any(character.isspace() or ord(character) < 0x20 or ord(character) > 0x7E for character in raw)
        or re.search(r"%(?![0-9A-Fa-f]{2})", raw)
    ):
        raise ValueError("WS Path 格式无效")
    return raw


def _host(value: object) -> str:
    try:
        return normalize_hostname(str(value or "").split(",", 1)[0].strip())
    except HostnameError as exc:
        raise ValueError(f"节点 SNI/Host 无效：{exc}") from exc


def _build(protocol: str, sni: object, host_header: object, port: object, ws_path: object) -> NodeRouteTemplate:
    try:
        normalized_port = int(port or 443)
    except (TypeError, ValueError) as exc:
        raise ValueError("节点端口无效") from exc
    if normalized_port not in SUPPORTED_TLS_PORTS:
        raise ValueError("节点端口必须是 Cloudflare HTTPS 端口：443/2053/2083/2087/2096/8443")
    normalized_sni = _host(sni)
    normalized_host = _host(host_header or normalized_sni)
    return NodeRouteTemplate(protocol, normalized_sni, normalized_host, normalized_port, _path(ws_path))


def _decode_vmess(value: str) -> dict[str, object]:
    encoded = value.split("://", 1)[1].split("#", 1)[0].strip().replace("-", "+").replace("_", "/")
    encoded += "=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        payload = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("VMess 节点 Base64/JSON 内容无效") from exc
    if not isinstance(payload, dict):
        raise ValueError("VMess 节点内容必须是 JSON 对象")
    return payload


def _stream_settings(*, sni: str, host: str, path: str, fingerprint: str = "", alpn: str = "") -> dict[str, object]:
    tls: dict[str, object] = {"serverName": sni, "allowInsecure": False}
    if fingerprint:
        tls["fingerprint"] = fingerprint
    protocols = [item.strip() for item in alpn.split(",") if item.strip()]
    if protocols:
        tls["alpn"] = protocols
    return {
        "network": "ws",
        "security": "tls",
        "tlsSettings": tls,
        "wsSettings": {"path": path, "headers": {"Host": host}},
    }


def _uuid(value: object) -> str:
    raw = str(value or "").strip()
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError) as exc:
        raise ValueError("节点 UUID 无效") from exc


def parse_node_profile(value: object) -> NodeProfile:
    raw = str(value or "").strip()
    lowered = raw.lower()
    if lowered.startswith("vmess://"):
        payload = _decode_vmess(raw)
        network = str(payload.get("net", "")).strip().lower()
        if network != "ws":
            raise ValueError("当前只支持 VMess/VLESS 的 WebSocket 节点")
        security = str(payload.get("tls") or payload.get("security") or "").strip().lower()
        if security not in {"tls", "xtls"}:
            raise ValueError("节点必须启用 TLS，才能验证 Cloudflare Argo 入口")
        raw_host = str(payload.get("host", "")).split(",", 1)[0].strip()
        raw_sni = str(payload.get("sni") or raw_host or payload.get("add") or "").strip()
        route = _build("VMess", raw_sni, raw_host or raw_sni, payload.get("port", 443), payload.get("path", "/"))
        original_address = str(payload.get("add") or "").strip()
        if not original_address or len(original_address) > 253:
            raise ValueError("VMess 节点 server/address 无效")
        user_id = _uuid(payload.get("id"))
        try:
            alter_id = int(payload.get("aid") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("VMess alterId 无效") from exc
        if alter_id < 0 or alter_id > 65535:
            raise ValueError("VMess alterId 无效")
        outbound = {
            "tag": "rr-node",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": original_address,
                    "port": route.port,
                    "users": [{
                        "id": user_id,
                        "alterId": alter_id,
                        "security": str(payload.get("scy") or "auto").strip() or "auto",
                    }],
                }],
            },
            "streamSettings": _stream_settings(
                sni=route.sni,
                host=route.host_header,
                path=route.ws_path,
                fingerprint=str(payload.get("fp") or "").strip(),
                alpn=str(payload.get("alpn") or "").strip(),
            ),
        }
        return NodeProfile(route, json.dumps(outbound, ensure_ascii=False, separators=(",", ":")))
    if lowered.startswith("vless://"):
        try:
            parsed = urllib.parse.urlsplit(raw.split("#", 1)[0])
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=False)
            first = lambda name: query.get(name, [""])[0]
            network = first("type").strip().lower() or "tcp"
            security = first("security").strip().lower()
            raw_host = first("host").split(",", 1)[0].strip()
            raw_sni = first("sni").strip() or raw_host or (parsed.hostname or "")
            port = parsed.port or 443
        except (ValueError, UnicodeError) as exc:
            raise ValueError("VLESS 节点链接格式无效") from exc
        if network != "ws":
            raise ValueError("当前只支持 VMess/VLESS 的 WebSocket 节点")
        if security not in {"tls", "xtls"}:
            raise ValueError("节点必须启用 TLS，不能是 Reality 或明文节点")
        route = _build("VLESS", raw_sni, raw_host or raw_sni, port, first("path") or "/")
        user_id = _uuid(urllib.parse.unquote(parsed.username or ""))
        original_address = parsed.hostname or ""
        if not original_address:
            raise ValueError("VLESS 节点 server/address 无效")
        user: dict[str, object] = {
            "id": user_id,
            "encryption": first("encryption").strip() or "none",
        }
        flow = first("flow").strip()
        if flow:
            user["flow"] = flow
        outbound = {
            "tag": "rr-node",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": original_address,
                    "port": route.port,
                    "users": [user],
                }],
            },
            "streamSettings": _stream_settings(
                sni=route.sni,
                host=route.host_header,
                path=route.ws_path,
                fingerprint=first("fp").strip(),
                alpn=first("alpn").strip(),
            ),
        }
        return NodeProfile(route, json.dumps(outbound, ensure_ascii=False, separators=(",", ":")))
    raise ValueError("请粘贴完整的 vmess:// 或 vless:// 节点链接")


def parse_node_link(value: object) -> NodeRouteTemplate:
    return parse_node_profile(value).route


__all__ = ["NodeProfile", "NodeRouteTemplate", "parse_node_link", "parse_node_profile"]
