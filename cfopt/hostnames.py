from __future__ import annotations

import ipaddress
import re
import urllib.parse


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class HostnameError(ValueError):
    """Raised when a hostname is not safe for SNI or DNS use."""


def normalize_hostname(value: object) -> str:
    """Return a canonical fully-qualified ASCII hostname.

    The UI accepts a hostname and, for convenience, an HTTP(S) URL.  IP literals,
    wildcard labels, credentials, and one-label names are intentionally rejected.
    """
    raw = str(value or "").strip().strip("\"'`[](){}<>").rstrip(".")
    if not raw:
        raise HostnameError("域名为空")
    if raw.startswith("*."):
        raise HostnameError("不支持通配符域名")

    parsed_host = ""
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise HostnameError("只接受域名或 HTTP/HTTPS 地址")
        parsed_host = parsed.hostname
    elif any(char in raw for char in "/?#"):
        parsed = urllib.parse.urlsplit("//" + raw)
        parsed_host = parsed.hostname or ""
    elif raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            parsed_host = host
    raw = (parsed_host or raw).strip().rstrip(".").lower()

    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise HostnameError("IP 地址不能作为域名")

    try:
        ascii_name = raw.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError) as exc:
        raise HostnameError("域名编码无效") from exc
    if len(ascii_name) > 253 or "." not in ascii_name:
        raise HostnameError("请输入完整域名")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in ascii_name.split(".")):
        raise HostnameError("域名格式无效")
    return ascii_name
